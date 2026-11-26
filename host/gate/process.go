package gate

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	stdlog "log"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"runtime"
	"runtime/metrics"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yongjohnlee80/golib/server/rpc"

	core "github.com/yongjohnlee80/autopanel/core/gate"
)

// THE GATE PROCESS — the part of AutoPanel that faces the internet. It serves
// :80 and :443 from a routing table and certificates the core hands it over
// the link, and holds nothing else: this file and its imports reach no store,
// no vault and no ACME client (a test holds that).

// Caller is a connection to the core's link socket.
type Caller interface {
	Call(ctx context.Context, verb string, param any, out any) error
	Close() error
}

// Dialer connects to the core's link socket.
type Dialer func(ctx context.Context) (Caller, error)

// ReportEvery is how often the gate sends its request counts to the core. A
// variable so a test need not wait.
var ReportEvery = 5 * time.Second

// certFresh is how long the gate serves a certificate before asking the core
// again. The core renews in the background; the gate picks the new one up at
// its next ask, so no invalidation crosses the link. A variable so a test need
// not wait an hour.
var certFresh = time.Hour

// freshUntil is when the gate asks the core again for a certificate it got at
// now: after certFresh, and no later than the certificate's end. A certificate
// not yet in the last third of its life is asked for again as that third
// begins, so the request that should start its renewal reaches the core then,
// not up to certFresh later.
func freshUntil(leaf *x509.Certificate, now time.Time) time.Time {
	fresh := now.Add(certFresh)
	if leaf.NotAfter.Before(fresh) {
		fresh = leaf.NotAfter
	}
	renewFrom := leaf.NotAfter.Add(-leaf.NotAfter.Sub(leaf.NotBefore) / 3)
	if now.Before(renewFrom) && renewFrom.Before(fresh) {
		fresh = renewFrom
	}
	return fresh
}

// errReconfigured is a core that now names other listen addresses than the
// gate is serving: the gate stops, and its unit starts it again on the new ones.
var errReconfigured = errors.New("gate: the core's listen addresses changed")

const acmeChallengePath = "/.well-known/acme-challenge/"

// acmeTLS1 is the ALPN protocol of a TLS-ALPN-01 challenge handshake (RFC 8737).
const acmeTLS1 = "acme-tls/1"

// Run serves the gate until ctx ends. It waits for the core's link socket to
// answer before it listens, since its addresses come from there; after that a
// core that stops takes nothing with it: the table and the certificates in
// hand keep serving, and the gate reconnects when the core is back.
func Run(ctx context.Context, dial Dialer, log *slog.Logger) error {
	l := &link{dial: dial}
	defer l.close()

	var hello Hello
	wait := newBackoff()
	for {
		err := l.call(ctx, VerbHello, nil, &hello)
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return nil
		}
		log.Warn("gate: waiting for the core", "err", err)
		if !wait.sleep(ctx) {
			return nil
		}
	}
	SetSiteSocket(hello.SiteSocket) // a site's route is served there, whatever a route says
	trusted, err := parseTrusted(hello.Trusted)
	if err != nil {
		return err
	}

	table := core.NewTable[http.Handler]()
	g := &process{link: l, log: log, table: table, hello: hello, trusted: trusted, streams: newForwarder(log),
		certs: &certCache{link: l, table: table, held: map[string]heldCert{}, flights: map[string]*flight{}}}
	g.trustedNow.Store(&trusted)
	g.api = newAPIServer(l, log, func() Trusted { return *g.trustedNow.Load() }, g.up.Load)
	g.certs.also = g.api.isHost // the API's host has a certificate, though no route names it
	g.tunnels = newTunnels(l, log)
	g.streams.tunnel = g.tunnels.dial
	tunnelTLS := g.tunnels.tlsConfig(g.certs.get)
	// The first table before the first request: a gate that listens with an
	// empty table answers 404 for every site.
	for {
		err := g.sync(ctx)
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return nil
		}
		log.Warn("gate: reading the routes", "err", err)
		if !wait.sleep(ctx) {
			return nil
		}
	}

	trustedNow := func() Trusted {
		if t := g.trustedNow.Load(); t != nil {
			return *t
		}
		return nil
	}
	httpsLn, err := listenBounded(ctx, hello.HTTPS, httpsConns, peerConns, trustedNow)
	if err != nil {
		return err
	}
	plainLn, err := listenBounded(ctx, hello.HTTP, plainConns, peerConns, trustedNow)
	if err != nil {
		_ = httpsLn.Close()
		return err
	}
	g.httpsLn, g.plainLn = httpsLn, plainLn
	srvLog := stdlog.New(&serverLog{log: log}, "", 0)
	g.inFlight = newInFlight(proxyInFlight, proxyPerClient)
	routes := proxied(g.inFlight, trustedNow, requestStall, upgradedStall, Handler(table))
	// A member's read of a site's document, on the app host: a proxied
	// request like any site's, under the same cap and the same clock.
	g.api.site = proxied(g.inFlight, trustedNow, requestStall, upgradedStall, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := NewProxy(core.SiteRoute(1, "site.local"), trustedNow(), nil)
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		p.ServeHTTP(w, r)
	}))
	https := &http.Server{
		Handler: g.tunnels.or(counted(&g.https, g.api.or(routes))), // no routes: every request is the gate's
		TLSConfig: &tls.Config{
			GetCertificate: g.certs.get,
			NextProtos:     []string{"h2", "http/1.1", acmeTLS1}, // HTTP's first; acme-tls/1 stays, for the TLS-ALPN challenge
			MinVersion:     tls.VersionTLS12,
			// An agent's handshake, and only that, gets the tunnel's settings:
			// no browser is asked for a certificate.
			GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
				if isTunnel(h) {
					return tunnelTLS, nil
				}
				return nil, nil
			},
		},
		ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: httpsHeaderBytes,
		ConnContext: connContext,
		HTTP2:       &http.HTTP2Config{MaxConcurrentStreams: h2Streams, MaxReceiveBufferPerStream: h2StreamWindow, MaxReceiveBufferPerConnection: h2ConnWindow, MaxReadFrameSize: h2FrameBytes},
		ErrorLog:    srvLog,
	}
	plain := &http.Server{
		Handler:           counted(&g.http, g.challengeOr(g.api.notPlain(http.HandlerFunc(toHTTPS)))),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 16 << 10, ErrorLog: srvLog, ConnContext: connContext,
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	g.tunnels.ctx = ctx
	defer g.tunnels.stopAll()
	var wg sync.WaitGroup
	errs := make(chan error, 6)
	run := func(name string, fn func(context.Context) error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := fn(ctx); err != nil && !errors.Is(err, context.Canceled) {
				errs <- fmt.Errorf("%s: %w", name, err)
				cancel()
			}
		}()
	}
	run("gate https", func(ctx context.Context) error { return serveUntil(ctx, https, httpsLn, true) })
	run("gate http", func(ctx context.Context) error { return serveUntil(ctx, plain, plainLn, false) })
	run("gate routes", g.follow)
	run("gate streams", g.followStreams)
	run("gate probes", g.streams.probes)
	run("gate tunnels", g.tunnels.follow)
	run("gate report", g.report)
	log.Info("gate serving", "https", hello.HTTPS, "http", hello.HTTP, "core", hello.Version, "routes", len(table.Routes()))
	<-ctx.Done()
	wg.Wait()
	close(errs)
	return <-errs // nil on a clean stop
}

// process is a running gate.
type process struct {
	link    *link
	log     *slog.Logger
	table   *Table
	certs   *certCache
	hello   Hello
	trusted Trusted
	rev     int64 // the table's revision; only sync and follow touch it, one at a time
	streams *forwarder
	api     *apiServer
	tunnels *tunnels

	trustedNow atomic.Pointer[Trusted] // trusted, for whoever reads it while follow may change it
	up         atomic.Bool             // the core answered the last time it was asked

	https, http atomic.Int64 // requests served, per listener

	httpsLn, plainLn *boundedListener
	inFlight         *inFlight // requests being proxied
}

func parseTrusted(prefixes []string) (Trusted, error) {
	var out Trusted
	for _, s := range prefixes {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("gate: the core sent a trusted proxy that is no prefix: %q", s)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// sync asks for the table after the revision in hand and swaps it in. It
// returns when the core answers: at once when the gate is behind, and
// otherwise when the table next changes. It is how a change reaches the gate
// without the core dialling it.
func (g *process) sync(ctx context.Context) error {
	var r Routes
	if err := g.link.call(ctx, VerbRoutes, After{After: g.rev}, &r); err != nil {
		return err
	}
	routes := make([]core.Route, 0, len(r.Routes))
	for _, v := range r.Routes {
		routes = append(routes, core.Route{ID: core.RouteID(v.ID), Host: v.Host, PathPrefix: v.PathPrefix, Upstream: v.Upstream})
	}
	g.rev = r.Rev // a table that cannot be built is not asked for again until it changes
	g.up.Store(true)
	if err := g.api.set(r.API); err != nil {
		g.log.Error("gate: API settings the gate cannot use; the old ones stay", "err", err)
	}
	if err := g.api.setApps(r.Apps); err != nil {
		g.log.Error("gate: the applications' settings the gate cannot use; the old ones stay", "err", err)
	}
	snap, err := Build(routes, g.trusted, g.tunnels.dial)
	if err != nil {
		g.log.Error("gate: a routing table the gate cannot build; the old one stays", "err", err)
		return nil
	}
	g.table.Swap(snap)
	g.certs.prune()
	return nil
}

// follow keeps the table current until ctx ends. After the link was lost it
// says hello again: the core may have restarted with other settings.
func (g *process) follow(ctx context.Context) error {
	wait := newBackoff()
	lost := false
	for ctx.Err() == nil {
		if lost {
			var h Hello
			if err := g.link.call(ctx, VerbHello, nil, &h); err != nil {
				if !wait.sleep(ctx) {
					return nil
				}
				continue
			}
			if h.HTTPS != g.hello.HTTPS || h.HTTP != g.hello.HTTP {
				return errReconfigured
			}
			if t, err := parseTrusted(h.Trusted); err == nil {
				g.trusted = t
				g.trustedNow.Store(&t)
			}
			SetSiteSocket(h.SiteSocket) // a core restarted with another setting: its word now
			g.rev = 0                   // whatever the core holds now, take it
			lost = false
			g.log.Info("gate: the core is back", "core", h.Version)
		}
		if err := g.sync(ctx); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if !isVerbError(err) {
				lost = true
				g.up.Store(false)
				g.log.Warn("gate: the link to the core is down; serving what is in hand", "err", err)
			}
			if !wait.sleep(ctx) {
				return nil
			}
			continue
		}
		wait.reset()
	}
	return nil
}

// followStreams keeps the streams the gate forwards the ones the core names,
// until ctx ends. Like the routes, they outlive a core that went away: the
// streams in hand keep forwarding, and the gate asks again from the start once
// the link is back.
func (g *process) followStreams(ctx context.Context) error {
	defer g.streams.stopAll()
	wait := newBackoff()
	var rev int64
	for ctx.Err() == nil {
		var s Streams
		if err := g.link.call(ctx, VerbStreams, After{After: rev}, &s); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if !isVerbError(err) {
				rev = 0 // the link was lost: whatever the core holds when it is back, take it
			}
			if !wait.sleep(ctx) {
				return nil
			}
			continue
		}
		wait.reset()
		rev = s.Rev
		g.streams.apply(ctx, s.Total, s.Streams)
	}
	return nil
}

// report sends the request counts, the gate's process and its memory to the
// core, every ReportEvery: a report that stops coming is how the core knows
// the gate is gone.
func (g *process) report(ctx context.Context) error {
	t := time.NewTicker(ReportEvery)
	defer t.Stop()
	var lastConns, lastProxied int64
	memlog := os.Getenv("AUTOPANEL_GATE_MEMLOG") != "" // a line of the runtime's memory with every report: for measuring
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			now := Report{HTTPSRequests: g.https.Load(), HTTPRequests: g.http.Load(), PID: os.Getpid(), MemoryBytes: residentBytes(),
				StreamsOpen: g.streams.openNow(), StreamsServed: g.streams.served.Load(), StreamsRefused: g.streams.refused.Load()}
			now.Tunnels = g.tunnels.states()
			now.ConnsOpen, now.ConnsRefused = int64(g.httpsLn.openNow()+g.plainLn.openNow()), g.httpsLn.refused.Load()+g.plainLn.refused.Load()
			now.ProxiedNow, now.ProxiedRefused = int64(g.inFlight.now()), g.inFlight.refused.Load()
			if memlog {
				rt, live, fixed := runtimeBytes()
				g.log.Info("gate: memory", "runtime_bytes", rt, "heap_live_bytes", live, "runtime_fixed_bytes", fixed, "resident_bytes", now.MemoryBytes,
					"proxied_now", now.ProxiedNow, "connections_now", now.ConnsOpen, "wide_now", g.httpsLn.wide.now()+g.plainLn.wide.now(), "streams_open", now.StreamsOpen)
			}
			if now.ConnsRefused != lastConns || now.ProxiedRefused != lastProxied {
				g.log.Warn("gate: at its limits", "requests_refused", now.ProxiedRefused-lastProxied, "connections_closed", now.ConnsRefused-lastConns,
					"proxied_now", now.ProxiedNow, "connections_now", now.ConnsOpen)
				lastConns, lastProxied = now.ConnsRefused, now.ProxiedRefused
			}
			if p := g.streams.probed.Load(); p != nil {
				now.ProbedAt, now.Unproxied = p.at, p.unproxied
			}
			cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			_ = g.link.call(cctx, VerbReport, now, nil)
			cancel()
		}
	}
}

// residentBytes is the memory the process holds in RAM, from its own
// /proc/self/statm: what its unit's MemoryMax is counted against, but for the
// page cache. Where that cannot be read, it is what the Go runtime holds.
func residentBytes() uint64 {
	if b, err := os.ReadFile("/proc/self/statm"); err == nil {
		if f := strings.Fields(string(b)); len(f) > 1 {
			if pages, err := strconv.ParseUint(f[1], 10, 64); err == nil && pages > 0 {
				return pages * uint64(os.Getpagesize())
			}
		}
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.Sys
}

// challengeOr answers an ACME HTTP-01 request with what the core says, and
// passes every other request to next. Only a request under the challenge path
// costs a call.
func (g *process) challengeOr(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, acmeChallengePath) {
			ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
			var a ChallengeAnswer
			err := g.link.call(ctx, VerbChallenge, ChallengeAsk{Host: r.Host, Path: r.URL.Path}, &a)
			cancel()
			if err == nil && a.Handled {
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(a.Status)
				_, _ = w.Write(a.Body)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// counted counts each request to next in n.
func counted(n *atomic.Int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		next.ServeHTTP(w, r)
	})
}

// toHTTPS redirects plain HTTP to the same host and path over HTTPS. The host
// is canonicalised first; a request naming no valid host gets 404.
func toHTTPS(w http.ResponseWriter, r *http.Request) {
	host, err := core.CanonicalHost(r.Host)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusPermanentRedirect)
}

// --- the link ---------------------------------------------------------------

// link is the gate's connection to the core, redialled when it is lost.
type link struct {
	dial Dialer
	mu   sync.Mutex
	cur  Caller
}

// isVerbError reports whether err is the core's answer rather than a lost
// connection: the link is then fine.
func isVerbError(err error) bool {
	var re *rpc.Error
	return errors.As(err, &re)
}

func (l *link) conn(ctx context.Context) (Caller, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.cur != nil {
		return l.cur, nil
	}
	dctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	c, err := l.dial(dctx)
	if err != nil {
		return nil, err
	}
	l.cur = c
	return c, nil
}

// call calls verb on the core. A connection that failed is dropped, so the
// next call dials again.
func (l *link) call(ctx context.Context, verb string, param, out any) error {
	c, err := l.conn(ctx)
	if err != nil {
		return err
	}
	err = c.Call(ctx, verb, param, out)
	if err != nil && !isVerbError(err) && ctx.Err() == nil {
		l.mu.Lock()
		if l.cur == c {
			l.cur = nil
		}
		l.mu.Unlock()
		_ = c.Close()
	}
	return err
}

func (l *link) close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.cur != nil {
		_ = l.cur.Close()
		l.cur = nil
	}
}

// backoff waits longer after each failure, up to five seconds.
type backoff struct{ d time.Duration }

func newBackoff() *backoff { return &backoff{d: 100 * time.Millisecond} }

func (b *backoff) reset() { b.d = 100 * time.Millisecond }

// sleep waits, and reports whether ctx is still live.
func (b *backoff) sleep(ctx context.Context) bool {
	t := time.NewTimer(b.d)
	defer t.Stop()
	if b.d *= 2; b.d > 5*time.Second {
		b.d = 5 * time.Second
	}
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// --- certificates -----------------------------------------------------------

// certCache holds the certificates the core has handed the gate, by name.
type certCache struct {
	// also admits a name no route holds that still has a certificate: the
	// API's host. nil: none.
	also  func(name string) bool
	link  *link
	table *Table

	mu      sync.Mutex
	held    map[string]heldCert
	flights map[string]*flight // one ask per name at a time
}

type heldCert struct {
	cert  *tls.Certificate
	fresh time.Time // ask the core again after this
}

type flight struct {
	done chan struct{}
	cert *tls.Certificate
	err  error
}

var errNoCertificate = errors.New("gate: no certificate for this name")

// get serves a handshake. A name no route holds is refused here, without a
// call: a stranger's SNI costs the core nothing. A challenge handshake always
// goes to the core, which alone knows the orders in flight.
func (cc *certCache) get(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if len(h.SupportedProtos) == 1 && h.SupportedProtos[0] == acmeTLS1 {
		ctx, cancel := context.WithTimeout(h.Context(), 10*time.Second)
		defer cancel()
		return cc.ask(ctx, Name{Name: h.ServerName, ALPN: true})
	}
	name, err := core.CanonicalHost(h.ServerName)
	if err != nil || !cc.holds(name) {
		return nil, errNoCertificate
	}
	cc.mu.Lock()
	have, ok := cc.held[name]
	if ok && time.Now().Before(have.fresh) {
		cc.mu.Unlock()
		return have.cert, nil
	}
	f, flying := cc.flights[name]
	if !flying {
		f = &flight{done: make(chan struct{})}
		cc.flights[name] = f
		go cc.fetch(name, f)
	}
	cc.mu.Unlock()

	select {
	case <-f.done:
	case <-h.Context().Done():
		return nil, h.Context().Err()
	}
	if f.err != nil {
		// Stale but valid beats a failed handshake while the core is away.
		if ok && time.Now().Before(have.cert.Leaf.NotAfter) {
			return have.cert, nil
		}
		return nil, f.err
	}
	return f.cert, nil
}

// fetch asks the core for name's certificate, for every handshake waiting on
// f. The core may be obtaining it from the CA, so the ask outlives any one
// handshake.
func (cc *certCache) fetch(name string, f *flight) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	f.cert, f.err = cc.ask(ctx, Name{Name: name})
	cc.mu.Lock()
	if f.err == nil {
		cc.held[name] = heldCert{cert: f.cert, fresh: freshUntil(f.cert.Leaf, time.Now())}
	}
	delete(cc.flights, name)
	cc.mu.Unlock()
	close(f.done)
}

func (cc *certCache) ask(ctx context.Context, n Name) (*tls.Certificate, error) {
	var c Cert
	if err := cc.link.call(ctx, VerbCert, n, &c); err != nil {
		return nil, err
	}
	if len(c.Chain) == 0 {
		return nil, errNoCertificate
	}
	key, err := x509.ParsePKCS8PrivateKey(c.Key)
	if err != nil {
		return nil, fmt.Errorf("gate: the core sent a key that does not parse: %w", err)
	}
	leaf, err := x509.ParseCertificate(c.Chain[0])
	if err != nil {
		return nil, fmt.Errorf("gate: the core sent a certificate that does not parse: %w", err)
	}
	return &tls.Certificate{Certificate: c.Chain, PrivateKey: key, Leaf: leaf}, nil
}

// prune forgets the certificates of names the table no longer holds.
func (cc *certCache) prune() {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	for name := range cc.held {
		if !cc.holds(name) {
			delete(cc.held, name)
		}
	}
}

// holds reports whether name may have a certificate here: a route names it, or
// it is the API's host.
func (cc *certCache) holds(name string) bool {
	return cc.table.Holds(name) || (cc.also != nil && cc.also(name))
}

// serverLog is where the two servers write. A failed handshake or a reset
// connection is the internet's weather and is dropped; anything else (a
// handler that panicked, an accept that failed) is counted and logged, at
// most one line a second.
type serverLog struct {
	log     *slog.Logger
	mu      sync.Mutex
	last    time.Time
	dropped int
}

func (l *serverLog) Write(b []byte) (int, error) {
	line := strings.TrimSpace(string(b))
	for _, weather := range []string{"TLS handshake error", "http2: server: error reading preface", "http: URL query contains semicolon"} {
		if strings.Contains(line, weather) {
			return len(b), nil
		}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if now := time.Now(); now.Sub(l.last) >= time.Second {
		if len(line) > 2048 {
			line = line[:2048]
		}
		l.log.Error("gate: the HTTP server reported", "line", line, "not_shown", l.dropped)
		l.last, l.dropped = now, 0
	} else {
		l.dropped++
	}
	return len(b), nil
}

// serveUntil runs srv on ln until ctx ends, then lets requests in flight finish
// for a few seconds and closes what is left.
func serveUntil(ctx context.Context, srv *http.Server, ln net.Listener, withTLS bool) error {
	done := make(chan error, 1)
	go func() {
		if withTLS {
			done <- srv.ServeTLS(ln, "", "") // certificates come from TLSConfig
			return
		}
		done <- srv.Serve(ln)
	}()
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
		_ = srv.Close()
		return nil
	}
}

// runtimeBytes is the Go runtime's memory now: held, all it has mapped less
// what it has given back (GOMEMLIMIT is a limit on this); live, the heap that
// survived the last collection; and fixed, what it holds beside the heap's
// objects (stacks, its own tables), which no collection gives back.
func runtimeBytes() (held, live, fixed uint64) {
	names := []string{"/memory/classes/total:bytes", "/memory/classes/heap/released:bytes", "/gc/heap/live:bytes",
		"/memory/classes/heap/stacks:bytes", "/memory/classes/os-stacks:bytes", "/memory/classes/metadata/mspan/inuse:bytes",
		"/memory/classes/metadata/mcache/inuse:bytes", "/memory/classes/metadata/other:bytes", "/memory/classes/other:bytes",
		"/memory/classes/profiling/buckets:bytes"}
	samples := make([]metrics.Sample, len(names))
	for i, n := range names {
		samples[i].Name = n
	}
	metrics.Read(samples)
	v := func(i int) uint64 {
		if samples[i].Value.Kind() != metrics.KindUint64 {
			return 0
		}
		return samples[i].Value.Uint64()
	}
	for i := 3; i < len(names); i++ {
		fixed += v(i)
	}
	return v(0) - v(1), v(2), fixed
}
