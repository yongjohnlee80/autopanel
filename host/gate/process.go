package gate

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	httpserver "github.com/yongjohnlee80/golib/server/http"
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
	trusted, err := parseTrusted(hello.Trusted)
	if err != nil {
		return err
	}

	table := core.NewTable[http.Handler]()
	g := &process{link: l, log: log, table: table, hello: hello, trusted: trusted,
		certs: &certCache{link: l, table: table, held: map[string]heldCert{}, flights: map[string]*flight{}}}
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

	https := httpserver.New(httpserver.Addr(hello.HTTPS),
		httpserver.WithTLSConfig(&tls.Config{
			GetCertificate: g.certs.get,
			NextProtos:     []string{"h2", "http/1.1", acmeTLS1}, // HTTP's first; acme-tls/1 stays, for the TLS-ALPN challenge
			MinVersion:     tls.VersionTLS12,
		}),
		httpserver.ReadHeaderTimeout(10*time.Second), httpserver.IdleTimeout(120*time.Second),
		httpserver.MaxHeaderBytes(64<<10), httpserver.NotFound(counted(&g.https, Handler(table)).ServeHTTP)) // no routes: every request is the gate's
	plain := httpserver.New(httpserver.Addr(hello.HTTP),
		httpserver.ReadHeaderTimeout(10*time.Second), httpserver.IdleTimeout(60*time.Second),
		httpserver.MaxHeaderBytes(16<<10), httpserver.NotFound(counted(&g.http, g.challengeOr(http.HandlerFunc(toHTTPS))).ServeHTTP))

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	errs := make(chan error, 4)
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
	run("gate https", https.Run)
	run("gate http", plain.Run)
	run("gate routes", g.follow)
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

	https, http atomic.Int64 // requests served, per listener
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
	snap, err := Build(routes, g.trusted)
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
			}
			g.rev = 0 // whatever the core holds now, take it
			lost = false
			g.log.Info("gate: the core is back", "core", h.Version)
		}
		if err := g.sync(ctx); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if !isVerbError(err) {
				lost = true
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

// report sends the request counts to the core, when they changed.
func (g *process) report(ctx context.Context) error {
	t := time.NewTicker(ReportEvery)
	defer t.Stop()
	var sent Report
	first := true
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			now := Report{HTTPSRequests: g.https.Load(), HTTPRequests: g.http.Load()}
			if now == sent && !first {
				continue
			}
			cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			if err := g.link.call(cctx, VerbReport, now, nil); err == nil {
				sent, first = now, false
			}
			cancel()
		}
	}
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
	if err != nil || !cc.table.Holds(name) {
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
		fresh := time.Now().Add(certFresh)
		if na := f.cert.Leaf.NotAfter; na.Before(fresh) {
			fresh = na
		}
		cc.held[name] = heldCert{cert: f.cert, fresh: fresh}
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
		if !cc.table.Holds(name) {
			delete(cc.held, name)
		}
	}
}
