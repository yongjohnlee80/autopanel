package gate

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yongjohnlee80/golib/server/rpc"

	core "github.com/yongjohnlee80/autopanel/core/gate"
)

// fakeCore answers the link's verbs as the core does, from memory: a table
// with a revision, a self-signed certificate for each name it is told to
// hold, and one challenge.
type fakeCore struct {
	t *testing.T

	mu      sync.Mutex
	hello   Hello
	rev     int64
	routes  []core.RouteView
	changed chan struct{} // closed when the table changes, or the core goes down
	down    bool
	epoch   int            // counts the core's stops: a connection from before one is lost
	asks    map[string]int // link.cert calls, by name
	certs   map[string]Cert
	pool    *x509.CertPool
	reports []Report
	streams Streams // link.streams: its Rev counts the changes
	api     *API    // the HTTPS API's settings; nil: off
	calls   []APIAsk
	apiHold chan struct{} // when set, link.api waits for it to close
	apiBody []byte        // when set, link.api's result
	agents  Agents        // link.agents: its Rev counts the changes
	enrols  []EnrolAsk    // link.enrol calls
	enrolAs string        // the agent a token enrols as; "": every token is refused
}

// setAgents names the enrolled agents.
func (f *fakeCore) setAgents(agents ...AgentKey) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.agents = Agents{Rev: f.agents.Rev + 1, Agents: agents}
	f.wake()
}

// setAPI changes the API's settings, as sys.api.set does.
func (f *fakeCore) setAPI(a *API) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.api = a
	f.rev++
	f.wake()
}

func newFakeCore(t *testing.T, https, http string) *fakeCore {
	return &fakeCore{t: t, hello: Hello{Version: "test", HTTPS: https, HTTP: http}, rev: 100,
		changed: make(chan struct{}), asks: map[string]int{}, certs: map[string]Cert{}, pool: x509.NewCertPool()}
}

// hold makes the core hold a certificate for name.
func (f *fakeCore) hold(name string) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		DNSNames: []string{name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		f.t.Fatal(err)
	}
	pk, _ := x509.MarshalPKCS8PrivateKey(key)
	leaf, _ := x509.ParseCertificate(der)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.certs[name] = Cert{Chain: [][]byte{der}, Key: pk, NotAfter: tmpl.NotAfter.Unix()}
	f.pool.AddCert(leaf)
}

func (f *fakeCore) wake() {
	close(f.changed)
	f.changed = make(chan struct{})
}

func (f *fakeCore) setRoutes(routes ...core.RouteView) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routes = routes
	f.rev++
	f.wake()
}

// setDown stops (or starts) the core: every open connection fails.
// setStreams names the streams the gate should forward.
func (f *fakeCore) setStreams(total int, streams ...Stream) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.streams = Streams{Rev: f.streams.Rev + 1, Total: total, Streams: streams}
	f.wake()
}

func (f *fakeCore) setDown(down bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.down = down
	if down {
		f.epoch++
	}
	f.wake()
}

func (f *fakeCore) asked(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.asks[name]
}

func (f *fakeCore) lastReport() Report {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.reports) == 0 {
		return Report{}
	}
	return f.reports[len(f.reports)-1]
}

var errLinkLost = errors.New("the link is lost")

func (f *fakeCore) dial(context.Context) (Caller, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return nil, errLinkLost
	}
	return &fakeConn{f: f, epoch: f.epoch}, nil
}

type fakeConn struct {
	f     *fakeCore
	epoch int
}

func (c *fakeConn) Close() error { return nil }

func (c *fakeConn) Call(ctx context.Context, verb string, param any, out any) error {
	f := c.f
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down || f.epoch != c.epoch {
		return errLinkLost
	}
	switch verb {
	case VerbHello:
		*out.(*Hello) = f.hello
	case VerbRoutes:
		for f.rev == param.(After).After {
			ch := f.changed
			f.mu.Unlock()
			select {
			case <-ch:
			case <-ctx.Done():
				f.mu.Lock()
				return ctx.Err()
			}
			f.mu.Lock()
			if f.down || f.epoch != c.epoch {
				return errLinkLost
			}
		}
		*out.(*Routes) = Routes{Rev: f.rev, Routes: append([]core.RouteView(nil), f.routes...), API: f.api}
	case VerbAPI:
		a := param.(APIAsk)
		f.calls = append(f.calls, a)
		if hold := f.apiHold; hold != nil {
			f.mu.Unlock()
			select {
			case <-hold:
			case <-ctx.Done():
				f.mu.Lock()
				return ctx.Err()
			}
			f.mu.Lock()
		}
		if f.apiBody != nil {
			*out.(*APIAnswer) = APIAnswer{Result: f.apiBody}
			break
		}
		*out.(*APIAnswer) = APIAnswer{Result: []byte(`{"verb":"` + a.Verb + `"}`)}
	case VerbCert:
		n := param.(Name)
		f.asks[n.Name]++
		cert, ok := f.certs[n.Name]
		if !ok || n.ALPN {
			return &rpc.Error{Code: -32190, Message: "no route names this host"}
		}
		*out.(*Cert) = cert
	case VerbChallenge:
		a := param.(ChallengeAsk)
		if a.Host == "app.example.com" && a.Path == acmeChallengePath+"token" {
			*out.(*ChallengeAnswer) = ChallengeAnswer{Handled: true, Status: 200, Body: []byte("token.thumbprint")}
		}
	case VerbReport:
		f.reports = append(f.reports, param.(Report))
	case VerbStreams:
		for f.streams.Rev == param.(After).After {
			ch := f.changed
			f.mu.Unlock()
			select {
			case <-ch:
			case <-ctx.Done():
				f.mu.Lock()
				return ctx.Err()
			}
			f.mu.Lock()
			if f.down || f.epoch != c.epoch {
				return errLinkLost
			}
		}
		*out.(*Streams) = Streams{Rev: f.streams.Rev, Total: f.streams.Total, Streams: append([]Stream(nil), f.streams.Streams...)}
	case VerbAgents:
		for f.agents.Rev == param.(After).After {
			ch := f.changed
			f.mu.Unlock()
			select {
			case <-ch:
			case <-ctx.Done():
				f.mu.Lock()
				return ctx.Err()
			}
			f.mu.Lock()
			if f.down || f.epoch != c.epoch {
				return errLinkLost
			}
		}
		*out.(*Agents) = Agents{Rev: f.agents.Rev, Agents: append([]AgentKey(nil), f.agents.Agents...)}
	case VerbEnrol:
		a := param.(EnrolAsk)
		f.enrols = append(f.enrols, a)
		if f.enrolAs == "" {
			return &rpc.Error{Code: -32274, Message: "the enrolment was refused"}
		}
		*out.(*Enrolled) = Enrolled{Name: f.enrolAs}
	default:
		return &rpc.Error{Code: rpc.CodeMethodNotFound, Message: "unknown method: " + verb}
	}
	return nil
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// get asks the gate's TLS listener for path as name, on a new connection, so
// every call is a handshake.
func get(f *fakeCore, name, path string) (int, string, error) {
	f.mu.Lock()
	addr, pool := f.hello.HTTPS, f.pool
	f.mu.Unlock()
	tr := &http.Transport{DisableKeepAlives: true, TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: name},
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", addr)
		}}
	defer tr.CloseIdleConnections()
	res, err := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Get("https://" + name + path)
	if err != nil {
		return 0, "", err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(body), nil
}

func until(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatal(what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// startGate runs the gate against f until the test ends, and waits for its
// TLS listener.
func startGate(t *testing.T, f *fakeCore) (done chan error, cancel context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done = make(chan error, 1)
	go func() { done <- Run(ctx, f.dial, slog.New(slog.NewTextHandler(io.Discard, nil))) }()
	until(t, "the gate never listened", func() bool {
		c, err := net.Dial("tcp", f.hello.HTTPS)
		if err != nil {
			return false
		}
		_ = c.Close()
		return true
	})
	return done, cancel
}

// TestTheGateServesWhatTheCoreHandsIt drives a gate whose core is in memory:
// it proxies a routed name over TLS with the certificate the core gave, asks
// for that certificate once, never asks for a name no route holds, answers an
// ACME challenge with the core's words, follows a change of routes, and
// reports its request counts.
func TestTheGateServesWhatTheCoreHandsIt(t *testing.T) {
	defer func(d time.Duration) { ReportEvery = d }(ReportEvery)
	ReportEvery = 30 * time.Millisecond
	up := upstream(t)
	f := newFakeCore(t, freeAddr(t), freeAddr(t))
	f.hold("app.example.com")
	f.hold("later.example.com")
	f.setRoutes(core.RouteView{ID: 1, Host: "app.example.com", PathPrefix: "/", Upstream: up.URL})
	done, cancel := startGate(t, f)

	for i := 0; i < 2; i++ {
		if code, body, err := get(f, "app.example.com", "/hello"); err != nil || code != 200 || body != "/hello" {
			t.Fatalf("request %d through the gate = %d %q, %v", i, code, body, err)
		}
	}
	if n := f.asked("app.example.com"); n != 1 {
		t.Errorf("the gate asked for the certificate %d times in two handshakes; want once", n)
	}
	if _, _, err := get(f, "later.example.com", "/"); err == nil {
		t.Error("a handshake for a name no route holds succeeded")
	}
	if n := f.asked("later.example.com"); n != 0 {
		t.Errorf("a name no route holds cost the core %d calls; want none", n)
	}

	plain := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Timeout: 5 * time.Second}
	ask := func(host, path string) (int, string, string) {
		req, _ := http.NewRequest("GET", "http://"+f.hello.HTTP+path, nil)
		req.Host = host
		res, err := plain.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(body), res.Header.Get("Location")
	}
	if code, body, _ := ask("app.example.com", acmeChallengePath+"token"); code != 200 || body != "token.thumbprint" {
		t.Errorf("the challenge answered %d %q; want the core's answer", code, body)
	}
	if code, _, loc := ask("app.example.com", acmeChallengePath+"other"); code != http.StatusPermanentRedirect || !strings.HasPrefix(loc, "https://app.example.com/") {
		t.Errorf("a challenge that is not the core's answered %d to %q; want the redirect", code, loc)
	}
	if code, _, loc := ask("App.Example.com", "/a?b=1"); code != http.StatusPermanentRedirect || loc != "https://app.example.com/a?b=1" {
		t.Errorf("plain HTTP answered %d to %q; want a 308 to the canonical https URL", code, loc)
	}

	f.setRoutes(core.RouteView{ID: 1, Host: "app.example.com", PathPrefix: "/", Upstream: up.URL},
		core.RouteView{ID: 2, Host: "later.example.com", PathPrefix: "/", Upstream: up.URL})
	until(t, "the added route never reached the gate", func() bool {
		code, _, err := get(f, "later.example.com", "/x")
		return err == nil && code == 200
	})

	// A table the gate cannot build leaves the old one serving.
	f.setRoutes(core.RouteView{ID: 3, Host: "Not Canonical", PathPrefix: "/", Upstream: up.URL})
	time.Sleep(100 * time.Millisecond)
	if code, _, err := get(f, "app.example.com", "/still"); err != nil || code != 200 {
		t.Errorf("after a table that cannot be built the gate answered %d, %v; want the old table", code, err)
	}

	until(t, "the gate never reported its counts", func() bool {
		r := f.lastReport()
		return r.HTTPSRequests >= 4 && r.HTTPRequests == 3
	})
	// A report carries the gate's process and its memory, and comes whether or
	// not a request did: it is how the core knows the gate is there.
	if r := f.lastReport(); r.PID != os.Getpid() || r.MemoryBytes == 0 {
		t.Errorf("the gate's report = %+v; want this process and its memory", r)
	}
	f.mu.Lock()
	n := len(f.reports)
	f.mu.Unlock()
	until(t, "the gate stopped reporting once its counts stopped changing", func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		return len(f.reports) >= n+3
	})

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the gate stopped with %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the gate did not stop")
	}
}

// TestTheGateOutlivesTheCore stops the core under a serving gate: the routes
// and the certificate in hand keep serving, past the certificate's hour too;
// what changed meanwhile arrives when the core is back; and a core that
// returns with other listen addresses stops the gate, for its unit to start
// it again on them.
func TestTheGateOutlivesTheCore(t *testing.T) {
	defer func(d time.Duration) { certFresh = d }(certFresh)
	certFresh = 50 * time.Millisecond
	up := upstream(t)
	f := newFakeCore(t, freeAddr(t), freeAddr(t))
	f.hold("app.example.com")
	f.hold("new.example.com")
	f.setRoutes(core.RouteView{ID: 1, Host: "app.example.com", PathPrefix: "/", Upstream: up.URL})
	done, _ := startGate(t, f)
	if code, _, err := get(f, "app.example.com", "/"); err != nil || code != 200 {
		t.Fatalf("before the core stopped: %d, %v", code, err)
	}

	f.setDown(true)
	time.Sleep(2 * certFresh) // the certificate in hand is past its hour
	for i := 0; i < 3; i++ {
		if code, body, err := get(f, "app.example.com", "/down"); err != nil || code != 200 || body != "/down" {
			t.Fatalf("with the core down, request %d = %d %q, %v; want the route and the certificate in hand", i, code, body, err)
		}
	}

	f.mu.Lock()
	f.routes = []core.RouteView{{ID: 2, Host: "new.example.com", PathPrefix: "/", Upstream: up.URL}}
	f.rev = 7 // a core that restarted counts from somewhere else
	f.mu.Unlock()
	f.setDown(false)
	until(t, "what changed while the core was down never reached the gate", func() bool {
		code, _, err := get(f, "new.example.com", "/")
		return err == nil && code == 200
	})
	if _, _, err := get(f, "app.example.com", "/"); err == nil {
		t.Error("a route removed while the core was down is still served")
	}

	f.setDown(true)
	f.mu.Lock()
	f.hello.HTTP = freeAddr(t)
	f.mu.Unlock()
	f.setDown(false)
	select {
	case err := <-done:
		if !errors.Is(err, errReconfigured) {
			t.Fatalf("the gate stopped with %v; want the changed addresses", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("a core with other listen addresses did not stop the gate")
	}
}

// TestTheGateReachesNoStoreVaultOrACMEClient lists what this package links.
// The gate process faces the internet, so the packages that hold the store,
// the master key and the ACME account must not be among them.
func TestTheGateReachesNoStoreVaultOrACMEClient(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Skipf("go list: %v", err)
	}
	for _, dep := range strings.Fields(string(out)) {
		for _, banned := range []string{"/autopanel/store", "/autopanel/internal/keyslot", "/autopanel/internal/certs",
			"/autopanel/internal/auth", "/autopanel/internal/hostcmd", "caddyserver/certmagic", "mholt/acmez", "/golib/dao"} {
			if strings.Contains(dep, banned) {
				t.Errorf("the gate links %s", dep)
			}
		}
	}
}

// TestTheGateForwardsTheCoresStreams: a stream the core names is bound and
// forwarded with a PROXY header, keeps forwarding while the core is away, is
// counted in the report, and is let go when the core takes it back.
func TestTheGateForwardsTheCoresStreams(t *testing.T) {
	defer func(d time.Duration) { ReportEvery = d }(ReportEvery)
	ReportEvery = 30 * time.Millisecond
	b := newBackend(t)
	f := newFakeCore(t, freeAddr(t), freeAddr(t))
	startGate(t, f)
	s := Stream{Name: "smtp", Listen: freeAddr(t), To: b.l.Addr().String(), IdleSecs: 60, PerClient: 10}
	f.setStreams(200, s)
	var c net.Conn
	until(t, "the gate never bound the stream", func() bool {
		var err error
		c, err = net.Dial("tcp", s.Listen)
		return err == nil
	})
	defer c.Close()
	if h := <-b.headers; !bytes.HasPrefix(h, proxySignature) {
		t.Fatalf("no PROXY header: % x", h)
	}
	until(t, "the open stream was never reported", func() bool { return f.lastReport().StreamsOpen == 1 })

	f.setDown(true)
	if _, err := c.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, make([]byte, 2)); err != nil {
		t.Fatalf("a stream should outlive the core: %v", err)
	}
	f.setDown(false)

	f.setStreams(200)
	until(t, "a stream the core took back is still bound", func() bool {
		l, err := net.Listen("tcp", s.Listen)
		if err != nil {
			return false
		}
		l.Close()
		return true
	})
}

// A certificate in hand is asked for again after an hour, at its end, or as
// the last third of its life begins, whichever is first.
func TestWhenTheGateAsksAgainForACertificate(t *testing.T) {
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	leaf := &x509.Certificate{NotBefore: from, NotAfter: from.Add(90 * 24 * time.Hour)}
	day := func(n int) time.Time { return from.Add(time.Duration(n) * 24 * time.Hour) }
	for _, tc := range []struct {
		name string
		now  time.Time
		want time.Time
	}{
		{"young: an hour", day(10), day(10).Add(time.Hour)},
		{"the last third begins within the hour: then", day(60).Add(-20 * time.Minute), day(60)},
		{"in the last third: an hour", day(61), day(61).Add(time.Hour)},
		{"its end is within the hour: its end", day(90).Add(-10 * time.Minute), day(90)},
	} {
		if got := freshUntil(leaf, tc.now); !got.Equal(tc.want) {
			t.Errorf("%s: asked again at %v; want %v", tc.name, got, tc.want)
		}
	}
}

// TestTheGateServesTheAPIOnItsOwnHost drives the whole gate: once the core
// names the API's host, the gate takes a certificate for it though no route
// holds it, answers /v1/health itself and passes a call to the core; a route's
// host is served as before; and once the core turns the API off, the name is a
// stranger's again.
func TestTheGateServesTheAPIOnItsOwnHost(t *testing.T) {
	up := upstream(t)
	f := newFakeCore(t, freeAddr(t), freeAddr(t))
	f.hold("app.example.com")
	f.hold("api.example.com")
	f.setRoutes(core.RouteView{ID: 1, Host: "app.example.com", PathPrefix: "/", Upstream: up.URL})
	startGate(t, f)

	if _, _, err := get(f, "api.example.com", "/v1/health"); err == nil {
		t.Fatal("the API's host answered before the core named it")
	}
	f.setAPI(&API{Host: "api.example.com"})
	until(t, "the gate never served the API's host", func() bool {
		code, body, err := get(f, "api.example.com", "/v1/health")
		return err == nil && code == 200 && body == `{"status":"ok"}`
	})
	// A call, over TLS, with a token: the core gets it and its answer comes back.
	f.mu.Lock()
	addr, pool := f.hello.HTTPS, f.pool
	f.mu.Unlock()
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "api.example.com"},
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", addr)
		}}
	defer tr.CloseIdleConnections()
	req, _ := http.NewRequest("POST", "https://api.example.com/v1/call/gate.route.list", nil)
	req.Header.Set("Authorization", goodBearer)
	res, err := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || string(body) != `{"verb":"gate.route.list"}` {
		t.Fatalf("a call through the gate: %d %q", res.StatusCode, body)
	}
	f.mu.Lock()
	calls := len(f.calls)
	f.mu.Unlock()
	if calls != 1 {
		t.Fatalf("the core got %d calls; want the one", calls)
	}
	// The API's path on a routed host is the upstream's, not the gate's.
	if code, body, err := get(f, "app.example.com", "/v1/health"); err != nil || code != 200 || body != "/v1/health" {
		t.Fatalf("a routed host: %d %q, %v", code, body, err)
	}
	// Plain HTTP for the API's host is refused, not redirected.
	hreq, _ := http.NewRequest("GET", "http://"+f.hello.HTTP+"/v1/health", nil)
	hreq.Host = "api.example.com"
	plain := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Timeout: 5 * time.Second}
	if res, err := plain.Do(hreq); err != nil || res.StatusCode != 400 {
		t.Fatalf("the API's host without TLS: %v, %v", res, err)
	}
	// Off again: the name is no longer the gate's, and its certificate is forgotten.
	f.setAPI(nil)
	until(t, "the API's host kept answering after it was turned off", func() bool {
		_, _, err := get(f, "api.example.com", "/v1/health")
		return err != nil
	})
}

// TestAFullAPIDoesNotHoldUpTheSites: with every API slot taken by a call the
// core has not answered, a site's handshake still gets its certificate and its
// request is still proxied; and each call then gets its answer whole, at the
// largest an answer may be. (What that costs the gate in memory is not measured
// here: this core is in the test's process and hands over one shared slice. The
// bound is the sum of the limits at the top of api.go.)
func TestAFullAPIDoesNotHoldUpTheSites(t *testing.T) {
	up := upstream(t)
	f := newFakeCore(t, freeAddr(t), freeAddr(t))
	f.hold("app.example.com")
	f.hold("api.example.com")
	f.setRoutes(core.RouteView{ID: 1, Host: "app.example.com", PathPrefix: "/", Upstream: up.URL})
	startGate(t, f)
	f.setAPI(&API{Host: "api.example.com"})
	until(t, "the gate never served the API's host", func() bool {
		code, _, err := get(f, "api.example.com", "/v1/health")
		return err == nil && code == 200
	})
	hold := make(chan struct{})
	f.mu.Lock()
	f.apiHold, f.apiBody = hold, append(append([]byte{'"'}, bytes.Repeat([]byte("x"), apiAnswer-2)...), '"')
	addr, pool := f.hello.HTTPS, f.pool
	f.mu.Unlock()

	client := func() *http.Client {
		return &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{DisableKeepAlives: true,
			TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "api.example.com"},
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "tcp", addr)
			}}}
	}
	var wg sync.WaitGroup
	sizes := make(chan int, apiInFlight)
	for i := range apiInFlight {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("POST", "https://api.example.com/v1/call/sys.status", nil)
			req.Header.Set("Authorization", goodBearer)
			req.Header.Set("Cf-Connecting-Ip", "203.0.113."+strconv.Itoa(i+1)) // ignored: the peer is not trusted
			res, err := client().Do(req)
			if err != nil {
				sizes <- -1
				return
			}
			n, _ := io.Copy(io.Discard, res.Body)
			res.Body.Close()
			sizes <- int(n)
		}()
	}
	until(t, "the API's slots never filled", func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		return len(f.calls) == apiInFlight
	})
	// Every slot is taken, and the core is slow: a site is not held up.
	start := time.Now()
	if code, body, err := get(f, "app.example.com", "/while-full"); err != nil || code != 200 || body != "/while-full" {
		t.Fatalf("a site while the API is full: %d %q, %v", code, body, err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("a site's request took %s while the API was full", d)
	}
	close(hold)
	wg.Wait()
	close(sizes)
	for n := range sizes {
		if n != apiAnswer {
			t.Fatalf("a call at the answer's limit came back as %d bytes; want %d", n, apiAnswer)
		}
	}
}
