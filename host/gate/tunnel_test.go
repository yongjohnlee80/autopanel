package gate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	core "github.com/yongjohnlee80/autopanel/core/gate"
	"github.com/yongjohnlee80/autopanel/internal/agent"
	"github.com/yongjohnlee80/autopanel/internal/tunnel"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// digestOf is a key's digest as the core lists it.
func digestOf(t *testing.T, key ed25519.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	return tunnel.KeyDigest(&x509.Certificate{RawSubjectPublicKeyInfo: der})
}

func newKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	k, err := agent.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// echoTarget is a service on this machine that sends back what it is sent.
func echoTarget(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return l.Addr().String()
}

// tunnelServer is the gate's tunnel handling on a TLS server of its own, with
// a core in memory: what the gate's :443 does for an agent, and nothing else.
func tunnelServer(t *testing.T, f *fakeCore) (*tunnels, *httptest.Server, *x509.CertPool) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ts := newTunnels(&link{dial: f.dial}, quiet())
	ts.ctx = ctx
	srv := httptest.NewUnstartedServer(ts.or(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "a site")
	})))
	tunnelTLS := ts.tlsConfig(func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &srv.TLS.Certificates[0], nil })
	srv.TLS = &tls.Config{NextProtos: []string{"h2", "http/1.1"}, GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		if isTunnel(h) {
			return tunnelTLS, nil
		}
		return nil, nil
	}}
	srv.StartTLS()
	go func() { _ = ts.follow(ctx) }()
	t.Cleanup(func() { cancel(); ts.stopAll(); srv.Close() })
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return ts, srv, pool
}

// runAgent runs an agent against srv until the test ends.
func runAgent(t *testing.T, srv *httptest.Server, pool *x509.CertPool, key ed25519.PrivateKey, targets map[string]agent.Target) (agent.Options, context.CancelFunc) {
	t.Helper()
	o := agent.Options{Server: "example.com", Key: key, Targets: targets, DialAddr: srv.Listener.Addr().String(), Roots: pool}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = agent.Run(ctx, o) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("the agent never stopped")
		}
	})
	return o, cancel
}

func up(ts *tunnels, name string) func() bool {
	return func() bool {
		for _, s := range ts.states() {
			if s.Name == name {
				return true
			}
		}
		return false
	}
}

func TestAnEnrolledAgentsTunnelCarriesStreams(t *testing.T) {
	f := newFakeCore(t, "", "")
	ts, srv, pool := tunnelServer(t, f)
	key := newKey(t)
	f.setAgents(AgentKey{Name: "nas", Key: digestOf(t, key)})
	until(t, "the gate never heard of the agent's key", func() bool { _, ok := ts.nameOf(digestOf(t, key)); return ok })
	runAgent(t, srv, pool, key, map[string]agent.Target{"echo": {To: echoTarget(t)}, "dead": {To: "127.0.0.1:1"}})
	until(t, "the tunnel never came up", up(ts, "nas"))

	st := ts.states()[0]
	if !reflect.DeepEqual(st.Targets, []string{"dead", "echo"}) || st.From != "127.0.0.1" || st.Since == 0 {
		t.Fatalf("the tunnel's state = %+v", st)
	}
	ctx := context.Background()
	c, err := ts.dial(ctx, "nas", "echo")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("through the tunnel")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 18)
	if _, err := io.ReadFull(c, got); err != nil || string(got) != "through the tunnel" {
		t.Fatalf("read %q, %v", got, err)
	}
	if n := ts.states()[0].Streams; n != 1 {
		t.Fatalf("streams = %d, want the one open", n)
	}
	_ = c.Close()
	_ = c.Close() // twice gives its place back once
	if n, all := ts.states()[0].Streams, ts.open.Load(); n != 0 || all != 0 {
		t.Fatalf("after closing: %d of the agent's, %d in all", n, all)
	}

	// What the agent's file does not list is not reachable, by any spelling.
	for _, name := range []string{"nope", "127.0.0.1:22", "echo ", "ECHO", "../echo", ""} {
		if _, err := ts.dial(ctx, "nas", name); !errors.Is(err, tunnel.ErrRefused) {
			t.Errorf("target %q: %v, want refused", name, err)
		}
	}
	// A target the file lists and that is not there is refused the same way.
	if _, err := ts.dial(ctx, "nas", "dead"); !errors.Is(err, tunnel.ErrRefused) {
		t.Errorf("a dead target: %v", err)
	}
	if _, err := ts.dial(ctx, "other", "echo"); !errors.Is(err, ErrTunnelDown) {
		t.Errorf("an agent that is not connected: %v", err)
	}
	if ts.open.Load() != 0 {
		t.Fatalf("refused streams still hold %d places", ts.open.Load())
	}
}

func TestTheTunnelsLimits(t *testing.T) {
	f := newFakeCore(t, "", "")
	ts, srv, pool := tunnelServer(t, f)
	key := newKey(t)
	f.setAgents(AgentKey{Name: "nas", Key: digestOf(t, key)})
	until(t, "the gate never heard of the agent's key", func() bool { _, ok := ts.nameOf(digestOf(t, key)); return ok })
	runAgent(t, srv, pool, key, map[string]agent.Target{"echo": {To: echoTarget(t)}})
	until(t, "the tunnel never came up", up(ts, "nas"))

	ctx := context.Background()
	var held []net.Conn
	for i := range tunnelStreams {
		c, err := ts.dial(ctx, "nas", "echo")
		if err != nil {
			t.Fatalf("stream %d: %v", i, err)
		}
		held = append(held, c)
	}
	if _, err := ts.dial(ctx, "nas", "echo"); !errors.Is(err, ErrTunnelFull) {
		t.Fatalf("a stream past one agent's limit: %v", err)
	}
	if ts.open.Load() != tunnelStreams {
		t.Fatalf("the refused stream kept a place: %d", ts.open.Load())
	}
	_ = held[0].Close()
	c, err := ts.dial(ctx, "nas", "echo")
	if err != nil {
		t.Fatalf("a freed place was not given: %v", err)
	}
	_ = c.Close()
	for _, c := range held[1:] {
		_ = c.Close()
	}
	// Every agent's streams together.
	ts.open.Store(tunnelStreamsTotal)
	if _, err := ts.dial(ctx, "nas", "echo"); !errors.Is(err, ErrTunnelFull) {
		t.Fatalf("a stream past the limit for all: %v", err)
	}
	ts.open.Store(0)
}

func TestAKeyTheCoreDoesNotListGetsNoTunnel(t *testing.T) {
	f := newFakeCore(t, "", "")
	ts, srv, pool := tunnelServer(t, f)
	known, stranger := newKey(t), newKey(t)
	f.setAgents(AgentKey{Name: "nas", Key: digestOf(t, known)})
	until(t, "the gate never heard of the agent's key", func() bool { _, ok := ts.nameOf(digestOf(t, known)); return ok })
	runAgent(t, srv, pool, stranger, nil)
	time.Sleep(500 * time.Millisecond)
	if len(ts.states()) != 0 {
		t.Fatalf("a stranger's key has a tunnel: %+v", ts.states())
	}

	// Over the tunnel's protocol nothing of a site is served, to a stranger or
	// to an agent.
	for _, key := range []ed25519.PrivateKey{stranger, known} {
		o := agent.Options{Server: "example.com", Key: key, DialAddr: srv.Listener.Addr().String(), Roots: pool}
		code := tunnelGet(t, o, "/")
		if code != http.StatusNotFound {
			t.Errorf("a request for a site over the tunnel's protocol = %d, want 404", code)
		}
	}
}

// tunnelGet makes a plain GET over the tunnel's protocol with the agent's key.
func tunnelGet(t *testing.T, o agent.Options, path string) int {
	t.Helper()
	conn, err := tls.Dial("tcp", o.DialAddr, &tls.Config{ServerName: "example.com", RootCAs: o.Roots, NextProtos: []string{tunnel.ALPN},
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return agentCert(t, o.Key), nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.WriteString(conn, "GET "+path+" HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	b, _ := io.ReadAll(conn)
	var code int
	if f := strings.Fields(string(b)); len(f) > 1 {
		for _, ch := range f[1] {
			code = code*10 + int(ch-'0')
		}
	}
	return code
}

func agentCert(t *testing.T, key ed25519.PrivateKey) *tls.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// A browser's handshake is never asked for a certificate, and is served the
// site; a handshake that offers the tunnel's protocol among others is a
// browser's too.
func TestABrowserIsNeverAskedForACertificate(t *testing.T) {
	f := newFakeCore(t, "", "")
	_, srv, pool := tunnelServer(t, f)
	for what, protos := range map[string][]string{
		"a browser":                          {"h2", "http/1.1"},
		"HTTP/1.1 alone":                     {"http/1.1"},
		"no protocol at all":                 nil,
		"the tunnel's protocol among others": {tunnel.ALPN, "http/1.1"},
	} {
		asked := false
		conn, err := tls.Dial("tcp", srv.Listener.Addr().String(), &tls.Config{ServerName: "example.com", RootCAs: pool, NextProtos: protos,
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				asked = true
				return &tls.Certificate{}, nil
			}})
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		if asked {
			t.Errorf("%s was asked for a client certificate", what)
		}
		if p := conn.ConnectionState().NegotiatedProtocol; p == tunnel.ALPN {
			t.Errorf("%s was given the tunnel's protocol", what)
		}
		_ = conn.Close()
	}
	// And an agent's handshake with no certificate does not complete.
	conn, err := tls.Dial("tcp", srv.Listener.Addr().String(), &tls.Config{ServerName: "example.com", RootCAs: pool, NextProtos: []string{tunnel.ALPN}})
	if err == nil {
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		_, _ = io.WriteString(conn, "GET /tunnel HTTP/1.1\r\nHost: example.com\r\n\r\n")
		if b, _ := io.ReadAll(conn); strings.Contains(string(b), "101") {
			t.Fatal("a tunnel was given to a handshake with no certificate")
		}
		_ = conn.Close()
	}
}

func TestEnrolmentGoesToTheCoreWithTheProvenKey(t *testing.T) {
	f := newFakeCore(t, "", "")
	ts, srv, pool := tunnelServer(t, f)
	key := newKey(t)
	o := agent.Options{Server: "example.com", Key: key, DialAddr: srv.Listener.Addr().String(), Roots: pool}
	ctx := context.Background()

	if _, err := agent.Enrol(ctx, o, "ape_wrong"); !errors.Is(err, agent.ErrRefused) {
		t.Fatalf("a token the core refuses: %v", err)
	}
	f.mu.Lock()
	f.enrolAs = "nas"
	f.mu.Unlock()
	name, err := agent.Enrol(ctx, o, "ape_0123456789abcdef_secret\n")
	if err != nil || name != "nas" {
		t.Fatalf("Enrol = %q, %v", name, err)
	}
	f.mu.Lock()
	last := f.enrols[len(f.enrols)-1]
	f.mu.Unlock()
	if last.Token != "ape_0123456789abcdef_secret" || last.Key != digestOf(t, key) || last.Client != "127.0.0.1" {
		t.Fatalf("the core was asked %+v", last)
	}
	// A body far past a token's length never reaches the core.
	before := len(f.enrols)
	if _, err := agent.Enrol(ctx, o, strings.Repeat("a", enrolBody+1)); !errors.Is(err, agent.ErrRefused) {
		t.Fatalf("a huge token: %v", err)
	}
	if len(f.enrols) != before {
		t.Fatal("a body that is no token cost the core a call")
	}
	// One address is counted: after its share, it waits for the next minute,
	// and the core hears nothing of it.
	var limited bool
	for range enrolPerClient {
		if _, err := agent.Enrol(ctx, o, "ape_x"); err != nil && !errors.Is(err, agent.ErrRefused) && strings.Contains(err.Error(), "too many") {
			limited = true
		}
	}
	if !limited {
		t.Fatal("one address enrolled without limit")
	}
	asked := len(f.enrols)
	_, _ = agent.Enrol(ctx, o, "ape_x")
	if len(f.enrols) != asked {
		t.Fatal("a limited enrolment still reached the core")
	}
	ts.now = func() time.Time { return time.Now().Add(time.Minute) }
	if _, err := agent.Enrol(ctx, o, "ape_x"); err != nil {
		t.Fatalf("the next minute: %v", err)
	}
	// With the core away the answer is not a refusal: the token is unspent.
	f.setDown(true)
	if _, err := agent.Enrol(ctx, o, "ape_x"); err == nil || errors.Is(err, agent.ErrRefused) {
		t.Fatalf("with the core away: %v", err)
	}
}

func TestARemovedAgentIsCutOffAtOnceAndANewDialReplacesTheOld(t *testing.T) {
	f := newFakeCore(t, "", "")
	ts, srv, pool := tunnelServer(t, f)
	key := newKey(t)
	f.setAgents(AgentKey{Name: "nas", Key: digestOf(t, key)})
	until(t, "the gate never heard of the agent's key", func() bool { _, ok := ts.nameOf(digestOf(t, key)); return ok })
	targets := map[string]agent.Target{"echo": {To: echoTarget(t)}}
	runAgent(t, srv, pool, key, targets)
	until(t, "the tunnel never came up", up(ts, "nas"))
	c, err := ts.dial(context.Background(), "nas", "echo")
	if err != nil {
		t.Fatal(err)
	}

	// The same agent dials again (its machine restarted): the new connection
	// is the tunnel, and the old one is closed.
	ts.mu.Lock()
	old := ts.live["nas"]
	ts.mu.Unlock()
	runAgent(t, srv, pool, key, targets)
	until(t, "the second dial never took over", func() bool {
		ts.mu.Lock()
		defer ts.mu.Unlock()
		return ts.live["nas"] != nil && ts.live["nas"] != old
	})
	select {
	case <-old.client.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the connection that was replaced stayed open")
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadAll(c); err == nil {
		t.Error("a stream on the replaced connection ended as if nothing had happened")
	}
	_ = c.Close()

	// Removed: the tunnel closes at once, and its key is admitted no more.
	f.setAgents()
	until(t, "a removed agent kept its tunnel", func() bool { return len(ts.states()) == 0 })
	time.Sleep(1500 * time.Millisecond) // the agents dial again, and are refused
	if len(ts.states()) != 0 {
		t.Fatalf("a removed agent's key was admitted again: %+v", ts.states())
	}
	if ts.open.Load() != 0 {
		t.Fatalf("%d places are held by streams of tunnels that are gone", ts.open.Load())
	}
}

// The whole gate: an agent's tunnel on the HTTPS port beside a site, in the
// gate's report, and still up after the server's time limits for a request
// have passed.
func TestTheGateHoldsATunnelOnItsHTTPSPort(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out the server's 15-second limits")
	}
	defer func(d time.Duration) { ReportEvery = d }(ReportEvery)
	ReportEvery = 50 * time.Millisecond
	site := upstream(t)
	f := newFakeCore(t, freeAddr(t), freeAddr(t))
	f.hold("app.example.com")
	f.setRoutes(core.RouteView{ID: 1, Host: "app.example.com", PathPrefix: "/", Upstream: site.URL})
	key := newKey(t)
	f.setAgents(AgentKey{Name: "nas", Key: digestOf(t, key)})
	startGate(t, f)

	o := agent.Options{Server: "app.example.com", Key: key, Targets: map[string]agent.Target{"echo": {To: echoTarget(t)}}, DialAddr: f.hello.HTTPS, Roots: f.pool}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = agent.Run(ctx, o) }()
	reported := func() []TunnelState { return f.lastReport().Tunnels }
	until(t, "the gate never reported the tunnel", func() bool { return len(reported()) == 1 })
	st := reported()[0]
	if st.Name != "nas" || !reflect.DeepEqual(st.Targets, []string{"echo"}) {
		t.Fatalf("reported = %+v", st)
	}
	// The site is served as before, on the same port.
	if code, body, err := get(f, "app.example.com", "/hello"); err != nil || code != 200 || body != "/hello" {
		t.Fatalf("the site beside the tunnel = %d %q, %v", code, body, err)
	}
	time.Sleep(17 * time.Second)
	if now := reported(); len(now) != 1 || now[0].Since != st.Since {
		t.Fatalf("after the server's limits the tunnel is %+v, was %+v", now, st)
	}
	// A name with no certificate here gets no tunnel: the handshake fails as
	// a browser's would.
	bad := o
	bad.Server = "other.example.com"
	if _, err := agent.Enrol(ctx, bad, "ape_x"); err == nil {
		t.Fatal("a tunnel handshake for a name the gate does not serve succeeded")
	}
}

// An agent removed and enrolled again under the same name, between two of the
// gate's reads of the list, has another key: the tunnel the old key holds is
// closed, though the name never left the list.
func TestAnAgentsNewKeyEndsTheOldKeysTunnel(t *testing.T) {
	f := newFakeCore(t, "", "")
	ts, srv, pool := tunnelServer(t, f)
	oldKey, newKey := newKey(t), newKey(t)
	f.setAgents(AgentKey{Name: "nas", Key: digestOf(t, oldKey)})
	until(t, "the gate never heard of the agent's key", func() bool { _, ok := ts.nameOf(digestOf(t, oldKey)); return ok })
	runAgent(t, srv, pool, oldKey, nil)
	until(t, "the tunnel never came up", up(ts, "nas"))
	ts.mu.Lock()
	old := ts.live["nas"]
	ts.mu.Unlock()

	f.setAgents(AgentKey{Name: "nas", Key: digestOf(t, newKey)})
	select {
	case <-old.client.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the old key kept its tunnel under the name that is another key's now")
	}
	time.Sleep(1500 * time.Millisecond) // the old key dials again, and is refused
	if len(ts.states()) != 0 {
		t.Fatalf("the old key was admitted again: %+v", ts.states())
	}
	runAgent(t, srv, pool, newKey, nil)
	until(t, "the new key got no tunnel", up(ts, "nas"))
}
