package gate

import (
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
		*out.(*Routes) = Routes{Rev: f.rev, Routes: append([]core.RouteView(nil), f.routes...)}
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
