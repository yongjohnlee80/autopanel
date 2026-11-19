package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yongjohnlee80/autopanel/internal/tunnel"
)

// fakeGate is the gate as an agent meets it: a TLS server that asks for a
// client certificate, takes an enrolment, and turns a connection into a
// tunnel it holds the client end of.
type fakeGate struct {
	srv  *httptest.Server
	pool *x509.CertPool

	mu      sync.Mutex
	keys    []string // the digest of each key that asked for a tunnel or enrolled
	tokens  []string
	refuse  bool                // refuse every tunnel
	tunnels chan *tunnel.Client // each tunnel taken
	hold    []net.Conn
}

func newFakeGate(t *testing.T) *fakeGate {
	t.Helper()
	g := &fakeGate{tunnels: make(chan *tunnel.Client, 8)}
	g.srv = httptest.NewUnstartedServer(http.HandlerFunc(g.serve))
	// As the gate does it: the agent's protocol is read and not answered.
	g.srv.TLS = &tls.Config{GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
		return &tls.Config{Certificates: g.srv.TLS.Certificates, ClientAuth: tls.RequireAnyClientCert, MinVersion: tls.VersionTLS13}, nil
	}}
	g.srv.StartTLS()
	t.Cleanup(func() {
		g.mu.Lock()
		for _, c := range g.hold {
			_ = c.Close()
		}
		g.mu.Unlock()
		g.srv.Close()
	})
	g.pool = x509.NewCertPool()
	g.pool.AddCert(g.srv.Certificate())
	return g
}

func (g *fakeGate) serve(w http.ResponseWriter, r *http.Request) {
	key := tunnel.KeyDigest(r.TLS.PeerCertificates[0])
	g.mu.Lock()
	g.keys = append(g.keys, key)
	refuse := g.refuse
	g.mu.Unlock()
	switch {
	case r.Method == http.MethodPost && r.URL.Path == tunnel.EnrolPath:
		b, _ := io.ReadAll(r.Body)
		g.mu.Lock()
		g.tokens = append(g.tokens, string(b))
		g.mu.Unlock()
		if string(b) != "ape_good" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"name": "nas"})
	case r.Method == http.MethodGet && r.URL.Path == tunnel.ConnectPath && r.Header.Get("Upgrade") == tunnel.ALPN:
		if refuse {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		_, _ = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: "+tunnel.ALPN+"\r\n\r\n")
		c, err := tunnel.NewClient(context.Background(), conn, 8)
		if err != nil {
			_ = conn.Close()
			return
		}
		g.mu.Lock()
		g.hold = append(g.hold, conn)
		g.mu.Unlock()
		g.tunnels <- c
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (g *fakeGate) options(t *testing.T, targets map[string]Target) Options {
	t.Helper()
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	return Options{Server: "example.com", Key: key, Targets: targets, DialAddr: g.srv.Listener.Addr().String(), Roots: g.pool}
}

func (g *fakeGate) next(t *testing.T) *tunnel.Client {
	t.Helper()
	select {
	case c := <-g.tunnels:
		return c
	case <-time.After(10 * time.Second):
		t.Fatal("no tunnel reached the gate")
		return nil
	}
}

func echoAddr(t *testing.T) string {
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

func run(t *testing.T, o Options) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, o) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Run: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("the agent never stopped")
		}
	})
}

func TestTheAgentServesItsFilesTargetsAndNoOther(t *testing.T) {
	g := newFakeGate(t)
	o := g.options(t, map[string]Target{"echo": {To: echoAddr(t)}, "gone": {To: "127.0.0.1:1"}})
	run(t, o)
	c := g.next(t)
	ctx := context.Background()

	s, err := c.Open(ctx, "echo")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = s.Write([]byte("hello"))
	got := make([]byte, 5)
	if _, err := io.ReadFull(s, got); err != nil || string(got) != "hello" {
		t.Fatalf("read %q, %v", got, err)
	}
	_ = s.Close()

	// Its names are answered; never where they lead.
	s, err = c.Open(ctx, tunnel.TargetsName)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(s)
	var names []string
	if err := json.Unmarshal(b, &names); err != nil || !reflect.DeepEqual(names, []string{"echo", "gone"}) {
		t.Fatalf("the targets' names = %s, %v", b, err)
	}
	if strings.Contains(string(b), "127.0.0.1") {
		t.Fatalf("the agent told the gate an address: %s", b)
	}
	// Anything the file does not list is refused: an address, a port, a path,
	// a name near one it has.
	for _, name := range []string{o.Targets["echo"].To, "127.0.0.1:22", "localhost:22", "22", "echo/", "Echo", "echo\x00", ".", "..", ".targets2", "unix:/run/docker.sock", ""} {
		if _, err := c.Open(ctx, name); !errors.Is(err, tunnel.ErrRefused) {
			t.Errorf("target %q: %v, want refused", name, err)
		}
	}
	if _, err := c.Open(ctx, "gone"); !errors.Is(err, tunnel.ErrRefused) {
		t.Errorf("a target that is not there: %v", err)
	}
}

func TestTheAgentDialsAgainWhenTheTunnelIsLost(t *testing.T) {
	g := newFakeGate(t)
	o := g.options(t, map[string]Target{"echo": {To: echoAddr(t)}})
	run(t, o)
	first := g.next(t)
	_ = first.Close() // the gate restarted
	second := g.next(t)
	s, err := second.Open(context.Background(), "echo")
	if err != nil {
		t.Fatalf("the new tunnel carries nothing: %v", err)
	}
	_ = s.Close()
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.keys) < 2 || g.keys[0] != g.keys[1] {
		t.Fatalf("the agent came back as someone else: %v", g.keys)
	}
}

func TestAnAgentTheGateRefusesKeepsTryingAndTheGatesNameIsChecked(t *testing.T) {
	g := newFakeGate(t)
	g.refuse = true
	o := g.options(t, nil)
	if served, err := o.connect(context.Background()); served || !errors.Is(err, ErrRefused) {
		t.Fatalf("connect = %v, %v", served, err)
	}
	// A certificate for another name, or from an issuer the agent does not
	// trust, is no gate of this agent's.
	wrong := o
	wrong.Server = "other.example.net"
	if _, err := wrong.connect(context.Background()); err == nil || errors.Is(err, ErrRefused) {
		t.Fatalf("a gate with another name's certificate: %v", err)
	}
	untrusted := o
	untrusted.Roots = x509.NewCertPool()
	if _, err := untrusted.connect(context.Background()); err == nil || errors.Is(err, ErrRefused) {
		t.Fatalf("a gate nobody vouches for: %v", err)
	}
}

func TestAListTheAgentCannotServeIsRefused(t *testing.T) {
	key, _ := NewKey()
	for what, o := range map[string]Options{
		"a name in capitals":     {Targets: map[string]Target{"Photos": {To: "127.0.0.1:1"}}},
		"the reserved name":      {Targets: map[string]Target{tunnel.TargetsName: {To: "127.0.0.1:1"}}},
		"a name with a slash":    {Targets: map[string]Target{"a/b": {To: "127.0.0.1:1"}}},
		"an address and no port": {Targets: map[string]Target{"a": {To: "127.0.0.1"}}},
		"no address":             {Targets: map[string]Target{"a": {}}},
		"too many streams":       {MaxStreams: 5000},
	} {
		o.Key, o.Server = key, "example.com"
		if err := Run(context.Background(), o); err == nil {
			t.Errorf("%s was accepted", what)
		}
	}
}

func TestAKeyKeepsItsFingerprintThroughItsFile(t *testing.T) {
	key, _ := NewKey()
	b, err := EncodeKey(key)
	if err != nil {
		t.Fatal(err)
	}
	back, err := DecodeKey(b)
	if err != nil || !back.Equal(key) {
		t.Fatalf("DecodeKey = %v", err)
	}
	fp, _ := Fingerprint(key)
	fp2, _ := Fingerprint(back)
	if fp != fp2 || !strings.HasPrefix(fp, "SHA256:") || len(fp) != len("SHA256:")+43 {
		t.Fatalf("fingerprints %q, %q", fp, fp2)
	}
	for _, bad := range []string{"", "not pem", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"} {
		if _, err := DecodeKey([]byte(bad)); err == nil {
			t.Errorf("DecodeKey(%q) succeeded", bad)
		}
	}
}

// cli runs the command against g.
func cli(t *testing.T, g *fakeGate, stdin string, args ...string) (int, string, string) {
	t.Helper()
	reach = func(o *Options) { o.DialAddr, o.Roots = g.srv.Listener.Addr().String(), g.pool }
	t.Cleanup(func() { reach = nil })
	var out, errs bytes.Buffer
	code := Main(args, strings.NewReader(stdin), &out, &errs, "v-test")
	return code, out.String(), errs.String()
}

func TestEnrollingFromTheCommandLine(t *testing.T) {
	g := newFakeGate(t)
	dir := t.TempDir()
	config := filepath.Join(dir, "etc", "agent.yaml")
	keyFile := filepath.Join(dir, "etc", "agent.key")

	// A refused token leaves nothing behind.
	code, _, errs := cli(t, g, "", "--config", config, "enroll", "example.com", "ape_wrong")
	if code != 1 || !strings.Contains(errs, "refused the token") {
		t.Fatalf("a wrong token: %d %q", code, errs)
	}
	if _, err := os.Stat(keyFile); err == nil {
		t.Fatal("a refused enrolment left a key")
	}

	// The token on standard input.
	code, out, errs := cli(t, g, "ape_good\n", "--config", config, "enroll", "example.com")
	if code != 0 || !strings.Contains(out, "Enrolled as nas.") || !strings.Contains(out, "SHA256:") {
		t.Fatalf("enroll = %d %q %q", code, out, errs)
	}
	st, err := os.Stat(keyFile)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("the key file: %v, %v", st, err)
	}
	f, err := readFile(config)
	if err != nil || f.Server != "example.com" || len(f.Targets) != 0 {
		t.Fatalf("the file it started = %+v, %v", f, err)
	}
	// The fingerprint it printed is of the key the gate saw.
	key, _ := readKey(keyFile)
	fp, _ := Fingerprint(key)
	cert, _ := certificate(key)
	g.mu.Lock()
	seen := g.keys[len(g.keys)-1]
	g.mu.Unlock()
	if !strings.Contains(out, fp) || seen != tunnel.KeyDigest(cert.Leaf) {
		t.Fatalf("printed %q; the gate saw %s", out, seen)
	}
	if code, out, _ := cli(t, g, "", "--config", config, "fingerprint"); code != 0 || strings.TrimSpace(out) != fp {
		t.Fatalf("fingerprint = %d %q", code, out)
	}

	// Enrolled again (the agent was removed and added): the key stays.
	if code, _, errs := cli(t, g, "", "--config", config, "enroll", "example.com", "ape_good"); code != 0 {
		t.Fatalf("a second enrolment: %q", errs)
	}
	again, _ := readKey(keyFile)
	if !again.Equal(key) {
		t.Fatal("a second enrolment replaced the key")
	}
	// The file is one server's.
	if code, _, errs := cli(t, g, "", "--config", config, "enroll", "elsewhere.example.com", "ape_good"); code != 1 || !strings.Contains(errs, "is for the server") {
		t.Fatalf("another server: %d %q", code, errs)
	}
	for _, args := range [][]string{{"enroll"}, {"enroll", "a", "b", "c"}, {"frobnicate"}} {
		if code, _, _ := cli(t, g, "", append([]string{"--config", config}, args...)...); code == 0 {
			t.Errorf("%v succeeded", args)
		}
	}
	if code, _, errs := cli(t, g, "", "--config", config, "enroll", "example.com"); code != 1 || !strings.Contains(errs, "no token") {
		t.Fatalf("no token: %d %q", code, errs)
	}
	if code, out, _ := cli(t, g, "", "version"); code != 0 || strings.TrimSpace(out) != "v-test" {
		t.Fatalf("version = %q", out)
	}
}

func TestTheFileIsReadStrictlyAndTheKeyIsItsOwnersAlone(t *testing.T) {
	g := newFakeGate(t)
	dir := t.TempDir()
	config := filepath.Join(dir, "agent.yaml")
	write := func(body string) {
		if err := os.WriteFile(config, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Before enrolment there is no key: run says what to do.
	write("server: example.com\ntargets: {}\n")
	if code, _, errs := cli(t, g, "", "--config", config, "run"); code != 1 || !strings.Contains(errs, "enrol first") {
		t.Fatalf("run with no key: %d %q", code, errs)
	}
	key, _ := NewKey()
	if err := WriteKey(filepath.Join(dir, "agent.key"), key); err != nil {
		t.Fatal(err)
	}
	if err := WriteKey(filepath.Join(dir, "agent.key"), key); err == nil {
		t.Fatal("a key file was replaced")
	}
	for what, c := range map[string]struct{ body, want string }{
		"a misspelt field":     {"server: example.com\ntarget:\n  a: {to: \"127.0.0.1:1\"}\n", "not found"},
		"a misspelt target":    {"server: example.com\ntargets:\n  a: {too: \"127.0.0.1:1\"}\n", "not found"},
		"no server":            {"targets: {}\n", "names no server"},
		"a target of no shape": {"server: example.com\ntargets:\n  a: {to: \"nowhere\"}\n", "not host:port"},
	} {
		write(c.body)
		if code, _, errs := cli(t, g, "", "--config", config, "run"); code != 1 || !strings.Contains(errs, c.want) {
			t.Errorf("%s: %d %q", what, code, errs)
		}
	}
	write("server: example.com\ntargets: {}\n")
	if err := os.Chmod(filepath.Join(dir, "agent.key"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, errs := cli(t, g, "", "--config", config, "run"); code != 1 || !strings.Contains(errs, "read by others") {
		t.Fatalf("a key others can read: %d %q", code, errs)
	}
	if code, _, errs := cli(t, g, "", "--config", filepath.Join(dir, "none.yaml"), "run"); code != 1 || errs == "" {
		t.Fatalf("no file: %d %q", code, errs)
	}
}
