package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"

	"github.com/yongjohnlee80/autopanel/core/gate"
	hostcontrol "github.com/yongjohnlee80/autopanel/host/control"
	"github.com/yongjohnlee80/autopanel/internal/auth"
	"github.com/yongjohnlee80/autopanel/internal/sysinfo"
	"github.com/yongjohnlee80/autopanel/store"
)

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// TestTheDaemonEndToEnd runs AutoPanel as --init and --serve make it, in a
// temporary directory, and drives it as the TUI does: the keyfile unlocks the
// vault at start, the control socket needs a login, a route added there is
// served by the gate at once, and a second AutoPanel on the store is refused.
// No ACME call is made: the test only crosses the plain listener.
func TestTheDaemonEndToEnd(t *testing.T) {
	// The host reads are the test's own: no real socket table, no journal.
	defer func(l func() ([]sysinfo.Listener, error), s func(context.Context, int) ([]sysinfo.SSHLogin, error)) {
		readListeners, readSSHLogins = l, s
	}(readListeners, readSSHLogins)
	readListeners = func() ([]sysinfo.Listener, error) {
		return []sysinfo.Listener{{Proto: "tcp", Address: "0.0.0.0", Port: 22}, {Proto: "udp", Address: "0.0.0.0", Port: 3478},
			{Proto: "tcp", Address: "127.0.0.1", Port: 7777}}, nil
	}
	readSSHLogins = func(context.Context, int) ([]sysinfo.SSHLogin, error) {
		return []sysinfo.SSHLogin{{At: 4102444800, User: "root", From: "192.0.2.66", Result: "failed", Detail: "password"}}, nil
	}

	dir := t.TempDir()
	cfg := Config{
		StateDir: filepath.Join(dir, "state"), Socket: filepath.Join(dir, "run", "control.sock"),
		Engine: "sqlite", HTTPAddr: freeAddr(t), HTTPSAddr: freeAddr(t),
		CA: certmagic.LetsEncryptStagingCA, Email: "admin@example.com",
		Keyfile: filepath.Join(dir, "keyslot", "service.key"),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := Init(ctx, cfg, "root", strings.NewReader("short\n")); err == nil {
		t.Fatal("Init accepted a short passphrase")
	}
	if err := Init(ctx, cfg, "root", strings.NewReader("a long master passphrase\n")); err != nil {
		t.Fatal(err)
	}
	if err := Init(ctx, cfg, "root", strings.NewReader("a long master passphrase\n")); !errors.Is(err, store.ErrInitialized) {
		t.Fatalf("a second Init = %v; want ErrInitialized", err)
	}

	if err := os.MkdirAll(filepath.Dir(cfg.Socket), 0o700); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	done := make(chan error, 1)
	go func() { done <- ServeContext(ctx, cfg, log) }()
	deadline := time.Now().Add(10 * time.Second)
	for !hostcontrol.InUse(cfg.Socket) {
		if time.Now().After(deadline) {
			t.Fatal("the control socket never came up")
		}
		time.Sleep(50 * time.Millisecond)
	}

	if err := ServeContext(ctx, cfg, log); err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("a second AutoPanel on the same socket = %v", err)
	}

	c, err := hostcontrol.Dial(ctx, cfg.Socket)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var in auth.LoggedIn
	if err := c.Call(ctx, "auth.login", auth.Login{User: "root", Passphrase: "a long master passphrase"}, &in); err != nil {
		t.Fatal(err)
	}
	if in.Unlocked {
		t.Error("the login unlocked the vault, so the keyfile did not at start")
	}
	var st Status
	if err := c.Call(ctx, "sys.status", nil, &st); err != nil || st.Challenge != "http-01, tls-alpn-01" || st.Store != "sqlite" {
		t.Fatalf("status = %+v, %v", st, err)
	}

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "upstream") }))
	defer up.Close()
	var added gate.RouteView
	if err := c.Call(ctx, "gate.route.add", gate.RouteSpec{Host: "app.example.com", Upstream: up.URL}, &added); err != nil {
		t.Fatal(err)
	}

	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Timeout: 5 * time.Second}
	req, _ := http.NewRequest("GET", "http://"+cfg.HTTPAddr+"/path?q=1", nil)
	req.Host = "App.Example.com"
	res, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusPermanentRedirect || res.Header.Get("Location") != "https://app.example.com/path?q=1" {
		t.Fatalf("plain HTTP answered %d %q; want a 308 to the canonical https URL", res.StatusCode, res.Header.Get("Location"))
	}

	var cs CertState
	if err := c.Call(ctx, "certs.cloudflare.set", Token{Token: "test-token"}, &cs); err != nil || cs.Challenge != "dns-01 (cloudflare)" {
		t.Fatalf("certs.cloudflare.set = %+v, %v", cs, err)
	}
	if err := c.Call(ctx, "certs.cloudflare.clear", nil, &cs); err != nil || cs.Challenge != "http-01, tls-alpn-01" {
		t.Fatalf("certs.cloudflare.clear = %+v, %v", cs, err)
	}

	// The System menu's verbs. The metrics count the request above; the
	// audit log is newest first; the logins merge the panel's own with the
	// host's SSH logins; the ports name AutoPanel's own and a route's
	// upstream; the preferences are kept.
	var ms Metrics
	if err := c.Call(ctx, "sys.metrics", nil, &ms); err != nil || ms.HTTPRequests != 1 || ms.Goroutines == 0 || ms.RuntimeBytes == 0 || ms.Routes != 1 {
		t.Fatalf("sys.metrics = %+v, %v", ms, err)
	}
	var entries []store.AuditEntry
	if err := c.Call(ctx, "sys.audit.list", Limit{Limit: 3}, &entries); err != nil || len(entries) != 3 || entries[0].ID <= entries[1].ID {
		t.Fatalf("sys.audit.list = %+v, %v", entries, err)
	}
	if entries[0].Action != "secret.delete" || !strings.HasPrefix(entries[0].Actor, "root") {
		t.Fatalf("the newest audit entry = %+v; want the token's removal, by root", entries[0])
	}
	var ls Logins
	if err := c.Call(ctx, "sys.logins", nil, &ls); err != nil || ls.SSHNote != "" || len(ls.Attempts) != 2 {
		t.Fatalf("sys.logins = %+v, %v", ls, err)
	}
	if a := ls.Attempts[0]; a.Source != "ssh" || a.User != "root" || a.From != "192.0.2.66" || a.Result != "failed" {
		t.Fatalf("the newest attempt = %+v; want the SSH one", a)
	}
	if a := ls.Attempts[1]; a.Source != "panel" || a.User != "root" || a.Result != "ok" {
		t.Fatalf("the panel's login = %+v", a)
	}
	var ports []Port
	if err := c.Call(ctx, "sys.ports", nil, &ports); err != nil || len(ports) != 3 {
		t.Fatalf("sys.ports = %+v, %v", ports, err)
	}
	if ports[0].Use != "SSH (usual for this port)" || ports[1].Proto != "udp" || ports[1].Use != "TURN/STUN (usual for this port)" || ports[2].Use != "" {
		t.Fatalf("sys.ports named them %+v", ports)
	}
	var prefs Prefs
	if err := c.Call(ctx, "sys.prefs.get", nil, &prefs); err != nil || prefs != (Prefs{}) {
		t.Fatalf("the preferences start as %+v, %v; want none", prefs, err)
	}
	if err := c.Call(ctx, "sys.prefs.set", Prefs{Theme: "nord"}, &prefs); err != nil || prefs != (Prefs{Theme: "nord"}) {
		t.Fatalf("sys.prefs.set theme = %+v, %v", prefs, err)
	}
	if err := c.Call(ctx, "sys.prefs.set", Prefs{Language: "ko_KR"}, &prefs); err != nil || prefs != (Prefs{Theme: "nord", Language: "ko_KR"}) {
		t.Fatalf("sys.prefs.set language = %+v, %v", prefs, err)
	}
	if err := c.Call(ctx, "sys.prefs.set", Prefs{Theme: "../x"}, &prefs); err == nil || !strings.Contains(err.Error(), "letters, digits") {
		t.Fatalf("sys.prefs.set took a value that is no name: %+v, %v", prefs, err)
	}

	// The certificate service is the configuration's until the panel chooses
	// one; the choice is kept in the store and reported by sys.status.
	if cs.CA != certmagic.LetsEncryptStagingCA {
		t.Fatalf("the certificate service starts as %q; want the configuration's staging", cs.CA)
	}
	if err := c.Call(ctx, "certs.ca.set", CA{CA: "production"}, &cs); err != nil || cs.CA != certmagic.LetsEncryptProductionCA {
		t.Fatalf("certs.ca.set production = %+v, %v", cs, err)
	}
	if err := c.Call(ctx, "sys.status", nil, &st); err != nil || st.CA != certmagic.LetsEncryptProductionCA {
		t.Fatalf("status after the switch = %+v, %v", st, err)
	}
	if err := c.Call(ctx, "certs.ca.set", CA{CA: "https://ca.example.com/directory"}, &cs); err == nil || !strings.Contains(err.Error(), "staging or production") {
		t.Fatalf("certs.ca.set took a service that is neither: %+v, %v", cs, err)
	}
	if err := c.Call(ctx, "sys.status", nil, &st); err != nil || st.CA != certmagic.LetsEncryptProductionCA {
		t.Fatalf("a refused switch changed the service: %+v, %v", st, err)
	}
	if err := c.Call(ctx, "certs.ca.set", CA{CA: "staging"}, &cs); err != nil || cs.CA != certmagic.LetsEncryptStagingCA {
		t.Fatalf("certs.ca.set staging = %+v, %v", cs, err)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve stopped with %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Serve did not stop")
	}
}
