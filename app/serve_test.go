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
