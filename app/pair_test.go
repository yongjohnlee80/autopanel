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
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/yongjohnlee80/golib/server/rpc"

	"github.com/yongjohnlee80/autopanel/core/gate"
	"github.com/yongjohnlee80/autopanel/core/services"
	hostcontrol "github.com/yongjohnlee80/autopanel/host/control"
	hostgate "github.com/yongjohnlee80/autopanel/host/gate"
	hostservices "github.com/yongjohnlee80/autopanel/host/services"
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

// testConfig is a configuration in a temporary directory, with its sockets'
// directory made.
func testConfig(t *testing.T) Config {
	t.Helper()
	dir := t.TempDir()
	cfg := Config{
		StateDir: filepath.Join(dir, "state"), Socket: filepath.Join(dir, "run", "control.sock"),
		LinkSocket: filepath.Join(dir, "run", "link.sock"),
		Engine:     "sqlite", HTTPAddr: freeAddr(t), HTTPSAddr: freeAddr(t),
		CA: certmagic.LetsEncryptStagingCA, Email: "admin@example.com",
		Keyfile: filepath.Join(dir, "keyslot", "service.key"),
	}
	if err := os.MkdirAll(filepath.Dir(cfg.Socket), 0o700); err != nil {
		t.Fatal(err)
	}
	return cfg
}

// until polls ok for ten seconds.
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

// coreUp waits for the core's two sockets, and says why when the core stopped
// instead.
func coreUp(t *testing.T, cfg Config, done chan error) {
	t.Helper()
	until(t, "the core's sockets never came up", func() bool {
		select {
		case err := <-done:
			t.Fatalf("the core stopped before its sockets came up: %v", err)
		default:
		}
		return hostcontrol.InUse(cfg.Socket) && hostcontrol.InUse(cfg.LinkSocket)
	})
}

// wireCode is the code of the wire error err is, or 0.
func wireCode(err error) int64 {
	var re *rpc.Error
	if errors.As(err, &re) {
		return re.Code
	}
	return 0
}

// recordedGate is a GateControl that only counts what the core asked of it.
type recordedGate struct {
	mu                      sync.Mutex
	starts, restarts, stops int
	fail                    error
}

func (g *recordedGate) count(n *int) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	*n++
	return g.fail
}

func (g *recordedGate) Start(context.Context) error   { return g.count(&g.starts) }
func (g *recordedGate) Restart(context.Context) error { return g.count(&g.restarts) }
func (g *recordedGate) Stop(context.Context) error    { return g.count(&g.stops) }

func (g *recordedGate) counts() (int, int, int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.starts, g.restarts, g.stops
}

// TestTheCoreAndTheGateEndToEnd runs AutoPanel as --init, --core and --gate
// make it, in a temporary directory, as two halves joined only by the link
// socket, and drives it as the TUI does: the keyfile unlocks the vault at
// start, the control socket needs a login, a route added there reaches the
// gate over the link, and a second core on the store is refused. No ACME call
// is made: the test only crosses the plain listener.
func TestTheCoreAndTheGateEndToEnd(t *testing.T) {
	// The host reads are the test's own: no real socket table, no journal.
	defer func(l func(context.Context) ([]sysinfo.Listener, error), s func(context.Context, int) ([]sysinfo.SSHLogin, error), u func(int) string) {
		readListeners, readSSHLogins, userName = l, s, u
	}(readListeners, readSSHLogins, userName)
	var listening []sysinfo.Listener // set once the configuration names the gate's ports
	readListeners = func(context.Context) ([]sysinfo.Listener, error) { return listening, nil }
	userName = func(uid int) string { return map[int]string{0: "root", 33: "www-data"}[uid] }
	readSSHLogins = func(context.Context, int) ([]sysinfo.SSHLogin, error) {
		return []sysinfo.SSHLogin{{At: 4102444800, User: "root", From: "192.0.2.66", Result: "failed", Detail: "password"}}, nil
	}

	defer func(d time.Duration) { hostgate.ReportEvery = d }(hostgate.ReportEvery)
	hostgate.ReportEvery = 50 * time.Millisecond

	cfg := testConfig(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// The gate of this test runs in this process. Another program holds the
	// plain port's number on another address.
	listening = []sysinfo.Listener{
		{Proto: "tcp", Address: "0.0.0.0", Port: 22, UID: 0, Process: "sshd", PID: 612},
		{Proto: "udp", Address: "0.0.0.0", Port: 3478, UID: sysinfo.NoUID},
		{Proto: "tcp", Address: "127.0.0.1", Port: 7777, UID: sysinfo.NoUID},
		{Proto: "tcp", Address: "127.0.0.1", Port: portOf(cfg.HTTPSAddr), UID: 0, Process: "autopanel", PID: os.Getpid()},
		{Proto: "tcp", Address: "192.0.2.1", Port: portOf(cfg.HTTPAddr), UID: 33, Process: "nginx", PID: 4242},
		{Proto: "tcp", Address: "127.0.0.1", Port: portOf(cfg.HTTPAddr), UID: sysinfo.NoUID},
	}

	if err := Init(ctx, cfg, "root", strings.NewReader("short\n")); err == nil {
		t.Fatal("Init accepted a short passphrase")
	}
	if err := Init(ctx, cfg, "root", strings.NewReader("a long master passphrase\n")); err != nil {
		t.Fatal(err)
	}
	if err := Init(ctx, cfg, "root", strings.NewReader("a long master passphrase\n")); !errors.Is(err, store.ErrInitialized) {
		t.Fatalf("a second Init = %v; want ErrInitialized", err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	gc := &recordedGate{}
	done := make(chan error, 1)
	go func() { done <- CoreContext(ctx, cfg, log, gc) }()
	coreUp(t, cfg, done)
	until(t, "the core never started the gate", func() bool { s, _, _ := gc.counts(); return s == 1 })

	if err := CoreContext(ctx, cfg, log, nil); err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("a second core on the same socket = %v", err)
	}

	// The gate, as --gate runs it: it knows the link socket and nothing else.
	gateDone := make(chan error, 1)
	go func() { gateDone <- hostgate.Run(ctx, LinkDialer(cfg.LinkSocket), log) }()
	until(t, "the gate never listened", func() bool {
		c, err := net.Dial("tcp", cfg.HTTPAddr)
		if err != nil {
			return false
		}
		_ = c.Close()
		return true
	})

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
	// The link socket, as the gate sees it: its configuration, the table held
	// open until it changes, and no certificate for a name no route holds.
	// Each socket offers its own verbs and none of the other's.
	lc, err := hostcontrol.Dial(ctx, cfg.LinkSocket)
	if err != nil {
		t.Fatal(err)
	}
	defer lc.Close()
	var hello hostgate.Hello
	if err := lc.Call(ctx, hostgate.VerbHello, nil, &hello); err != nil || hello.HTTP != cfg.HTTPAddr || hello.HTTPS != cfg.HTTPSAddr {
		t.Fatalf("link.hello = %+v, %v", hello, err)
	}
	var table hostgate.Routes
	if err := lc.Call(ctx, hostgate.VerbRoutes, hostgate.After{}, &table); err != nil || table.Rev == 0 || len(table.Routes) != 0 {
		t.Fatalf("link.routes = %+v, %v; want an empty table with a revision", table, err)
	}
	next := make(chan hostgate.Routes, 1)
	go func() {
		var r hostgate.Routes
		if err := lc.Call(ctx, hostgate.VerbRoutes, hostgate.After{After: table.Rev}, &r); err == nil {
			next <- r
		}
	}()
	select {
	case r := <-next:
		t.Fatalf("link.routes answered %+v with nothing changed", r)
	case <-time.After(200 * time.Millisecond):
	}
	if err := lc.Call(ctx, hostgate.VerbCert, hostgate.Name{Name: "stranger.example.com"}, nil); wireCode(err) != -32190 {
		t.Fatalf("link.cert for a name no route holds = %v; want link.unknown_host", err)
	}
	if err := lc.Call(ctx, "sys.status", nil, nil); wireCode(err) != rpc.CodeMethodNotFound {
		t.Fatalf("the link socket answered a control verb: %v", err)
	}
	if err := c.Call(ctx, hostgate.VerbHello, nil, nil); wireCode(err) != rpc.CodeMethodNotFound {
		t.Fatalf("the control socket answered a link verb: %v", err)
	}

	var added gate.RouteView
	// A route's host must be under a registered domain.
	if err := c.Call(ctx, "gate.route.add", gate.RouteSpec{Host: "app.example.com", Upstream: up.URL}, nil); wireCode(err) != -32155 {
		t.Fatalf("a route under no domain = %v; want gate.no_domain", err)
	}
	if err := c.Call(ctx, "gate.domain.add", gate.DomainRef{Name: "Example.COM."}, nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Call(ctx, "gate.route.add", gate.RouteSpec{Host: "app.example.com", Upstream: up.URL}, &added); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-next:
		if r.Rev == table.Rev || len(r.Routes) != 1 || r.Routes[0].Host != "app.example.com" || r.Routes[0].Upstream != up.URL {
			t.Fatalf("the held link.routes answered %+v; want the new route", r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the held link.routes never answered the added route")
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
	until(t, "the gate's request count never reached the core", func() bool {
		return c.Call(ctx, "sys.metrics", nil, &ms) == nil && ms.HTTPRequests == 1
	})
	if ms.Goroutines == 0 || ms.RuntimeBytes == 0 || ms.Routes != 1 {
		t.Fatalf("sys.metrics = %+v", ms)
	}
	// The gate reports its process and its memory with its counts.
	if g := ms.Gate; !g.Running || g.PID != os.Getpid() || g.MemoryBytes == 0 {
		t.Fatalf("sys.metrics' gate = %+v; want this process, running, with its memory", g)
	}
	var entries []store.AuditEntry
	if err := c.Call(ctx, "sys.audit.list", Limit{Limit: 3}, &entries); err != nil || len(entries) != 3 || entries[0].ID <= entries[1].ID {
		t.Fatalf("sys.audit.list = %+v, %v", entries, err)
	}
	if entries[0].Action != "secret.delete" || !strings.HasPrefix(entries[0].Actor, "root") {
		t.Fatalf("the newest audit entry = %+v; want the token's removal, by root", entries[0])
	}
	// The gate's lifecycle is the core's: each action is audited before it
	// runs, and its outcome after.
	if err := c.Call(ctx, "sys.gate.restart", nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, restarts, stops := gc.counts(); restarts != 1 || stops != 0 {
		t.Fatalf("after sys.gate.restart the gate saw %d restarts, %d stops", restarts, stops)
	}
	if err := c.Call(ctx, "sys.audit.list", Limit{Limit: 1}, &entries); err != nil || len(entries) != 1 ||
		entries[0].Action != "sys.gate.restart" || entries[0].Outcome != "ok" || !strings.HasPrefix(entries[0].Actor, "root") {
		t.Fatalf("the restart's audit entry = %+v, %v; want one entry, by root, with the outcome ok", entries, err)
	}
	gc.mu.Lock()
	gc.fail = errors.New("the unit is masked")
	gc.mu.Unlock()
	if err := c.Call(ctx, "sys.gate.stop", nil, nil); wireCode(err) != -32183 || strings.Contains(err.Error(), "masked") {
		t.Fatalf("a failed sys.gate.stop = %v; want sys.gate_control_failed, without the host's detail", err)
	}
	if err := c.Call(ctx, "sys.audit.list", Limit{Limit: 1}, &entries); err != nil || entries[0].Action != "sys.gate.stop" || entries[0].Outcome != "sys.gate_control_failed" {
		t.Fatalf("the failed stop's audit entry = %+v, %v", entries, err)
	}
	if _, err := (&sysModule{}).gateStop(ctx, struct{}{}); !errors.Is(err, errNoGateControl) {
		t.Fatalf("a core that runs no gate unit answered %v", err)
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
	if err := c.Call(ctx, "sys.ports", nil, &ports); err != nil || len(ports) != 6 {
		t.Fatalf("sys.ports = %+v, %v", ports, err)
	}
	// A socket carries its process and its user when the host names them, and
	// then no guess from its port. Only a socket whose process is unknown is
	// given its port's usual service.
	if p := ports[0]; p.Process != "sshd" || p.PID != 612 || p.User != "root" || p.Use != "" {
		t.Fatalf("the SSH port = %+v; want its process and user, and no guess", p)
	}
	if p := ports[1]; p.Proto != "udp" || p.Process != "" || p.User != "" || p.Use != "TURN/STUN (usual for this port)" {
		t.Fatalf("a socket with no process = %+v; want its port's usual service", p)
	}
	if ports[2].Use != "" {
		t.Fatalf("an unknown port = %+v", ports[2])
	}
	// AutoPanel's own are the gate's ports held by the gate's process, or by
	// one the host does not name: another program on the same port is itself.
	if p := ports[3]; p.Use != "AutoPanel: HTTPS (the proxy)" || p.Process != "autopanel" {
		t.Fatalf("the gate's HTTPS socket = %+v", p)
	}
	if p := ports[4]; p.Use != "" || p.Process != "nginx" || p.User != "www-data" {
		t.Fatalf("another program on the gate's plain port = %+v; want it named as itself", p)
	}
	if p := ports[5]; !strings.HasPrefix(p.Use, "AutoPanel: HTTP (") {
		t.Fatalf("the gate's plain socket, its process unknown = %+v", p)
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
	for name, ch := range map[string]chan error{"the core": done, "the gate": gateDone} {
		select {
		case err := <-ch:
			if err != nil {
				t.Fatalf("%s stopped with %v", name, err)
			}
		case <-time.After(15 * time.Second):
			t.Fatalf("%s did not stop", name)
		}
	}
}

// machine is the services' host with its files real and its machine not: a
// stack's definition is staged and read as on a host, from folders of the
// test's own, and no user is made, no image pulled and no unit started.
type machine struct {
	*hostservices.Host
	mu      sync.Mutex
	podman  [2]int
	users   map[string]bool
	units   map[string]map[string]string // stack → unit file → text
	running map[string]bool              // by systemd service
	pulled  []string
}

func newMachine(t *testing.T, stacks string) *machine {
	t.Helper()
	return &machine{Host: hostservices.New(filepath.Join(t.TempDir(), "services"), stacks), podman: [2]int{4, 9},
		users: map[string]bool{}, units: map[string]map[string]string{}, running: map[string]bool{}}
}

func (h *machine) Podman(context.Context) (int, int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.podman == [2]int{} {
		return 0, 0, services.ErrNoPodman
	}
	return h.podman[0], h.podman[1], nil
}

func (h *machine) EnsureUser(_ context.Context, name string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.users[name] = true
	return nil
}

func (h *machine) Commit(context.Context, string, services.Commit) error { return nil }

func (h *machine) Install(_ context.Context, u services.Unit) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.units[u.Name] == nil {
		h.units[u.Name] = map[string]string{}
	}
	for _, f := range u.Files {
		h.units[u.Name][f.Path] = string(f.Body)
	}
	return nil
}

func (h *machine) DeleteUnits(_ context.Context, name string, paths []string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, p := range paths {
		delete(h.units[name], p)
	}
	return nil
}

func (h *machine) HasImage(context.Context, string, string) (bool, error) { return true, nil }

func (h *machine) Pull(_ context.Context, _ string, ref string) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pulled = append(h.pulled, ref)
	return "sha256:" + strings.Repeat("a", 64), nil
}

func (h *machine) set(units []string, on bool) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, u := range units {
		h.running[u] = on
	}
	return nil
}

func (h *machine) Start(_ context.Context, _ string, u []string) error   { return h.set(u, true) }
func (h *machine) Restart(_ context.Context, _ string, u []string) error { return h.set(u, true) }
func (h *machine) Stop(_ context.Context, _ string, u []string) error    { return h.set(u, false) }

func (h *machine) Uninstall(_ context.Context, name string, _ bool) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.units, name)
	delete(h.users, name)
	return nil
}

func (h *machine) Running(_ context.Context, _ string, units []string) (map[string]services.Running, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := map[string]services.Running{}
	for _, u := range units {
		out[u] = services.Running{Active: "inactive", Sub: "dead"}
		if h.running[u] {
			out[u] = services.Running{Active: "active", Sub: "running", MemoryBytes: 1 << 20, Since: 1700000000}
		}
	}
	return out, nil
}

func (h *machine) Health(_ context.Context, name string) (map[string]string, error) {
	return map[string]string{name + "-web": "healthy"}, nil
}

func (h *machine) Logs(_ context.Context, _, container string, _ int) ([]string, error) {
	return []string{container + ": listening"}, nil
}

func (h *machine) Listening(context.Context, string) ([]services.PortUse, error) { return nil, nil }

// definition writes a stack's folder as an administrator would.
func definition(t *testing.T, stacks, name string, files map[string]string) {
	t.Helper()
	for file, text := range files {
		p := filepath.Join(stacks, name, file)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

const blogCompose = `services:
  web:
    image: example.com/blog:1
    user: "1000:1000"
    read_only: true
    mem_limit: 64m
    environment: {TOKEN: "${TOKEN}"}
    volumes: ["./site.conf:/etc/site.conf:ro", "./posts:/posts"]
    ports: ["127.0.0.1:8081:8080", "3478:3478/udp"]
`

// TestStacksThroughTheControlSocket adds a stack as the panel would: the
// review changes nothing, every changing verb leaves its audit entry first
// with the review it accepts, a refusal names its cause, and Open ports names
// the stack's sockets by its name.
func TestStacksThroughTheControlSocket(t *testing.T) {
	defer func(l func(context.Context) ([]sysinfo.Listener, error), u func(int) string, h func(Config) services.Host) {
		readListeners, userName, serviceHost = l, u, h
	}(readListeners, userName, serviceHost)
	readListeners = func(context.Context) ([]sysinfo.Listener, error) {
		return []sysinfo.Listener{
			{Proto: "udp", Address: "0.0.0.0", Port: 3478, UID: 990, Process: "rootlessport", PID: 77},
			{Proto: "udp", Address: "0.0.0.0", Port: 3479, UID: 991, Process: "other", PID: 78},
		}, nil
	}
	userName = func(uid int) string { return map[int]string{990: "ap-blog", 991: "ap-other"}[uid] }
	stacks := filepath.Join(t.TempDir(), "stacks")
	definition(t, stacks, "blog", map[string]string{"compose.yaml": blogCompose, ".env": "TOKEN=t0ken-value\n", "site.conf": "listen 8080\n"})
	host := newMachine(t, stacks)
	host.podman = [2]int{}
	serviceHost = func(Config) services.Host { return host }

	cfg := testConfig(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := Init(ctx, cfg, "root", strings.NewReader("a long master passphrase\n")); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	done := make(chan error, 1)
	go func() { done <- CoreContext(ctx, cfg, log, nil) }()
	coreUp(t, cfg, done)
	c, err := hostcontrol.Dial(ctx, cfg.Socket)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Call(ctx, "services.add", services.Accept{Name: "blog", Accept: "x"}, nil); wireCode(err) != rpc.CodeAccessDenied {
		t.Fatalf("an add before login = %v", err)
	}
	if err := c.Call(ctx, "auth.login", auth.Login{User: "root", Passphrase: "a long master passphrase"}, nil); err != nil {
		t.Fatal(err)
	}
	var entries []store.AuditEntry
	newest := func() store.AuditEntry {
		t.Helper()
		if err := c.Call(ctx, "sys.audit.list", Limit{Limit: 6}, &entries); err != nil {
			t.Fatalf("sys.audit.list = %+v, %v", entries, err)
		}
		for _, e := range entries {
			if e.Outcome != "" {
				return e
			}
		}
		t.Fatalf("no privileged entry among %+v", entries)
		return store.AuditEntry{}
	}

	// The review reads the definition, and makes nothing.
	var folders []services.Folder
	if err := c.Call(ctx, "services.available", nil, &folders); err != nil || len(folders) != 1 || folders[0].Name != "blog" {
		t.Fatalf("services.available = %+v, %v", folders, err)
	}
	var review services.Review
	if err := c.Call(ctx, "services.check", services.Ref{Name: "blog"}, &review); err != nil {
		t.Fatal(err)
	}
	if len(review.SHA256) != 64 || len(review.Files) != 3 || len(review.Containers) != 1 || review.Containers[0].User != "1000:1000" ||
		review.Containers[0].Image != "example.com/blog:1" || len(review.Containers[0].Ports) != 2 {
		t.Fatalf("the review = %+v", review)
	}
	warned := map[string]bool{}
	for _, f := range review.Findings {
		if f.Severity != services.Warning {
			t.Fatalf("the review refuses: %+v", f)
		}
		warned[f.ID] = true
		if strings.Contains(f.Detail, "t0ken-value") {
			t.Fatalf("a finding shows a value of .env: %+v", f)
		}
	}
	if !warned["image-by-tag"] || !warned["public-port"] || !warned["reach"] || warned["no-memory-limit"] || warned["image-user"] {
		t.Fatalf("the warnings = %v", warned)
	}
	var list []services.View
	if err := c.Call(ctx, "services.list", nil, &list); err != nil || len(list) != 0 || len(host.users) != 0 {
		t.Fatalf("after a review, services.list = %+v, %v; users %v", list, err, host.users)
	}

	// No Podman: the add is refused, saying so, with its entry.
	accept := services.Accept{Name: "blog", Accept: review.SHA256}
	if err := c.Call(ctx, "services.add", accept, nil); wireCode(err) != -32196 {
		t.Fatalf("an add with no Podman = %v; want services.no_podman", err)
	}
	if e := newest(); e.Action != "services.add" || e.Subject != `name "blog" accept "`+review.SHA256+`"` || e.Outcome != "services.no_podman" || !strings.HasPrefix(e.Actor, "root") {
		t.Fatalf("the refused add's entry = %+v", e)
	}
	host.mu.Lock()
	host.podman = [2]int{4, 8}
	host.mu.Unlock()
	if err := c.Call(ctx, "services.add", accept, nil); wireCode(err) != -32197 {
		t.Fatalf("an add on Podman 4.8 = %v; want services.old_podman", err)
	}
	host.mu.Lock()
	host.podman = [2]int{4, 9}
	host.mu.Unlock()

	// A review that is not this definition's: refused, with nothing made.
	if err := c.Call(ctx, "services.add", services.Accept{Name: "blog", Accept: strings.Repeat("0", 64)}, nil); wireCode(err) != -32195 {
		t.Fatalf("an add of another review = %v; want services.changed", err)
	}
	// A definition the policy refuses: the error names what.
	definition(t, stacks, "bad", map[string]string{"compose.yaml": "services:\n  x: {image: example.com/x:1, volumes: [\"/etc:/host\"]}\n"})
	var bad services.Review
	if err := c.Call(ctx, "services.check", services.Ref{Name: "bad"}, &bad); err != nil {
		t.Fatal(err)
	}
	if err := c.Call(ctx, "services.add", services.Accept{Name: "bad", Accept: bad.SHA256}, nil); wireCode(err) != -32194 || !strings.Contains(err.Error(), "absolute-path") {
		t.Fatalf("an add of a refused stack = %v; want services.refused naming the finding", err)
	}
	if e := newest(); e.Action != "services.add" || e.Outcome != "services.refused" {
		t.Fatalf("the refused stack's entry = %+v", e)
	}
	if len(host.users) != 0 {
		t.Fatalf("a refused add made a user: %v", host.users)
	}

	var v services.View
	if err := c.Call(ctx, "services.add", accept, &v); err != nil {
		t.Fatal(err)
	}
	if v.Name != "blog" || v.User != "ap-blog" || v.State != "deployed" || v.SHA256 != review.SHA256 || len(v.Containers) != 1 ||
		v.Containers[0].Active != "active" || v.Containers[0].Health != "healthy" || !strings.HasPrefix(v.Containers[0].Digest, "sha256:") {
		t.Fatalf("the added stack = %+v", v)
	}
	if e := newest(); e.Action != "services.add" || e.Outcome != "ok" {
		t.Fatalf("the add's entry = %+v", e)
	}
	host.mu.Lock()
	unit := host.units["blog"][".config/containers/systemd/blog-web.container"]
	host.mu.Unlock()
	if !strings.Contains(unit, "Image=example.com/blog@sha256:") || strings.Contains(unit, "t0ken-value") || !strings.Contains(unit, "EnvironmentFile=%h/stack/.autopanel/web.env\n") {
		t.Fatalf("the unit names its image by a tag, or holds a value of .env:\n%s", unit)
	}
	// The value of .env is nowhere in the store either.
	for _, name := range []string{"autopanel.db", "autopanel.db-wal"} {
		if b, err := os.ReadFile(filepath.Join(cfg.StateDir, name)); err == nil && strings.Contains(string(b), "t0ken-value") {
			t.Fatalf("%s holds a value of .env", name)
		}
	}

	// A stop is one privileged verb, with the service it names in its entry.
	if err := c.Call(ctx, "services.stop", services.Ref{Name: "blog", Service: "web"}, &v); err != nil || !v.Containers[0].Stopped || v.Containers[0].Active != "inactive" {
		t.Fatalf("after a stop = %+v, %v", v, err)
	}
	if e := newest(); e.Action != "services.stop" || e.Subject != `name "blog" service "web"` || e.Outcome != "ok" {
		t.Fatalf("the stop's entry = %+v", e)
	}
	if err := c.Call(ctx, "services.start", services.Ref{Name: "blog"}, &v); err != nil || v.Containers[0].Stopped || v.Containers[0].Active != "active" {
		t.Fatalf("after a start = %+v, %v", v, err)
	}
	if err := c.Call(ctx, "services.stop", services.Ref{Name: "blog", Service: "nothing"}, nil); wireCode(err) != -32187 {
		t.Fatalf("a stop of a service the stack has not = %v; want services.no_service", err)
	}

	// A stack's sockets are named by its stack; another user's are not.
	var ports []Port
	if err := c.Call(ctx, "sys.ports", nil, &ports); err != nil || len(ports) != 2 {
		t.Fatalf("sys.ports = %+v, %v", ports, err)
	}
	if ports[0].Use != "service blog" || ports[0].User != "ap-blog" || ports[1].Use != "" {
		t.Fatalf("the ports = %+v; want the first named as the stack blog", ports)
	}
	var logs services.Logs
	if err := c.Call(ctx, "services.logs", services.LogsAsk{Name: "blog", Service: "web"}, &logs); err != nil || len(logs.Lines) != 1 || logs.Lines[0] != "blog-web: listening" {
		t.Fatalf("services.logs = %+v, %v", logs, err)
	}
	if err := c.Call(ctx, "services.logs", services.LogsAsk{Name: "../blog"}, &logs); wireCode(err) != -32193 {
		t.Fatalf("logs of a name that is none = %v; want services.bad_name", err)
	}
	if err := c.Call(ctx, "services.remove", services.Remove{Name: "blog", Purge: true}, nil); err != nil {
		t.Fatal(err)
	}
	if e := newest(); e.Action != "services.remove" || e.Outcome != "ok" {
		t.Fatalf("the removal's entry = %+v", e)
	}
	if err := c.Call(ctx, "services.list", nil, &list); err != nil || len(list) != 0 {
		t.Fatalf("services.list after the removal = %+v, %v", list, err)
	}
	if err := c.Call(ctx, "services.start", services.Ref{Name: "blog"}, nil); wireCode(err) != -32191 {
		t.Fatalf("a start of a removed stack = %v; want services.not_found", err)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the core stopped with %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the core did not stop")
	}
}
