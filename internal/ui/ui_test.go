package ui

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/yongjohnlee80/golib/tui"
	tuidecl "github.com/yongjohnlee80/golib/tui/decl"
	"github.com/yongjohnlee80/golib/tui/decl/decltest"

	"github.com/yongjohnlee80/autopanel/core/gate"
	"github.com/yongjohnlee80/autopanel/core/services"
	"github.com/yongjohnlee80/autopanel/internal/sysinfo"
)

// fakeClient is a Client over a daemon in memory, recording what it was asked.
type fakeClient struct {
	mu      sync.Mutex
	routes  []gate.RouteView
	domains []gate.DomainView
	nextID  int64
	added   []gate.RouteSpec
	updated []gate.RouteSpec
	removed []int64
	reads   int
	addErr  error
	ca      string   // the ACME directory the status reports
	setCAs  []string // what SetCA was asked for
	caErr   error
	logins  []string // the users Login was asked for, a "!" after a refused one
	prefs   Prefs    // what Prefs answers
	kept    []Prefs  // what SetPrefs was asked to keep
	sshNote string

	metricsErr   error // what Metrics answers, when set
	metricsReads int
	domainAsks   []string // "add example.org" or "remove example.com"

	mail fakeMail // the Mail menu's verbs (mail_test.go)

	stacks    []services.View            // what Stacks answers
	reviews   map[string]services.Review // what CheckStack answers, by stack
	checks    []string                   // the stacks CheckStack was asked for
	applies   []string                   // "add web <sha>": what ApplyStack was asked for
	applyErrs []error                    // what the next ApplyStacks answer, in turn
	pulls     []string                   // "web" or "web/app": what PullStack was asked for
	unitAsks  []string                   // "stop web/app": what StackUnit was asked for
	removals  []string                   // "web" or "web purge": what RemoveStack was asked for
	logAsks   []string                   // "web" or "web/app": what StackLogs was asked for
	imports   []string                   // "/home/ada/blog as blog": what ImportStack was asked for
	reimports []string                   // what ReimportStack was asked for
	folders   map[string]services.Listing
	files     map[string]services.PreviewText
}

func newFakeClient() *fakeClient {
	return &fakeClient{nextID: 3, ca: certmagic.LetsEncryptStagingCA,
		routes: []gate.RouteView{
			{ID: 1, Host: "app.example.com", PathPrefix: "/", Upstream: "http://127.0.0.1:8080"},
			{ID: 2, Host: "api.example.com", PathPrefix: "/v1", Upstream: "http://127.0.0.1:9090"},
		},
		domains: []gate.DomainView{{Name: "example.com", Routes: 2}, {Name: "example.net", Routes: 0}},
	}
}

// passphrase is the one the fake service accepts, for any user.
const passphrase = "a long master passphrase"

func (f *fakeClient) Login(_ context.Context, user, pass string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if pass != passphrase {
		f.logins = append(f.logins, user+"!")
		return errors.New("wrong user or passphrase")
	}
	f.logins = append(f.logins, user)
	return nil
}

func (f *fakeClient) Routes(context.Context) ([]gate.RouteView, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	return append([]gate.RouteView(nil), f.routes...), nil
}

func (f *fakeClient) Status(context.Context) (Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return Status{Version: "v0.1.0", HTTPS: ":443", HTTP: ":80", Store: "sqlite",
		CA: f.ca, Challenge: "http-01",
		Routes: len(f.routes), Uptime: "1m0s"}, nil
}

func (f *fakeClient) Add(_ context.Context, s gate.RouteSpec) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.addErr != nil {
		return f.addErr
	}
	if !slices.ContainsFunc(f.domains, func(d gate.DomainView) bool { return gate.Under(s.Host, d.Name) }) {
		return gate.ErrNoDomain // as the daemon: a route's host is under a registered domain
	}
	f.added = append(f.added, s)
	f.routes = append(f.routes, gate.RouteView{ID: f.nextID, Host: s.Host, PathPrefix: s.PathPrefix, Upstream: s.Upstream})
	f.nextID++
	return nil
}

func (f *fakeClient) Update(_ context.Context, s gate.RouteSpec) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.updated = append(f.updated, s)
	return nil
}

func (f *fakeClient) Remove(_ context.Context, id int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removed = append(f.removed, id)
	for i, r := range f.routes {
		if r.ID == id {
			f.routes = append(f.routes[:i], f.routes[i+1:]...)
			break
		}
	}
	return nil
}

func (f *fakeClient) SetCA(_ context.Context, ca string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setCAs = append(f.setCAs, ca)
	if f.caErr != nil {
		return f.caErr
	}
	f.ca = map[string]string{"staging": certmagic.LetsEncryptStagingCA, "production": certmagic.LetsEncryptProductionCA}[ca]
	return nil
}

func (f *fakeClient) Domains(context.Context) ([]gate.DomainView, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]gate.DomainView, 0, len(f.domains))
	for _, d := range f.domains {
		d.Routes = 0
		for _, r := range f.routes {
			if gate.Under(r.Host, d.Name) {
				d.Routes++
			}
		}
		out = append(out, d)
	}
	return out, nil
}

func (f *fakeClient) AddDomain(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.domainAsks = append(f.domainAsks, "add "+name)
	for _, d := range f.domains {
		if d.Name == name {
			return gate.ErrDomainExists
		}
	}
	f.domains = append(f.domains, gate.DomainView{Name: name})
	return nil
}

func (f *fakeClient) RemoveDomain(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.domainAsks = append(f.domainAsks, "remove "+name)
	for _, r := range f.routes {
		if gate.Under(r.Host, name) {
			return gate.ErrDomainInUse
		}
	}
	for i, d := range f.domains {
		if d.Name == name {
			f.domains = append(f.domains[:i], f.domains[i+1:]...)
			return nil
		}
	}
	return gate.ErrNoSuchDomain
}

// someMetrics is a host 42% busy on 4 CPUs, half its memory used, a quarter of
// its swap, a quarter of its disk, up 3 days and 4 hours, with two interfaces.
func someMetrics() Metrics {
	var m Metrics
	m.Uptime, m.Goroutines, m.HeapBytes, m.RuntimeBytes = "1m0s", 12, 3<<20, 9<<20
	m.HTTPSRequests, m.HTTPRequests, m.Routes = 41, 7, 2
	m.Gate.Running, m.Gate.PID, m.Gate.MemoryBytes = true, 177, 18<<20
	m.Host.Load.One, m.Host.Load.Five, m.Host.Load.Fifteen = 0.5, 0.25, 0.1
	m.Host.MemTotal, m.Host.MemAvailable = 2<<30, 1<<30
	m.Host.DiskTotal, m.Host.DiskFree = 40<<30, 30<<30
	m.Activity = sysinfo.Sample{CPUPercent: 42, CPUs: 4, SwapTotal: 1 << 30, SwapFree: 768 << 20, Uptime: 3*86400 + 4*3600 + 120, Seconds: 5,
		Network: []sysinfo.IfaceRate{
			{Iface: sysinfo.Iface{Name: "podman0", RxBytes: 3 << 20, TxBytes: 1 << 20}, RxPerSec: 512, TxPerSec: 0},
			{Iface: sysinfo.Iface{Name: "eth0", RxBytes: 5 << 30, TxBytes: 2 << 30, RxErrors: 1, TxErrors: 2}, RxPerSec: 1500, TxPerSec: 2_300_000},
		}}
	return m
}

func (f *fakeClient) Metrics(context.Context) (Metrics, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.metricsReads++
	if f.metricsErr != nil {
		return Metrics{}, f.metricsErr
	}
	return someMetrics(), nil
}

func (f *fakeClient) AuditLog(context.Context) ([]AuditEntry, error) {
	return []AuditEntry{
		{ID: 9, At: 1794211200, Actor: "root (local:999)", Action: "route.add", Subject: "route 2 api.example.com/v1", Detail: "http://127.0.0.1:9090"},
		{ID: 8, At: 1794211100, Actor: "local:999", Action: "auth.login", Subject: "user root", Detail: "ok"},
	}, nil
}

func (f *fakeClient) Logins(context.Context) (Logins, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return Logins{SSHNote: f.sshNote, Attempts: []LoginAttempt{
		{At: 1794211200, Source: "ssh", User: "admin", From: "192.0.2.66", Result: "failed", Detail: "password, invalid user"},
		{At: 1794211100, Source: "panel", User: "root", From: "local:999", Result: "ok"},
	}}, nil
}

func (f *fakeClient) Ports(context.Context) ([]Port, error) {
	return []Port{
		{Proto: "tcp", Address: "0.0.0.0", Port: 22, Process: "sshd", PID: 612, User: "root"},
		{Proto: "tcp", Address: "*", Port: 443, Process: "autopanel", PID: 177, User: "autopanel", Use: "AutoPanel: HTTPS (the proxy)"},
		{Proto: "udp", Address: "0.0.0.0", Port: 3478, Use: "TURN/STUN (usual for this port)"},
	}, nil
}

func (f *fakeClient) Prefs(context.Context) (Prefs, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.prefs, nil
}

func (f *fakeClient) SetPrefs(_ context.Context, p Prefs) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.kept = append(f.kept, p)
	return nil
}

// keptPrefs is what the panel asked the daemon to keep.
func (f *fakeClient) keptPrefs() []Prefs {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Prefs(nil), f.kept...)
}

func (f *fakeClient) snapshot() (added, updated []gate.RouteSpec, removed []int64, reads int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]gate.RouteSpec(nil), f.added...), append([]gate.RouteSpec(nil), f.updated...),
		append([]int64(nil), f.removed...), f.reads
}

// TestRoutesModel: the routes list's rows are the routes, a column per role,
// keyed by id so the cursor keeps its route across a read.
func TestRoutesModel(t *testing.T) {
	routes, _ := newFakeClient().Routes(context.Background())
	h := newHost(context.Background(), newFakeClient(), "v0.1.0")
	h.setRoutes(routes)

	if n := h.routesModel.RowCount(nil); n != 2 {
		t.Fatalf("RowCount = %d, want 2", n)
	}
	want := []map[string]string{
		{"key": "1", "id": "1", "host": "app.example.com", "path": "/", "upstream": "http://127.0.0.1:8080"},
		{"key": "2", "id": "2", "host": "api.example.com", "path": "/v1", "upstream": "http://127.0.0.1:9090"},
	}
	for row, roles := range want {
		for role, w := range roles {
			if got := h.routesModel.Data(tuidecl.Index{Row: row}, role).Raw; got != w {
				t.Errorf("row %d %s = %q, want %q", row, role, got, w)
			}
		}
		if got := h.routesModel.Key(tuidecl.Index{Row: row}); got != roles["key"] {
			t.Errorf("row %d key = %q, want %q", row, got, roles["key"])
		}
	}
	if r, ok := h.route(1); !ok || r.ID != 2 {
		t.Errorf("route(1) = %+v, %v; want route 2", r, ok)
	}
	for _, row := range []int{-1, 2} {
		if _, ok := h.route(row); ok {
			t.Errorf("route(%d) found a route", row)
		}
	}
	h.setRoutes(nil)
	if n := h.routesModel.RowCount(nil); n != 0 {
		t.Errorf("RowCount after an empty read = %d, want 0", n)
	}
}

func TestShortCA(t *testing.T) {
	for in, want := range map[string]string{
		"https://acme-staging-v02.api.letsencrypt.org/directory": "LE staging",
		"https://acme-v02.api.letsencrypt.org/directory":         "LE production",
		"https://ca.internal/acme/directory":                     "https://ca.internal/acme/directory",
		"":                                                       "-",
	} {
		if got := shortCA(inEnglish{}, in); got != want {
			t.Errorf("shortCA(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestStatusLine(t *testing.T) {
	s, _ := newFakeClient().Status(context.Background())
	got := statusLine(inEnglish{}, s)
	for _, part := range []string{"v0.1.0", "CA LE staging", "2 routes", "up 1m0s"} {
		if !strings.Contains(got, part) {
			t.Errorf("statusLine = %q, missing %q", got, part)
		}
	}
}

func TestFormSpec(t *testing.T) {
	cases := []struct {
		name                   string
		id                     int64
		host, prefix, upstream string
		want                   gate.RouteSpec
	}{
		{"empty prefix defaults to /", 0, "app.example.com", "", "http://127.0.0.1:8080",
			gate.RouteSpec{Host: "app.example.com", PathPrefix: "/", Upstream: "http://127.0.0.1:8080"}},
		{"blank prefix defaults to /", 0, "app.example.com", "   ", "http://u",
			gate.RouteSpec{Host: "app.example.com", PathPrefix: "/", Upstream: "http://u"}},
		{"fields trimmed, id kept", 7, "  api.example.com ", " /v1 ", " http://u:9 ",
			gate.RouteSpec{ID: 7, Host: "api.example.com", PathPrefix: "/v1", Upstream: "http://u:9"}},
	}
	for _, c := range cases {
		if got := formSpec(c.id, c.host, c.prefix, c.upstream); got != c.want {
			t.Errorf("%s: formSpec = %+v, want %+v", c.name, got, c.want)
		}
	}
}

// TestEveryQMLFileIsSound lints what the package ships: Main.qml under every
// theme, the dialogs and the views, parsed and type-checked against the
// vocabulary, the App singleton's sources and its commands (decl's Check, as
// qmllint).
func TestEveryQMLFileIsSound(t *testing.T) {
	h := newHost(context.Background(), newFakeClient(), "v0.1.0")
	decltest.Check(t, h.options(nil)...)
}

// TestEveryLanguageIsWhole judges the six catalogs: every message English has,
// each access key on English's letter, no two rows of a menu on one key.
func TestEveryLanguageIsWhole(t *testing.T) {
	h := newHost(context.Background(), newFakeClient(), "v0.1.0")
	decltest.CheckLanguages(t, h.options(nil)...)
}

// TestEveryMessageIsInEveryCatalog: each catalog holds exactly English's ids,
// so no language falls back to English for a message of the panel's, and
// every id is autopanel.<kind>.<area>.<slug>.
func TestEveryMessageIsInEveryCatalog(t *testing.T) {
	set := englishCatalog()
	want := set.IDs("en")
	if len(want) < 300 {
		t.Fatalf("the English catalog holds %d messages", len(want))
	}
	for _, lang := range languages {
		got := set.IDs(lang)
		if strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Errorf("%s holds %d messages, English %d; they differ", lang, len(got), len(want))
		}
	}
	for _, id := range want {
		if parts := strings.Split(id, "."); len(parts) != 4 || parts[0] != "autopanel" {
			t.Errorf("%s is not autopanel.<kind>.<area>.<slug>", id)
		}
	}
	for _, id := range []string{"autopanel.status.bar.line", "autopanel.notice.certs.caNow", "autopanel.value.logins.closed"} {
		if englishText(id) == id {
			t.Errorf("the English catalog has no %s", id)
		}
	}
}

// open runs the panel on a test backend against c, as Run does on a
// terminal: it stops at the login dialog.
func open(t *testing.T, c Client) *decltest.Screen {
	t.Helper()
	_, s := openHost(t, c, 120, 36)
	return s
}

// openHost is open at a size, with the host the screen runs.
func openHost(t *testing.T, c Client, w, ht int) (*host, *decltest.Screen) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	h := newHost(ctx, c, "v0.1.0")
	h.brw.start = "/home/ada"
	return h, decltest.RunWith(t, w, ht, func(p *tuidecl.Program) error { h.attach(p); return nil }, h.options(nil)...)
}

// signIn answers the login dialog as root: the passphrase field has the
// keyboard, and Enter signs in.
func signIn(t *testing.T, s *decltest.Screen) {
	t.Helper()
	s.WaitForText(t, "Sign in to AutoPanel")
	s.Keys(t, decltest.Type(passphrase)...)
	s.Keys(t, enter)
	s.WaitFor(t, "the login dialog to close", func(sc string) bool { return !strings.Contains(sc, "Sign in to AutoPanel") })
}

// start runs the panel against c and signs in.
func start(t *testing.T, c Client) *decltest.Screen {
	t.Helper()
	s := open(t, c)
	signIn(t, s)
	return s
}

// startHost is start, with the host.
func startHost(t *testing.T, c Client) (*host, *decltest.Screen) {
	t.Helper()
	h, s := openHost(t, c, 120, 36)
	signIn(t, s)
	return h, s
}

// openRoutes opens the proxy routes panel through the menu bar, as a user
// does: Alt+R opens Routes, p is "Proxy routes…".
func openRoutes(t *testing.T, s *decltest.Screen) {
	t.Helper()
	s.WaitForText(t, "CA LE staging") // the first read is in
	s.Keys(t, decltest.Alt('r'))
	s.WaitForText(t, "Proxy routes…")
	s.Keys(t, decltest.Rune('p'))
	waitFact(t, s, "Upstream", "http://127.0.0.1:8080") // the first route's details
}

var (
	enter     = tui.KeyEvent{Kind: tui.KeyPress, Code: tui.KeyEnter}
	escape    = tui.KeyEvent{Kind: tui.KeyPress, Code: tui.KeyEscape}
	tab       = tui.KeyEvent{Kind: tui.KeyPress, Code: tui.KeyTab}
	backspace = tui.KeyEvent{Kind: tui.KeyPress, Code: tui.KeyBackspace}
)

// TestTheMainScreen: the menu bar with the dock in its corner, the seven
// widgets, the status bar; no line of keys. The routes panel opens from its
// menu row and q closes it, not the program; r reads again, and q on the
// main screen quits.
func TestTheMainScreen(t *testing.T) {
	f := newFakeClient()
	s := start(t, f)
	s.WaitForText(t, "System    Routes    Certs    Services    Mail    Users    Go    View    Help")
	for _, part := range []string{"Host", "Network", "Stacks", "Traffic", "Certificates", "Ports", "Activity",
		"CA LE staging", "2 routes", "◫  ▦  ⇅  ↯  ✓  ⊡  ≡"} {
		s.WaitForText(t, part)
	}
	for _, gone := range []string{"r refresh", "q quit", "Menus: Alt"} {
		if strings.Contains(s.String(), gone) {
			t.Fatalf("the main screen shows a key hint %q:\n%s", gone, s)
		}
	}
	openRoutes(t, s)
	s.Keys(t, decltest.Rune('q')) // closes the routes panel, not the program
	s.WaitFor(t, "the routes panel to close", func(sc string) bool { return !strings.Contains(sc, "Proxy routes") })
	select {
	case <-s.Quit():
		t.Fatalf("q in the routes panel quit the program:\n%s", s)
	default:
	}

	_, _, _, before := f.snapshot()
	s.Keys(t, decltest.Rune('r'))
	s.WaitFor(t, "a read again", func(string) bool { _, _, _, reads := f.snapshot(); return reads > before })

	s.Keys(t, decltest.Rune('q'))
	select {
	case <-s.Quit():
	case <-time.After(decltest.WaitTimeout):
		t.Fatalf("q did not quit:\n%s", s)
	}
}

func TestCtrlCQuits(t *testing.T) {
	s := start(t, newFakeClient())
	s.WaitForText(t, "CA LE staging")
	s.Keys(t, decltest.Ctrl('c'))
	select {
	case <-s.Quit():
	case <-time.After(decltest.WaitTimeout):
		t.Fatalf("Ctrl+C did not quit:\n%s", s)
	}
}

// TestTheRoutesPanel: two panes, the routes on the left and the selected one
// whole on the right, its domain and the stack its upstream reaches named.
func TestTheRoutesPanel(t *testing.T) {
	f := withStacks()
	s := start(t, f)
	openRoutes(t, s)
	for _, part := range []string{"Routes · 2 · read at", "Details", "[ Add… ]", "[ Domains… ]", "[ Close (q) ]"} {
		s.WaitForText(t, part)
	}
	for _, f := range [][2]string{{"Route", "#1"}, {"Host", "app.example.com"}, {"Domain", "example.com"}, {"Stack", "web-app"}} {
		waitFact(t, s, f[0], f[1])
	}
	s.Keys(t, decltest.Rune('j'))
	waitFact(t, s, "Path prefix", "/v1")
	waitFact(t, s, "Stack", "-")
}

// TestAddThroughTheForm: a subdomain typed, the one domain chosen first, and
// the upstream typed; a refused add keeps the form, as typed, saying why; a
// second add starts empty.
func TestAddThroughTheForm(t *testing.T) {
	f := newFakeClient()
	f.domains = []gate.DomainView{{Name: "example.com"}}
	f.addErr = errors.New("gate: a route for this host and path prefix exists")
	s := start(t, f)
	openRoutes(t, s)

	s.Keys(t, decltest.Rune('a'))
	s.WaitForText(t, "Add route")
	s.WaitForText(t, "example.com") // the one domain, chosen
	s.Keys(t, decltest.Type("new")...)
	s.Keys(t, tab, tab, tab) // past the domain and the path prefix, left at "/"
	s.Keys(t, decltest.Type("http://127.0.0.1:7000")...)
	s.Keys(t, enter)
	s.WaitForText(t, "error: gate: a route for this host and path prefix exists")
	if !strings.Contains(s.String(), "Add route") || !strings.Contains(s.String(), "127.0.0.1:7000") {
		t.Fatalf("a refused add closed the form or lost what was typed:\n%s", s)
	}

	f.mu.Lock()
	f.addErr = nil
	f.mu.Unlock()
	s.Keys(t, enter)
	s.WaitForText(t, "added new.example.com/")
	gone(t, s, "Add route")
	added, _, _, _ := f.snapshot()
	want := gate.RouteSpec{Host: "new.example.com", PathPrefix: "/", Upstream: "http://127.0.0.1:7000"}
	if len(added) != 1 || added[0] != want {
		t.Fatalf("added = %+v, want [%+v]", added, want)
	}

	// A second add starts empty, though the first form was typed in.
	s.Keys(t, decltest.Rune('a'))
	s.WaitForText(t, "Add route")
	if strings.Contains(s.String(), "7000") {
		t.Fatalf("the form kept the last route's text:\n%s", s)
	}
	s.Keys(t, escape)
	gone(t, s, "Add route")
}

// TestEditTheSelectedRoute: the form opens on the route, its host split into
// the subdomain and its domain.
func TestEditTheSelectedRoute(t *testing.T) {
	f := newFakeClient()
	s := start(t, f)
	openRoutes(t, s)

	s.Keys(t, decltest.Rune('j'), enter) // the second row, Enter edits it
	s.WaitForText(t, "Edit route #2")
	s.WaitForText(t, "api")
	s.Keys(t, tab, tab, tab) // the domain, the path, the upstream
	s.Keys(t, decltest.Type("1")...)
	s.Keys(t, enter)
	s.WaitForText(t, "updated api.example.com/v1")
	_, updated, _, _ := f.snapshot()
	want := gate.RouteSpec{ID: 2, Host: "api.example.com", PathPrefix: "/v1", Upstream: "http://127.0.0.1:90901"}
	if len(updated) != 1 || updated[0] != want {
		t.Fatalf("updated = %+v, want [%+v]", updated, want)
	}
}

func TestRemoveAsksFirst(t *testing.T) {
	f := newFakeClient()
	s := start(t, f)
	openRoutes(t, s)

	s.Keys(t, decltest.Rune('r'))
	s.WaitForText(t, "Remove route #1")
	s.Keys(t, escape)
	gone(t, s, "Remove route #1")
	if _, _, removed, _ := f.snapshot(); len(removed) != 0 {
		t.Fatalf("removed without a yes: %v", removed)
	}

	s.Keys(t, decltest.Rune('r'))
	s.WaitForText(t, "Remove route #1")
	s.Keys(t, enter) // No is first: Enter alone removes nothing
	gone(t, s, "Remove route #1")
	if _, _, removed, _ := f.snapshot(); len(removed) != 0 {
		t.Fatalf("Enter removed: %v", removed)
	}

	s.Keys(t, decltest.Rune('r'))
	s.WaitForText(t, "Remove route #1")
	s.Keys(t, decltest.Rune('y'))
	s.WaitForText(t, "removed #1")
	s.WaitFor(t, "the list without route 1", func(sc string) bool { return !strings.Contains(sc, "app.example.com") })
	if _, _, removed, _ := f.snapshot(); len(removed) != 1 || removed[0] != 1 {
		t.Fatalf("removed = %v, want [1]", removed)
	}
}

// TestCertsTypeSwitchesTheService: Certs → Type → Production asks the daemon
// for production, and the certificates widget and the status bar then show
// what the daemon reports. A switch the daemon refuses says why and leaves the
// service as it was.
func TestCertsTypeSwitchesTheService(t *testing.T) {
	f := newFakeClient()
	s := start(t, f)
	s.WaitForText(t, "CA LE staging")
	s.WaitForText(t, "Issuer: Let's Encrypt staging")

	choose := func(letter rune) {
		t.Helper()
		s.Keys(t, decltest.Alt('c'))
		s.WaitForText(t, "Cloudflare token…")
		s.Keys(t, decltest.Rune('t'))
		s.WaitForText(t, "Production (trusted certificates)")
		s.Keys(t, decltest.Rune(letter))
	}

	choose('p')
	s.WaitForText(t, "certificates now come from Let's Encrypt production")
	s.WaitForText(t, "CA LE production")
	gone(t, s, "Issuer: Let's Encrypt staging") // the widget's line is production's now, wrapped at its width
	f.mu.Lock()
	asked := append([]string(nil), f.setCAs...)
	f.caErr = errors.New("certs: the vault is locked")
	f.mu.Unlock()
	if len(asked) != 1 || asked[0] != "production" {
		t.Fatalf("SetCA was asked for %v, want [production]", asked)
	}

	choose('s')
	s.WaitForText(t, "error: certs: the vault is locked")
	if !strings.Contains(s.String(), "CA LE production") {
		t.Fatalf("a refused switch changed what the panel shows:\n%s", s)
	}
}

// TestHelpAboutShowsTheVersions: Help → About names the panel's version and
// the running daemon's.
func TestHelpAboutShowsTheVersions(t *testing.T) {
	s := start(t, newFakeClient())
	s.WaitForText(t, "CA LE staging")
	s.Keys(t, decltest.Alt('h'))
	s.WaitForText(t, "About AutoPanel")
	s.Keys(t, decltest.Rune('a'))
	for _, part := range []string{"AutoPanel v0.1.0", "Daemon", "v0.1.0 · up 1m0s", "Apache-2.0", "github.com/yongjohnlee80/autopanel", "Close (q)"} {
		s.WaitForText(t, part)
	}
	s.Keys(t, escape)
	gone(t, s, "Apache-2.0")
}

// TestHelpKeysListsEveryKey: Help → Keys is a card of every key, by where it
// works; F1 opens it too.
func TestHelpKeysListsEveryKey(t *testing.T) {
	s := start(t, newFakeClient())
	s.WaitForText(t, "CA LE staging")
	s.Keys(t, decltest.Alt('h'))
	s.WaitForText(t, "Keys")
	s.Keys(t, decltest.Rune('k'))
	for _, part := range []string{"EVERYWHERE", "show these keys", "THE WIDGETS OF THE MAIN SCREEN", "PANELS"} {
		s.WaitForText(t, part)
	}
	s.Keys(t, decltest.Rune('q'))
	gone(t, s, "EVERYWHERE")
	s.Keys(t, tui.KeyEvent{Kind: tui.KeyPress, Code: tui.KeyF1})
	s.WaitForText(t, "EVERYWHERE")
	text := keysText(inEnglish{})
	for _, sec := range keySections {
		for _, r := range sec.rows {
			if !strings.Contains(text, r.keys) {
				t.Errorf("Help › Keys lacks %q", r.keys)
			}
		}
	}
}

// openSystem opens a row of the System menu by its access key.
func openSystem(t *testing.T, s *decltest.Screen, key rune) {
	t.Helper()
	s.Keys(t, decltest.Alt('y'))
	s.WaitForText(t, "Login attempts…")
	s.Keys(t, decltest.Rune(key))
}

// TestSystemMonitors: each row of the System menu opens its panel and reads
// it. The list's title says how many rows and when; the audit log, the logins
// and the ports are two panes, the selected row whole on the right. r in a
// panel reads it again.
func TestSystemMonitors(t *testing.T) {
	f := newFakeClient()
	f.sshNote = "SSH logins are not shown: the journal could not be read."
	s := start(t, f)
	s.WaitForText(t, "CA LE staging")

	openSystem(t, s, 'm')
	for _, part := range []string{"HTTPS requests", "41", "Core memory", "3.0 MiB in use · 9.0 MiB held", "Gate memory", "18.0 MiB · process 177",
		"0.50 · 0.25 · 0.10 (1, 5 and 15 minutes)", "1.0 GiB available of 2.0 GiB", "30.0 GiB free of 40.0 GiB", "Metrics · 10 · read at "} {
		s.WaitForText(t, part)
	}
	s.Keys(t, decltest.Rune('q'))
	gone(t, s, "Core memory")

	openSystem(t, s, 'a')
	for _, part := range []string{"Audit log", "Entries · 2 · read at ", "route.add"} {
		s.WaitForText(t, part)
	}
	for _, f := range [][2]string{{"Subject", "route 2 api.example.com/v1"}, {"Detail", "http://127.0.0.1:9090"}, {"Entry", "#9"}} {
		waitFact(t, s, f[0], f[1])
	}
	s.Keys(t, decltest.Rune('j'))
	waitFact(t, s, "Action", "auth.login")
	s.Keys(t, decltest.Rune('q'))
	gone(t, s, "Entries · 2")

	openSystem(t, s, 'l')
	for _, part := range []string{"Login attempts", "the journal could not be read", "admin", "failed"} {
		s.WaitForText(t, part)
	}
	waitFact(t, s, "From", "192.0.2.66")
	waitFact(t, s, "Detail", "password, invalid user")
	s.Keys(t, decltest.Rune('q'))
	gone(t, s, "192.0.2.66")

	openSystem(t, s, 'p')
	for _, part := range []string{"Open ports", "Sockets · 3 · read at ", "3478", "sshd (612)"} {
		s.WaitForText(t, part)
	}
	waitFact(t, s, "Process", "sshd (612)")
	waitFact(t, s, "User", "root")
	s.Keys(t, decltest.Rune('j'), decltest.Rune('j'))
	waitFact(t, s, "For", "TURN/STUN (usual for this port)")
	_, _, _, reads := f.snapshot()
	s.Keys(t, decltest.Rune('r')) // the panel's r: its own read, not the Window's
	s.WaitForText(t, "Sockets · 3 · read at ")
	if _, _, _, now := f.snapshot(); now != reads {
		t.Fatalf("r in a panel read the routes again: it is the panel's key there")
	}
}

// click presses and releases the left button on a cell.
func click(t *testing.T, s *decltest.Screen, x, y int) {
	t.Helper()
	s.Keys(t, tui.MouseEvent{Kind: tui.MousePress, Button: tui.MouseLeft, X: x, Y: y},
		tui.MouseEvent{Kind: tui.MouseRelease, Button: tui.MouseLeft, X: x, Y: y})
}

// dockAt is the cell of an icon in the dock, the menu bar's corner.
func dockAt(t *testing.T, s *decltest.Screen, icon string) (x, y int) {
	t.Helper()
	bar := strings.Split(s.String(), "\n")[0]
	i := strings.LastIndex(bar, icon)
	if i < 0 {
		t.Fatalf("no %s in the dock:\n%s", icon, s)
	}
	return len([]rune(bar[:i])), 0
}

// TestTheDockHidesAndShowsAPanel: an open panel's icon is in the dock; a
// click hides the panel, its state kept, and a click shows it again; Close
// closes it, and its icon goes.
func TestTheDockHidesAndShowsAPanel(t *testing.T) {
	s := start(t, newFakeClient())
	openRoutes(t, s)
	s.WaitFor(t, "the routes' icon in the dock", func(sc string) bool { return strings.Contains(strings.Split(sc, "\n")[0], "⇄") })

	x, y := dockAt(t, s, "⇄")
	click(t, s, x, y)
	gone(t, s, "Proxy routes")
	if !strings.Contains(strings.Split(s.String(), "\n")[0], "⇄") {
		t.Fatalf("a hidden panel left the dock:\n%s", s)
	}
	click(t, s, x, y)
	s.WaitForText(t, "Proxy routes")
	waitFact(t, s, "Host", "app.example.com")

	s.Keys(t, escape)
	gone(t, s, "Proxy routes")
	s.WaitFor(t, "the routes' icon to leave the dock", func(sc string) bool { return !strings.Contains(strings.Split(sc, "\n")[0], "⇄") })
}

// TestAPanelMovesAndResizes: Alt with the left button drags a panel, and Alt
// with the right button resizes it from its corner.
func TestAPanelMovesAndResizes(t *testing.T) {
	s := start(t, newFakeClient())
	openRoutes(t, s)
	at := func() (x, y, w int) { // the panel's title cell, and its top row's width
		for y, line := range strings.Split(s.String(), "\n") {
			if i := strings.Index(line, "┌ Proxy routes "); i >= 0 {
				rest := []rune(line[i:])
				end := 0
				for end < len(rest) && rest[end] != '┐' {
					end++
				}
				return len([]rune(line[:i])), y, end + 1
			}
		}
		return -1, -1, 0
	}
	x0, y0, w0 := at()
	if x0 < 0 {
		t.Fatalf("no routes panel on the screen:\n%s", s)
	}
	s.Keys(t, tui.MouseEvent{Kind: tui.MousePress, Button: tui.MouseLeft, Mods: tui.ModAlt, X: x0 + 20, Y: y0 + 3},
		tui.MouseEvent{Kind: tui.MouseMotion, Button: tui.MouseLeft, X: x0 + 14, Y: y0 + 1},
		tui.MouseEvent{Kind: tui.MouseRelease, Button: tui.MouseLeft, X: x0 + 14, Y: y0 + 1})
	s.WaitFor(t, "the panel to move 6 left and 2 up", func(string) bool { x, y, _ := at(); return x == x0-6 && y == y0-2 })

	x1, y1, _ := at()
	s.Keys(t, tui.MouseEvent{Kind: tui.MousePress, Button: tui.MouseRight, Mods: tui.ModAlt, X: x1 + w0 - 2, Y: y1 + 5},
		tui.MouseEvent{Kind: tui.MouseMotion, Button: tui.MouseRight, X: x1 + w0 - 12, Y: y1 + 5},
		tui.MouseEvent{Kind: tui.MouseRelease, Button: tui.MouseRight, X: x1 + w0 - 12, Y: y1 + 5})
	s.WaitFor(t, "the panel to be narrower, its corner kept", func(string) bool {
		x, y, w := at()
		return x == x1 && y == y1 && w < w0
	})
}

// TestLanguageSwitchesEverything: System → Language → 한국어 relabels the
// menus, the widgets and the text composed in Go (the status line, a widget's
// values, a panel's details, the tooltips); the choice is kept. A panel opened
// on a daemon that holds a language opens in it.
func TestLanguageSwitchesEverything(t *testing.T) {
	f := newFakeClient()
	h, s := startHost(t, f)
	s.WaitForText(t, "CA LE staging")
	openSystem(t, s, 'g')
	s.WaitForText(t, "한국어")
	s.Keys(t, decltest.Rune('2'))
	ko := map[string]string{}
	for _, id := range []string{"autopanel.menu.routes.title", "autopanel.menu.view.title", "autopanel.title.widget.host",
		"autopanel.title.widget.network", "autopanel.value.ca.shortStaging", "autopanel.tip.panel.close"} {
		ko[id] = onLoop(h, func() string { return h.tr(id) })
		if ko[id] == englishText(id) {
			t.Errorf("%s is English in Korean: %q", id, ko[id])
		}
	}
	for _, id := range []string{"autopanel.menu.routes.title", "autopanel.menu.view.title", "autopanel.title.widget.host", "autopanel.title.widget.network"} {
		word, _, _ := strings.Cut(ko[id], "(&") // a menu's "라우트(&r)" is drawn "라우트(r)": its word before the key
		s.WaitForText(t, strings.TrimSpace(word))
	}
	s.WaitForText(t, "CA "+ko["autopanel.value.ca.shortStaging"])
	if got := onLoop(h, func() string {
		c, ok := h.p.Find("routesClose")
		if !ok {
			return ""
		}
		return c.(interface{ ToolTip() string }).ToolTip()
	}); got != ko["autopanel.tip.panel.close"] {
		t.Errorf("the close tooltip after the switch = %q, want %q", got, ko["autopanel.tip.panel.close"])
	}
	s.WaitFor(t, "the language to be kept", func(string) bool {
		k := f.keptPrefs()
		return len(k) == 1 && k[0] == Prefs{Language: "ko_KR"}
	})

	g := newFakeClient()
	g.prefs = Prefs{Language: "ja_JP"}
	h2, s2 := startHost(t, g)
	s2.WaitFor(t, "the kept language", func(string) bool {
		return onLoop(h2, func() string { return h2.language }) == "ja_JP"
	})
	s2.WaitForText(t, "CA "+onLoop(h2, func() string { return h2.tr("autopanel.value.ca.shortStaging") }))
	if k := g.keptPrefs(); len(k) != 0 {
		t.Fatalf("opening in the kept language wrote it again: %+v", k)
	}
}

// TestThemeSwitchesAndIsKept: System → Theme → Nord reloads the layout under
// that theme, with the screen's state as it was, and the choice is kept. A
// panel opened on a daemon that holds a theme opens in it.
func TestThemeSwitchesAndIsKept(t *testing.T) {
	f := newFakeClient()
	s := start(t, f)
	s.WaitForText(t, "CA LE staging")
	openSystem(t, s, 't')
	s.WaitForText(t, "Tokyo Night")
	s.Keys(t, decltest.Rune('n'))
	s.WaitForText(t, "theme: nord")
	s.WaitForText(t, "CA LE staging") // the state survived the reload
	s.WaitFor(t, "the theme to be kept", func(string) bool {
		k := f.keptPrefs()
		return len(k) == 1 && k[0] == Prefs{Theme: "nord"}
	})
	openRoutes(t, s) // the reloaded screen still works

	g := newFakeClient()
	g.prefs = Prefs{Theme: "sepia", Language: "en"}
	h, s2 := startHost(t, g)
	s2.WaitForText(t, "CA LE staging")
	s2.WaitFor(t, "the kept theme to be shown", func(string) bool { return onLoop(h, func() string { return h.theme }) == "sepia" })
}

func TestBytesText(t *testing.T) {
	for in, want := range map[uint64]string{0: "0 B", 1023: "1023 B", 1024: "1.0 KiB", 1536: "1.5 KiB", 3 << 20: "3.0 MiB", 5 << 30: "5.0 GiB"} {
		if got := bytesText(in); got != want {
			t.Errorf("bytesText(%d) = %q, want %q", in, got, want)
		}
	}
}

// TestThePanelOpensOnTheLogin: nothing is read before a login. A wrong
// passphrase opens the dialog again with the reason and the user as typed,
// and the passphrase is never on the screen; the right one signs in, and the
// screen is then read.
func TestThePanelOpensOnTheLogin(t *testing.T) {
	f := newFakeClient()
	s := open(t, f)
	for _, part := range []string{"Sign in to AutoPanel", "User", "root", "Passphrase", "Sign in", "Quit"} {
		s.WaitForText(t, part)
	}
	if _, _, _, reads := f.snapshot(); reads != 0 {
		t.Fatalf("the panel read the routes %d times before a login", reads)
	}

	s.Keys(t, decltest.Type("not the passphrase")...)
	if strings.Contains(s.String(), "not the passphrase") {
		t.Fatalf("the passphrase is on the screen as typed:\n%s", s)
	}
	s.Keys(t, enter)
	s.WaitForText(t, "error: wrong user or passphrase")
	s.WaitForText(t, "Sign in to AutoPanel") // open again
	if _, _, _, reads := f.snapshot(); reads != 0 {
		t.Fatalf("a refused login read the routes (%d reads)", reads)
	}

	s.Keys(t, decltest.Type(passphrase)...) // the field was emptied, and has the keyboard
	s.Keys(t, enter)
	s.WaitForText(t, "signed in as root")
	s.WaitForText(t, "CA LE staging")
	if strings.Contains(s.String(), "Sign in to AutoPanel") {
		t.Fatalf("the login stayed open after signing in:\n%s", s)
	}
	f.mu.Lock()
	got := strings.Join(f.logins, ",")
	f.mu.Unlock()
	if got != "root!,root" {
		t.Fatalf("logins = %s, want root!,root", got)
	}
}

// TestALoginAsAnotherUser: the user field takes another name, kept across a
// refusal.
func TestALoginAsAnotherUser(t *testing.T) {
	f := newFakeClient()
	s := open(t, f)
	s.WaitForText(t, "Sign in to AutoPanel")
	shiftTab := tui.KeyEvent{Kind: tui.KeyPress, Code: tui.KeyTab, Mods: tui.ModShift}
	s.Keys(t, shiftTab) // back to the user field, from the passphrase
	s.Keys(t, decltest.Type("2")...)
	s.Keys(t, enter) // Enter in the user field moves to the passphrase
	s.Keys(t, decltest.Type(passphrase)...)
	s.Keys(t, enter)
	s.WaitForText(t, "signed in as root2")
}

// TestCancellingTheLoginQuits: signed out, the panel has nothing to show.
func TestCancellingTheLoginQuits(t *testing.T) {
	f := newFakeClient()
	s := open(t, f)
	s.WaitForText(t, "Sign in to AutoPanel")
	s.Keys(t, escape)
	select {
	case <-s.Quit():
	case <-time.After(decltest.WaitTimeout):
		t.Fatalf("Escape at the login did not quit:\n%s", s)
	}
	if _, _, _, reads := f.snapshot(); reads != 0 {
		t.Fatalf("a cancelled login read the routes (%d reads)", reads)
	}
}

// waitFact waits for a details pane's line: the label, the spaces that line
// the values up, then the value.
func waitFact(t *testing.T, s *decltest.Screen, label, value string) {
	t.Helper()
	re := regexp.MustCompile(regexp.QuoteMeta(label) + ` {2,}` + regexp.QuoteMeta(value))
	s.WaitFor(t, label+" "+value, func(sc string) bool { return re.MatchString(sc) })
}

// onLoop runs fn on the UI loop and returns its answer.
func onLoop[T any](h *host, fn func() T) T {
	ch := make(chan T, 1)
	h.p.Post(func() { ch <- fn() })
	return <-ch
}

// run runs fn on the loop, failing the test on its error.
func run(t *testing.T, h *host, fn func() error) {
	t.Helper()
	if err := onLoop(h, fn); err != nil {
		t.Fatal(err)
	}
}
