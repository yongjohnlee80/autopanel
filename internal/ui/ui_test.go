package ui

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/yongjohnlee80/golib/tui"
	tuidecl "github.com/yongjohnlee80/golib/tui/decl"
	"github.com/yongjohnlee80/golib/tui/decl/decltest"

	"github.com/yongjohnlee80/autopanel/core/gate"
)

// fakeClient is a Client over routes in memory, recording what it was asked.
type fakeClient struct {
	mu      sync.Mutex
	routes  []gate.RouteView
	nextID  int64
	added   []gate.RouteSpec
	updated []gate.RouteSpec
	removed []int64
	reads   int
	addErr  error
	ca      string   // the ACME directory the status reports
	setCAs  []string // what SetCA was asked for
	caErr   error
}

func newFakeClient() *fakeClient {
	return &fakeClient{nextID: 3, ca: certmagic.LetsEncryptStagingCA, routes: []gate.RouteView{
		{ID: 1, Host: "app.example.com", PathPrefix: "/", Upstream: "http://127.0.0.1:8080"},
		{ID: 2, Host: "api.example.com", PathPrefix: "/v1", Upstream: "http://127.0.0.1:9090"},
	}}
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

func (f *fakeClient) snapshot() (added, updated []gate.RouteSpec, removed []int64, reads int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]gate.RouteSpec(nil), f.added...), append([]gate.RouteSpec(nil), f.updated...),
		append([]int64(nil), f.removed...), f.reads
}

// TestRoutesModel: the table's rows are the routes, a column per role, keyed
// by id so the cursor keeps its route across a refresh.
func TestRoutesModel(t *testing.T) {
	routes, _ := newFakeClient().Routes(context.Background())
	h := newHost(context.Background(), newFakeClient(), "v0.1.0")
	h.setRoutes(routes)

	if n := h.model.RowCount(nil); n != 2 {
		t.Fatalf("RowCount = %d, want 2", n)
	}
	want := []map[string]string{
		{"key": "1", "id": "1", "host": "app.example.com", "path": "/", "upstream": "http://127.0.0.1:8080"},
		{"key": "2", "id": "2", "host": "api.example.com", "path": "/v1", "upstream": "http://127.0.0.1:9090"},
	}
	for row, roles := range want {
		for role, w := range roles {
			if got := h.model.Data(tuidecl.Index{Row: row}, role).Raw; got != w {
				t.Errorf("row %d %s = %q, want %q", row, role, got, w)
			}
		}
		if got := h.model.Key(tuidecl.Index{Row: row}); got != roles["key"] {
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
	if n := h.model.RowCount(nil); n != 0 {
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
		if got := shortCA(in); got != want {
			t.Errorf("shortCA(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestStatusLine(t *testing.T) {
	s, _ := newFakeClient().Status(context.Background())
	got := statusLine(s)
	for _, part := range []string{"v0.1.0", "CA LE staging", "2 routes", "up 1m0s"} {
		if !strings.Contains(got, part) {
			t.Errorf("statusLine = %q, missing %q", got, part)
		}
	}
}

// TestOverview: the main screen names every fact of the status, and says of
// staging that browsers do not trust it and where to switch.
func TestOverview(t *testing.T) {
	s, _ := newFakeClient().Status(context.Background())
	line := func(s Status) string {
		var b strings.Builder
		for _, f := range overview(s) {
			b.WriteString(f[0] + "=" + f[1] + "\n")
		}
		return b.String()
	}
	got := line(s)
	for _, part := range []string{"Version=v0.1.0\n", "HTTPS=:443\n", "HTTP=:80 ", "Store=sqlite\n",
		"Certificates=Let's Encrypt staging", "browsers do not trust", "Certs → Type", "Challenge=http-01\n", "Routes=2\n", "Uptime=1m0s\n"} {
		if !strings.Contains(got, part) {
			t.Errorf("overview = %q, missing %q", got, part)
		}
	}
	s.CA = certmagic.LetsEncryptProductionCA
	if got := line(s); !strings.Contains(got, "Let's Encrypt production") || strings.Contains(got, "do not trust") {
		t.Errorf("overview on production = %q", got)
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

// TestEveryQMLFileIsSound lints what the package ships: Main.qml and both
// dialogs, parsed and type-checked against the vocabulary, the App
// singleton's sources and its commands (decl's Check, as qmllint).
func TestEveryQMLFileIsSound(t *testing.T) {
	h := newHost(context.Background(), newFakeClient(), "v0.1.0")
	decltest.Check(t, h.options(nil)...)
}

// start runs the panel on a test backend against c, as Run does on a terminal.
func start(t *testing.T, c Client) *decltest.Screen {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	h := newHost(ctx, c, "v0.1.0")
	return decltest.RunWith(t, 120, 30, func(p *tuidecl.Program) error { h.attach(p); return nil }, h.options(nil)...)
}

// openRoutes opens the proxy routes manager through the menu bar, as a user
// does: Alt+R opens Routes, p is "Proxy routes…".
func openRoutes(t *testing.T, s *decltest.Screen) {
	t.Helper()
	s.WaitForText(t, "CA LE staging") // the first read is in
	s.Keys(t, decltest.Alt('r'))
	s.WaitForText(t, "Proxy routes…")
	s.Keys(t, decltest.Rune('p'))
	s.WaitForText(t, "api.example.com")
}

var (
	enter  = tui.KeyEvent{Kind: tui.KeyPress, Code: tui.KeyEnter}
	escape = tui.KeyEvent{Kind: tui.KeyPress, Code: tui.KeyEscape}
	tab    = tui.KeyEvent{Kind: tui.KeyPress, Code: tui.KeyTab}
)

func TestShowsRoutesRefreshesAndQuits(t *testing.T) {
	f := newFakeClient()
	s := start(t, f)
	// The menu bar, the overview and the status bar; the routes are not on
	// the main screen.
	for _, part := range []string{"Routes", "Certs", "Services", "Users", "System", "Help",
		"Overview", "Let's Encrypt staging", "CA LE staging", "2 routes", "r refresh"} {
		s.WaitForText(t, part)
	}
	if strings.Contains(s.String(), "api.example.com") {
		t.Fatalf("the routes are on the main screen:\n%s", s)
	}
	openRoutes(t, s)
	s.Keys(t, decltest.Rune('q')) // closes the manager, not the panel
	s.WaitFor(t, "the manager to close", func(sc string) bool { return !strings.Contains(sc, "api.example.com") })
	select {
	case <-s.Quit():
		t.Fatalf("q in the manager quit the panel:\n%s", s)
	default:
	}

	s.Keys(t, decltest.Rune('r'))
	s.WaitFor(t, "a second read", func(string) bool { _, _, _, reads := f.snapshot(); return reads >= 2 })

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

func TestAddThroughTheForm(t *testing.T) {
	f := newFakeClient()
	f.addErr = errors.New("gate: a route for this host and path prefix exists")
	s := start(t, f)
	openRoutes(t, s)

	s.Keys(t, decltest.Rune('a'))
	s.WaitForText(t, "Add route")
	s.Keys(t, decltest.Type("new.example.com")...)
	s.Keys(t, tab, tab) // past the path prefix, left at "/"
	s.Keys(t, decltest.Type("http://127.0.0.1:7000")...)
	s.Keys(t, enter)
	s.WaitForText(t, "error: gate: a route for this host and path prefix exists")
	if !strings.Contains(s.String(), "Add route") || !strings.Contains(s.String(), "new.example.com") {
		t.Fatalf("a refused add closed the form or lost what was typed:\n%s", s)
	}

	f.mu.Lock()
	f.addErr = nil
	f.mu.Unlock()
	s.Keys(t, enter)
	s.WaitForText(t, "added new.example.com/")
	s.WaitForText(t, "http://127.0.0.1:7000") // the table was read again
	if strings.Contains(s.String(), "Add route") {
		t.Fatalf("the form stayed open after the add:\n%s", s)
	}
	added, _, _, _ := f.snapshot()
	want := gate.RouteSpec{Host: "new.example.com", PathPrefix: "/", Upstream: "http://127.0.0.1:7000"}
	if len(added) != 1 || added[0] != want {
		t.Fatalf("added = %+v, want [%+v]", added, want)
	}

	// A second add starts empty, though the first form was typed in.
	s.Keys(t, decltest.Rune('a'))
	s.WaitForText(t, "Add route")
	if strings.Contains(s.String(), "new.example.com") { // the screen behind the dialog is dimmed out
		t.Fatalf("the form kept the last route's text:\n%s", s)
	}
	s.Keys(t, escape)
	s.WaitFor(t, "the form to close", func(sc string) bool { return !strings.Contains(sc, "Add route") })
}

func TestEditTheSelectedRoute(t *testing.T) {
	f := newFakeClient()
	s := start(t, f)
	openRoutes(t, s)

	s.Keys(t, decltest.Rune('j'), enter) // the second row, Enter edits it
	s.WaitForText(t, "Edit route #2")
	s.Keys(t, tab, tab)
	s.Keys(t, decltest.Type("1")...) // upstream http://127.0.0.1:90901
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

	s.Keys(t, decltest.Rune('d'))
	s.WaitForText(t, "Remove route #1")
	s.Keys(t, escape)
	s.WaitFor(t, "the question to close", func(sc string) bool { return !strings.Contains(sc, "Remove route #1") })
	if _, _, removed, _ := f.snapshot(); len(removed) != 0 {
		t.Fatalf("removed without a yes: %v", removed)
	}

	s.Keys(t, decltest.Rune('d'))
	s.WaitForText(t, "Remove route #1")
	s.Keys(t, decltest.Rune('y'))
	s.WaitForText(t, "removed #1")
	s.WaitFor(t, "the table without route 1", func(sc string) bool { return !strings.Contains(sc, "app.example.com") })
	if _, _, removed, _ := f.snapshot(); len(removed) != 1 || removed[0] != 1 {
		t.Fatalf("removed = %v, want [1]", removed)
	}
}

// TestCertsTypeSwitchesTheService: Certs → Type → Production asks the daemon
// for production, and the overview and status bar then show what the daemon
// reports. A switch the daemon refuses says why and leaves the service as it
// was.
func TestCertsTypeSwitchesTheService(t *testing.T) {
	f := newFakeClient()
	s := start(t, f)
	s.WaitForText(t, "CA LE staging")

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
	s.WaitForText(t, "real certificates, trusted by browsers")
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
	for _, part := range []string{"AutoPanel v0.1.0", "Daemon", "v0.1.0 · up 1m0s", "Apache-2.0", "github.com/yongjohnlee80/autopanel"} {
		s.WaitForText(t, part)
	}
	s.Keys(t, escape)
	s.WaitFor(t, "About to close", func(sc string) bool { return !strings.Contains(sc, "Apache-2.0") })
}
