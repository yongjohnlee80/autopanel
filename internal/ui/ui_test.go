package ui

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yongjohnlee80/golib/tui"

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
}

func newFakeClient() *fakeClient {
	return &fakeClient{nextID: 3, routes: []gate.RouteView{
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
		CA: "https://acme-staging-v02.api.letsencrypt.org/directory", Challenge: "http-01",
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

func (f *fakeClient) snapshot() (added, updated []gate.RouteSpec, removed []int64, reads int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]gate.RouteSpec(nil), f.added...), append([]gate.RouteSpec(nil), f.updated...),
		append([]int64(nil), f.removed...), f.reads
}

func TestRouteSource(t *testing.T) {
	routes, _ := newFakeClient().Routes(context.Background())
	src := &routeSource{routes: routes}

	var titles []string
	for _, f := range src.Fields() {
		titles = append(titles, f.Title)
	}
	if got := strings.Join(titles, ","); got != "ID,Host,Path,Upstream" {
		t.Fatalf("Fields = %s", got)
	}
	if src.Len() != 2 {
		t.Fatalf("Len = %d, want 2", src.Len())
	}
	want := [][]string{
		{"1", "app.example.com", "/", "http://127.0.0.1:8080"},
		{"2", "api.example.com", "/v1", "http://127.0.0.1:9090"},
	}
	for row, cells := range want {
		for col, w := range cells {
			if got := src.Cell(row, col); got != w {
				t.Errorf("Cell(%d, %d) = %q, want %q", row, col, got, w)
			}
		}
	}
	for _, rc := range [][2]int{{-1, 0}, {2, 0}, {0, 4}} {
		if got := src.Cell(rc[0], rc[1]); got != "" {
			t.Errorf("Cell(%d, %d) = %q, want empty", rc[0], rc[1], got)
		}
	}
	if (&routeSource{}).Len() != 0 {
		t.Error("an empty source has rows")
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
	for _, part := range []string{"v0.1.0", "https :443", "http :80", "store sqlite", "CA LE staging", "http-01", "2 routes", "up 1m0s"} {
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

// harness runs the panel on a TestBackend.
type harness struct {
	t    *testing.T
	tb   *tui.TestBackend
	resc chan error
}

func start(t *testing.T, c Client) *harness {
	t.Helper()
	tb := tui.NewTestBackend(120, 30)
	ctx, cancel := context.WithCancel(context.Background())
	h := &harness{t: t, tb: tb, resc: make(chan error, 1)}
	go func() { h.resc <- run(ctx, c, tui.WithBackend(tb), tui.WithMinFrameInterval(0)) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-h.resc:
		case <-time.After(5 * time.Second):
			t.Errorf("the panel did not stop within 5s")
		}
	})
	return h
}

func (h *harness) keys(codes ...rune) {
	h.t.Helper()
	for _, r := range codes {
		text := ""
		if r >= 0x20 && r < 0xE000 {
			text = string(r)
		}
		if err := h.tb.Inject(tui.KeyEvent{Kind: tui.KeyPress, Code: r, Text: text}); err != nil {
			h.t.Fatalf("inject: %v", err)
		}
	}
}

func (h *harness) typeText(s string) { h.t.Helper(); h.keys([]rune(s)...) }

func (h *harness) waitFor(desc string, cond func() bool) {
	h.t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	h.t.Fatalf("timed out waiting for %s\n%s", desc, h.tb.String())
}

func (h *harness) waitText(sub string) {
	h.t.Helper()
	h.waitFor("the screen to show "+sub, func() bool { return strings.Contains(h.tb.String(), sub) })
}

func TestRunShowsRoutesAndQuits(t *testing.T) {
	f := newFakeClient()
	h := start(t, f)
	h.waitText("api.example.com")
	h.waitText("LE staging")
	h.waitText("q quit")

	h.keys('r')
	h.waitFor("a second read", func() bool { _, _, _, reads := f.snapshot(); return reads >= 2 })

	h.keys('q')
	select {
	case err := <-h.resc:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		h.resc <- nil // for the cleanup
	case <-time.After(5 * time.Second):
		t.Fatalf("q did not end Run")
	}
}

func TestAddThroughForm(t *testing.T) {
	f := newFakeClient()
	f.addErr = errors.New("gate: a route for this host and path prefix exists")
	h := start(t, f)
	h.waitText("api.example.com")

	h.keys('a')
	h.waitText("Add route")
	h.typeText("new.example.com")
	h.keys(tui.KeyTab, tui.KeyTab) // past the path prefix, left at "/"
	h.typeText("http://127.0.0.1:7000")
	h.keys(tui.KeyEnter)
	h.waitText("route for this host and path prefix exists")
	if !strings.Contains(h.tb.String(), "Add route") {
		t.Fatalf("the form closed on an error:\n%s", h.tb.String())
	}

	f.mu.Lock()
	f.addErr = nil
	f.mu.Unlock()
	h.keys(tui.KeyEnter)
	h.waitText("added new.example.com/")
	h.waitText("http://127.0.0.1:7000") // the table was read again
	added, _, _, _ := f.snapshot()
	want := gate.RouteSpec{Host: "new.example.com", PathPrefix: "/", Upstream: "http://127.0.0.1:7000"}
	if len(added) != 1 || added[0] != want {
		t.Fatalf("added = %+v, want [%+v]", added, want)
	}
}

func TestRemoveAsksFirst(t *testing.T) {
	f := newFakeClient()
	h := start(t, f)
	h.waitText("api.example.com")

	h.keys('d')
	h.waitText("Remove route #1")
	h.keys(tui.KeyEscape)
	h.waitFor("the dialog to close", func() bool { return !strings.Contains(h.tb.String(), "Remove route #1") })
	if _, _, removed, _ := f.snapshot(); len(removed) != 0 {
		t.Fatalf("removed without a yes: %v", removed)
	}

	h.keys('d')
	h.waitText("Remove route #1")
	h.keys('y')
	h.waitText("removed #1")
	if _, _, removed, _ := f.snapshot(); len(removed) != 1 || removed[0] != 1 {
		t.Fatalf("removed = %v, want [1]", removed)
	}
}
