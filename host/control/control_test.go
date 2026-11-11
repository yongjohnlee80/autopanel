package control

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/yongjohnlee80/golib/server/rpc"

	"github.com/yongjohnlee80/autopanel/core/audit"
	"github.com/yongjohnlee80/autopanel/core/gate"
)

// memRoutes is gate.Routes in memory, recording each write's actor.
type memRoutes struct {
	mu     sync.Mutex
	next   gate.RouteID
	rs     []gate.Route
	actors []string
}

func (m *memRoutes) All(context.Context) ([]gate.Route, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]gate.Route(nil), m.rs...), nil
}

func (m *memRoutes) Add(ctx context.Context, r gate.Route) (gate.Route, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, x := range m.rs {
		if x.Host == r.Host && x.PathPrefix == r.PathPrefix {
			return gate.Route{}, gate.ErrDuplicate
		}
	}
	m.next++
	r.ID = m.next
	m.rs = append(m.rs, r)
	m.actors = append(m.actors, audit.Actor(ctx))
	return r, nil
}

func (m *memRoutes) Update(context.Context, gate.Route) (gate.Route, error) {
	return gate.Route{}, errors.New("disk on fire at /secret/path") // an undeclared error
}

func (m *memRoutes) Remove(context.Context, gate.RouteID) (gate.Route, error) {
	return gate.Route{}, gate.ErrNotFound
}

func TestTheControlSocketServesVerbsAndKeepsErrorsPublicOrBare(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sock := filepath.Join(t.TempDir(), "c.sock") // TempDir is 0700, as CheckDir wants
	routes := &memRoutes{}
	reloads := 0
	gm := gate.NewModule(routes, func(context.Context) error { reloads++; return nil })
	srv, err := Listen(sock, slog.New(slog.NewTextHandler(io.Discard, nil)), gm)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()

	dctx, dcancel := context.WithTimeout(ctx, 5*time.Second)
	defer dcancel()
	c, err := Dial(dctx, sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	var added gate.RouteView
	if err := c.Call(dctx, "gate.route.add", gate.RouteSpec{Host: "Example.com", Upstream: "http://127.0.0.1:8080"}, &added); err != nil {
		t.Fatal(err)
	}
	if added.ID != 1 || added.Host != "example.com" || added.PathPrefix != "/" || reloads != 1 {
		t.Fatalf("add = %+v (reloads %d)", added, reloads)
	}
	if len(routes.actors) != 1 || routes.actors[0] == "unknown" {
		t.Fatalf("the write's actor = %v; want the socket's local:<uid>", routes.actors)
	}
	var list []gate.RouteView
	if err := c.Call(dctx, "gate.route.list", nil, &list); err != nil || len(list) != 1 {
		t.Fatalf("list = %+v, %v", list, err)
	}

	wireErr := func(err error) *rpc.Error {
		var re *rpc.Error
		if !errors.As(err, &re) {
			t.Fatalf("not a wire error: %v", err)
		}
		return re
	}
	if re := wireErr(c.Call(dctx, "gate.route.add", gate.RouteSpec{Host: "example.com", Upstream: "http://127.0.0.1:9"}, nil)); re.Code != -32151 {
		t.Errorf("a duplicate answered %+v; want gate.duplicate (-32151)", re)
	}
	if re := wireErr(c.Call(dctx, "gate.route.add", gate.RouteSpec{Host: "bad host", Upstream: "http://127.0.0.1:9"}, nil)); re.Code != -32152 {
		t.Errorf("a bad host answered %+v; want gate.bad_host (-32152)", re)
	}
	if re := wireErr(c.Call(dctx, "gate.route.add", map[string]any{"host": "a.example", "upstream": "http://x", "evil": 1}, nil)); re.Code != rpc.CodeInvalidParams {
		t.Errorf("an unknown field answered %+v; want invalid params", re)
	}
	re := wireErr(c.Call(dctx, "gate.route.update", gate.RouteSpec{ID: 1, Host: "example.com", Upstream: "http://127.0.0.1:1"}, nil))
	if re.Code != rpc.CodeInternal || re.Message == "" || containsAny(re.Message, "secret", "disk") {
		t.Errorf("an undeclared error answered %+v; want a bare internal error (R13)", re)
	}
	if reloads != 1 {
		t.Errorf("failed writes reloaded the table: %d reloads; want 1", reloads)
	}

	if _, err := Listen(sock, slog.New(slog.NewTextHandler(io.Discard, nil)), gm); err == nil {
		t.Error("a second Listen on a live socket succeeded")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the server did not stop")
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
	}
	return false
}
