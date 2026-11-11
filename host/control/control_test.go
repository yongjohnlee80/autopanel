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
	"github.com/yongjohnlee80/autopanel/internal/auth"
	"github.com/yongjohnlee80/autopanel/internal/keyslot"
)

var cheap = keyslot.Params{Time: 1, MemKiB: 1024, Threads: 1}

type slots map[string]keyslot.PassphraseSlot

func (s slots) PassphraseSlot(_ context.Context, name string) (keyslot.PassphraseSlot, error) {
	if p, ok := s[name]; ok {
		return p, nil
	}
	return keyslot.PassphraseSlot{}, errors.New("no such user")
}

type auditLog struct {
	mu      sync.Mutex
	entries []string
}

func (a *auditLog) Audit(_ context.Context, actor, action, subject, detail string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, actor+" "+action+" "+subject+" "+detail)
	return nil
}

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
	mk, _ := keyslot.NewMasterKey()
	rootSlot, err := keyslot.SealPassphrase(mk, "a long master passphrase", cheap)
	if err != nil {
		t.Fatal(err)
	}
	vault := &keyslot.Vault{}
	unlocked := 0
	log := &auditLog{}
	am, err := auth.New(slots{"root": rootSlot}, log, vault, func(context.Context) { unlocked++ }, cheap)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := Listen(sock, slog.New(slog.NewTextHandler(io.Discard, nil)), gm, am)
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

	wireErr := func(err error) *rpc.Error {
		var re *rpc.Error
		if !errors.As(err, &re) {
			t.Fatalf("not a wire error: %v", err)
		}
		return re
	}
	if re := wireErr(c.Call(dctx, "gate.route.list", nil, nil)); re.Code != rpc.CodeAccessDenied {
		t.Fatalf("a verb before login answered %+v; want access denied", re)
	}
	if re := wireErr(c.Call(dctx, "auth.login", auth.Login{User: "root", Passphrase: "wrong"}, nil)); re.Code != -32160 {
		t.Fatalf("a wrong passphrase answered %+v; want auth.bad_login", re)
	}
	if re := wireErr(c.Call(dctx, "auth.login", auth.Login{User: "nobody", Passphrase: "a long master passphrase"}, nil)); re.Code != -32160 {
		t.Fatalf("an unknown user answered %+v; want the same auth.bad_login", re)
	}
	if re := wireErr(c.Call(dctx, "auth.login", auth.Login{User: "root", Passphrase: "a long master passphrase"}, nil)); re.Code != -32161 {
		t.Fatalf("a retry inside the wait answered %+v; want auth.throttled", re)
	}
	time.Sleep(1100 * time.Millisecond) // root failed once: a one-second wait
	var in auth.LoggedIn
	if err := c.Call(dctx, "auth.login", auth.Login{User: "root", Passphrase: "a long master passphrase"}, &in); err != nil {
		t.Fatal(err)
	}
	if in.User != "root" || !in.Unlocked || !vault.Unlocked() || unlocked != 1 {
		t.Fatalf("login = %+v, vault unlocked %v, onUnlock ran %d times", in, vault.Unlocked(), unlocked)
	}

	var added gate.RouteView
	if err := c.Call(dctx, "gate.route.add", gate.RouteSpec{Host: "Example.com", Upstream: "http://127.0.0.1:8080"}, &added); err != nil {
		t.Fatal(err)
	}
	if added.ID != 1 || added.Host != "example.com" || added.PathPrefix != "/" || reloads != 1 {
		t.Fatalf("add = %+v (reloads %d)", added, reloads)
	}
	if len(routes.actors) != 1 || len(routes.actors[0]) < 6 || routes.actors[0][:6] != "root (" {
		t.Fatalf("the write's actor = %v; want root (local:<uid>)", routes.actors)
	}
	if len(log.entries) < 2 || !containsAny(log.entries[0], "attempt") {
		t.Errorf("the login's attempt was not audited first: %v", log.entries)
	}
	var list []gate.RouteView
	if err := c.Call(dctx, "gate.route.list", nil, &list); err != nil || len(list) != 1 {
		t.Fatalf("list = %+v, %v", list, err)
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
