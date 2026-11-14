package control

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yongjohnlee80/golib/server/rpc"

	"github.com/yongjohnlee80/autopanel/core/audit"
	"github.com/yongjohnlee80/autopanel/core/gate"
	"github.com/yongjohnlee80/autopanel/internal/auth"
	"github.com/yongjohnlee80/autopanel/internal/keyslot"
	"github.com/yongjohnlee80/autopanel/internal/module"
	"github.com/yongjohnlee80/autopanel/internal/peercred"
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

// anyDomain is gate.Domains holding one domain that covers every test host.
type anyDomain struct{}

func (anyDomain) All(context.Context) ([]gate.Domain, error) {
	return []gate.Domain{{Name: "example.com"}}, nil
}
func (anyDomain) Add(context.Context, gate.Domain) error { return nil }
func (anyDomain) Remove(context.Context, string) error   { return nil }

func TestTheControlSocketServesVerbsAndKeepsErrorsPublicOrBare(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sock := filepath.Join(t.TempDir(), "c.sock") // TempDir is 0700, as CheckDir wants
	routes := &memRoutes{}
	reloads := 0
	gm := gate.NewModule(routes, anyDomain{}, func(context.Context) error { reloads++; return nil })
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
	srv, err := Listen(sock, slog.New(slog.NewTextHandler(io.Discard, nil)), Access{}, gm, am)
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

	if _, err := Listen(sock, slog.New(slog.NewTextHandler(io.Discard, nil)), Access{}, gm); err == nil {
		t.Error("a second Listen on a live socket succeeded")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the server did not stop")
	}
}

// TestTheSocketAdmitsOnlyTheUsersItNames binds a socket for another user's
// processes: this process, which is not that user, is dropped at accept, and
// a client that expects another user's server refuses this one. The mode is
// the one asked for.
func TestTheSocketAdmitsOnlyTheUsersItNames(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sock := filepath.Join(t.TempDir(), "link.sock")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	gm := gate.NewModule(&memRoutes{}, anyDomain{}, func(context.Context) error { return nil })
	srv, err := Listen(sock, log, Access{Peers: []int{os.Getuid() + 1}, Mode: 0o660}, gm)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	if fi, err := os.Stat(sock); err != nil || fi.Mode().Perm() != 0o660 {
		t.Fatalf("the socket's mode = %v, %v; want 0660", fi.Mode().Perm(), err)
	}

	dctx, dcancel := context.WithTimeout(ctx, 5*time.Second)
	defer dcancel()
	if c, err := Dial(dctx, sock); err == nil {
		// The dial itself succeeds: the kernel queues it. The server then
		// drops the connection without a byte, so the first call fails.
		err = c.Call(dctx, "gate.route.list", nil, nil)
		_ = c.Close()
		var re *rpc.Error
		if err == nil || errors.As(err, &re) {
			t.Fatalf("a peer the socket does not name was answered: %v", err)
		}
	}
	if c, err := Dial(dctx, sock, os.Getuid()+1); err == nil {
		_ = c.Close()
		t.Fatal("a client that expects another user's server connected to this one")
	} else if !errors.Is(err, peercred.ErrOtherUser) {
		t.Fatalf("the refusal = %v; want ErrOtherUser", err)
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

// attempts is an Auditor in memory: each entry as it stands, and the order in
// which the entry and the verb's effect happened.
type attempts struct {
	mu      sync.Mutex
	fail    error
	entries []string // "actor|action|subject|outcome"
	order   []string
}

func (a *attempts) AuditAttempt(_ context.Context, actor, action, subject string) (int64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fail != nil {
		return 0, a.fail
	}
	a.entries = append(a.entries, action+"|"+subject+"|attempt")
	a.order = append(a.order, "entry "+action)
	return int64(len(a.entries)), nil
}

func (a *attempts) AuditResult(_ context.Context, id int64, outcome string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	e := a.entries[id-1]
	a.entries[id-1] = e[:len(e)-len("attempt")] + outcome
	return nil
}

func (a *attempts) did(what string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.order = append(a.order, what)
}

var (
	errHostSaysNo = errors.New("the host refused")
	errOption     = errors.New("an option was refused")
)

type optionErr struct{}

func (optionErr) Error() string        { return "option port: out of range, at /secret/path" }
func (optionErr) Is(target error) bool { return target == errOption }
func (optionErr) PublicDetail() string { return "port: a port is a number from 1024 to 65535" }

// hostModule has one privileged verb, which acts unless told to fail, and one
// that is not privileged.
type hostModule struct{ log *attempts }

func (hostModule) Name() string { return "host" }

func (hostModule) Errors() []module.PublicError {
	return []module.PublicError{
		{Err: errHostSaysNo, Code: -32900, Name: "host.refused", Message: "the host refused"},
		{Err: errOption, Code: -32901, Name: "host.bad_option", Message: "an option was refused"},
	}
}

type hostAsk struct {
	Name string `json:"name,omitempty"`
	Fail string `json:"fail,omitempty"`
}

func (m hostModule) Verbs() []module.Verb {
	act := func(_ context.Context, p hostAsk) (struct{}, error) {
		m.log.did("effect")
		switch p.Fail {
		case "declared":
			return struct{}{}, errHostSaysNo
		case "option":
			return struct{}{}, optionErr{}
		case "undeclared":
			return struct{}{}, errors.New("exit status 1: /secret/path")
		}
		return struct{}{}, nil
	}
	return []module.Verb{
		module.Handle(module.Contract{Verb: "host.act", Privileged: true, Open: true}, act),
		module.Handle(module.Contract{Verb: "host.read", Open: true}, func(context.Context, struct{}) (struct{}, error) { return struct{}{}, nil }),
	}
}

// TestAPrivilegedVerbLeavesItsRecordFirst: the entry is written before the
// verb runs and carries the outcome after it, on failure too; with the audit
// log unwritable the verb is refused and nothing is done.
func TestAPrivilegedVerbLeavesItsRecordFirst(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	sock := filepath.Join(t.TempDir(), "c.sock")
	aud := &attempts{}
	hm := hostModule{log: aud}
	if _, err := Listen(sock, log, Access{}, hm); err == nil {
		t.Fatal("a socket with a privileged verb and no audit log was served")
	}
	srv, err := Listen(sock, log, Access{Audit: aud}, hm)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	c, err := Dial(ctx, sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	wire := func(err error) *rpc.Error {
		var re *rpc.Error
		if !errors.As(err, &re) {
			t.Fatalf("not a wire error: %v", err)
		}
		return re
	}

	if err := c.Call(ctx, "host.act", hostAsk{Name: "turn"}, nil); err != nil {
		t.Fatal(err)
	}
	if re := wire(c.Call(ctx, "host.act", hostAsk{Name: "turn", Fail: "declared"}, nil)); re.Code != -32900 {
		t.Fatalf("a declared failure = %+v", re)
	}
	if re := wire(c.Call(ctx, "host.act", hostAsk{Fail: "undeclared"}, nil)); re.Code != rpc.CodeInternal || containsAny(re.Message, "secret") {
		t.Fatalf("an undeclared failure = %+v", re)
	}
	// A declared error that says more crosses with what it adds, and nothing else of it.
	if re := wire(c.Call(ctx, "host.act", hostAsk{Fail: "option"}, nil)); re.Code != -32901 ||
		re.Message != "an option was refused: port: a port is a number from 1024 to 65535" {
		t.Fatalf("a detailed error = %+v", re)
	}
	if re := wire(c.Call(ctx, "host.act", map[string]any{"name": "x", "evil": 1}, nil)); re.Code != rpc.CodeInvalidParams {
		t.Fatalf("bad params = %+v", re)
	}
	if err := c.Call(ctx, "host.read", nil, nil); err != nil {
		t.Fatal(err)
	}
	want := []string{
		`host.act|name "turn"|ok`, `host.act|name "turn"|host.refused`, "host.act||failed", "host.act||host.bad_option", `host.act|name "x"|invalid params`,
	}
	aud.mu.Lock()
	entries, order := append([]string(nil), aud.entries...), append([]string(nil), aud.order...)
	aud.mu.Unlock()
	if len(entries) != len(want) {
		t.Fatalf("the entries = %q; want %q", entries, want)
	}
	for i := range want {
		if entries[i] != want[i] {
			t.Errorf("entry %d = %q; want %q", i, entries[i], want[i])
		}
	}
	// Each effect follows its own entry. The call with bad params left an
	// entry and had no effect; the verb that is not privileged left no entry.
	wantOrder := []string{"entry host.act", "effect", "entry host.act", "effect", "entry host.act", "effect", "entry host.act", "effect", "entry host.act"}
	if len(order) != len(wantOrder) {
		t.Fatalf("the order = %q", order)
	}
	for i := range wantOrder {
		if order[i] != wantOrder[i] {
			t.Fatalf("the order = %q; want every entry before its effect", order)
		}
	}

	// A subject is the caller's, not yet validated: it is quoted and cut short.
	_ = c.Call(ctx, "host.act", hostAsk{Name: "x\ny"}, nil)
	_ = c.Call(ctx, "host.act", hostAsk{Name: "a\nb" + string(make([]byte, 200))}, nil)
	aud.mu.Lock()
	last := aud.entries[len(aud.entries)-2:]
	aud.mu.Unlock()
	if last[0] != `host.act|name "x\ny"|ok` || len(last[1]) > 320 || containsAny(last[1], "\x00", "\n") {
		t.Fatalf("the subjects = %q", last)
	}

	// The audit log cannot be written: the verb is refused, and does nothing.
	aud.mu.Lock()
	aud.fail = errors.New("disk full")
	effects := len(aud.order)
	aud.mu.Unlock()
	if re := wire(c.Call(ctx, "host.act", hostAsk{Name: "turn"}, nil)); re.Code != rpc.CodeInternal || containsAny(re.Message, "disk") {
		t.Fatalf("a verb whose entry could not be written = %+v", re)
	}
	aud.mu.Lock()
	if len(aud.order) != effects {
		t.Fatalf("the verb ran without its entry: %q", aud.order[effects:])
	}
	aud.mu.Unlock()
	if err := c.Call(ctx, "host.read", nil, nil); err != nil {
		t.Fatalf("a verb that is not privileged needs no entry: %v", err)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the server did not stop")
	}
}

// TestTheSubjectNamesWhatTheCallActsOn: an audit entry says which stack, which
// service, which folder an import copied and which review was accepted.
func TestTheSubjectNamesWhatTheCallActsOn(t *testing.T) {
	long := "/home/admin/" + strings.Repeat("x", 300)
	for _, c := range []struct {
		param map[string]any
		want  string
	}{
		{map[string]any{"name": "chat", "service": "web"}, `name "chat" service "web"`},
		{map[string]any{"from": "/home/admin/services/chat"}, `from "/home/admin/services/chat"`},
		{map[string]any{"from": "/srv/chat", "name": "chat", "accept": "abc"}, `name "chat" from "/srv/chat" accept "abc"`},
		{map[string]any{"from": long}, `from "` + long[:160] + `"`},
		{map[string]any{"other": "x"}, ``},
		// Mail: the account and the domain, never the password.
		{map[string]any{"address": "ana@example.com", "password": "hunter2-long-password"}, `address "ana@example.com"`},
		{map[string]any{"host": "mail.example.com", "domain": "example.com"}, `host "mail.example.com" domain "example.com"`},
	} {
		if got := subject([]any{c.param}); got != c.want {
			t.Errorf("subject(%v) = %q; want %q", c.param, got, c.want)
		}
	}
}
