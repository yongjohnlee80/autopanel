package mail

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/yongjohnlee80/autopanel/core/mail/provider/memory"
	"github.com/yongjohnlee80/autopanel/core/services"
)

// These tests set mail up through the real services module, with the mail
// module as its guard, as the core wires them: the review, the guard's
// findings, the sha256 the add is given and the add itself are the services
// module's own. Only the machine under both is played. The fakes elsewhere in
// this package answer for the services module, and so cannot catch a
// disagreement between the two (v0.2.7's guard refused its own setup).

// memStacks is the services module's store, in memory.
type memStacks struct {
	mu sync.Mutex
	m  map[string]services.Service
}

func (s *memStacks) All(context.Context) ([]services.Service, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []services.Service
	for _, v := range s.m {
		out = append(out, v)
	}
	return out, nil
}
func (s *memStacks) Get(_ context.Context, name string) (services.Service, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[name]
	if !ok {
		return services.Service{}, services.ErrNotFound
	}
	return v, nil
}
func (s *memStacks) Add(_ context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[name]; ok {
		return services.ErrDuplicate
	}
	s.m[name] = services.Service{Name: name, State: services.Deploying}
	return nil
}
func (s *memStacks) update(name string, fn func(*services.Service)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[name]
	if !ok {
		return services.ErrNotFound
	}
	fn(&v)
	s.m[name] = v
	return nil
}
func (s *memStacks) SetState(_ context.Context, name string, st services.State) error {
	return s.update(name, func(v *services.Service) { v.State = st })
}
func (s *memStacks) SetPending(_ context.Context, name string, p services.Pending) error {
	return s.update(name, func(v *services.Service) { v.Pending = &p })
}
func (s *memStacks) SetApplied(_ context.Context, name string, a services.Applied) error {
	return s.update(name, func(v *services.Service) {
		v.Applied, v.Pending, v.State, v.AppliedAt = a, nil, services.Deployed, time.Now()
	})
}
func (s *memStacks) SetStopped(_ context.Context, name string, stopped []string) error {
	return s.update(name, func(v *services.Service) { v.Stopped = stopped })
}
func (s *memStacks) Remove(_ context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, name)
	return nil
}
func (s *memStacks) Source(context.Context, string) (services.Source, bool, error) {
	return services.Source{}, false, nil
}
func (s *memStacks) SetSource(context.Context, string, services.Source) error { return nil }

// machine is the host under the services module. Its stacks' directory is
// the mail host's: a definition there is what the mail host wrote. It plays
// only what a review and an add ask; any other call reaches the nil
// services.Host and fails the test.
type machine struct {
	services.Host
	mail   *fakeHost
	mu     sync.Mutex
	staged []byte
	hand   []byte // a definition the administrator wrote into the folder by hand
	users  map[string]bool
	units  map[string]bool
	starts int
}

func (h *machine) definition() []byte {
	if h.hand != nil {
		return h.hand
	}
	return h.mail.definition
}

func (h *machine) Podman(context.Context) (int, int, error) { return 4, 9, nil }
func (h *machine) Stage(_ context.Context, name string) ([]byte, []byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	def := h.definition()
	if name != Stack || def == nil {
		return nil, nil, services.ErrNoDefinition
	}
	h.staged = slices.Clone(def)
	return def, nil, nil
}
func (h *machine) StageDraft(_ context.Context, _ string, compose []byte) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.staged = slices.Clone(compose)
	return nil
}
func (h *machine) StagePaths(_ context.Context, _ string, paths []string) ([]services.Input, []string, []string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	sum := sha256.Sum256(h.staged)
	return []services.Input{{Path: "compose.yaml", Mode: 0o400, Size: int64(len(h.staged)), SHA256: hex.EncodeToString(sum[:])}},
		paths, nil, nil
}
func (h *machine) Look(context.Context, string, []string) (map[string]bool, []string, error) {
	return map[string]bool{}, nil, nil
}
func (h *machine) Listening(context.Context, string) ([]services.PortUse, error) { return nil, nil }
func (h *machine) Changed(context.Context, string, services.Manifest, time.Time) bool {
	return false
}
func (h *machine) EnsureUser(_ context.Context, name string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.users[name] = true
	return nil
}
func (h *machine) HasImage(context.Context, string, string) (bool, error) { return false, nil }
func (h *machine) Pull(context.Context, string, string) (string, error) {
	return "sha256:" + hex.EncodeToString(make([]byte, 32)), nil
}
func (h *machine) Commit(context.Context, string, services.Commit) error { return nil }
func (h *machine) Install(_ context.Context, u services.Unit) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, f := range u.Files {
		h.units[f.Path] = true
	}
	return nil
}
func (h *machine) DeleteUnits(context.Context, string, []string) error { return nil }
func (h *machine) Start(context.Context, string, []string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.starts++
	return nil
}
func (h *machine) Restart(context.Context, string, []string) error { return nil }
func (h *machine) Stop(context.Context, string, []string) error    { return nil }
func (h *machine) Running(_ context.Context, _ string, units []string) (map[string]services.Running, error) {
	out := map[string]services.Running{}
	for _, u := range units {
		out[u] = services.Running{Active: "active", Sub: "running", Since: time.Now().Unix()}
	}
	return out, nil
}
func (h *machine) Health(context.Context, string) (map[string]string, error) {
	return map[string]string{}, nil
}

// wired is a mail module and the real services module, wired as the core
// wires them.
func wired(t *testing.T) (*Module, *services.Module, *fakeStore, *fakeVault, *fakeHost, *machine) {
	t.Helper()
	st := &fakeStore{}
	v := &fakeVault{m: map[string][]byte{}}
	h := &fakeHost{}
	mach := &machine{mail: h, users: map[string]bool{}, units: map[string]bool{}}
	svcs := services.NewModule(&memStacks{m: map[string]services.Service{}}, mach)
	m := NewModule(st, v, fakeRegistry{"example.net", "example.org"}, svcs, h, &memory.Product{Server: memory.New(), Key: "k"}, func(bool) {},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	svcs.SetGuard(m)
	return m, svcs, st, v, h, mach
}

func refusedIn(r services.Review) []string {
	var out []string
	for _, f := range r.Findings {
		if f.Severity == services.Refused {
			out = append(out, f.ID)
		}
	}
	return out
}

// TestSettingMailUpThroughTheServicesModule: Set up mail's review is the
// services module's, judged by the mail guard, and is not refused; Add and
// start adds the stack through the services module with that review's
// sha256, and only then is mail recorded.
func TestSettingMailUpThroughTheServicesModule(t *testing.T) {
	m, svcs, st, v, h, mach := wired(t)
	ctx := context.Background()

	out, err := m.setup(ctx, SetupAsk{Host: "mail.example.net", Domain: "example.net"})
	if err != nil {
		t.Fatal(err)
	}
	if r := refusedIn(out.Review); len(r) != 0 {
		t.Fatalf("Set up mail's own review is refused: %v", r)
	}
	if out.SHA256 == "" || len(out.Review.Containers) != 1 || out.Review.Containers[0].Service != "mail" {
		t.Fatalf("the review: %+v", out.Review)
	}
	if st.state != nil || h.definition != nil || len(mach.users) != 0 || len(v.m) != 0 {
		t.Fatal("Set up mail wrote before Add and start")
	}

	if _, err := m.apply(ctx, Accept{Accept: out.SHA256}); err != nil {
		t.Fatalf("Add and start: %v", err)
	}
	if st.state == nil || st.state.Host != "mail.example.net" {
		t.Fatalf("mail is not recorded: %+v", st.state)
	}
	if !mach.users[Stack] || mach.starts != 1 || len(mach.units) == 0 {
		t.Fatalf("the stack was not added and started: users %v, starts %d, units %v", mach.users, mach.starts, mach.units)
	}
	if state, _, err := svcs.Up(ctx, Stack); err != nil || state == "" {
		t.Fatalf("the services module does not hold the stack: %q, %v", state, err)
	}
	// Recorded, the guard rests on the record: the open setup is closed.
	if m.setupOpen.Load() {
		t.Fatal("the guard is still open after the setup was applied")
	}
	if f := m.Review(ctx, Stack, m.compose()); len(f) != 0 {
		t.Fatalf("the guard's findings on the recorded stack: %+v", f)
	}
}

// TestTheGuardStillRefusesAHandWrittenMailStack: before any setup, and while
// one waits to be applied, a definition of the stack mail that is not
// AutoPanel's is refused, by review and by add.
func TestTheGuardStillRefusesAHandWrittenMailStack(t *testing.T) {
	m, svcs, _, _, _, mach := wired(t)
	ctx := context.Background()
	hand := []byte("services:\n  mail:\n    image: registry.invalid/mail:latest\n")

	if r, err := svcs.CheckDraft(ctx, Stack, m.compose()); err != nil || !slices.Contains(refusedIn(r), "reserved-name") {
		t.Fatalf("AutoPanel's definition with no setup open: %v, %v; want reserved-name", refusedIn(r), err)
	}
	mach.hand = hand
	if err := svcs.Add(ctx, Stack, "anything"); err == nil {
		t.Fatal("a hand-written mail stack was added with no setup")
	}

	out, err := m.setup(ctx, SetupAsk{Host: "mail.example.net", Domain: "example.net"})
	if err != nil {
		t.Fatal(err)
	}
	// A setup waits: a hand-written definition is still not admitted, even
	// given its own review's sha256.
	r, err := svcs.CheckDraft(ctx, Stack, hand)
	if err != nil || !slices.Contains(refusedIn(r), "reserved-name") {
		t.Fatalf("a hand-written definition while a setup waits: %v, %v; want reserved-name", refusedIn(r), err)
	}
	if err := svcs.Add(ctx, Stack, r.SHA256); !errors.Is(err, services.ErrRefused) {
		t.Fatalf("adding a hand-written mail stack while a setup waits: %v; want refused", err)
	}
	if out.SHA256 == r.SHA256 {
		t.Fatal("the hand-written definition reviewed as AutoPanel's")
	}
}

// TestASetupLeftOpenClosesTheGuardWhenItEnds: once a setup is applied, the
// guard rests on the record, and a setup that failed before its review
// leaves the guard closed.
func TestASetupLeftOpenClosesTheGuardWhenItEnds(t *testing.T) {
	m, _, _, _, _, _ := wired(t)
	ctx := context.Background()
	prod(m).CPUError = errors.New("no sse4_2")
	if _, err := m.setup(ctx, SetupAsk{Host: "mail.example.net", Domain: "example.net"}); !errors.Is(err, ErrCPU) {
		t.Fatalf("an old processor: %v", err)
	}
	if m.setupOpen.Load() {
		t.Fatal("a setup refused at its first check left the guard open")
	}
	prod(m).CPUError = nil
	if _, err := m.setup(ctx, SetupAsk{Host: "mail.example.net", Domain: "example.net"}); err != nil {
		t.Fatal(err)
	}
	if !m.setupOpen.Load() {
		t.Fatal("a setup waiting to be applied left the guard closed")
	}
}

func (h *machine) Uninstall(_ context.Context, name string, _ bool) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.users, name)
	h.units = map[string]bool{}
	return nil
}
