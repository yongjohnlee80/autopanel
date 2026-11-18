package mail

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yongjohnlee80/autopanel/core/gate"
	"github.com/yongjohnlee80/autopanel/core/mail/provider/memory"
	"github.com/yongjohnlee80/autopanel/core/services"
)

// --- fakes ---------------------------------------------------------------------

type fakeStore struct {
	mu      sync.Mutex
	state   *State
	domains []string
	owned   map[string]map[string]Owned
	dkim    map[string]map[string]DKIMRow
}

func (f *fakeStore) State(context.Context) (State, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.state == nil {
		return State{}, false, nil
	}
	return *f.state, true, nil
}
func (f *fakeStore) Create(_ context.Context, host, d string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.state != nil {
		return ErrSetUp
	}
	f.state = &State{Host: host, CreatedAt: 1}
	f.domains = append(f.domains, d)
	return nil
}
func (f *fakeStore) Drop(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.state, f.domains = nil, nil
	return nil
}
func (f *fakeStore) Forget(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.state == nil || f.state.Bootstrapped != 0 {
		return ErrSetUp
	}
	f.state, f.domains = nil, nil
	return nil
}
func (f *fakeStore) SetBootstrapped(_ context.Context, at int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.state.Bootstrapped = at
	return nil
}
func (f *fakeStore) Domains(context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.domains), nil
}
func (f *fakeStore) AddDomain(_ context.Context, n string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.domains = append(f.domains, n)
	return nil
}
func (f *fakeStore) RemoveDomain(_ context.Context, n string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.domains = slices.DeleteFunc(f.domains, func(d string) bool { return d == n })
	return nil
}

func (f *fakeStore) Owned(_ context.Context, owner string) ([]Owned, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Owned
	for _, o := range f.owned[owner] {
		out = append(out, o)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name+out[i].Type < out[j].Name+out[j].Type })
	return out, nil
}
func (f *fakeStore) PutOwned(_ context.Context, owner string, o Owned) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.owned == nil {
		f.owned = map[string]map[string]Owned{}
	}
	if f.owned[owner] == nil {
		f.owned[owner] = map[string]Owned{}
	}
	f.owned[owner][o.Name+" "+o.Type] = o
	return nil
}
func (f *fakeStore) DeleteOwned(_ context.Context, owner, name, typ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.owned[owner], name+" "+typ)
	return nil
}
func (f *fakeStore) DKIM(_ context.Context, d string) ([]DKIMRow, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []DKIMRow
	for _, r := range f.dkim[d] {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Selector < out[j].Selector })
	return out, nil
}
func (f *fakeStore) PutDKIM(_ context.Context, d string, r DKIMRow) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.dkim == nil {
		f.dkim = map[string]map[string]DKIMRow{}
	}
	if f.dkim[d] == nil {
		f.dkim[d] = map[string]DKIMRow{}
	}
	f.dkim[d][r.Selector] = r
	return nil
}
func (f *fakeStore) DeleteDKIM(_ context.Context, d, sel string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.dkim[d], sel)
	return nil
}

type fakeVault struct {
	mu     sync.Mutex
	locked bool
	m      map[string][]byte
}

func (v *fakeVault) Put(_ context.Context, n string, b []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.locked {
		return ErrLocked
	}
	v.m[n] = slices.Clone(b)
	return nil
}
func (v *fakeVault) Get(_ context.Context, n string) ([]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.locked {
		return nil, ErrLocked
	}
	b, ok := v.m[n]
	if !ok {
		return nil, ErrNoSecret
	}
	return b, nil
}
func (v *fakeVault) Delete(_ context.Context, n string) error { delete(v.m, n); return nil }

type fakeRegistry []string

func (r fakeRegistry) All(context.Context) ([]gate.Domain, error) {
	out := make([]gate.Domain, 0, len(r))
	for _, n := range r {
		out = append(out, gate.Domain{Name: n})
	}
	return out, nil
}

type fakeStacks struct {
	mu       sync.Mutex
	user     bool
	since    int64
	restarts int
	absent   bool     // the stack was never added: Up answers services.ErrNotFound
	added    []string // the sha256 each Add was given
	addErr   error    // what the next Add answers
}

func (s *fakeStacks) CheckDraft(_ context.Context, _ string, compose []byte) (services.Review, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.absent {
		return services.Review{}, services.ErrDuplicate
	}
	return services.Review{SHA256: "reviewed-compose", Findings: []services.Finding{}}, nil
}
func (s *fakeStacks) Add(_ context.Context, _ string, accept string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.addErr; err != nil {
		s.addErr = nil
		return err
	}
	if !s.absent {
		return services.ErrDuplicate
	}
	s.added = append(s.added, accept)
	s.absent = false
	return nil
}

func (s *fakeStacks) Check(context.Context, string) (services.Review, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.absent {
		return services.Review{}, services.ErrNotFound
	}
	return services.Review{SHA256: "reviewed-compose", Findings: []services.Finding{}}, nil
}
func (s *fakeStacks) RemoveOwned(context.Context, string, bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.absent = true
	return nil
}
func (s *fakeStacks) EnsureUser(context.Context, string) error { s.user = true; return nil }
func (s *fakeStacks) Up(context.Context, string) (string, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.absent {
		return "", 0, services.ErrNotFound
	}
	return "applied", s.since, nil
}
func (s *fakeStacks) Restart(context.Context, string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.restarts++
	s.since = time.Now().Unix() + 1
	return nil
}

type fakeHost struct {
	journal    []string // what the stack printed
	definition []byte
	loopback   int // InstallLoopback calls
	ensured    atomic.Int32
	reload     bool
	mu         sync.Mutex
	txt        map[string][]string // what public resolvers answer
	reverse    []string            // what the host's address resolves back to
	reverseErr error
	smtpErr    error // what a connection out to port 25 meets
	smtpTries  int
}

func (h *fakeHost) CPU() (string, map[string]bool, error) {
	return "amd64", map[string]bool{"sse4_2": true}, nil
}
func (h *fakeHost) WriteDefinition(_ context.Context, b []byte) error { h.definition = b; return nil }
func (h *fakeHost) RemoveDefinition(context.Context) error            { h.definition = nil; return nil }
func (h *fakeHost) RemoveLoopback(context.Context, int) error         { h.loopback--; return nil }
func (h *fakeHost) StackUID(context.Context) (int, error)             { return 990, nil }
func (h *fakeHost) Journal(context.Context, time.Time) ([]string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.journal), nil
}
func (h *fakeHost) Forwarder(context.Context) (string, error)  { return "10.89.0.0/24", nil }
func (h *fakeHost) PublicIPv4(context.Context) (string, error) { return "192.0.2.10", nil }

func (h *fakeHost) ReverseNames(context.Context, string) ([]string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.reverse, h.reverseErr
}

func (h *fakeHost) SMTPOut(context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.smtpTries++
	return h.smtpErr
}
func (h *fakeHost) ResolveTXT(_ context.Context, name string) ([]string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.txt[name], nil
}
func (h *fakeHost) InstallLoopback(context.Context, int) error { h.loopback++; return nil }
func (h *fakeHost) EnsureLoopback(context.Context, int) (bool, error) {
	h.ensured.Add(1)
	return h.reload, nil
}

// setUpMail is Set up mail, then Add and start, on a stack never added.
func setUpMail(t *testing.T, m *Module, stacks *fakeStacks) {
	t.Helper()
	ctx := context.Background()
	stacks.absent = true
	out, err := m.setup(ctx, SetupAsk{Host: "mail.example.net", Domain: "example.net"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.apply(ctx, Accept{Accept: out.SHA256}); err != nil {
		t.Fatal(err)
	}
}

// prod is a test module's product, and mem its server.
func prod(m *Module) *memory.Product { return m.product.(*memory.Product) }
func mem(m *Module) *memory.Server   { return prod(m).Server }

func newTestModule(t *testing.T) (*Module, *fakeStore, *fakeVault, *fakeStacks, *fakeHost, *atomic.Bool) {
	st := &fakeStore{}
	v := &fakeVault{m: map[string][]byte{}}
	stacks := &fakeStacks{}
	h := &fakeHost{journal: []string{"starting", "one-time: once-printed"}}
	on := new(atomic.Bool)
	product := &memory.Product{Server: memory.New(), Key: "the-key"}
	m := NewModule(st, v, fakeRegistry{"example.net", "example.org"}, stacks, h, product, func(b bool) { on.Store(b) },
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	return m, st, v, stacks, h, on
}

// --- the definition and the guard --------------------------------------------------

// TestTheDefinitionIsTheProducts: the stack's definition is the product's,
// with mail's loopback ports and its management port.
func TestTheDefinitionIsTheProducts(t *testing.T) {
	m, _, _, _, _, _ := newTestModule(t)
	def := string(m.compose())
	for _, port := range []string{"127.0.0.1:10025:", "127.0.0.1:10465:", "127.0.0.1:10587:", "127.0.0.1:10993:", "127.0.0.1:18480:"} {
		if !strings.Contains(def, port) {
			t.Errorf("the definition does not publish %s: %s", port, def)
		}
	}
	if !strings.Contains(def, memory.Image) {
		t.Fatal("the definition is not the product's")
	}
}

func TestTheGuard(t *testing.T) {
	m, st, _, _, _, _ := newTestModule(t)
	ctx := context.Background()
	if f := m.Review(ctx, Stack, m.compose()); len(f) != 1 || f[0].Severity != services.Refused {
		t.Fatalf("a mail stack nobody set up: %+v; want refused", f)
	}
	st.state = &State{Host: "mail.example.net"}
	if f := m.Review(ctx, Stack, m.compose()); len(f) != 0 {
		t.Fatalf("AutoPanel's own definition: %+v; want no finding", f)
	}
	if f := m.Review(ctx, Stack, append(m.compose(), "# edited\n"...)); len(f) != 1 || f[0].Severity != services.Warning {
		t.Fatalf("an edited definition: %+v; want a warning", f)
	}
	two := strings.Replace(string(m.compose()), "services:\n", "services:\n  webmail:\n    image: docker.io/library/nginx@sha256:"+strings.Repeat("a", 64)+"\n", 1)
	if f := m.Review(ctx, Stack, []byte(two)); len(f) != 1 || f[0].ID != "mail-one-service" || f[0].Severity != services.Refused {
		t.Fatalf("a second service in the mail stack: %+v; want refused", f)
	}
	if f := m.Review(ctx, "blog", []byte("anything")); f != nil {
		t.Fatalf("another stack: %+v", f)
	}
	if !m.Owns("mail") || m.Owns("blog") {
		t.Fatal("mail owns the stack mail, and no other")
	}
	var ports []int
	for _, c := range m.Reserved() {
		ports = append(ports, c.From)
	}
	if !slices.Equal(ports, []int{10025, 10465, 10587, 10993, 18480}) {
		t.Fatalf("reserved ports: %v", ports)
	}
	masked := m.Mask(Stack, []string{"starting", "one-time: Zx9-secret", "an ordinary line"})
	if masked[1] != "one-time: [hidden]" || masked[0] != "starting" || masked[2] != "an ordinary line" {
		t.Fatalf("masked: %q", masked)
	}
	if got := m.Mask("blog", []string{"one-time: x"}); got[0] != "one-time: x" {
		t.Fatal("only the mail stack's logs are masked")
	}
}

// --- setup -------------------------------------------------------------------------

func TestSetup(t *testing.T) {
	m, st, v, stacks, h, _ := newTestModule(t)
	ctx := context.Background()
	stacks.absent = true
	for name, p := range map[string]SetupAsk{
		"a bare name":            {Host: "mail", Domain: "example.net"},
		"an unregistered domain": {Host: "mail.example.net", Domain: "example.com"},
		"a subdomain only":       {Host: "mail.example.net", Domain: "lists.example.net"},
	} {
		if _, err := m.setup(ctx, p); err == nil {
			t.Errorf("%s: set up, want refused", name)
		}
	}
	prod(m).CPUError = errors.New("no sse4_2")
	if _, err := m.setup(ctx, SetupAsk{Host: "mail.example.net", Domain: "example.net"}); !errors.Is(err, ErrCPU) {
		t.Fatalf("an old processor: %v", err)
	}
	prod(m).CPUError = nil
	v.locked = true
	if _, err := m.setup(ctx, SetupAsk{Host: "mail.example.net", Domain: "example.net"}); !errors.Is(err, ErrLocked) {
		t.Fatalf("a locked vault: %v", err)
	}
	v.locked = false
	if _, err := m.apply(ctx, Accept{Accept: "x"}); !errors.Is(err, ErrNoPending) {
		t.Fatalf("an apply with nothing set up: %v", err)
	}

	// Set up mail reviews, and writes nothing: left here, it leaves no trace.
	nothing := func(when string) {
		t.Helper()
		if st.state != nil || len(st.domains) != 0 || len(v.m) != 0 || stacks.user || h.loopback != 0 || h.definition != nil || len(stacks.added) != 0 {
			t.Fatalf("%s: written: state %+v, domains %v, sealed %d, user %v, loopback %d, definition %d bytes, added %v",
				when, st.state, st.domains, len(v.m), stacks.user, h.loopback, len(h.definition), stacks.added)
		}
	}
	out, err := m.setup(ctx, SetupAsk{Host: "Mail.Example.net", Domain: "example.net"})
	if err != nil || out.Stack != "mail" || out.SHA256 == "" || out.Review.SHA256 != out.SHA256 {
		t.Fatalf("setup = %+v, %v", out, err)
	}
	nothing("after the review")
	// Asked again, with another host: the answers are replaced, still unwritten.
	out, err = m.setup(ctx, SetupAsk{Host: "post.example.net", Domain: "example.net"})
	if err != nil {
		t.Fatal(err)
	}
	nothing("after a second review")
	if _, err := m.apply(ctx, Accept{Accept: "not-the-review"}); !errors.Is(err, ErrChanged) {
		t.Fatalf("an apply of another review: %v", err)
	}

	// A step that fails undoes the ones before it.
	stacks.addErr = errors.New("podman: no network")
	if _, err := m.apply(ctx, Accept{Accept: out.SHA256}); err == nil {
		t.Fatal("an apply whose stack failed to add succeeded")
	}
	if st.state != nil || len(v.m) != 0 || h.loopback != 0 || h.definition != nil {
		t.Fatalf("a failed apply left: state %+v, sealed %d, loopback %d, definition %d bytes", st.state, len(v.m), h.loopback, len(h.definition))
	}

	// Add and start: every write, then the record.
	if _, err := m.apply(ctx, Accept{Accept: out.SHA256}); err != nil {
		t.Fatal(err)
	}
	if !stacks.user || h.loopback != 1 || string(h.definition) != string(m.compose()) || len(stacks.added) != 1 || stacks.added[0] != out.SHA256 {
		t.Fatalf("the user, the loopback rule, the definition, the add: %v %d %q %v", stacks.user, h.loopback, h.definition, stacks.added)
	}
	if st.state == nil || st.state.Host != "post.example.net" || !slices.Equal(st.domains, []string{"example.net"}) {
		t.Fatalf("recorded: %+v %v", st.state, st.domains)
	}
	var cfg Config
	if err := json.Unmarshal(v.m[sealedConfig], &cfg); err != nil || cfg.Host != "post.example.net" || cfg.DMARC != "quarantine" {
		t.Fatalf("the sealed settings: %+v %v", cfg, err)
	}
	if !m.IsHost("post.example.net") {
		t.Fatal("the mail host is not known for its certificate")
	}
	if _, err := m.apply(ctx, Accept{Accept: out.SHA256}); !errors.Is(err, ErrNoPending) {
		t.Fatalf("a second apply: %v", err)
	}
	if _, err := m.setup(ctx, SetupAsk{Host: "mail.example.net", Domain: "example.net"}); !errors.Is(err, ErrSetUp) {
		t.Fatalf("a second setup: %v", err)
	}
	if _, err := m.domainAdd(ctx, Name{Name: "example.org"}); !errors.Is(err, ErrNotReady) {
		t.Fatalf("a domain before Stalwart is set up: %v", err)
	}
}

// TestASetupLeftByAnOlderVersionIsDropped: v0.2.6 recorded mail before its
// stack was added. Such a half setup is dropped by the next Set up mail; one
// Stalwart took is never touched.
func TestASetupLeftByAnOlderVersionIsDropped(t *testing.T) {
	m, st, v, stacks, _, _ := newTestModule(t)
	ctx := context.Background()
	st.state = &State{Host: "old.example.net", CreatedAt: 1}
	st.domains = []string{"example.org"}
	v.m[sealedConfig] = []byte(`{"host":"old.example.net"}`)
	stacks.absent = true
	if _, err := m.setup(ctx, SetupAsk{Host: "mail.example.net", Domain: "example.net"}); err != nil {
		t.Fatal(err)
	}
	if st.state != nil || len(st.domains) != 0 || v.m[sealedConfig] != nil {
		t.Fatalf("the half setup is still there: %+v %v %q", st.state, st.domains, v.m[sealedConfig])
	}
	st.state = &State{Host: "old.example.net", CreatedAt: 1, Bootstrapped: 7}
	if _, err := m.setup(ctx, SetupAsk{Host: "mail.example.net", Domain: "example.net"}); !errors.Is(err, ErrSetUp) {
		t.Fatalf("a setup Stalwart took: %v", err)
	}
}

// --- the bootstrap: the product's steps, the module's record -------------------

func TestBootstrap(t *testing.T) {
	m, st, v, stacks, _, on := newTestModule(t)
	ctx := context.Background()
	setUpMail(t, m, stacks)
	p := prod(m)

	// Not running yet: nothing happens.
	state, _, _ := st.State(ctx)
	m.tryBootstrap(ctx, state)
	if p.Bootstraps != 0 {
		t.Fatal("bootstrapped before the stack ran")
	}
	stacks.since = time.Now().Unix()
	m.tryBootstrap(ctx, state)
	if m.progress.Error != "" {
		t.Fatalf("the bootstrap failed: %s", m.progress.Error)
	}
	if stacks.restarts != 2 {
		t.Fatalf("restarts %d; want the product's two", stacks.restarts)
	}
	// What the product sealed is under mail/, by its names; the one-time
	// credential it read from the journal is in it, and nowhere else.
	if string(v.m[sealedKey]) != p.Key || string(v.m[sealedServer+"admin"]) != "admin:once-printed" {
		t.Fatalf("sealed: key %q, admin %q", v.m[sealedKey], v.m[sealedServer+"admin"])
	}
	if state, _, _ = st.State(ctx); state.Bootstrapped == 0 {
		t.Fatal("not marked set up")
	}
	// The loop now switches the gate's streams on.
	ctx2, cancel := context.WithCancel(ctx)
	defer func(d time.Duration) { tick = d }(tick)
	tick = 10 * time.Millisecond
	go func() { _ = m.Run(ctx2) }()
	deadline := time.Now().Add(2 * time.Second)
	for !on.Load() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if !on.Load() {
		t.Fatal("the streams were not switched on for a set-up mail")
	}
	if _, err := m.domainAdd(ctx, Name{Name: "example.com"}); !errors.Is(err, ErrNotRegistered) {
		t.Fatalf("a domain not in the registry: %v", err)
	}
}

// TestABootstrapCarriesOnAfterAFailure: a bootstrap whose product sealed its
// administrator and then failed carries on from there; the first start's
// credential, gone with the restart, is not needed again.
func TestABootstrapCarriesOnAfterAFailure(t *testing.T) {
	m, st, v, stacks, h, _ := newTestModule(t)
	ctx := context.Background()
	setUpMail(t, m, stacks)
	v.m[sealedServer+"admin"] = []byte("admin:earlier")
	h.journal = nil // the credential is no longer printed
	stacks.since = time.Now().Unix()
	state, _, _ := st.State(ctx)
	m.tryBootstrap(ctx, state)
	if m.progress.Error != "" || string(v.m[sealedKey]) != prod(m).Key {
		t.Fatalf("carried on: error %q", m.progress.Error)
	}
}

// TestAKeyThatDoesNotSignInLeavesMailNotReady: the product's bootstrap ran,
// but the key it sealed is refused: mail is not marked set up.
func TestAKeyThatDoesNotSignInLeavesMailNotReady(t *testing.T) {
	m, st, v, stacks, _, _ := newTestModule(t)
	ctx := context.Background()
	setUpMail(t, m, stacks)
	v.m[sealedKey] = []byte("another key")
	stacks.since = time.Now().Unix()
	state, _, _ := st.State(ctx)
	m.tryBootstrap(ctx, state)
	if state, _, _ = st.State(ctx); state.Bootstrapped != 0 || !strings.Contains(m.progress.Error, "does not sign in") {
		t.Fatalf("bootstrapped %d, error %q", state.Bootstrapped, m.progress.Error)
	}
}

func TestTheLoopHoldsTheLoopbackRuleFirst(t *testing.T) {
	m, st, _, _, h, on := newTestModule(t)
	st.state = &State{Host: "mail.example.net", Bootstrapped: 5}
	h.reload = true
	defer func(d time.Duration) { tick = d }(tick)
	tick = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = m.Run(ctx) }()
	deadline := time.Now().Add(2 * time.Second)
	for (h.ensured.Load() == 0 || !on.Load()) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if n := h.ensured.Load(); n != 1 {
		t.Fatalf("the loopback rule was checked %d times at the start; want once (then hourly)", n)
	}
	m.mu.Lock()
	lb := m.progress.Loopback
	m.mu.Unlock()
	if !strings.HasPrefix(lb, "reloaded") {
		t.Fatalf("a reload is reported: %q", lb)
	}
}
