package mail

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yongjohnlee80/autopanel/core/gate"
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
}

func (s *fakeStacks) EnsureUser(context.Context, string) error { s.user = true; return nil }
func (s *fakeStacks) Up(context.Context, string) (string, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
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
	cpu        error
	definition []byte
	loopback   int // InstallLoopback calls
	ensured    atomic.Int32
	reload     bool
	mu         sync.Mutex
	txt        map[string][]string // what public resolvers answer
}

func (h *fakeHost) CPU() error                                        { return h.cpu }
func (h *fakeHost) WriteDefinition(_ context.Context, b []byte) error { h.definition = b; return nil }
func (h *fakeHost) StackUID(context.Context) (int, error)             { return 990, nil }
func (h *fakeHost) FirstPassword(context.Context, time.Time) (string, error) {
	return "once-printed", nil
}
func (h *fakeHost) Forwarder(context.Context) (string, error)  { return "10.89.0.0/24", nil }
func (h *fakeHost) PublicIPv4(context.Context) (string, error) { return "192.0.2.10", nil }
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

func newTestModule(t *testing.T) (*Module, *fakeStore, *fakeVault, *fakeStacks, *fakeHost, *atomic.Bool) {
	st := &fakeStore{}
	v := &fakeVault{m: map[string][]byte{}}
	stacks := &fakeStacks{}
	h := &fakeHost{}
	on := new(atomic.Bool)
	m := NewModule(st, v, fakeRegistry{"example.net", "example.org"}, stacks, h, func(b bool) { on.Store(b) },
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	return m, st, v, stacks, h, on
}

// --- the definition and the guard --------------------------------------------------

func TestTheComposeIsAcceptedAndPinned(t *testing.T) {
	st, findings := services.Parse(Compose(), nil)
	for _, f := range findings {
		if f.Severity == services.Refused {
			t.Errorf("the mail definition is refused: %+v", f)
		}
	}
	if len(st.Services) != 1 || !strings.Contains(st.Services[0].Image, "@sha256:") {
		t.Fatalf("one service, pinned by digest: %+v", st.Services)
	}
	s := st.Services[0]
	if !s.ReadOnly || !s.HasUser || s.MemLimit == 0 || !slices.Equal(s.CapAdd, []string{"NET_BIND_SERVICE"}) {
		t.Fatalf("read-only, its own user, a memory limit and one capability: %+v", s)
	}
	for _, p := range s.Ports {
		if p.Public() {
			t.Errorf("a mail port published beyond loopback: %+v", p)
		}
	}
}

func TestTheGuard(t *testing.T) {
	m, st, _, _, _, _ := newTestModule(t)
	ctx := context.Background()
	if f := m.Review(ctx, Stack, Compose()); len(f) != 1 || f[0].Severity != services.Refused {
		t.Fatalf("a mail stack nobody set up: %+v; want refused", f)
	}
	st.state = &State{Host: "mail.example.net"}
	if f := m.Review(ctx, Stack, Compose()); len(f) != 0 {
		t.Fatalf("AutoPanel's own definition: %+v; want no finding", f)
	}
	if f := m.Review(ctx, Stack, append(Compose(), "# edited\n"...)); len(f) != 1 || f[0].Severity != services.Warning {
		t.Fatalf("an edited definition: %+v; want a warning", f)
	}
	two := strings.Replace(string(Compose()), "services:\n", "services:\n  webmail:\n    image: docker.io/library/nginx@sha256:"+strings.Repeat("a", 64)+"\n", 1)
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
	masked := m.Mask(Stack, []string{"   username: admin", "   password: Zx9-secret", "an ordinary line"})
	if masked[1] != "   password: [hidden]" || masked[0] != "   username: admin" || masked[2] != "an ordinary line" {
		t.Fatalf("masked: %q", masked)
	}
	if got := m.Mask("blog", []string{"password: x"}); got[0] != "password: x" {
		t.Fatal("only the mail stack's logs are masked")
	}
}

// --- setup -------------------------------------------------------------------------

func TestSetup(t *testing.T) {
	m, st, v, stacks, h, _ := newTestModule(t)
	ctx := context.Background()
	for name, p := range map[string]SetupAsk{
		"a bare name":            {Host: "mail", Domain: "example.net"},
		"an unregistered domain": {Host: "mail.example.net", Domain: "example.com"},
		"a subdomain only":       {Host: "mail.example.net", Domain: "lists.example.net"},
	} {
		if _, err := m.setup(ctx, p); err == nil {
			t.Errorf("%s: set up, want refused", name)
		}
	}
	h.cpu = errors.New("no sse4_2")
	if _, err := m.setup(ctx, SetupAsk{Host: "mail.example.net", Domain: "example.net"}); !errors.Is(err, ErrCPU) {
		t.Fatalf("an old processor: %v", err)
	}
	h.cpu = nil
	v.locked = true
	if _, err := m.setup(ctx, SetupAsk{Host: "mail.example.net", Domain: "example.net"}); !errors.Is(err, ErrLocked) {
		t.Fatalf("a locked vault: %v", err)
	}
	v.locked = false
	out, err := m.setup(ctx, SetupAsk{Host: "Mail.Example.net", Domain: "example.net"})
	if err != nil || out.Stack != "mail" || out.SHA256 != ComposeSHA256() {
		t.Fatalf("setup = %+v, %v", out, err)
	}
	if !stacks.user || h.loopback != 1 || string(h.definition) != string(Compose()) {
		t.Fatalf("the user, the loopback rule, the definition: %v %d %q", stacks.user, h.loopback, h.definition)
	}
	if st.state.Host != "mail.example.net" || !slices.Equal(st.domains, []string{"example.net"}) {
		t.Fatalf("recorded: %+v %v", st.state, st.domains)
	}
	var cfg Config
	if err := json.Unmarshal(v.m[sealedConfig], &cfg); err != nil || cfg.Host != "mail.example.net" || cfg.DMARC != "quarantine" {
		t.Fatalf("the sealed settings: %+v %v", cfg, err)
	}
	if _, err := m.setup(ctx, SetupAsk{Host: "mail.example.net", Domain: "example.net"}); !errors.Is(err, ErrSetUp) {
		t.Fatalf("a second setup: %v", err)
	}
	if _, err := m.domainAdd(ctx, Name{Name: "example.org"}); !errors.Is(err, ErrNotReady) {
		t.Fatalf("a domain before Stalwart is set up: %v", err)
	}
}

// --- the bootstrap against a fake Stalwart ------------------------------------------

// stalwart is a fake of Stalwart's management API through a bootstrap: it
// answers the one-time password before set-up and the administrator and the
// key after, and records what it was told.
type stalwart struct {
	mu        sync.Mutex
	setUp     bool
	restarted func() bool
	listeners map[string]any
	keys      int
	domains   []string
}

func (s *stalwart) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var req struct {
		MethodCalls [][]json.RawMessage `json:"methodCalls"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	var method string
	var args map[string]any
	_ = json.Unmarshal(req.MethodCalls[0][0], &method)
	_ = json.Unmarshal(req.MethodCalls[0][1], &args)
	user, pass, basic := r.BasicAuth()
	bearer := r.Header.Get("Authorization") == "Bearer the-key"
	answer := func(v any) {
		_ = json.NewEncoder(w).Encode(map[string]any{"methodResponses": []any{[]any{method, v, "c"}}})
	}
	switch {
	case !s.setUp:
		if !basic || user != "admin" || pass != "once-printed" || method != "x:Bootstrap/set" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		s.setUp = true
		answer(map[string]any{"updated": map[string]any{"singleton": map[string]any{"username": "admin@example.net", "secret": "permanent"}}})
	case basic && user == "admin" && pass == "once-printed" && s.restarted():
		w.WriteHeader(http.StatusUnauthorized) // the printed password ends with the restart
	case !(basic && user == "admin@example.net" && pass == "permanent") && !bearer:
		w.WriteHeader(http.StatusUnauthorized)
	case method == "x:Domain/get":
		answer(map[string]any{"list": []any{map[string]any{"id": "b", "name": "example.net"}}})
	case method == "x:NetworkListener/get":
		answer(map[string]any{"list": []any{map[string]any{"id": "l1", "name": "smtp", "bind": map[string]bool{"[::]:25": true}, "protocol": "smtp"}}})
	case method == "x:NetworkListener/set":
		s.listeners = args
		answer(map[string]any{})
	case method == "x:ApiKey/set":
		s.keys++
		answer(map[string]any{"created": map[string]any{"k": map[string]any{"id": "k1", "secret": "the-key"}}})
	default:
		w.WriteHeader(http.StatusBadRequest)
	}
}

func TestBootstrap(t *testing.T) {
	m, st, v, stacks, _, on := newTestModule(t)
	ctx := context.Background()
	if _, err := m.setup(ctx, SetupAsk{Host: "mail.example.net", Domain: "example.net"}); err != nil {
		t.Fatal(err)
	}
	fake := &stalwart{restarted: func() bool { return stacks.restarts > 0 }}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	m.base = srv.URL

	// Not running yet: nothing happens.
	state, _, _ := st.State(ctx)
	m.tryBootstrap(ctx, state)
	if fake.setUp {
		t.Fatal("set up before the stack ran")
	}
	stacks.since = time.Now().Unix()
	m.tryBootstrap(ctx, state)
	if m.progress.Error != "" {
		t.Fatalf("the bootstrap failed: %s", m.progress.Error)
	}
	if !fake.setUp || stacks.restarts != 2 || fake.keys != 1 {
		t.Fatalf("set up %v, restarts %d, keys %d; want set up, restarted twice, one key", fake.setUp, stacks.restarts, fake.keys)
	}
	if string(v.m[sealedKey]) != "the-key" {
		t.Fatal("the API key is not sealed")
	}
	var admin Admin
	if err := json.Unmarshal(v.m[sealedAdmin], &admin); err != nil || admin.Secret != "permanent" {
		t.Fatalf("the administrator is not sealed: %+v %v", admin, err)
	}
	smtp := fake.listeners["update"].(map[string]any)["l1"].(map[string]any)
	if _, ok := smtp["overrideProxyTrustedNetworks"].(map[string]any)["10.89.0.0/24"]; !ok {
		t.Fatalf("the forwarder is not trusted: %v", smtp)
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

func TestABootstrapCarriesOnAfterAFailure(t *testing.T) {
	// A bootstrap that sealed the administrator and then failed carries on with
	// it: the printed password is gone after the restart, and is not needed.
	m, st, v, stacks, _, _ := newTestModule(t)
	ctx := context.Background()
	if _, err := m.setup(ctx, SetupAsk{Host: "mail.example.net", Domain: "example.net"}); err != nil {
		t.Fatal(err)
	}
	fake := &stalwart{setUp: true, restarted: func() bool { return true }}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	m.base = srv.URL
	raw, _ := json.Marshal(Admin{Username: "admin@example.net", Secret: "permanent"})
	v.m[sealedAdmin] = raw
	stacks.since = time.Now().Unix()
	state, _, _ := st.State(ctx)
	m.tryBootstrap(ctx, state)
	if m.progress.Error != "" || fake.keys != 1 {
		t.Fatalf("carried on: error %q, keys %d", m.progress.Error, fake.keys)
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
