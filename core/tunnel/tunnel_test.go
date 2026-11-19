package tunnel

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// memory is a Store with the real one's rules, for the module's tests. The
// store's own tests hold the real one to the same.
type memory struct {
	mu   sync.Mutex
	next int64
	rows map[int64]Agent
}

func newMemory() *memory { return &memory{rows: map[int64]Agent{}} }

func (m *memory) All(context.Context) ([]Agent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Agent, 0, len(m.rows))
	for _, a := range m.rows {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *memory) Add(_ context.Context, a Agent) (Agent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, o := range m.rows {
		if o.Name == a.Name {
			return Agent{}, ErrDuplicate
		}
	}
	m.next++
	a.ID = m.next
	m.rows[a.ID] = a
	return a, nil
}

func (m *memory) Enrol(_ context.Context, id, hash, key, from string, now int64) (Agent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, o := range m.rows {
		if o.Key == key {
			return Agent{}, ErrBadToken
		}
	}
	for i, a := range m.rows {
		if a.Key == "" && a.TokenID == id && a.TokenHash == hash && a.TokenExpires > now {
			a.Key, a.EnrolledFrom, a.EnrolledAt = key, from, now
			a.TokenID, a.TokenHash, a.TokenExpires = "", "", 0
			m.rows[i] = a
			return a, nil
		}
	}
	return Agent{}, ErrBadToken
}

func (m *memory) Remove(_ context.Context, id int64) (Agent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.rows[id]
	if !ok {
		return Agent{}, ErrNotFound
	}
	delete(m.rows, id)
	return a, nil
}

type fixture struct {
	*Module
	store   *memory
	at      time.Time
	reloads int
}

func newFixture() *fixture {
	f := &fixture{store: newMemory(), at: time.Unix(1_800_000_000, 0)}
	f.Module = NewModule(f.store, func(context.Context) error { f.reloads++; return nil }, nil)
	f.Module.now = func() time.Time { return f.at }
	return f
}

var (
	keyA = strings.Repeat("a1", 32)
	keyB = strings.Repeat("b2", 32)
)

func TestAnAgentEnrolsOnceWithItsToken(t *testing.T) {
	ctx := context.Background()
	f := newFixture()
	added, err := f.add(ctx, Name{Name: "nas"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(added.Token, "ape_") || added.Agent.State != "waiting" || added.Expires != f.at.Add(TokenLife).Unix() {
		t.Fatalf("added = %+v", added)
	}
	if f.reloads != 0 {
		t.Fatal("the gate was told of an agent that has no key yet")
	}
	// Only the secret's hash is kept.
	for _, a := range f.store.rows {
		if strings.Contains(added.Token, a.TokenHash) || a.TokenHash == "" {
			t.Fatalf("the stored row holds the secret, or no hash: %+v", a)
		}
	}
	if keys, _ := f.Keys(ctx); len(keys) != 0 {
		t.Fatalf("an agent that has not enrolled has a key: %v", keys)
	}

	name, err := f.Enrol(ctx, added.Token, keyA, "203.0.113.9")
	if err != nil || name != "nas" {
		t.Fatalf("Enrol = %q, %v", name, err)
	}
	if f.reloads != 1 {
		t.Fatalf("the gate was told %d times of the new key, want once", f.reloads)
	}
	if keys, _ := f.Keys(ctx); len(keys) != 1 || keys[0] != (Key{Name: "nas", Key: keyA}) {
		t.Fatalf("Keys = %v", keys)
	}
	list, _ := f.list(ctx, struct{}{})
	if len(list) != 1 || list[0].State != "enrolled" || list[0].EnrolledFrom != "203.0.113.9" || list[0].Fingerprint != Fingerprint(keyA) || !strings.HasPrefix(list[0].Fingerprint, "SHA256:") {
		t.Fatalf("list = %+v", list)
	}
	// The token is spent: not for the same key, not for another.
	for _, key := range []string{keyA, keyB} {
		if _, err := f.Enrol(ctx, added.Token, key, "198.51.100.1"); !errors.Is(err, ErrBadToken) {
			t.Fatalf("a spent token: %v", err)
		}
	}
	if ok, _ := f.Enrolled(ctx, "nas"); !ok {
		t.Fatal("nas is not enrolled")
	}
	if ok, _ := f.Enrolled(ctx, "other"); ok {
		t.Fatal("an agent nobody added is enrolled")
	}
}

func TestEveryOtherEnrolmentIsRefusedAlike(t *testing.T) {
	ctx := context.Background()
	f := newFixture()
	nas, _ := f.add(ctx, Name{Name: "nas"})
	home, _ := f.add(ctx, Name{Name: "home"})
	id, secret, ok := parseToken(nas.Token)
	if !ok {
		t.Fatalf("the module's own token does not parse: %q", nas.Token)
	}
	_, otherSecret, _ := parseToken(home.Token)
	for what, c := range map[string]struct{ token, key string }{
		"no token":                 {"", keyA},
		"no prefix":                {id + "_" + secret, keyA},
		"another kind of token":    {"apt_" + id + "_" + secret, keyA},
		"a wrong secret":           {"ape_" + id + "_" + otherSecret, keyA},
		"an unknown id":            {"ape_" + strings.Repeat("0", 16) + "_" + secret, keyA},
		"a secret cut short":       {nas.Token[:len(nas.Token)-1], keyA},
		"a token with more after":  {nas.Token + "x", keyA},
		"a very long token":        {"ape_" + strings.Repeat("a", 4096), keyA},
		"a key that is no digest":  {nas.Token, "abcd"},
		"a key in capitals":        {nas.Token, strings.ToUpper(keyA)},
		"a key with other letters": {nas.Token, strings.Repeat("zz", 32)},
	} {
		if _, err := f.Enrol(ctx, c.token, c.key, "198.51.100.1"); !errors.Is(err, ErrBadToken) {
			t.Errorf("%s: %v, want ErrBadToken", what, err)
		}
	}
	if f.reloads != 0 {
		t.Fatal("a refused enrolment told the gate something")
	}
	// A token past its time.
	f.at = f.at.Add(TokenLife)
	if _, err := f.Enrol(ctx, nas.Token, keyA, "198.51.100.1"); !errors.Is(err, ErrBadToken) {
		t.Fatalf("a token at its end: %v", err)
	}
	list, _ := f.list(ctx, struct{}{})
	if list[0].State != "expired" || list[1].State != "expired" {
		t.Fatalf("list = %+v", list)
	}
}

func TestAKeyIsOneAgents(t *testing.T) {
	ctx := context.Background()
	f := newFixture()
	nas, _ := f.add(ctx, Name{Name: "nas"})
	home, _ := f.add(ctx, Name{Name: "home"})
	if _, err := f.Enrol(ctx, nas.Token, keyA, "a"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Enrol(ctx, home.Token, keyA, "a"); !errors.Is(err, ErrBadToken) {
		t.Fatalf("a second agent with the first one's key: %v", err)
	}
	// Its token is not spent by that: the right key still enrols.
	if name, err := f.Enrol(ctx, home.Token, keyB, "a"); err != nil || name != "home" {
		t.Fatalf("Enrol = %q, %v", name, err)
	}
}

func TestAddingAndRemoving(t *testing.T) {
	ctx := context.Background()
	f := newFixture()
	for _, bad := range []string{"", "Nas", "9nas", "nas_1", "a b", strings.Repeat("a", 33), "nas/../x"} {
		if _, err := f.add(ctx, Name{Name: bad}); !errors.Is(err, ErrBadName) {
			t.Errorf("add %q: %v", bad, err)
		}
	}
	nas, err := f.add(ctx, Name{Name: "nas"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.add(ctx, Name{Name: "nas"}); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("a name twice: %v", err)
	}
	if _, err := f.Enrol(ctx, nas.Token, keyA, "a"); err != nil {
		t.Fatal(err)
	}
	before := f.reloads
	gone, err := f.remove(ctx, Ref{ID: nas.Agent.ID})
	if err != nil || gone.Name != "nas" {
		t.Fatalf("remove = %+v, %v", gone, err)
	}
	if f.reloads != before+1 {
		t.Fatal("the gate was not told an agent was removed: its tunnel would stay")
	}
	if keys, _ := f.Keys(ctx); len(keys) != 0 {
		t.Fatalf("a removed agent's key is still admitted: %v", keys)
	}
	if _, err := f.remove(ctx, Ref{ID: nas.Agent.ID}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("remove twice: %v", err)
	}
	for i := range MaxAgents {
		if _, err := f.add(ctx, Name{Name: "a" + strings.Repeat("x", i)}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.add(ctx, Name{Name: "one-more"}); !errors.Is(err, ErrTooMany) {
		t.Fatalf("an agent past the limit: %v", err)
	}
}

func TestTheListCarriesTheGatesWord(t *testing.T) {
	ctx := context.Background()
	f := newFixture()
	f.Module.status = func() map[string]Status {
		return map[string]Status{"nas": {Connected: true, Since: 5, Streams: 3, Targets: []string{"immich"}}, "ghost": {Connected: true}}
	}
	nas, _ := f.add(ctx, Name{Name: "nas"})
	list, _ := f.list(ctx, struct{}{})
	if list[0].Connected {
		t.Fatal("an agent that has not enrolled is shown as connected")
	}
	_, _ = f.Enrol(ctx, nas.Token, keyA, "a")
	list, _ = f.list(ctx, struct{}{})
	if len(list) != 1 || !list[0].Connected || list[0].Streams != 3 || len(list[0].Targets) != 1 {
		t.Fatalf("list = %+v", list)
	}
}
