package auth

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"
)

// memSessions is a SessionStore in memory.
type memSessions struct {
	rows    map[[32]byte]Session
	touches int
}

func (m *memSessions) PutSession(_ context.Context, s Session, max int, expired func(Session) bool) error {
	var mine []Session
	for h, o := range m.rows {
		if expired(o) {
			delete(m.rows, h)
			continue
		}
		if o.UserID == s.UserID {
			mine = append(mine, o)
		}
	}
	sort.Slice(mine, func(i, j int) bool { return mine[i].CreatedAt < mine[j].CreatedAt })
	for len(mine) >= max {
		delete(m.rows, mine[0].IDHash)
		mine = mine[1:]
	}
	m.rows[s.IDHash] = s
	return nil
}

func (m *memSessions) Session(_ context.Context, h [32]byte) (Session, error) {
	s, ok := m.rows[h]
	if !ok {
		return Session{}, ErrNoSession
	}
	return s, nil
}

func (m *memSessions) TouchSession(_ context.Context, h [32]byte, at int64) error {
	if s, ok := m.rows[h]; ok {
		s.SeenAt = at
		m.rows[h] = s
		m.touches++
	}
	return nil
}

func (m *memSessions) EndSession(_ context.Context, h [32]byte) error { delete(m.rows, h); return nil }

func (m *memSessions) EndUserSessions(_ context.Context, user int64, except *[32]byte) (int, error) {
	n := 0
	for h, s := range m.rows {
		if s.UserID == user && (except == nil || h != *except) {
			delete(m.rows, h)
			n++
		}
	}
	return n, nil
}

func (m *memSessions) UserSessions(_ context.Context, user int64) ([]Session, error) {
	var out []Session
	for _, s := range m.rows {
		if s.UserID == user {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
	return out, nil
}

func testSessions() (*Sessions, *memSessions, *time.Time) {
	mem := &memSessions{rows: map[[32]byte]Session{}}
	now := time.Unix(1_800_000_000, 0)
	ss := NewSessions(mem)
	ss.now = func() time.Time { return now }
	return ss, mem, &now
}

// TestASessionIsNewAtEveryLogin: the id and the key are fresh, what the
// browser gets is not what the store keeps, and a session id that came with
// the login request does not survive it, whoever's it was (fixation).
func TestASessionIsNewAtEveryLogin(t *testing.T) {
	ctx := context.Background()
	ss, mem, _ := testSessions()
	planted, err := ss.New(ctx, 7, HostApp, "203.0.113.9", "attacker", "")
	if err != nil {
		t.Fatal(err)
	}
	// The victim logs in with the planted cookie in the request.
	got, err := ss.New(ctx, 8, HostApp, "198.51.100.1", strings.Repeat("b", 500), planted.Cookie)
	if err != nil {
		t.Fatal(err)
	}
	if got.Cookie == planted.Cookie || got.CSRF == planted.CSRF || len(got.Cookie) < 43 {
		t.Fatalf("the session after a login is the one from before it: %+v and %+v", got, planted)
	}
	if _, err := ss.Resolve(ctx, planted.Cookie, HostApp); err != ErrNoSession {
		t.Fatalf("the planted session survived the login: %v", err)
	}
	s, err := ss.Resolve(ctx, got.Cookie, HostApp)
	if err != nil || s.UserID != 8 || s.Client != "198.51.100.1" || len(s.Agent) != maxAgent {
		t.Fatalf("Resolve = %+v, %v", s, err)
	}
	// The store holds neither the cookie nor the second token.
	for _, row := range mem.rows {
		for _, kept := range []string{string(row.IDHash[:]), string(row.CSRFKey[:])} {
			if strings.Contains(kept, got.Cookie) || strings.Contains(kept, got.CSRF) {
				t.Fatal("the store holds what the browser holds")
			}
		}
	}
	if got.ExpiresAt != s.CreatedAt+12*3600 {
		t.Fatalf("the session's end is %d after its start", got.ExpiresAt-s.CreatedAt)
	}
}

// TestASessionBelongsToItsHostAndItsLimits: a session is refused on the other
// host, ends at its life whatever happens and after its idle time, each
// host's own; its last call is written at most once a minute.
func TestASessionBelongsToItsHostAndItsLimits(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		host, other string
		life, idle  time.Duration
	}{{HostApp, HostAdmin, 12 * time.Hour, 30 * time.Minute}, {HostAdmin, HostApp, 8 * time.Hour, 15 * time.Minute}} {
		ss, mem, now := testSessions()
		o, err := ss.New(ctx, 7, tc.host, "c", "a", "")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ss.Resolve(ctx, o.Cookie, tc.other); err != ErrNoSession {
			t.Fatalf("a %s session on the %s host: %v", tc.host, tc.other, err)
		}
		if _, err := ss.Resolve(ctx, "", tc.host); err != ErrNoSession {
			t.Fatalf("no cookie: %v", err)
		}
		if _, err := ss.Resolve(ctx, o.Cookie+"x", tc.host); err != ErrNoSession {
			t.Fatalf("another cookie: %v", err)
		}
		// Calls within a minute write nothing; one a minute later writes once.
		for range 5 {
			*now = now.Add(10 * time.Second)
			if _, err := ss.Resolve(ctx, o.Cookie, tc.host); err != nil {
				t.Fatal(err)
			}
		}
		if mem.touches != 0 {
			t.Fatalf("%d writes in the first minute", mem.touches)
		}
		*now = now.Add(15 * time.Second)
		if _, err := ss.Resolve(ctx, o.Cookie, tc.host); err != nil || mem.touches != 1 {
			t.Fatalf("after a minute: %v, %d writes", err, mem.touches)
		}
		// Kept alive by calls, it still ends at its life.
		start := *now
		for now.Sub(start) < tc.life-tc.idle {
			*now = now.Add(tc.idle - time.Minute)
			if _, err := ss.Resolve(ctx, o.Cookie, tc.host); err != nil {
				break
			}
		}
		*now = time.Unix(o.ExpiresAt, 0)
		if _, err := ss.Resolve(ctx, o.Cookie, tc.host); err != ErrNoSession {
			t.Fatalf("a %s session at the end of its life: %v", tc.host, err)
		}
		if len(mem.rows) != 0 {
			t.Fatal("an ended session was kept")
		}
		// Idle: one second short of the limit it lives, at the limit it is gone.
		o, _ = ss.New(ctx, 7, tc.host, "c", "a", "")
		*now = now.Add(tc.idle - time.Second)
		if _, err := ss.Resolve(ctx, o.Cookie, tc.host); err != nil {
			t.Fatalf("a %s session a second before its idle limit: %v", tc.host, err)
		}
		*now = now.Add(tc.idle)
		if _, err := ss.Resolve(ctx, o.Cookie, tc.host); err != ErrNoSession {
			t.Fatalf("a %s session idle for its limit: %v", tc.host, err)
		}
	}
	ss, _, _ := testSessions()
	if _, err := ss.New(ctx, 7, "api", "c", "a", ""); err != ErrNoSession {
		t.Fatalf("a session on a host that has none: %v", err)
	}
}

// TestTheSecondTokenIsTheSessionsAlone: it is the same in every tab and after
// a reload, another session's is refused, and so is none.
func TestTheSecondTokenIsTheSessionsAlone(t *testing.T) {
	ctx := context.Background()
	ss, _, _ := testSessions()
	a, _ := ss.New(ctx, 7, HostApp, "c", "a", "")
	b, _ := ss.New(ctx, 7, HostApp, "c", "a", "")
	sa, _ := ss.Resolve(ctx, a.Cookie, HostApp)
	sb, _ := ss.Resolve(ctx, b.Cookie, HostApp)
	if !ss.CSRF(sa, a.Cookie, a.CSRF) || ss.Token(sa, a.Cookie) != a.CSRF {
		t.Fatal("a session's own token is refused, or is not the same when asked for again")
	}
	for what, token := range map[string]string{"none": "", "another session's": b.CSRF, "the cookie itself": a.Cookie, "a cut one": a.CSRF[:len(a.CSRF)-1]} {
		if ss.CSRF(sa, a.Cookie, token) {
			t.Errorf("the token was accepted: %s", what)
		}
	}
	if ss.CSRF(sb, a.Cookie, a.CSRF) || ss.CSRF(sa, b.Cookie, a.CSRF) {
		t.Error("a token was accepted with another session or another cookie")
	}
}

// TestWhatEndsSessions: signing out ends one; a disabled user loses all; a
// passphrase change keeps the one that made it; an eleventh pushes out the
// oldest; a list shows only the live ones.
func TestWhatEndsSessions(t *testing.T) {
	ctx := context.Background()
	ss, mem, now := testSessions()
	var mine []Opened
	for range 3 {
		*now = now.Add(time.Second)
		o, err := ss.New(ctx, 7, HostApp, "c", "a", "")
		if err != nil {
			t.Fatal(err)
		}
		mine = append(mine, o)
	}
	other, _ := ss.New(ctx, 9, HostApp, "c", "a", "")
	if err := ss.End(ctx, mine[0].Cookie); err != nil {
		t.Fatal(err)
	}
	if _, err := ss.Resolve(ctx, mine[0].Cookie, HostApp); err != ErrNoSession {
		t.Fatal("a signed-out session lives")
	}
	if n, err := ss.EndOthers(ctx, 7, mine[2].Cookie); err != nil || n != 1 {
		t.Fatalf("EndOthers ended %d, %v; want the one other", n, err)
	}
	if _, err := ss.Resolve(ctx, mine[2].Cookie, HostApp); err != nil {
		t.Fatal("the session that changed the passphrase was ended by it")
	}
	if _, err := ss.Resolve(ctx, mine[1].Cookie, HostApp); err != ErrNoSession {
		t.Fatal("another session outlived the passphrase change")
	}
	if n, _ := ss.EndAll(ctx, 7); n != 1 {
		t.Fatalf("EndAll ended %d", n)
	}
	if _, err := ss.Resolve(ctx, other.Cookie, HostApp); err != nil {
		t.Fatal("another user's session was ended")
	}
	// Ten at most: the eleventh pushes out the oldest.
	var all []Opened
	for range MaxSessions + 1 {
		*now = now.Add(time.Second)
		o, _ := ss.New(ctx, 7, HostApp, "c", "a", "")
		all = append(all, o)
	}
	if _, err := ss.Resolve(ctx, all[0].Cookie, HostApp); err != ErrNoSession {
		t.Fatal("the oldest of eleven sessions lives")
	}
	if list, err := ss.List(ctx, 7); err != nil || len(list) != MaxSessions || list[0].CreatedAt < list[1].CreatedAt {
		t.Fatalf("List = %d sessions, %v", len(list), err)
	}
	// Rows past their limits go when a session is made, and are not listed before.
	*now = now.Add(13 * time.Hour)
	if list, _ := ss.List(ctx, 7); len(list) != 0 {
		t.Fatalf("%d dead sessions listed", len(list))
	}
	if _, err := ss.New(ctx, 9, HostApp, "c", "a", ""); err != nil {
		t.Fatal(err)
	}
	if len(mem.rows) != 1 {
		t.Fatalf("%d rows after a login 13 hours on; want the new one alone", len(mem.rows))
	}
}
