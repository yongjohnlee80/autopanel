// Package authtest is an in-memory auth.Store and auth.Secrets, for tests of
// the auth module and of what uses it. It keeps the store's rules: the last
// admin, root, a slot or a verifier, a step spent once.
package authtest

import (
	"bytes"
	"context"
	"sort"
	"sync"

	"github.com/yongjohnlee80/autopanel/internal/auth"
	"github.com/yongjohnlee80/autopanel/internal/keyslot"
)

// Store is auth.Store in memory.
type Store struct {
	mu       sync.Mutex
	users    map[int64]*auth.User
	slots    map[int64]keyslot.PassphraseSlot
	recovery map[int64][][]byte
	tokens   map[int64]*auth.Token
	next     int64
	nextTok  int64
}

// New is a store holding root, an admin with slot.
func New(rootName string, slot keyslot.PassphraseSlot) *Store {
	s := &Store{users: map[int64]*auth.User{}, slots: map[int64]keyslot.PassphraseSlot{},
		recovery: map[int64][][]byte{}, tokens: map[int64]*auth.Token{}}
	s.next = 1
	s.users[1] = &auth.User{ID: 1, Name: rootName, Role: auth.RoleAdmin, Root: true}
	s.slots[1] = slot
	return s
}

func (s *Store) find(name string) *auth.User {
	for _, u := range s.users {
		if u.Name == name {
			return u
		}
	}
	return nil
}

func (s *Store) PassphraseSlot(_ context.Context, name string) (keyslot.PassphraseSlot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.find(name)
	if u == nil {
		return keyslot.PassphraseSlot{}, auth.ErrNoUser
	}
	slot, ok := s.slots[u.ID]
	if !ok {
		return keyslot.PassphraseSlot{}, auth.ErrNoUser
	}
	return slot, nil
}

func (s *Store) User(_ context.Context, name string) (auth.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u := s.find(name); u != nil {
		return *u, nil
	}
	return auth.User{}, auth.ErrNoUser
}

func (s *Store) UserByID(_ context.Context, id int64) (auth.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, ok := s.users[id]; ok {
		return *u, nil
	}
	return auth.User{}, auth.ErrNoUser
}

func (s *Store) Users(context.Context) ([]auth.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []auth.User{}
	for _, u := range s.users {
		out = append(out, *u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *Store) AddUser(_ context.Context, name string, role auth.Role, slot *keyslot.PassphraseSlot, verifier string, mustChange bool) (auth.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.find(name) != nil {
		return auth.User{}, auth.ErrUserExists
	}
	s.next++
	u := &auth.User{ID: s.next, Name: name, Role: role, Verifier: verifier, MustChange: mustChange}
	s.users[u.ID] = u
	if slot != nil {
		s.slots[u.ID] = *slot
	}
	return *u, nil
}

func (s *Store) othersLeft(id int64) int {
	n := 0
	for _, u := range s.users {
		if u.ID != id && u.Role == auth.RoleAdmin && u.DisabledAt == 0 {
			n++
		}
	}
	return n
}

func (s *Store) SetLogin(_ context.Context, id int64, role auth.Role, slot *keyslot.PassphraseSlot, verifier string, mustChange bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[id]
	if !ok {
		return auth.ErrNoUser
	}
	if u.Role == auth.RoleAdmin && role != auth.RoleAdmin {
		if u.Root {
			return auth.ErrRootUser
		}
		if s.othersLeft(id) == 0 {
			return auth.ErrLastAdmin
		}
	}
	u.Role, u.Verifier, u.MustChange = role, verifier, mustChange
	delete(s.slots, id)
	if slot != nil {
		s.slots[id] = *slot
	}
	return nil
}

func (s *Store) SetDisabled(_ context.Context, id int64, disabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[id]
	if !ok {
		return auth.ErrNoUser
	}
	if disabled {
		if u.Root {
			return auth.ErrRootUser
		}
		if u.Role == auth.RoleAdmin && s.othersLeft(id) == 0 {
			return auth.ErrLastAdmin
		}
		u.DisabledAt = 1
	} else {
		u.DisabledAt = 0
	}
	return nil
}

func (s *Store) RemoveUser(_ context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[id]
	if !ok {
		return auth.ErrNoUser
	}
	if u.Root {
		return auth.ErrRootUser
	}
	if u.Role == auth.RoleAdmin && s.othersLeft(id) == 0 {
		return auth.ErrLastAdmin
	}
	delete(s.users, id)
	delete(s.slots, id)
	for tid, t := range s.tokens {
		if t.UserID == id {
			delete(s.tokens, tid)
		}
	}
	return nil
}

func (s *Store) RecordFailure(_ context.Context, id int64, lockAfter int, lockUntil int64) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.users[id]
	u.FailCount++
	n := u.FailCount
	if n >= lockAfter && !u.Root {
		u.LockedUntil, u.FailCount = lockUntil, 0
	}
	return n, nil
}

func (s *Store) RecordLogin(_ context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.users[id]
	u.FailCount, u.LockedUntil, u.LastLoginAt = 0, 0, 1
	return nil
}

func (s *Store) ClearLock(_ context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[id].FailCount, s.users[id].LockedUntil = 0, 0
	return nil
}

func (s *Store) SetTOTP(_ context.Context, id int64, enrolled bool, recovery [][]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[id].TOTP, s.users[id].TOTPLastStep = enrolled, 0
	s.recovery[id] = recovery
	return nil
}

func (s *Store) SpendStep(_ context.Context, id, step int64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.users[id]
	if u.TOTPLastStep >= step {
		return false, nil
	}
	u.TOTPLastStep = step
	return true, nil
}

func (s *Store) SpendRecovery(_ context.Context, id int64, hash []byte) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, h := range s.recovery[id] {
		if bytes.Equal(h, hash) {
			s.recovery[id] = append(s.recovery[id][:i], s.recovery[id][i+1:]...)
			return true, nil
		}
	}
	return false, nil
}

func (s *Store) AddToken(_ context.Context, t auth.Token) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextTok++
	t.ID = s.nextTok
	t.Owner = s.users[t.UserID].Name
	s.tokens[t.ID] = &t
	return t.ID, nil
}

func (s *Store) Token(_ context.Context, id int64) (auth.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.tokens[id]; ok {
		return *t, nil
	}
	return auth.Token{}, auth.ErrNoToken
}

func (s *Store) Tokens(_ context.Context, userID int64) ([]auth.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []auth.Token{}
	for _, t := range s.tokens {
		if userID == 0 || t.UserID == userID {
			out = append(out, *t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *Store) RevokeToken(_ context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[id]
	if !ok || t.RevokedAt != 0 {
		return auth.ErrNoToken
	}
	t.RevokedAt = 1
	return nil
}

func (s *Store) TouchToken(_ context.Context, id, at int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.tokens[id]; ok {
		t.LastUsedAt = at
	}
	return nil
}

// Secrets is auth.Secrets in memory: sealed under the vault it is given, as
// the store's secret table is.
type Secrets struct {
	mu sync.Mutex
	m  map[string][]byte
}

func NewSecrets() *Secrets { return &Secrets{m: map[string][]byte{}} }

func aad(name string) string { return "autopanel:secret:" + name + ":v1" }

func (s *Secrets) PutSecret(_ context.Context, v *keyslot.Vault, name string, value []byte) error {
	sealed, err := v.Seal(aad(name), value)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[name] = sealed
	return nil
}

func (s *Secrets) Secret(_ context.Context, v *keyslot.Vault, name string) ([]byte, error) {
	s.mu.Lock()
	sealed, ok := s.m[name]
	s.mu.Unlock()
	if !ok {
		return nil, auth.ErrNoUser
	}
	return v.Open(aad(name), sealed)
}

func (s *Secrets) DeleteSecret(_ context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, name)
	return nil
}
