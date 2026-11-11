// Package auth is the panel's login: a user and the master passphrase. The
// passphrase slot that holds the master key is also the login's verifier, so a
// successful login can unlock a vault the keyfile didn't (AutoDB's design).
//
// Every attempt is audited before it is checked (R12); failures look the same
// whatever failed (golib auth's uniform failure); derivations run one at a
// time, under the controller's memory budget; and each failure doubles the
// wait before that user's next try, up to a minute.
package auth

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/yongjohnlee80/autopanel/core/audit"
	"github.com/yongjohnlee80/autopanel/internal/keyslot"
	"github.com/yongjohnlee80/autopanel/internal/module"
)

// Slots finds a user's passphrase slot. A missing user answers an error the
// module reports exactly as a wrong passphrase.
type Slots interface {
	PassphraseSlot(ctx context.Context, name string) (keyslot.PassphraseSlot, error)
}

// Auditor records an attempt on its own.
type Auditor interface {
	Audit(ctx context.Context, actor, action, subject, detail string) error
}

var (
	// ErrBadLogin is every failed login: no such user, or a wrong passphrase.
	ErrBadLogin = errors.New("auth: wrong user or passphrase")
	// ErrThrottled is a login tried before the user's wait has passed.
	ErrThrottled = errors.New("auth: too many failed logins; wait and try again")
)

// MaxWait caps the wait a run of failures builds up.
const MaxWait = time.Minute

// Module is auth.* .
type Module struct {
	slots    Slots
	audit    Auditor
	vault    *keyslot.Vault
	onUnlock func(context.Context) // runs when a login unlocked a locked vault
	dummy    keyslot.PassphraseSlot
	sem      chan struct{}
	now      func() time.Time

	mu    sync.Mutex
	fails map[string]failure
}

type failure struct {
	n     int
	until time.Time
}

// New returns the login module. dummyParams should be the real slots' cost, so
// a login for an unknown user costs what a wrong passphrase does.
func New(slots Slots, aud Auditor, vault *keyslot.Vault, onUnlock func(context.Context), dummyParams keyslot.Params) (*Module, error) {
	mk, err := keyslot.NewMasterKey()
	if err != nil {
		return nil, err
	}
	pass, err := keyslot.NewMasterKey() // a passphrase no one knows
	if err != nil {
		return nil, err
	}
	dummy, err := keyslot.SealPassphrase(mk, string(pass), dummyParams)
	if err != nil {
		return nil, err
	}
	return &Module{slots: slots, audit: aud, vault: vault, onUnlock: onUnlock, dummy: dummy,
		sem: make(chan struct{}, 1), now: time.Now, fails: map[string]failure{}}, nil
}

func (m *Module) Name() string { return "auth" }

// Login is auth.login's param.
type Login struct {
	User       string `json:"user"`
	Passphrase string `json:"passphrase"`
}

// LoggedIn is auth.login's answer.
type LoggedIn struct {
	User     string `json:"user"`
	Unlocked bool   `json:"unlocked"` // this login unlocked the vault
}

func (m *Module) Verbs() []module.Verb {
	return []module.Verb{module.Handle(module.Contract{Verb: "auth.login", Since: 1, Param: "{user, passphrase}", Result: "{user, unlocked}",
		Doc: "Logs this connection in. Every other verb needs it. A locked vault is unlocked by root's passphrase.", Open: true, Login: true}, m.login)}
}

func (m *Module) Errors() []module.PublicError {
	return []module.PublicError{
		{Err: ErrBadLogin, Code: -32160, Name: "auth.bad_login", Message: "wrong user or passphrase"},
		{Err: ErrThrottled, Code: -32161, Name: "auth.throttled", Message: "too many failed logins; wait and try again"},
	}
}

func (m *Module) login(ctx context.Context, p Login) (LoggedIn, error) {
	actor := audit.Actor(ctx)
	subject := "user " + p.User
	if err := m.audit.Audit(ctx, actor, "auth.login", subject, "attempt"); err != nil {
		return LoggedIn{}, err // no record, no attempt (R12)
	}
	m.mu.Lock()
	f := m.fails[p.User]
	m.mu.Unlock()
	if m.now().Before(f.until) {
		return LoggedIn{}, ErrThrottled
	}
	select {
	case m.sem <- struct{}{}:
	case <-ctx.Done():
		return LoggedIn{}, ctx.Err()
	}
	slot, slotErr := m.slots.PassphraseSlot(ctx, p.User)
	if slotErr != nil {
		slot = m.dummy // same cost, same answer: the user's existence isn't disclosed
	}
	mk, err := keyslot.OpenPassphrase(slot, p.Passphrase)
	<-m.sem
	if slotErr != nil || err != nil {
		m.fail(p.User)
		_ = m.audit.Audit(ctx, actor, "auth.login", subject, "failed")
		return LoggedIn{}, ErrBadLogin
	}
	m.mu.Lock()
	delete(m.fails, p.User)
	m.mu.Unlock()
	wasLocked := !m.vault.Unlocked()
	if err := m.vault.Unlock(mk); err != nil {
		return LoggedIn{}, err
	}
	if wasLocked && m.onUnlock != nil {
		m.onUnlock(ctx)
	}
	_ = m.audit.Audit(ctx, actor, "auth.login", subject, "ok")
	return LoggedIn{User: p.User, Unlocked: wasLocked}, nil
}

// maxTracked bounds the failure map: its keys are whatever names callers
// send, so it is a pre-auth store and must evict.
const maxTracked = 1024

func (m *Module) fail(user string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.fails) >= maxTracked {
		now := m.now()
		for u, f := range m.fails {
			if now.After(f.until) {
				delete(m.fails, u)
			}
		}
		if len(m.fails) >= maxTracked {
			for u := range m.fails { // still full of live waits: drop one, the map stays bounded
				delete(m.fails, u)
				break
			}
		}
	}
	f := m.fails[user]
	f.n++
	wait := time.Second << min(f.n-1, 6)
	if wait > MaxWait {
		wait = MaxWait
	}
	f.until = m.now().Add(wait)
	m.fails[user] = f
}
