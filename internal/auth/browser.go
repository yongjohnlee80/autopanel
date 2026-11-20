package auth

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/yongjohnlee80/golib/auth/password"

	"github.com/yongjohnlee80/autopanel/internal/keyslot"
)

// THE BROWSER LOGIN — the login that exists, by another way in: a name, a
// passphrase, a second factor, one answer for every failure. What differs is
// what a browser must never get and must never be able to do:
//
//   - it never opens the vault. An admin's passphrase is checked by opening
//     that admin's key slot, which yields the master key; here the key is
//     cleared the moment the slot has opened, and only "right" or "wrong"
//     leaves the check;
//   - the second factor's seed is read through the vault the host's keyfile
//     opened at start, never through a vault made from the passphrase. With
//     the vault locked, a user who has a second factor cannot sign in from a
//     browser, and the answer is the same failure;
//   - its failures are counted apart from the console's. Ten bad browser
//     logins lock a name for browser logins only, the first administrator
//     included: nobody on the internet can lock an administrator out of the
//     panel at the host;
//   - one browser login is being verified at a time and four may wait, so the
//     console's login waits for at most one of them.
//
// Decision: docs/decisions/auth.md#browser-sessions

// ErrBusy is a browser login refused because too many are waiting.
var ErrBusy = errors.New("auth: too many logins are waiting; try again shortly")

const (
	browserWaiting = 4 // browser logins that may wait for the one being verified
)

// browserGate lets one browser login in at a time, with a short queue.
type browserGate struct {
	inside chan struct{} // capacity 1
	queue  chan struct{} // capacity 1 + browserWaiting
}

func newBrowserGate() *browserGate {
	return &browserGate{inside: make(chan struct{}, 1), queue: make(chan struct{}, 1+browserWaiting)}
}

// enter takes a place: at once, after a wait, or not at all when the queue is
// full or the caller has gone.
func (g *browserGate) enter(ctx context.Context) bool {
	select {
	case g.queue <- struct{}{}:
	default:
		return false
	}
	select {
	case g.inside <- struct{}{}:
		return true
	case <-ctx.Done():
		<-g.queue
		return false
	}
}

func (g *browserGate) leave() {
	<-g.inside
	<-g.queue
}

// BrowserLogin checks a login that came from a browser at client and answers
// the user it is. It opens nothing and makes no session: the caller does
// that. Every failure is ErrBadLogin; a name in its wait or locked, known or
// not, is ErrThrottled; too many waiting is ErrBusy.
func (m *Module) BrowserLogin(ctx context.Context, p Login, client string) (User, error) {
	actor := "browser " + client
	subject := "user " + p.User
	if err := m.audit.Audit(ctx, actor, "auth.login", subject, "attempt"); err != nil {
		return User{}, err // no record, no attempt
	}
	if m.browserWaiting(p.User) {
		return User{}, ErrThrottled
	}
	if !m.browser.enter(ctx) {
		return User{}, ErrBusy
	}
	defer m.browser.leave()
	u, err := m.store.User(ctx, p.User)
	known := err == nil
	if err != nil && !errors.Is(err, ErrNoUser) {
		return User{}, err
	}
	if known && u.LockedUntil > m.now().Unix() {
		return User{}, ErrThrottled // locked at the console is locked here too
	}
	ok := false
	if known {
		if ok, err = m.passphraseIsRight(ctx, u, p.Passphrase); err != nil {
			return User{}, err
		}
	} else { // the same cost, the same answer
		_ = m.derive(ctx, func() {
			mk, _ := keyslot.OpenPassphrase(m.dummy, p.Passphrase)
			clear(mk)
		})
	}
	why := "passphrase"
	switch {
	case !known:
		why = "no such user"
	case !ok:
	case u.DisabledAt != 0:
		ok, why = false, "disabled"
	default:
		ok, why = m.secondFactor(ctx, u, nil, p.Code) // nil: through the vault the keyfile opened, or not at all
	}
	if !ok {
		m.browserFailed(p.User)
		_ = m.audit.Audit(ctx, actor, "auth.login", subject, "failed: "+why)
		return User{}, ErrBadLogin
	}
	m.browserCleared(p.User)
	_ = m.audit.Audit(ctx, actor, "auth.login", subject, "ok")
	return u, nil
}

// passphraseIsRight checks pass and answers only whether it is right. An
// admin's check opens the key slot; the master key it yields is cleared
// before this returns and is never handed on.
func (m *Module) passphraseIsRight(ctx context.Context, u User, pass string) (bool, error) {
	if u.Role == RoleAdmin {
		slot, err := m.store.PassphraseSlot(ctx, u.Name)
		if err != nil {
			return false, err
		}
		right := false
		if err := m.derive(ctx, func() {
			mk, oerr := keyslot.OpenPassphrase(slot, pass)
			right = oerr == nil
			clear(mk)
		}); err != nil {
			return false, err
		}
		return right, nil
	}
	var verr error
	if err := m.derive(ctx, func() { verr = password.Verify(u.Verifier, pass) }); err != nil {
		return false, err
	}
	return verr == nil, nil
}

// browserWaiting reports a name in its wait or its lock for browser logins.
func (m *Module) browserWaiting(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.now().Before(m.webFails[strings.ToLower(name)].until)
}

// browserFailed counts a browser's failure for a name, known or not: the
// doubling wait, and at every tenth in a row a lock of LockFor. The table is
// bounded; when it is full of names still waiting, a new name waits too
// rather than pushing one of them out.
func (m *Module) browserFailed(name string) {
	name = strings.ToLower(name)
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	if _, tracked := m.webFails[name]; !tracked && len(m.webFails) >= maxTracked {
		for k, f := range m.webFails {
			if now.After(f.until) {
				delete(m.webFails, k)
			}
		}
		if len(m.webFails) >= maxTracked {
			return // every tracked name is still waiting: none is forgotten for this one
		}
	}
	f := m.webFails[name]
	f.n++
	wait := time.Second << min(f.n-1, 6)
	if wait > MaxWait {
		wait = MaxWait
	}
	if f.n%LockAfter == 0 {
		wait = LockFor
	}
	f.until = now.Add(wait)
	m.webFails[name] = f
}

func (m *Module) browserCleared(name string) {
	m.mu.Lock()
	delete(m.webFails, strings.ToLower(name))
	m.mu.Unlock()
}
