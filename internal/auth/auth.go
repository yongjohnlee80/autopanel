// Package auth is the panel's users and their logins: roles (policy.go), an
// admin's passphrase slot that holds the master key, every other user's
// argon2id verifier, a second factor (TOTP and recovery codes), the lockout,
// and API tokens. It answers the control socket's Authorizer: every call of a
// logged-in connection is checked against the caller's role read fresh from
// the store.
//
// Every attempt is audited before it is checked (R12); every failure looks the
// same, whatever failed (H1); derivations run one at a time; the vault is
// unlocked only after the second factor passes (H2).
//
// Decision: docs/decisions/auth.md
package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yongjohnlee80/golib/auth/password"

	"github.com/yongjohnlee80/autopanel/core/audit"
	"github.com/yongjohnlee80/autopanel/internal/keyslot"
	"github.com/yongjohnlee80/autopanel/internal/module"
)

// Auditor records an attempt on its own.
type Auditor interface {
	Audit(ctx context.Context, actor, action, subject, detail string) error
}

var (
	// ErrBadLogin is every failed login: no such user, a wrong passphrase, a
	// missing or wrong code, a disabled user (H1).
	ErrBadLogin = errors.New("auth: wrong user, passphrase or code")
	// ErrThrottled is a login tried before its wait has passed, or of a locked
	// account (or an unknown name tried as often: M5).
	ErrThrottled = errors.New("auth: too many failed logins; wait and try again")
)

// MaxWait caps the wait a run of failures builds up.
const MaxWait = time.Minute

//go:embed data/common-passwords.txt
var commonText string

// Module is auth.*.
type Module struct {
	store    Store
	secrets  Secrets
	audit    Auditor
	vault    *keyslot.Vault
	onUnlock func(context.Context) // runs when a login unlocked a locked vault
	params   keyslot.Params
	dummy    keyslot.PassphraseSlot
	dummyVer string
	hasher   password.Argon2id
	sem      chan struct{}
	now      func() time.Time
	browser  *browserGate // one browser login verified at a time, a few waiting
	sessions *Sessions    // the browser sessions, ended when a user changes; nil in a test without them

	mu       sync.Mutex
	fails    map[string]failure // per name, known or not: the doubling wait, and an unknown name's lock
	webFails map[string]failure // the same for logins from a browser, counted apart (browser.go)
	touched  map[int64]int64    // a token's last_used_at, written once a minute (L4)
	tokFail  []int64            // token login failures in the last minute, for the burst alarm (N1)
}

type failure struct {
	n     int
	until time.Time
}

// New returns the module. params are the slots' cost, so an unknown user's
// login costs what a real one does.
func New(store Store, secrets Secrets, aud Auditor, vault *keyslot.Vault, onUnlock func(context.Context), params keyslot.Params) (*Module, error) {
	mk, err := keyslot.NewMasterKey()
	if err != nil {
		return nil, err
	}
	pass, err := keyslot.NewMasterKey() // a passphrase no one knows
	if err != nil {
		return nil, err
	}
	dummy, err := keyslot.SealPassphrase(mk, string(pass), params)
	if err != nil {
		return nil, err
	}
	h := password.Interactive()
	dv, err := h.Hash(string(pass))
	if err != nil {
		return nil, err
	}
	return &Module{store: store, secrets: secrets, audit: aud, vault: vault, onUnlock: onUnlock, params: params,
		dummy: dummy, dummyVer: dv, hasher: h, sem: make(chan struct{}, 1), now: time.Now,
		fails: map[string]failure{}, webFails: map[string]failure{}, browser: newBrowserGate(), touched: map[int64]int64{}}, nil
}

func (m *Module) Name() string { return "auth" }

func (m *Module) Errors() []module.PublicError {
	return []module.PublicError{
		{Err: ErrBadLogin, Code: -32160, Name: "auth.bad_login", Message: "wrong user, passphrase or code"},
		{Err: ErrThrottled, Code: -32161, Name: "auth.throttled", Message: "too many failed logins; wait and try again"},
		{Err: ErrForbidden, Code: -32162, Name: "auth.forbidden", Message: "your role may not do that"},
		{Err: ErrVaultLocked, Code: -32163, Name: "auth.vault_locked", Message: "the vault is locked until an admin logs in"},
		{Err: ErrMustChange, Code: -32164, Name: "auth.must_change", Message: "change your passphrase first (auth.passphrase.change)"},
		{Err: ErrExpired, Code: -32165, Name: "auth.expired", Message: "the session has expired; log in again"},
		{Err: ErrNoUser, Code: -32166, Name: "auth.no_user", Message: "no such user"},
		{Err: ErrUserExists, Code: -32167, Name: "auth.user_exists", Message: "a user of that name exists"},
		{Err: ErrLastAdmin, Code: -32168, Name: "auth.last_admin", Message: "that would leave no admin"},
		{Err: ErrRootUser, Code: -32169, Name: "auth.root", Message: "root is never removed, demoted or disabled"},
		{Err: ErrBadName, Code: -32120, Name: "auth.bad_name", Message: "a user's name is a lower-case letter, then letters, digits, . _ -, 32 at most"},
		{Err: ErrBadRole, Code: -32121, Name: "auth.bad_role", Message: "a role is admin, operator, mail or viewer"},
		{Err: ErrWeak, Code: -32122, Name: "auth.weak_passphrase", Message: "a passphrase is 12 characters at least, holds no user name, and is no common password"},
		{Err: ErrBadCode, Code: -32123, Name: "auth.bad_code", Message: "that code is not right"},
		{Err: ErrNoTOTP, Code: -32124, Name: "auth.no_totp", Message: "two-factor is not enrolled"},
		{Err: ErrTOTPAlready, Code: -32125, Name: "auth.totp_enrolled", Message: "two-factor is enrolled already"},
		{Err: ErrNoToken, Code: -32126, Name: "auth.no_token", Message: "no such token"},
		{Err: ErrNotOwn, Code: -32127, Name: "auth.not_own", Message: "that is another user's"},
		{Err: ErrBadTokenAsk, Code: -32128, Name: "auth.bad_token", Message: "a token's role is no higher than its owner's, and it lasts a year at most"},
		{Err: ErrNoSuchSession, Code: -32129, Name: "auth.no_session", Message: "no such session of yours"},
		{Err: ErrBusy, Code: -32119, Name: "auth.busy", Message: "too many logins are waiting; try again shortly"},
	}
}

// --- the caller -----------------------------------------------------------------

// whose is the user a principal is, or a token's owner, with the token.
func (m *Module) whose(ctx context.Context, principal string) (User, *Token, error) {
	kind, id, ok := strings.Cut(principal, ":")
	n, err := strconv.ParseInt(id, 10, 64)
	if !ok || err != nil {
		return User{}, nil, ErrExpired
	}
	switch kind {
	case "user":
		u, err := m.store.UserByID(ctx, n)
		if errors.Is(err, ErrNoUser) {
			return User{}, nil, ErrExpired
		}
		return u, nil, err
	case "token":
		t, err := m.store.Token(ctx, n)
		if errors.Is(err, ErrNoToken) {
			return User{}, nil, ErrExpired
		}
		if err != nil {
			return User{}, nil, err
		}
		u, err := m.store.UserByID(ctx, t.UserID)
		if errors.Is(err, ErrNoUser) {
			return User{}, nil, ErrExpired
		}
		return u, &t, err
	}
	return User{}, nil, ErrExpired
}

// caller is the user a verb runs for (a token's owner for a token).
func (m *Module) caller(ctx context.Context) (User, *Token, error) {
	return m.whose(ctx, module.Principal(ctx))
}

// mustChangeAllows are the verbs a user who must change its passphrase may
// still call (M2).
var mustChangeAllows = map[string]bool{
	"auth.whoami": true, "auth.passphrase.change": true, "auth.totp.begin": true, "auth.totp.confirm": true,
	"sys.prefs.get": true, "sys.status": true,
}

// Authorize is the control socket's Authorizer: the principal re-read from the
// store at every call (R1), its role against the verb's contract (H3).
func (m *Module) Authorize(ctx context.Context, principal string, since time.Time, c module.Contract) (string, error) {
	if !since.IsZero() && m.now().Sub(since) > SessionMax {
		return "", ErrExpired
	}
	u, t, err := m.whose(ctx, principal)
	if err != nil {
		return "", err
	}
	actor, role := u.Name, u.Role
	if t != nil {
		actor = "token " + t.Name + " of " + u.Name
		now := m.now().Unix()
		if t.RevokedAt != 0 || now >= t.ExpiresAt {
			return actor, ErrExpired
		}
		role = Effective(u.Role, t.Role)
		if c.AreaOf() == "auth" && c.Mutates { // a token never manages users, tokens or passphrases
			return actor, ErrForbidden
		}
		m.touch(ctx, t.ID, now)
	}
	switch {
	case u.DisabledAt != 0:
		return actor, ErrForbidden
	case u.MustChange && t == nil && !mustChangeAllows[c.Verb]: // the passphrase login's rule: a token is not one
		return actor, ErrMustChange
	case !Allows(role, c):
		return actor, ErrForbidden
	}
	return actor, nil
}

// touch writes a token's last use at most once a minute (L4).
func (m *Module) touch(ctx context.Context, id, now int64) {
	m.mu.Lock()
	last := m.touched[id]
	if now-last < 60 {
		m.mu.Unlock()
		return
	}
	m.touched[id] = now
	m.mu.Unlock()
	_ = m.store.TouchToken(ctx, id, now)
}

// --- passphrases ------------------------------------------------------------

// weak reports a passphrase too easy to guess (D4).
func (m *Module) weak(name, pass string) bool { return Weak(name, pass) }

var (
	commonOnce sync.Once
	common     map[string]bool
)

// Weak reports a passphrase too easy to guess (D4): shorter than 12
// characters, holding the user's name, or one of the 10,000 most common
// passwords.
func Weak(name, pass string) bool {
	commonOnce.Do(func() {
		common = map[string]bool{}
		for _, l := range strings.Split(commonText, "\n") {
			if l = strings.TrimSpace(strings.ToLower(l)); l != "" {
				common[l] = true
			}
		}
	})
	p := strings.ToLower(pass)
	return len([]rune(pass)) < 12 || (name != "" && strings.Contains(p, strings.ToLower(name))) || common[p]
}

// derive runs one derivation at a time, under the core's memory budget.
func (m *Module) derive(ctx context.Context, fn func()) error {
	select {
	case m.sem <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-m.sem }()
	fn()
	return nil
}

// checkPassphrase opens a user's login with pass: an admin's slot (answering
// the master key, which the caller must clear), any other user's verifier.
func (m *Module) checkPassphrase(ctx context.Context, u User, pass string) (mk []byte, ok bool, err error) {
	if u.Role == RoleAdmin {
		slot, err := m.store.PassphraseSlot(ctx, u.Name)
		if err != nil {
			return nil, false, err
		}
		var oerr error
		if err := m.derive(ctx, func() { mk, oerr = keyslot.OpenPassphrase(slot, pass) }); err != nil {
			return nil, false, err
		}
		return mk, oerr == nil, nil
	}
	var verr error
	if err := m.derive(ctx, func() { verr = password.Verify(u.Verifier, pass) }); err != nil {
		return nil, false, err
	}
	return nil, verr == nil, nil
}

// loginOf makes how a user logs in from a passphrase: a slot for an admin
// (the vault must be open), a verifier for any other role.
func (m *Module) loginOf(role Role, pass string) (*keyslot.PassphraseSlot, string, error) {
	if role == RoleAdmin {
		slot, err := m.vault.SealPassphrase(pass, m.params)
		if errors.Is(err, keyslot.ErrLocked) {
			return nil, "", ErrVaultLocked
		}
		return &slot, "", err
	}
	v, err := m.hasher.Hash(pass)
	return nil, v, err
}

func hashCode(code string) []byte {
	sum := sha256.Sum256([]byte(code))
	return sum[:]
}

func sameHash(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }

// audited records an outcome after the fact (the attempt was recorded first).
func (m *Module) audited(ctx context.Context, action, subject, detail string) {
	_ = m.audit.Audit(ctx, audit.Actor(ctx), action, subject, detail)
}

// Caller is the enabled user a verb runs for (a token's owner for a token),
// read from the store now. A principal that is no one, or a disabled user, is
// ErrExpired.
func (m *Module) Caller(ctx context.Context) (User, error) {
	u, _, err := m.caller(ctx)
	if err != nil {
		return User{}, err
	}
	if u.DisabledAt != 0 {
		return User{}, ErrExpired
	}
	return u, nil
}

// UserNamed is the user of that name, for another module that names users
// (a document's share list). ErrNoUser when there is none.
func (m *Module) UserNamed(ctx context.Context, name string) (User, error) {
	return m.store.User(ctx, name)
}

// UserByID is the user of that id. ErrNoUser when there is none.
func (m *Module) UserByID(ctx context.Context, id int64) (User, error) {
	return m.store.UserByID(ctx, id)
}
