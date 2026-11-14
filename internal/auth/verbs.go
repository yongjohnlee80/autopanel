package auth

import (
	"context"
	"crypto/rand"
	"errors"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/yongjohnlee80/autopanel/core/audit"
	"github.com/yongjohnlee80/autopanel/internal/keyslot"
	"github.com/yongjohnlee80/autopanel/internal/module"
)

func plain(c module.Contract) module.Contract { c.Discloses = module.Plain; return c }

func (m *Module) Verbs() []module.Verb {
	own := func(verb, param, result, doc string) module.Contract {
		return module.Contract{Verb: verb, Since: 6, Param: param, Result: result, Doc: doc, Mutates: true}
	}
	admin := own // the policy keeps auth.user.* the admin's: the contract is the same shape
	return []module.Verb{
		module.Handle(plain(module.Contract{Verb: "auth.login", Since: 1, Param: "{user, passphrase, code?}", Result: "{user, principal, role, unlocked, must_change}",
			Doc: "Logs this connection in, replacing any login it had. The code is the two-factor code (or a recovery code), empty without two-factor. Every failure is the same auth.bad_login. An admin's login unlocks a locked vault.", Open: true, Login: true}), m.login),
		module.Handle(plain(module.Contract{Verb: "auth.token.login", Since: 6, Param: "{token}", Result: "{user, principal, role}",
			Doc: "Logs this connection in with an API token (apt_<id>_<secret>), replacing any login it had.", Open: true, Login: true}), m.tokenLogin),
		module.Handle(plain(module.Contract{Verb: "auth.status", Since: 6, Result: "{vault_locked}",
			Doc: "Whether the vault is locked, before anyone logs in: then only an admin's login works for a user with two-factor.", Open: true}), m.status),
		module.Handle(plain(module.Contract{Verb: "auth.whoami", Since: 6, Result: "{user, role, by, totp, must_change, vault_locked, root}",
			Doc: "Who this connection is logged in as."}), m.whoami),
		module.Handle(module.Contract{Verb: "auth.user.list", Since: 6, Result: "[{name, role, root, totp, disabled, locked_until, last_login_at, must_change}]",
			Doc: "The panel's users. Admins only."}, m.userList),
		module.Handle(admin("auth.user.add", "{name, role, passphrase}", "{name, role}", "Makes a user, who must change the passphrase at the first login. An admin needs the vault open."), m.userAdd),
		module.Handle(admin("auth.user.role", "{name, role, passphrase}", "", "Changes a user's role, with a reset passphrase the user must change. To admin seals a key slot; from admin drops it."), m.userRole),
		module.Handle(admin("auth.user.reset", "{name, passphrase}", "", "Sets a user's passphrase, which the user must change at the next login."), m.userReset),
		module.Handle(admin("auth.user.disable", "{name, disabled}", "", "Disables a user (its tokens stop too), or enables it."), m.userDisable),
		module.Handle(admin("auth.user.unlock", "{name}", "", "Lifts a lockout after failed logins."), m.userUnlock),
		module.Handle(admin("auth.user.remove", "{name}", "", "Removes a user, its key slot, its two-factor and its tokens."), m.userRemove),
		module.Handle(own("auth.passphrase.change", "{old, new}", "", "Changes your own passphrase."), m.passphraseChange),
		module.Handle(own("auth.totp.begin", "", "{secret, uri}", "Starts two-factor enrolment: the secret is shown once, for an authenticator app."), m.totpBegin),
		module.Handle(own("auth.totp.confirm", "{code}", "{recovery}", "Enrols two-factor once a code from the app verifies; answers ten recovery codes, shown once."), m.totpConfirm),
		module.Handle(own("auth.totp.disable", "{code?, name?}", "", "Drops your two-factor (with a code), or an admin drops another user's."), m.totpDisable),
		module.Handle(plain(module.Contract{Verb: "auth.token.list", Since: 6, Result: "[{id, name, role, owner, created_at, expires_at, last_used_at, revoked}]",
			Doc: "Your API tokens; an admin's: every user's."}), m.tokenList),
		module.Handle(own("auth.token.create", "{name, role?, days?}", "{id, token, expires_at}", "Makes an API token, shown once: viewer unless asked, no higher than your role, 90 days unless asked, a year at most."), m.tokenCreate),
		module.Handle(own("auth.token.revoke", "{id}", "", "Revokes an API token: your own, or an admin's any."), m.tokenRevoke),
	}
}

// --- logging in ---------------------------------------------------------------

// Login is auth.login's param. The code is always sent, empty without
// two-factor (H1).
type Login struct {
	User       string `json:"user"`
	Passphrase string `json:"passphrase"`
	Code       string `json:"code"`
}

// LoggedIn is a login's answer.
type LoggedIn struct {
	User       string `json:"user"`
	Principal  string `json:"principal"`
	Role       Role   `json:"role"`
	Unlocked   bool   `json:"unlocked"`    // this login unlocked the vault
	MustChange bool   `json:"must_change"` // the passphrase must be changed before anything else
}

func (m *Module) login(ctx context.Context, p Login) (LoggedIn, error) {
	actor := audit.Actor(ctx)
	subject := "user " + p.User
	if err := m.audit.Audit(ctx, actor, "auth.login", subject, "attempt"); err != nil {
		return LoggedIn{}, err // no record, no attempt (R12)
	}
	if m.waiting(p.User) {
		return LoggedIn{}, ErrThrottled
	}
	u, err := m.store.User(ctx, p.User)
	known := err == nil
	if err != nil && !errors.Is(err, ErrNoUser) {
		return LoggedIn{}, err
	}
	if known && u.LockedUntil > m.now().Unix() {
		return LoggedIn{}, ErrThrottled // locked and unknown answer alike (M5)
	}
	var mk []byte
	ok := false
	if known {
		mk, ok, err = m.checkPassphrase(ctx, u, p.Passphrase)
		if err != nil {
			return LoggedIn{}, err
		}
	} else { // the same cost, the same answer: the name's existence is not disclosed
		_ = m.derive(ctx, func() { _, _ = keyslot.OpenPassphrase(m.dummy, p.Passphrase) })
	}
	defer clear(mk) // zeroed on every path (H2)
	why := "passphrase"
	switch {
	case !known:
		why = "no such user"
	case !ok:
	case u.DisabledAt != 0:
		ok, why = false, "disabled"
	default:
		ok, why = m.secondFactor(ctx, u, mk, p.Code)
	}
	if !ok {
		m.failed(ctx, p.User, u, known)
		_ = m.audit.Audit(ctx, actor, "auth.login", subject, "failed: "+why) // the reason is for an admin, never the caller
		return LoggedIn{}, ErrBadLogin
	}
	m.cleared(p.User)
	_ = m.store.RecordLogin(ctx, u.ID)
	unlocked := false
	if u.Role == RoleAdmin && !m.vault.Unlocked() { // only now: the second factor has passed (H2)
		if err := m.vault.Unlock(mk); err != nil {
			return LoggedIn{}, err
		}
		unlocked = true
		if m.onUnlock != nil {
			m.onUnlock(ctx)
		}
	}
	_ = m.audit.Audit(ctx, actor, "auth.login", subject, "ok") // sys.logins reads "ok"
	return LoggedIn{User: u.Name, Principal: "user:" + strconv.FormatInt(u.ID, 10), Role: u.Role, Unlocked: unlocked, MustChange: u.MustChange}, nil
}

// secondFactor checks the code: none without two-factor; a TOTP code (or a
// recovery code) with it, each used once (N2). An admin's seed opens with the
// master key its passphrase just opened, never the shared vault; any other
// user's with the vault, so its login waits for an admin's (section 4.1).
func (m *Module) secondFactor(ctx context.Context, u User, mk []byte, code string) (bool, string) {
	code = strings.TrimSpace(code)
	if !u.TOTP {
		if code != "" {
			return false, "a code without two-factor"
		}
		return true, ""
	}
	if code == "" {
		return false, "no code"
	}
	v := m.vault
	if mk != nil {
		v = &keyslot.Vault{}
		if err := v.Unlock(mk); err != nil {
			return false, "the key"
		}
	}
	seed, err := m.secrets.Secret(ctx, v, totpSecret(u.ID))
	defer clear(seed)
	if err != nil {
		if errors.Is(err, keyslot.ErrLocked) {
			return false, "the vault is locked"
		}
		return false, "the seed"
	}
	if step, ok := totpVerify(seed, code, m.now(), u.TOTPLastStep); ok {
		spent, err := m.store.SpendStep(ctx, u.ID, step)
		if err != nil || !spent {
			return false, "a code used already"
		}
		return true, ""
	}
	if spent, err := m.store.SpendRecovery(ctx, u.ID, hashCode(totpNormRecovery(code))); err == nil && spent {
		m.audited(ctx, "auth.login", "user "+u.Name, "a recovery code was used")
		return true, ""
	}
	return false, "the code"
}

// waiting reports a name still in its wait after failures, or an unknown
// name tried as often as a lockout allows (M5).
func (m *Module) waiting(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.now().Before(m.fails[name].until)
}

// maxTracked bounds the failure map: its keys are whatever names callers
// send, so it is a pre-auth store and must evict.
const maxTracked = 1024

// failed counts a failure: the doubling wait for the name; the lockout, in the
// store for a user, in memory for a name that is none (M5).
func (m *Module) failed(ctx context.Context, name string, u User, known bool) {
	m.mu.Lock()
	if len(m.fails) >= maxTracked {
		now := m.now()
		for k, f := range m.fails {
			if now.After(f.until) {
				delete(m.fails, k)
			}
		}
		for k := range m.fails {
			if len(m.fails) < maxTracked {
				break
			}
			delete(m.fails, k)
		}
	}
	f := m.fails[name]
	f.n++
	wait := time.Second << min(f.n-1, 6)
	if wait > MaxWait {
		wait = MaxWait
	}
	if !known && f.n%LockAfter == 0 {
		wait = LockFor
	}
	f.until = m.now().Add(wait)
	m.fails[name] = f
	m.mu.Unlock()
	if known {
		_, _ = m.store.RecordFailure(ctx, u.ID, LockAfter, m.now().Add(LockFor).Unix())
	}
}

func (m *Module) cleared(name string) {
	m.mu.Lock()
	delete(m.fails, name)
	m.mu.Unlock()
}

// TokenLogin is auth.token.login's param.
type TokenLogin struct {
	Token string `json:"token"`
}

// tokenLogin logs in with an API token. A token id is never locked (N1): its
// secret is 256 random bits; failures are audited, and a burst raises an alarm.
func (m *Module) tokenLogin(ctx context.Context, p TokenLogin) (LoggedIn, error) {
	actor := audit.Actor(ctx)
	id, secret, ok := parseToken(p.Token)
	subject := "token #" + strconv.FormatInt(id, 10)
	if err := m.audit.Audit(ctx, actor, "auth.token.login", subject, "attempt"); err != nil {
		return LoggedIn{}, err
	}
	var t Token
	var u User
	err := ErrBadLogin
	if ok {
		if t, err = m.store.Token(ctx, id); err == nil {
			u, err = m.store.UserByID(ctx, t.UserID)
		}
	}
	now := m.now().Unix()
	good := err == nil && sameHash(hashCode(secret), t.Hash) && t.RevokedAt == 0 && now < t.ExpiresAt && u.DisabledAt == 0
	if !good {
		m.tokenFailed(ctx)
		_ = m.audit.Audit(ctx, actor, "auth.token.login", subject, "failed")
		return LoggedIn{}, ErrBadLogin // an unknown id answers as a wrong secret (M5)
	}
	m.touch(ctx, t.ID, now)
	_ = m.audit.Audit(ctx, actor, "auth.token.login", subject, "ok")
	return LoggedIn{User: "token " + t.Name + " of " + u.Name, Principal: "token:" + strconv.FormatInt(t.ID, 10), Role: Effective(u.Role, t.Role)}, nil
}

// tokenBurst is how many failed token logins in a minute raise an alarm.
const tokenBurst = 20

func (m *Module) tokenFailed(ctx context.Context) {
	now := m.now().Unix()
	m.mu.Lock()
	keep := m.tokFail[:0]
	for _, t := range m.tokFail {
		if now-t < 60 {
			keep = append(keep, t)
		}
	}
	m.tokFail = append(keep, now)
	n := len(m.tokFail)
	m.mu.Unlock()
	if n == tokenBurst {
		m.audited(ctx, "auth.token.burst", "tokens", strconv.Itoa(n)+" failed token logins in a minute")
	}
}

// parseToken splits apt_<id>_<secret>.
func parseToken(s string) (int64, string, bool) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(s), "apt_")
	if !ok {
		return 0, "", false
	}
	idText, secret, ok := strings.Cut(rest, "_")
	id, err := strconv.ParseInt(idText, 10, 64)
	if !ok || err != nil || id <= 0 || len(secret) < 32 {
		return 0, "", false
	}
	return id, secret, true
}

// Status is auth.status's answer.
type Status struct {
	VaultLocked bool `json:"vault_locked"`
}

func (m *Module) status(context.Context, struct{}) (Status, error) {
	return Status{VaultLocked: !m.vault.Unlocked()}, nil
}

// Whoami is auth.whoami's answer.
type Whoami struct {
	User        string `json:"user"`
	Role        Role   `json:"role"`
	By          string `json:"by"` // "passphrase" or "token"
	TOTP        bool   `json:"totp"`
	MustChange  bool   `json:"must_change"`
	VaultLocked bool   `json:"vault_locked"`
	Root        bool   `json:"root"`
}

func (m *Module) whoami(ctx context.Context, _ struct{}) (Whoami, error) {
	u, t, err := m.caller(ctx)
	if err != nil {
		return Whoami{}, err
	}
	w := Whoami{User: u.Name, Role: u.Role, By: "passphrase", TOTP: u.TOTP, MustChange: u.MustChange, VaultLocked: !m.vault.Unlocked(), Root: u.Root}
	if t != nil {
		w.By, w.Role = "token", Effective(u.Role, t.Role)
	}
	return w, nil
}

// --- users ----------------------------------------------------------------------

// UserView is a user in auth.user.list.
type UserView struct {
	Name        string `json:"name"`
	Role        Role   `json:"role"`
	Root        bool   `json:"root"`
	TOTP        bool   `json:"totp"`
	Disabled    bool   `json:"disabled"`
	LockedUntil int64  `json:"locked_until"`
	LastLoginAt int64  `json:"last_login_at"`
	MustChange  bool   `json:"must_change"`
}

func (m *Module) userList(ctx context.Context, _ struct{}) ([]UserView, error) {
	us, err := m.store.Users(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]UserView, 0, len(us))
	for _, u := range us {
		out = append(out, UserView{Name: u.Name, Role: u.Role, Root: u.Root, TOTP: u.TOTP, Disabled: u.DisabledAt != 0,
			LockedUntil: u.LockedUntil, LastLoginAt: u.LastLoginAt, MustChange: u.MustChange})
	}
	return out, nil
}

// UserAsk names a user, and what to set.
type UserAsk struct {
	Name       string `json:"name"`
	Role       Role   `json:"role"`
	Passphrase string `json:"passphrase"`
	Disabled   bool   `json:"disabled"`
}

func (m *Module) userAdd(ctx context.Context, p UserAsk) (UserView, error) {
	switch {
	case !ValidName(p.Name):
		return UserView{}, ErrBadName
	case !p.Role.Valid():
		return UserView{}, ErrBadRole
	case m.weak(p.Name, p.Passphrase):
		return UserView{}, ErrWeak
	}
	slot, ver, err := m.loginOf(p.Role, p.Passphrase)
	if err != nil {
		return UserView{}, err
	}
	u, err := m.store.AddUser(ctx, p.Name, p.Role, slot, ver, true)
	if err != nil {
		return UserView{}, err
	}
	return UserView{Name: u.Name, Role: u.Role, MustChange: true}, nil
}

func (m *Module) named(ctx context.Context, name string) (User, error) {
	return m.store.User(ctx, name)
}

// userRole changes a role with a reset passphrase (M1): to admin seals a slot
// under it, from admin drops the slot and sets a verifier from it.
func (m *Module) userRole(ctx context.Context, p UserAsk) (struct{}, error) {
	u, err := m.named(ctx, p.Name)
	if err != nil {
		return struct{}{}, err
	}
	switch {
	case !p.Role.Valid():
		return struct{}{}, ErrBadRole
	case u.Root:
		return struct{}{}, ErrRootUser
	case m.weak(u.Name, p.Passphrase):
		return struct{}{}, ErrWeak
	}
	slot, ver, err := m.loginOf(p.Role, p.Passphrase)
	if err != nil {
		return struct{}{}, err
	}
	return struct{}{}, m.store.SetLogin(ctx, u.ID, p.Role, slot, ver, true)
}

func (m *Module) userReset(ctx context.Context, p UserAsk) (struct{}, error) {
	u, err := m.named(ctx, p.Name)
	if err != nil {
		return struct{}{}, err
	}
	if m.weak(u.Name, p.Passphrase) {
		return struct{}{}, ErrWeak
	}
	slot, ver, err := m.loginOf(u.Role, p.Passphrase)
	if err != nil {
		return struct{}{}, err
	}
	return struct{}{}, m.store.SetLogin(ctx, u.ID, u.Role, slot, ver, true)
}

func (m *Module) userDisable(ctx context.Context, p UserAsk) (struct{}, error) {
	u, err := m.named(ctx, p.Name)
	if err != nil {
		return struct{}{}, err
	}
	return struct{}{}, m.store.SetDisabled(ctx, u.ID, p.Disabled)
}

func (m *Module) userUnlock(ctx context.Context, p UserAsk) (struct{}, error) {
	u, err := m.named(ctx, p.Name)
	if err != nil {
		return struct{}{}, err
	}
	m.cleared(u.Name)
	return struct{}{}, m.store.ClearLock(ctx, u.ID)
}

func (m *Module) userRemove(ctx context.Context, p UserAsk) (struct{}, error) {
	u, err := m.named(ctx, p.Name)
	if err != nil {
		return struct{}{}, err
	}
	return struct{}{}, m.store.RemoveUser(ctx, u.ID)
}

// PassphraseAsk is auth.passphrase.change's param.
type PassphraseAsk struct {
	Old string `json:"old"`
	New string `json:"new"`
}

// passphraseChange re-seals an admin's slot under the new passphrase (with the
// master key its old one opens: no open vault needed), or replaces a
// verifier; must_change is cleared.
func (m *Module) passphraseChange(ctx context.Context, p PassphraseAsk) (struct{}, error) {
	u, t, err := m.caller(ctx)
	if err != nil {
		return struct{}{}, err
	}
	if t != nil {
		return struct{}{}, ErrForbidden
	}
	mk, ok, err := m.checkPassphrase(ctx, u, p.Old)
	defer clear(mk)
	if err != nil {
		return struct{}{}, err
	}
	if !ok {
		return struct{}{}, ErrBadLogin
	}
	if m.weak(u.Name, p.New) || p.New == p.Old {
		return struct{}{}, ErrWeak
	}
	if u.Role == RoleAdmin {
		var slot keyslot.PassphraseSlot
		if err := m.derive(ctx, func() { slot, err = keyslot.SealPassphrase(mk, p.New, m.params) }); err != nil {
			return struct{}{}, err
		}
		if err != nil {
			return struct{}{}, err
		}
		return struct{}{}, m.store.SetLogin(ctx, u.ID, u.Role, &slot, "", false)
	}
	ver, err := m.hasher.Hash(p.New)
	if err != nil {
		return struct{}{}, err
	}
	return struct{}{}, m.store.SetLogin(ctx, u.ID, u.Role, nil, ver, false)
}

// --- the second factor ------------------------------------------------------------

func totpSecret(id int64) string        { return "auth/totp/" + strconv.FormatInt(id, 10) }         // L3: bound to the user's id
func totpPendingSecret(id int64) string { return "auth/totp-pending/" + strconv.FormatInt(id, 10) } // until a code confirms it

// Enrol is auth.totp.begin's answer: the seed, shown once.
type Enrol struct {
	Secret string `json:"secret"` // base32, in groups of four
	URI    string `json:"uri"`    // otpauth://totp/…
}

func (m *Module) totpBegin(ctx context.Context, _ struct{}) (Enrol, error) {
	u, t, err := m.caller(ctx)
	if err != nil {
		return Enrol{}, err
	}
	if t != nil {
		return Enrol{}, ErrForbidden
	}
	if u.TOTP {
		return Enrol{}, ErrTOTPAlready
	}
	seed, err := totpNewSeed()
	if err != nil {
		return Enrol{}, err
	}
	defer clear(seed)
	if err := m.secrets.PutSecret(ctx, m.vault, totpPendingSecret(u.ID), seed); err != nil {
		if errors.Is(err, keyslot.ErrLocked) {
			return Enrol{}, ErrVaultLocked
		}
		return Enrol{}, err
	}
	return Enrol{Secret: groups(totpEncode(seed)), URI: totpURI("AutoPanel", u.Name, seed)}, nil
}

func groups(s string) string {
	var b strings.Builder
	for i, r := range s {
		if i > 0 && i%4 == 0 {
			b.WriteByte(' ')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// CodeAsk carries a two-factor code.
type CodeAsk struct {
	Code string `json:"code"`
	Name string `json:"name"`
}

// Recovery is auth.totp.confirm's answer: the codes, shown once.
type Recovery struct {
	Recovery []string `json:"recovery"`
}

func (m *Module) totpConfirm(ctx context.Context, p CodeAsk) (Recovery, error) {
	u, t, err := m.caller(ctx)
	if err != nil {
		return Recovery{}, err
	}
	if t != nil {
		return Recovery{}, ErrForbidden
	}
	seed, err := m.secrets.Secret(ctx, m.vault, totpPendingSecret(u.ID))
	defer clear(seed)
	if err != nil {
		if errors.Is(err, keyslot.ErrLocked) {
			return Recovery{}, ErrVaultLocked
		}
		return Recovery{}, ErrNoTOTP
	}
	if _, ok := totpVerify(seed, p.Code, m.now(), 0); !ok {
		return Recovery{}, ErrBadCode
	}
	codes, err := totpRecoveryCodes(10)
	if err != nil {
		return Recovery{}, err
	}
	hashes := make([][]byte, len(codes))
	for i, c := range codes {
		hashes[i] = hashCode(totpNormRecovery(c))
	}
	if err := m.secrets.PutSecret(ctx, m.vault, totpSecret(u.ID), seed); err != nil {
		return Recovery{}, err
	}
	_ = m.secrets.DeleteSecret(ctx, totpPendingSecret(u.ID))
	if err := m.store.SetTOTP(ctx, u.ID, true, hashes); err != nil {
		return Recovery{}, err
	}
	return Recovery{Recovery: codes}, nil
}

func (m *Module) totpDisable(ctx context.Context, p CodeAsk) (struct{}, error) {
	u, t, err := m.caller(ctx)
	if err != nil {
		return struct{}{}, err
	}
	if t != nil {
		return struct{}{}, ErrForbidden
	}
	target := u
	if p.Name != "" && p.Name != u.Name { // an admin, for another user (after a reset)
		if u.Role != RoleAdmin {
			return struct{}{}, ErrForbidden
		}
		if target, err = m.named(ctx, p.Name); err != nil {
			return struct{}{}, err
		}
	} else {
		if !u.TOTP {
			return struct{}{}, ErrNoTOTP
		}
		seed, err := m.secrets.Secret(ctx, m.vault, totpSecret(u.ID))
		defer clear(seed)
		if err != nil {
			if errors.Is(err, keyslot.ErrLocked) {
				return struct{}{}, ErrVaultLocked
			}
			return struct{}{}, err
		}
		if _, ok := totpVerify(seed, p.Code, m.now(), u.TOTPLastStep); !ok {
			return struct{}{}, ErrBadCode
		}
	}
	_ = m.secrets.DeleteSecret(ctx, totpSecret(target.ID))
	return struct{}{}, m.store.SetTOTP(ctx, target.ID, false, nil)
}

// --- tokens -------------------------------------------------------------------------

// TokenView is a token in auth.token.list: never its secret.
type TokenView struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	Role       Role   `json:"role"`
	Owner      string `json:"owner"`
	CreatedAt  int64  `json:"created_at"`
	ExpiresAt  int64  `json:"expires_at"`
	LastUsedAt int64  `json:"last_used_at"`
	Revoked    bool   `json:"revoked"`
}

func (m *Module) tokenList(ctx context.Context, _ struct{}) ([]TokenView, error) {
	u, _, err := m.caller(ctx)
	if err != nil {
		return nil, err
	}
	of := u.ID
	if u.Role == RoleAdmin {
		of = 0
	}
	ts, err := m.store.Tokens(ctx, of)
	if err != nil {
		return nil, err
	}
	out := make([]TokenView, 0, len(ts))
	for _, t := range ts {
		out = append(out, TokenView{ID: t.ID, Name: t.Name, Role: t.Role, Owner: t.Owner, CreatedAt: t.CreatedAt,
			ExpiresAt: t.ExpiresAt, LastUsedAt: t.LastUsedAt, Revoked: t.RevokedAt != 0})
	}
	return out, nil
}

// TokenAsk is auth.token.create's param, and revoke's.
type TokenAsk struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	Role Role   `json:"role"`
	Days int    `json:"days"`
}

// NewToken is a token, shown once.
type NewToken struct {
	ID        int64  `json:"id"`
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"`
}

const base62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// newSecret is 43 base62 characters: more than 256 random bits.
func newSecret() (string, error) {
	b := make([]byte, 43)
	max := big.NewInt(int64(len(base62)))
	for i := range b {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		b[i] = base62[n.Int64()]
	}
	return string(b), nil
}

func (m *Module) tokenCreate(ctx context.Context, p TokenAsk) (NewToken, error) {
	u, t, err := m.caller(ctx)
	if err != nil {
		return NewToken{}, err
	}
	if t != nil {
		return NewToken{}, ErrForbidden
	}
	role := p.Role
	if role == "" {
		role = RoleViewer // L2: an admin token only when asked for
	}
	days := p.Days
	if days == 0 {
		days = 90
	}
	name := strings.TrimSpace(p.Name)
	if !role.Valid() || !u.Role.holds(role) || days < 1 || days > 365 || name == "" || len(name) > 64 {
		return NewToken{}, ErrBadTokenAsk
	}
	secret, err := newSecret()
	if err != nil {
		return NewToken{}, err
	}
	now := m.now()
	exp := now.Add(time.Duration(days) * 24 * time.Hour).Unix()
	id, err := m.store.AddToken(ctx, Token{UserID: u.ID, Name: name, Hash: hashCode(secret), Role: role, CreatedAt: now.Unix(), ExpiresAt: exp})
	if err != nil {
		return NewToken{}, err
	}
	return NewToken{ID: id, Token: "apt_" + strconv.FormatInt(id, 10) + "_" + secret, ExpiresAt: exp}, nil
}

func (m *Module) tokenRevoke(ctx context.Context, p TokenAsk) (struct{}, error) {
	u, _, err := m.caller(ctx)
	if err != nil {
		return struct{}{}, err
	}
	t, err := m.store.Token(ctx, p.ID)
	if err != nil {
		return struct{}{}, err
	}
	if t.UserID != u.ID && u.Role != RoleAdmin {
		return struct{}{}, ErrNotOwn
	}
	return struct{}{}, m.store.RevokeToken(ctx, t.ID)
}
