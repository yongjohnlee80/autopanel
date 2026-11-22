package auth_test

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yongjohnlee80/golib/auth/totp"

	"github.com/yongjohnlee80/autopanel/internal/auth"
	"github.com/yongjohnlee80/autopanel/internal/auth/authtest"
	"github.com/yongjohnlee80/autopanel/internal/keyslot"
	"github.com/yongjohnlee80/autopanel/internal/module"
)

var cheap = keyslot.Params{Time: 1, MemKiB: 8, Threads: 1}

const rootPass = "a long master passphrase"

type nopAudit struct {
	mu      sync.Mutex
	entries []string
}

func (a *nopAudit) Audit(_ context.Context, actor, action, subject, detail string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, action+" "+subject+" "+detail)
	return nil
}

type fixture struct {
	m     *auth.Module
	store *authtest.Store
	vault *keyslot.Vault
	clock *time.Time
	aud   *nopAudit
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	mk, _ := keyslot.NewMasterKey()
	slot, err := keyslot.SealPassphrase(mk, rootPass, cheap)
	if err != nil {
		t.Fatal(err)
	}
	st := authtest.New("root", slot)
	vault := &keyslot.Vault{}
	aud := &nopAudit{}
	m, err := auth.New(st, authtest.NewSecrets(), aud, vault, nil, cheap)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	auth.SetClock(m, func() time.Time { return clock })
	return fixture{m: m, store: st, vault: vault, clock: &clock, aud: aud}
}

// call runs a verb of the module as principal.
func (f fixture) call(t *testing.T, principal, verb string, param any, out any) error {
	t.Helper()
	for _, v := range f.m.Verbs() {
		if v.Verb != verb {
			continue
		}
		ctx := module.WithPrincipal(context.Background(), principal)
		var params []any
		if param != nil {
			params = []any{toMap(param)}
		}
		res, err := v.Call(ctx, params)
		if err == nil && out != nil {
			fromMap(t, res, out)
		}
		return err
	}
	t.Fatalf("no verb %s", verb)
	return nil
}

func (f fixture) login(t *testing.T, user, pass, code string) (auth.LoggedIn, error) {
	t.Helper()
	var in auth.LoggedIn
	err := f.call(t, "", "auth.login", auth.Login{User: user, Passphrase: pass, Code: code}, &in)
	return in, err
}

func TestALoginFailsTheSameWhateverFailed(t *testing.T) {
	f := newFixture(t)
	for _, c := range [][3]string{{"root", "wrong passphrase", ""}, {"nobody", rootPass, ""}, {"root", rootPass, "123456"}} {
		*f.clock = f.clock.Add(2 * time.Minute) // past each wait
		if _, err := f.login(t, c[0], c[1], c[2]); !errors.Is(err, auth.ErrBadLogin) {
			t.Fatalf("%v: %v; want the one bad_login", c, err)
		}
	}
	*f.clock = f.clock.Add(2 * time.Minute)
	in, err := f.login(t, "root", rootPass, "")
	if err != nil || in.Principal != "user:1" || !in.Unlocked || !f.vault.Unlocked() {
		t.Fatalf("root's login = %+v, %v", in, err)
	}
}

func TestTenFailuresLockAndAnUnknownNameAlike(t *testing.T) {
	f := newFixture(t)
	if err := f.call(t, "", "auth.login", auth.Login{User: "root", Passphrase: rootPass}, nil); err != nil {
		t.Fatal(err)
	}
	var u auth.UserView
	if err := f.call(t, "user:1", "auth.user.add", auth.UserAsk{Name: "ana", Role: auth.RoleOperator, Passphrase: "a fine long passphrase 1"}, &u); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < auth.LockAfter; i++ {
		*f.clock = f.clock.Add(2 * time.Minute)
		_, _ = f.login(t, "ana", "wrong one", "")
		_, _ = f.login(t, "ghost", "wrong one", "")
	}
	*f.clock = f.clock.Add(2 * time.Minute)
	if _, err := f.login(t, "ana", "a fine long passphrase 1", ""); !errors.Is(err, auth.ErrThrottled) {
		t.Fatalf("a locked account with its right passphrase: %v; want throttled", err)
	}
	if _, err := f.login(t, "ghost", "anything at all", ""); !errors.Is(err, auth.ErrThrottled) {
		t.Fatalf("an unknown name tried as often: %v; want throttled, as a locked account (M5)", err)
	}
	*f.clock = f.clock.Add(auth.LockFor + time.Minute)
	if _, err := f.login(t, "ana", "a fine long passphrase 1", ""); err != nil {
		t.Fatalf("after the lock: %v", err)
	}
	// Root on the console is slowed, never locked.
	for i := 0; i < auth.LockAfter+2; i++ {
		*f.clock = f.clock.Add(2 * time.Minute)
		_, _ = f.login(t, "root", "wrong", "")
	}
	*f.clock = f.clock.Add(2 * time.Minute)
	if _, err := f.login(t, "root", rootPass, ""); err != nil {
		t.Fatalf("root after many failures: %v; root is never locked out", err)
	}
}

func TestTheSecondFactor(t *testing.T) {
	f := newFixture(t)
	if _, err := f.login(t, "root", rootPass, ""); err != nil {
		t.Fatal(err)
	}
	var e auth.Enrol
	if err := f.call(t, "user:1", "auth.totp.begin", nil, &e); err != nil {
		t.Fatal(err)
	}
	seed, err := totp.Decode(strings.ReplaceAll(e.Secret, " ", ""))
	if err != nil || !strings.HasPrefix(e.URI, "otpauth://totp/") {
		t.Fatalf("enrol: %+v, %v", e, err)
	}
	if err := f.call(t, "user:1", "auth.totp.confirm", auth.CodeAsk{Code: "000000"}, nil); !errors.Is(err, auth.ErrBadCode) && err != nil {
		t.Logf("a wrong code at confirm: %v", err)
	}
	var rec auth.Recovery
	if err := f.call(t, "user:1", "auth.totp.confirm", auth.CodeAsk{Code: totp.Code(seed, *f.clock)}, &rec); err != nil || len(rec.Recovery) != 10 {
		t.Fatalf("confirm: %d codes, %v", len(rec.Recovery), err)
	}

	// A fresh core: the vault is locked again.
	f2 := f
	f2.vault = &keyslot.Vault{}
	m2, err := auth.New(f.store, authtestSecrets(f), f.aud, f2.vault, nil, cheap)
	if err != nil {
		t.Fatal(err)
	}
	auth.SetClock(m2, func() time.Time { return *f.clock })
	f2.m = m2
	*f.clock = f.clock.Add(time.Minute)
	if _, err := f2.login(t, "root", rootPass, ""); !errors.Is(err, auth.ErrBadLogin) {
		t.Fatalf("the right passphrase without the code: %v; want bad_login (H1)", err)
	}
	if f2.vault.Unlocked() {
		t.Fatal("a passphrase without its code unlocked the vault (H2)")
	}
	*f.clock = f.clock.Add(2 * time.Minute)
	code := totp.Code(seed, *f.clock)
	if _, err := f2.login(t, "root", rootPass, code); err != nil || !f2.vault.Unlocked() {
		t.Fatalf("passphrase and code: %v", err)
	}
	if _, err := f2.login(t, "root", rootPass, code); !errors.Is(err, auth.ErrBadLogin) {
		t.Fatalf("the same code again: %v; want refused (used once)", err)
	}
	*f.clock = f.clock.Add(2 * time.Minute)
	if _, err := f2.login(t, "root", rootPass, rec.Recovery[0]); err != nil {
		t.Fatalf("a recovery code: %v", err)
	}
	*f.clock = f.clock.Add(2 * time.Minute)
	if _, err := f2.login(t, "root", rootPass, rec.Recovery[0]); !errors.Is(err, auth.ErrBadLogin) {
		t.Fatalf("a recovery code twice: %v", err)
	}
}

// authtestSecrets is the fixture's secrets, shared by a second module.
func authtestSecrets(f fixture) auth.Secrets { return auth.SecretsOf(f.m) }

func TestRolesAndTheAuthorizer(t *testing.T) {
	f := newFixture(t)
	if _, err := f.login(t, "root", rootPass, ""); err != nil {
		t.Fatal(err)
	}
	for _, u := range []auth.UserAsk{{Name: "vic", Role: auth.RoleViewer}, {Name: "mo", Role: auth.RoleMail}, {Name: "op", Role: auth.RoleOperator}} {
		u.Passphrase = "a fine long passphrase for " + strings.ToUpper(u.Name[:1]) + "x" + u.Name[1:]
		if err := f.call(t, "user:1", "auth.user.add", u, nil); err != nil {
			t.Fatal(err)
		}
	}
	ids := map[string]string{}
	us, _ := f.store.Users(context.Background())
	for _, u := range us {
		ids[u.Name] = "user:" + strconv.FormatInt(u.ID, 10)
	}
	authz := func(who string, c module.Contract) error {
		_, err := f.m.Authorize(context.Background(), ids[who], time.Time{}, c)
		return err
	}
	// A new user must change its passphrase first (M2).
	if err := authz("vic", module.Contract{Verb: "gate.route.list", Discloses: module.Plain}); !errors.Is(err, auth.ErrMustChange) {
		t.Fatalf("a user with must_change: %v", err)
	}
	for _, n := range []string{"vic", "mo", "op"} {
		if err := f.call(t, ids[n], "auth.passphrase.change", auth.PassphraseAsk{Old: "a fine long passphrase for " + strings.ToUpper(n[:1]) + "x" + n[1:], New: "another long passphrase, number " + strconv.Itoa(len(n))}, nil); err != nil {
			t.Fatalf("%s changing its passphrase: %v", n, err)
		}
	}
	for _, c := range []struct {
		who  string
		c    module.Contract
		want bool
	}{
		{"vic", module.Contract{Verb: "gate.route.list", Discloses: module.Plain}, true},
		{"vic", module.Contract{Verb: "gate.route.add", Mutates: true}, false},
		{"vic", module.Contract{Verb: "services.logs"}, false}, // Sensitive by default (H3)
		{"op", module.Contract{Verb: "services.logs"}, true},
		{"op", module.Contract{Verb: "sys.gate.stop", Area: "sys.admin", Mutates: true}, false},
		{"op", module.Contract{Verb: "auth.user.add", Mutates: true}, false},
		{"mo", module.Contract{Verb: "mail.account.add", Mutates: true}, true},
		{"mo", module.Contract{Verb: "mail.setup", Area: "mail.admin", Mutates: true}, false},
		{"mo", module.Contract{Verb: "services.list", Discloses: module.Plain}, false},
		{"mo", module.Contract{Verb: "auth.token.create", Mutates: true}, true},
	} {
		if err := authz(c.who, c.c); (err == nil) != c.want {
			t.Errorf("%s calling %s: %v; want allowed %v", c.who, c.c.Verb, err, c.want)
		}
	}
	// A disable takes effect at the next call (R1).
	if err := f.call(t, "user:1", "auth.user.disable", auth.UserAsk{Name: "op", Disabled: true}, nil); err != nil {
		t.Fatal(err)
	}
	if err := authz("op", module.Contract{Verb: "gate.route.list", Discloses: module.Plain}); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("a disabled user's next call: %v", err)
	}
	// A session past its limit (D6).
	if _, err := f.m.Authorize(context.Background(), "user:1", f.clock.Add(-auth.SessionMax-time.Minute), module.Contract{Verb: "sys.status"}); !errors.Is(err, auth.ErrExpired) {
		t.Fatalf("an old session: %v", err)
	}
}

func TestTheLastAdminAndRoot(t *testing.T) {
	f := newFixture(t)
	if _, err := f.login(t, "root", rootPass, ""); err != nil {
		t.Fatal(err)
	}
	if err := f.call(t, "user:1", "auth.user.role", auth.UserAsk{Name: "root", Role: auth.RoleViewer, Passphrase: "a reset passphrase here"}, nil); !errors.Is(err, auth.ErrRootUser) {
		t.Fatalf("demoting root: %v", err)
	}
	if err := f.call(t, "user:1", "auth.user.add", auth.UserAsk{Name: "ada", Role: auth.RoleAdmin, Passphrase: "short"}, nil); !errors.Is(err, auth.ErrWeak) {
		t.Fatalf("a weak passphrase: %v", err)
	}
	if err := f.call(t, "user:1", "auth.user.add", auth.UserAsk{Name: "ada", Role: auth.RoleAdmin, Passphrase: "unbelievable"}, nil); !errors.Is(err, auth.ErrWeak) {
		t.Fatalf("a common passphrase: %v", err)
	}
	if err := f.call(t, "user:1", "auth.user.add", auth.UserAsk{Name: "ada", Role: auth.RoleAdmin, Passphrase: "ada has a long passphrase"}, nil); !errors.Is(err, auth.ErrWeak) {
		t.Fatalf("a passphrase with the name in it: %v", err)
	}
	if err := f.call(t, "user:1", "auth.user.add", auth.UserAsk{Name: "ada", Role: auth.RoleAdmin, Passphrase: "a reset passphrase here"}, nil); err != nil {
		t.Fatal(err)
	}
	// Ada logs in with her slot, and must change it; her new one re-seals the slot.
	*f.clock = f.clock.Add(time.Minute)
	in, err := f.login(t, "ada", "a reset passphrase here", "")
	if err != nil || !in.MustChange || in.Role != auth.RoleAdmin {
		t.Fatalf("ada's first login: %+v, %v", in, err)
	}
	if err := f.call(t, in.Principal, "auth.passphrase.change", auth.PassphraseAsk{Old: "a reset passphrase here", New: "her very own passphrase"}, nil); err != nil {
		t.Fatal(err)
	}
	*f.clock = f.clock.Add(time.Minute)
	if _, err := f.login(t, "ada", "her very own passphrase", ""); err != nil {
		t.Fatalf("ada with her own passphrase: %v", err)
	}
	// Demoting ada drops her slot; she is a verifier user now.
	if err := f.call(t, "user:1", "auth.user.role", auth.UserAsk{Name: "ada", Role: auth.RoleViewer, Passphrase: "a second reset passphrase"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.PassphraseSlot(context.Background(), "ada"); err == nil {
		t.Fatal("a demoted admin kept a key slot")
	}
}

func TestTokens(t *testing.T) {
	f := newFixture(t)
	if _, err := f.login(t, "root", rootPass, ""); err != nil {
		t.Fatal(err)
	}
	var nt auth.NewToken
	if err := f.call(t, "user:1", "auth.token.create", auth.TokenAsk{Name: "backup"}, &nt); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(nt.Token, "apt_1_") || nt.ExpiresAt != f.clock.Add(90*24*time.Hour).Unix() {
		t.Fatalf("a new token: %+v", nt)
	}
	var in auth.LoggedIn
	if err := f.call(t, "", "auth.token.login", auth.TokenLogin{Token: nt.Token}, &in); err != nil || in.Role != auth.RoleViewer {
		t.Fatalf("a token login: %+v, %v; want viewer unless asked (L2)", in, err)
	}
	if _, err := f.m.Authorize(context.Background(), in.Principal, time.Time{}, module.Contract{Verb: "auth.token.create", Mutates: true}); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("a token making a token: %v", err)
	}
	if err := f.call(t, "", "auth.token.login", auth.TokenLogin{Token: wrongSecret(nt.Token)}, nil); !errors.Is(err, auth.ErrBadLogin) {
		t.Fatalf("a wrong secret: %v", err)
	}
	if err := f.call(t, "", "auth.token.login", auth.TokenLogin{Token: "apt_99_" + strings.Repeat("a", 43)}, nil); !errors.Is(err, auth.ErrBadLogin) {
		t.Fatalf("an unknown id: %v; want as a wrong secret", err)
	}
	if err := f.call(t, "user:1", "auth.token.create", auth.TokenAsk{Name: "x", Days: 400}, nil); !errors.Is(err, auth.ErrBadTokenAsk) {
		t.Fatalf("a token past a year: %v", err)
	}
	if err := f.call(t, "user:1", "auth.token.revoke", auth.TokenAsk{ID: nt.ID}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.Authorize(context.Background(), in.Principal, time.Time{}, module.Contract{Verb: "sys.status", Discloses: module.Plain}); !errors.Is(err, auth.ErrExpired) {
		t.Fatalf("a revoked token's next call: %v", err)
	}
}

func toMap(v any) any { return v }

func fromMap(t *testing.T, res any, out any) {
	t.Helper()
	if err := module.Decode(res, out); err != nil {
		t.Fatal(err)
	}
}

// TestTheCallerAndAUserByNameOrID covers what another module asks of this
// one: who a verb runs for, read from the store now, and a user by name or id.
func TestTheCallerAndAUserByNameOrID(t *testing.T) {
	f := newFixture(t)
	if _, err := f.login(t, "root", rootPass, ""); err != nil {
		t.Fatal(err)
	}
	if err := f.call(t, "user:1", "auth.user.add", auth.UserAsk{Name: "ada", Role: auth.RoleViewer, Passphrase: "a reset passphrase here"}, nil); err != nil {
		t.Fatal(err)
	}
	ada, err := f.m.UserNamed(context.Background(), "ada")
	if err != nil || ada.Name != "ada" {
		t.Fatalf("UserNamed = %+v, %v", ada, err)
	}
	if u, err := f.m.UserByID(context.Background(), ada.ID); err != nil || u.Name != "ada" {
		t.Fatalf("UserByID = %+v, %v", u, err)
	}
	if _, err := f.m.UserNamed(context.Background(), "nobody"); !errors.Is(err, auth.ErrNoUser) {
		t.Fatalf("a name no user has: %v", err)
	}

	as := module.WithPrincipal(context.Background(), fmt.Sprintf("user:%d", ada.ID))
	if u, err := f.m.Caller(as); err != nil || u.Name != "ada" {
		t.Fatalf("Caller = %+v, %v", u, err)
	}
	if _, err := f.m.Caller(context.Background()); err == nil {
		t.Fatal("a call with no principal has a caller")
	}
	if err := f.call(t, "user:1", "auth.user.disable", auth.UserAsk{Name: "ada", Disabled: true}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.Caller(as); !errors.Is(err, auth.ErrExpired) {
		t.Fatalf("a disabled user as the caller: %v", err)
	}
}
