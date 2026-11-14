package ui

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/yongjohnlee80/golib/tui/decl/decltest"

	"github.com/yongjohnlee80/autopanel/internal/auth"
)

// fakeAccount is the daemon's users, two-factor and tokens, in memory.
type fakeAccount struct {
	user        string      // who logged in
	code        string      // the code Login wants: "" without two-factor
	me          auth.Whoami // what Whoami answers (its user is who logged in)
	vaultLocked bool
	users       []auth.UserView
	tokens      []auth.TokenView
	asks        []string // "add bo viewer", "remove ana", "revoke 1", "totp on", …
	passes      []string // the passphrases that reached the daemon; never shown
}

func (a *fakeAccount) role() auth.Role {
	if a.me.Role == "" {
		return auth.RoleAdmin
	}
	return a.me.Role
}

// The code the fake's authenticator app shows, and the recovery codes.
const (
	totpCode     = "123456"
	recoveryCode = "k7qd-2mxe-pv9a"
	tokenSecret  = "apt_7_Q2hlY2tUaGlzSXNOb3RBUmVhbFRva2VuQXRBbGw"
)

func (f *fakeClient) VaultLocked(context.Context) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.acct.vaultLocked, nil
}

func (f *fakeClient) Whoami(context.Context) (auth.Whoami, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w := f.acct.me
	w.User, w.Role = f.acct.user, f.acct.role()
	return w, nil
}

func (f *fakeClient) ask(s string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.acct.asks = append(f.acct.asks, s)
}

func (f *fakeClient) accountAsked() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.acct.asks...)
}

func (f *fakeClient) Users(context.Context) ([]auth.UserView, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]auth.UserView(nil), f.acct.users...), nil
}

func (f *fakeClient) UserAdd(_ context.Context, name, role, pass string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.acct.asks = append(f.acct.asks, "add "+name+" "+role)
	f.acct.passes = append(f.acct.passes, pass)
	f.acct.users = append(f.acct.users, auth.UserView{Name: name, Role: auth.Role(role), MustChange: true})
	return nil
}

func (f *fakeClient) UserRole(_ context.Context, name, role, pass string) error {
	f.ask("role " + name + " " + role)
	return nil
}

func (f *fakeClient) UserReset(_ context.Context, name, pass string) error {
	f.ask("reset " + name)
	return nil
}

func (f *fakeClient) UserDisable(_ context.Context, name string, disabled bool) error {
	f.ask(map[bool]string{true: "disable ", false: "enable "}[disabled] + name)
	return nil
}

func (f *fakeClient) UserUnlock(_ context.Context, name string) error {
	f.ask("unlock " + name)
	return nil
}

func (f *fakeClient) UserRemove(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.acct.asks = append(f.acct.asks, "remove "+name)
	for i, u := range f.acct.users {
		if u.Name == name {
			f.acct.users = append(f.acct.users[:i], f.acct.users[i+1:]...)
			break
		}
	}
	return nil
}

func (f *fakeClient) PassphraseChange(_ context.Context, old, pass string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if old != passphrase {
		return auth.ErrBadLogin
	}
	f.acct.passes = append(f.acct.passes, pass)
	f.acct.me.MustChange = false
	return nil
}

func (f *fakeClient) TOTPBegin(context.Context) (auth.Enrol, error) {
	f.ask("totp begin")
	return auth.Enrol{Secret: "JBSW Y3DP EHPK 3PXP", URI: "otpauth://totp/AutoPanel:root?secret=JBSWY3DPEHPK3PXP&issuer=AutoPanel"}, nil
}

func (f *fakeClient) TOTPConfirm(_ context.Context, code string) (auth.Recovery, error) {
	if code != totpCode {
		return auth.Recovery{}, auth.ErrBadCode
	}
	f.ask("totp on")
	return auth.Recovery{Recovery: []string{recoveryCode, "w3nf-8hzc-r4ty"}}, nil
}

func (f *fakeClient) TOTPDisable(_ context.Context, code string) error {
	if code != totpCode {
		return auth.ErrBadCode
	}
	f.ask("totp off")
	return nil
}

func (f *fakeClient) Tokens(context.Context) ([]auth.TokenView, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]auth.TokenView(nil), f.acct.tokens...), nil
}

func (f *fakeClient) TokenCreate(_ context.Context, name, role string, days int) (auth.NewToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.acct.asks = append(f.acct.asks, "token "+name+" "+role)
	exp := time.Now().AddDate(0, 0, days).Unix()
	f.acct.tokens = append(f.acct.tokens, auth.TokenView{ID: 7, Name: name, Role: auth.Role(role), Owner: f.acct.user, ExpiresAt: exp})
	return auth.NewToken{ID: 7, Token: tokenSecret, ExpiresAt: exp}, nil
}

func (f *fakeClient) TokenRevoke(_ context.Context, id int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.acct.tokens {
		if f.acct.tokens[i].ID == id {
			f.acct.tokens[i].Revoked = true
			f.acct.asks = append(f.acct.asks, "revoke "+f.acct.tokens[i].Name)
			return nil
		}
	}
	return auth.ErrNoToken
}

// withUsers is a client with root and two more users.
func withUsers() *fakeClient {
	f := newFakeClient()
	f.acct.me.Root = true
	f.acct.users = []auth.UserView{
		{Name: "ana", Role: auth.RoleOperator, TOTP: true, LastLoginAt: 1},
		{Name: "root", Role: auth.RoleAdmin, Root: true, TOTP: true},
		{Name: "zed", Role: auth.RoleViewer, LockedUntil: time.Now().Add(10 * time.Minute).Unix()},
	}
	return f
}

func waitAsked(t *testing.T, s *decltest.Screen, f *fakeClient, want string) {
	t.Helper()
	s.WaitFor(t, want, func(string) bool { return slices.Contains(f.accountAsked(), want) })
}

// TestTheUsersPanel: an admin's Users lists everyone with role, factor and
// state; Add asks the name, the role (viewer unless changed) and a first
// passphrase that is never on the screen; Remove asks first.
func TestTheUsersPanel(t *testing.T) {
	f := withUsers()
	h, s := startHost(t, f)
	s.WaitForText(t, "CA LE staging")
	run(t, h, h.openUsers)
	for _, part := range []string{"Users", "ana", "operator", "2FA", "zed", "locked", "Last login"} {
		s.WaitForText(t, part)
	}
	if strings.Contains(s.String(), "an admin has no two-factor") {
		t.Fatal("every admin has two-factor, and the panel says one has none")
	}
	run(t, h, func() error { return h.userMoved(1) })
	s.WaitForText(t, "Root is the first admin")

	run(t, h, h.userAdd)
	s.WaitForText(t, "Add a user")
	s.Keys(t, decltest.Type("Bo Smith")...)
	s.Keys(t, enter)
	s.WaitForText(t, "a name is a lower-case letter")
	for range len("Bo Smith") {
		s.Keys(t, backspace)
	}
	s.Keys(t, decltest.Type("bo")...)
	s.Keys(t, enter)
	s.WaitForText(t, "Role: admin, operator, mail or viewer")
	s.Keys(t, enter) // viewer, as offered
	s.WaitForText(t, "A first passphrase for bo")
	const pw = "a first passphrase for bo"
	s.Keys(t, decltest.Type(pw)...)
	if strings.Contains(s.String(), pw) {
		t.Fatal("the passphrase is on the screen")
	}
	s.Keys(t, enter)
	s.WaitForText(t, "bo added")
	waitAsked(t, s, f, "add bo viewer")
	s.WaitForText(t, "must change")
	f.mu.Lock()
	passes := f.acct.passes
	f.mu.Unlock()
	if len(passes) != 1 || passes[0] != pw {
		t.Fatalf("what reached the daemon: %d passphrases", len(passes))
	}

	f.mu.Lock()
	f.acct.users = append(f.acct.users, auth.UserView{Name: "eve", Role: auth.RoleAdmin})
	f.mu.Unlock()
	run(t, h, func() error { h.loadUsers(); return nil })
	s.WaitForText(t, "an admin has no two-factor")
	run(t, h, func() error { return h.userUnlock(2) })
	waitAsked(t, s, f, "unlock zed")
	run(t, h, func() error { return h.userRemove(0) })
	s.WaitForText(t, "Remove ana and their API tokens?")
	s.Keys(t, decltest.Rune('y'))
	waitAsked(t, s, f, "remove ana")
	s.WaitForText(t, "ana removed")
}

// TestUsersIsForAdmins: anyone else is told so (the daemon refuses regardless).
func TestUsersIsForAdmins(t *testing.T) {
	f := withUsers()
	f.acct.me.Root = false
	f.acct.me.Role = auth.RoleViewer
	h, s := startHost(t, f)
	s.WaitForText(t, "CA LE staging")
	if onLoop(h, func() auth.Role { return h.me.Role }) != auth.RoleViewer {
		t.Fatal("the panel does not know it is a viewer's")
	}
	run(t, h, h.openUsers)
	s.WaitForText(t, "only an admin manages users")
}

// TestAPassphraseMustChangeFirst: a user whose passphrase an admin set reads
// nothing until they have changed it: the old, then the new twice, a weak or a
// different second one refused in the dialog.
func TestAPassphraseMustChangeFirst(t *testing.T) {
	f := newFakeClient()
	f.acct.me.MustChange = true
	s := start(t, f)
	s.WaitForText(t, "Change your passphrase")
	s.WaitForText(t, "change your passphrase before anything else")
	if _, _, _, reads := f.snapshot(); reads != 0 {
		t.Fatalf("the panel read the routes %d times before the change", reads)
	}
	s.Keys(t, decltest.Type(passphrase)...)
	s.Keys(t, enter)
	s.WaitForText(t, "A new passphrase")
	s.Keys(t, decltest.Type("unbelievable")...) // twelve, and common
	s.Keys(t, enter)
	s.WaitForText(t, "no common password")
	for range len("unbelievable") {
		s.Keys(t, backspace)
	}
	const pw = "a fresh and long passphrase"
	s.Keys(t, decltest.Type(pw)...)
	s.Keys(t, enter)
	s.WaitForText(t, "The new passphrase again")
	s.Keys(t, decltest.Type(pw+"!")...)
	s.Keys(t, enter)
	s.WaitForText(t, "not the same passphrase")
	s.Keys(t, backspace)
	s.Keys(t, enter)
	s.WaitForText(t, "passphrase changed")
	s.WaitForText(t, "CA LE staging") // now it reads
	if strings.Contains(s.String(), pw) {
		t.Fatal("the passphrase is on the screen")
	}
	f.mu.Lock()
	passes := f.acct.passes
	f.mu.Unlock()
	if len(passes) != 1 || passes[0] != pw {
		t.Fatalf("what reached the daemon: %d passphrases", len(passes))
	}
}

// TestTwoFactorEnrolment: the secret and its link are shown, a wrong code is
// refused in the dialog, the right one turns two-factor on, and the recovery
// codes are shown once: closed, they are in no source.
func TestTwoFactorEnrolment(t *testing.T) {
	f := newFakeClient()
	h, s := startHost(t, f)
	s.WaitForText(t, "CA LE staging")
	run(t, h, h.openTwoFactor)
	s.WaitForText(t, "Turn on two-factor")
	s.WaitForText(t, "JBSW Y3DP EHPK 3PXP")
	s.Keys(t, decltest.Type("000000")...)
	s.Keys(t, enter)
	s.WaitForText(t, "that code is not right")
	for range 6 {
		s.Keys(t, backspace)
	}
	s.Keys(t, decltest.Type(totpCode)...)
	s.Keys(t, enter)
	s.WaitForText(t, "Recovery codes")
	s.WaitForText(t, recoveryCode)
	s.WaitForText(t, "This is shown once")
	waitAsked(t, s, f, "totp on")
	if strings.Contains(s.String(), "JBSW Y3DP") {
		t.Fatal("the secret stayed on the screen after the enrolment")
	}
	s.Keys(t, escape)
	s.WaitFor(t, "the codes to leave the screen", func(sc string) bool { return !strings.Contains(sc, recoveryCode) })

	run(t, h, h.openTwoFactor) // on now: it asks a code to turn it off
	s.WaitForText(t, "Turn off two-factor")
	s.Keys(t, decltest.Type(totpCode)...)
	s.Keys(t, enter)
	waitAsked(t, s, f, "totp off")
	s.WaitForText(t, "two-factor is off")
}

// TestTheLoginAsksTheCode: with two-factor, the code goes with the passphrase;
// without it the login is refused like any wrong answer.
func TestTheLoginAsksTheCode(t *testing.T) {
	f := newFakeClient()
	f.acct.code = totpCode
	s := open(t, f)
	s.WaitForText(t, "Two-factor code")
	s.Keys(t, decltest.Type(passphrase)...)
	s.Keys(t, enter, enter)
	s.WaitForText(t, "error: wrong user or passphrase")
	s.Keys(t, decltest.Type(passphrase)...)
	s.Keys(t, enter)
	s.Keys(t, decltest.Type(totpCode)...)
	s.Keys(t, enter)
	s.WaitForText(t, "signed in as root")
	f.mu.Lock()
	got := strings.Join(f.logins, ",")
	f.mu.Unlock()
	if got != "root!,root" {
		t.Fatalf("logins = %s, want root!,root", got)
	}
}

// TestTheLoginSaysTheVaultIsLocked: before anyone types (N3).
func TestTheLoginSaysTheVaultIsLocked(t *testing.T) {
	f := newFakeClient()
	f.acct.vaultLocked = true
	s := open(t, f)
	s.WaitForText(t, "The vault is locked")
	g := newFakeClient()
	s2 := open(t, g)
	s2.WaitForText(t, "Two-factor code")
	if strings.Contains(s2.String(), "The vault is locked") {
		t.Fatal("an open vault is said to be locked")
	}
}

// TestAnAPITokenIsShownOnce: New token asks a name, a role and the days, and
// shows the token once; Revoke asks first.
func TestAnAPITokenIsShownOnce(t *testing.T) {
	f := newFakeClient()
	h, s := startHost(t, f)
	s.WaitForText(t, "CA LE staging")
	run(t, h, h.openTokens)
	s.WaitForText(t, "A token is for scripts")
	run(t, h, h.tokenCreate)
	s.WaitForText(t, "A name for the token")
	s.Keys(t, decltest.Type("backup")...)
	s.Keys(t, enter)
	s.WaitForText(t, "Role: admin, operator, mail or viewer")
	s.Keys(t, enter)
	s.WaitForText(t, "Days it lasts")
	for range 2 {
		s.Keys(t, backspace)
	}
	s.Keys(t, decltest.Type("400")...)
	s.Keys(t, enter)
	s.WaitForText(t, "a token lasts 1 to 365 days")
	for range 3 {
		s.Keys(t, backspace)
	}
	s.Keys(t, decltest.Type("30")...)
	s.Keys(t, enter)
	s.WaitForText(t, "New API token")
	s.WaitForText(t, tokenSecret)
	waitAsked(t, s, f, "token backup viewer")
	s.Keys(t, escape)
	s.WaitFor(t, "the token to leave the screen", func(sc string) bool { return !strings.Contains(sc, tokenSecret) })
	s.WaitForText(t, "backup")

	run(t, h, func() error { return h.tokenRevoke(0) })
	s.WaitForText(t, "Revoke token backup?")
	s.Keys(t, decltest.Rune('y'))
	waitAsked(t, s, f, "revoke backup")
	s.WaitForText(t, "revoked")
}

// TestIdleSignsOut: thirty minutes with no key ask for the login again, and a
// secret on the screen leaves it.
func TestIdleSignsOut(t *testing.T) {
	f := newFakeClient()
	h, s := startHost(t, f)
	s.WaitForText(t, "CA LE staging")
	run(t, h, h.openTwoFactor)
	s.WaitForText(t, "JBSW Y3DP EHPK 3PXP")
	onLoop(h, func() bool { h.lastAction = time.Now().Add(-time.Hour); h.checkIdle(); return true })
	s.WaitForText(t, "Sign in to AutoPanel")
	s.WaitForText(t, "signed out after 30 minutes idle")
	if strings.Contains(s.String(), "JBSW Y3DP") {
		t.Fatal("the two-factor secret stayed on the screen after signing out")
	}
	signIn(t, s)
	s.WaitForText(t, "signed in as root")
}

// TestAnExpiredSessionSignsOut: the daemon's auth.expired asks for the login.
func TestAnExpiredSessionSignsOut(t *testing.T) {
	f := newFakeClient()
	h, s := startHost(t, f)
	s.WaitForText(t, "CA LE staging")
	onLoop(h, func() bool { h.failed(errors.Join(auth.ErrExpired)); return true })
	s.WaitForText(t, "Sign in to AutoPanel")
	s.WaitForText(t, "the session has ended")
}
