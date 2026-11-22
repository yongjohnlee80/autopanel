package auth_test

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/yongjohnlee80/golib/auth/totp"

	"github.com/yongjohnlee80/autopanel/internal/auth"
	"github.com/yongjohnlee80/autopanel/internal/module"
)

// callIn runs a verb as principal, by the browser session given (none: the
// console).
func (f fixture) callIn(t *testing.T, sc *auth.SessionCall, principal, verb string, param, out any) error {
	t.Helper()
	for _, v := range f.m.Verbs() {
		if v.Verb != verb {
			continue
		}
		ctx := module.WithPrincipal(context.Background(), principal)
		if sc != nil {
			ctx = auth.WithSession(ctx, *sc)
		}
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

// withSessions is a fixture whose module ends browser sessions, root logged
// in at the console (the vault open), and a user ana (operator) besides.
func withSessions(t *testing.T) (fixture, *auth.Sessions, string) {
	t.Helper()
	f := newFixture(t)
	ss := auth.MemSessions(func() time.Time { return *f.clock })
	f.m.SetSessions(ss)
	if _, err := f.login(t, "root", rootPass, ""); err != nil {
		t.Fatal(err)
	}
	if err := f.call(t, "user:1", "auth.user.add", auth.UserAsk{Name: "ana", Role: auth.RoleOperator, Passphrase: anaFirst}, nil); err != nil {
		t.Fatal(err)
	}
	u, err := f.store.User(context.Background(), "ana")
	if err != nil {
		t.Fatal(err)
	}
	return f, ss, "user:" + strconv.FormatInt(u.ID, 10)
}

const anaFirst = "a first passphrase for her"

func open(t *testing.T, ss *auth.Sessions, user int64, host string) auth.Opened {
	t.Helper()
	o, err := ss.New(context.Background(), user, host, "203.0.113.5", "test", "")
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func live(ss *auth.Sessions, cookie, host string) bool {
	_, err := ss.Resolve(context.Background(), cookie, host)
	return err == nil
}

// TestACredentialAsksThePassphraseAgain: making a token and starting or
// dropping a second factor need the caller's passphrase, on the console as
// from a browser.
func TestACredentialAsksThePassphraseAgain(t *testing.T) {
	f, _, _ := withSessions(t)
	for _, pass := range []string{"", "not the passphrase at all"} {
		if err := f.call(t, "user:1", "auth.token.create", auth.TokenAsk{Name: "ci", Passphrase: pass}, nil); !errors.Is(err, auth.ErrBadLogin) {
			t.Fatalf("a token with passphrase %q: %v", pass, err)
		}
		if err := f.call(t, "user:1", "auth.totp.begin", auth.PassAsk{Passphrase: pass}, nil); !errors.Is(err, auth.ErrBadLogin) {
			t.Fatalf("two-factor begun with passphrase %q: %v", pass, err)
		}
	}
	var e auth.Enrol
	if err := f.call(t, "user:1", "auth.totp.begin", auth.PassAsk{Passphrase: rootPass}, &e); err != nil {
		t.Fatal(err)
	}
	seed, _ := totp.Decode(strings.ReplaceAll(e.Secret, " ", ""))
	if err := f.call(t, "user:1", "auth.totp.confirm", auth.CodeAsk{Code: totp.Code(seed, *f.clock)}, nil); err != nil {
		t.Fatal(err)
	}
	*f.clock = f.clock.Add(time.Minute)
	code := totp.Code(seed, *f.clock)
	if err := f.call(t, "user:1", "auth.totp.disable", auth.CodeAsk{Code: code, Passphrase: "wrong wrong wrong"}, nil); !errors.Is(err, auth.ErrBadLogin) {
		t.Fatalf("two-factor dropped without the passphrase: %v", err)
	}
	if err := f.call(t, "user:1", "auth.totp.disable", auth.CodeAsk{Code: code, Passphrase: rootPass}, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(f.aud.entries, "\n"), "auth.confirm user root failed") {
		t.Fatal("a wrong passphrase asked again is not on record")
	}
}

// TestAWrongPassphraseFromABrowserCounts: a session cannot guess at the
// passphrase faster than the login allows.
func TestAWrongPassphraseFromABrowserCounts(t *testing.T) {
	f, ss, _ := withSessions(t)
	o := open(t, ss, 1, auth.HostApp)
	sc := &auth.SessionCall{Host: auth.HostApp, Cookie: o.Cookie}
	if err := f.callIn(t, sc, "user:1", "auth.token.create", auth.TokenAsk{Name: "ci", Passphrase: "a wrong one, the first"}, nil); !errors.Is(err, auth.ErrBadLogin) {
		t.Fatal(err)
	}
	if err := f.callIn(t, sc, "user:1", "auth.token.create", auth.TokenAsk{Name: "ci", Passphrase: rootPass}, nil); !errors.Is(err, auth.ErrThrottled) {
		t.Fatalf("at once after a wrong one: %v; want the wait", err)
	}
	if err := f.callIn(t, sc, "user:1", "auth.passphrase.change", auth.PassphraseAsk{Old: rootPass, New: "and a new one that is long"}, nil); !errors.Is(err, auth.ErrThrottled) {
		t.Fatalf("a passphrase change in the wait: %v", err)
	}
	if err := f.call(t, "user:1", "auth.token.create", auth.TokenAsk{Name: "ci", Passphrase: rootPass}, nil); err != nil {
		t.Fatalf("the console is not in the browser's wait: %v", err)
	}
	*f.clock = f.clock.Add(2 * time.Second)
	if err := f.callIn(t, sc, "user:1", "auth.token.create", auth.TokenAsk{Name: "ci2", Passphrase: rootPass}, nil); err != nil {
		t.Fatalf("after the wait: %v", err)
	}
}

// TestWhatEndsSessions: each event of the record ends the sessions it names.
func TestWhatEndsSessions(t *testing.T) {
	f, ss, ana := withSessions(t)
	anaID, _ := strconv.ParseInt(strings.TrimPrefix(ana, "user:"), 10, 64)
	sc := func(o auth.Opened) *auth.SessionCall { return &auth.SessionCall{Host: auth.HostApp, Cookie: o.Cookie} }

	// a passphrase changed from a session keeps that one and ends the others
	a, b := open(t, ss, anaID, auth.HostApp), open(t, ss, anaID, auth.HostApp)
	second := "her second long passphrase"
	if err := f.callIn(t, sc(a), ana, "auth.passphrase.change", auth.PassphraseAsk{Old: anaFirst, New: second}, nil); err != nil {
		t.Fatal(err)
	}
	if !live(ss, a.Cookie, auth.HostApp) || live(ss, b.Cookie, auth.HostApp) {
		t.Fatal("a passphrase change from a session: that one ends, or another lives")
	}
	// at the console it ends them all
	third := "her third long passphrase"
	if err := f.call(t, ana, "auth.passphrase.change", auth.PassphraseAsk{Old: second, New: third}, nil); err != nil {
		t.Fatal(err)
	}
	if live(ss, a.Cookie, auth.HostApp) {
		t.Fatal("a passphrase change at the console left a browser session")
	}
	for _, c := range []struct {
		what string
		verb string
		ask  any
	}{
		{"disabled", "auth.user.disable", auth.UserAsk{Name: "ana", Disabled: true}},
		{"enabled again: nothing to end", "auth.user.disable", auth.UserAsk{Name: "ana", Disabled: false}},
		{"reset", "auth.user.reset", auth.UserAsk{Name: "ana", Passphrase: "a reset passphrase for her"}},
		{"its role changed", "auth.user.role", auth.UserAsk{Name: "ana", Role: auth.RoleViewer, Passphrase: "a role passphrase for her"}},
	} {
		o := open(t, ss, anaID, auth.HostApp)
		root := open(t, ss, 1, auth.HostApp)
		if err := f.call(t, "user:1", c.verb, c.ask, nil); err != nil {
			t.Fatalf("%s: %v", c.what, err)
		}
		if gone := !live(ss, o.Cookie, auth.HostApp); gone != (c.verb != "auth.user.disable" || c.ask.(auth.UserAsk).Disabled) {
			t.Fatalf("%s: her session gone = %v", c.what, gone)
		}
		if !live(ss, root.Cookie, auth.HostApp) {
			t.Fatalf("%s: another user's session ended", c.what)
		}
	}
	// the second factor removed, by an admin for her
	o := open(t, ss, anaID, auth.HostApp)
	if err := f.call(t, "user:1", "auth.totp.disable", auth.CodeAsk{Name: "ana", Passphrase: rootPass}, nil); err != nil {
		t.Fatal(err)
	}
	if live(ss, o.Cookie, auth.HostApp) {
		t.Fatal("her second factor removed, her session lives")
	}
	if !strings.Contains(strings.Join(f.aud.entries, "\n"), "auth.session.end user ana the user was disabled") {
		t.Fatalf("an ending is not on record: %v", f.aud.entries)
	}
}

// TestTheAppHostIsYourOwnAccount: from the app host an admin manages nobody
// else's tokens or second factor; that is the admin host's.
func TestTheAppHostIsYourOwnAccount(t *testing.T) {
	f, ss, ana := withSessions(t)
	second := "her second long passphrase"
	if err := f.call(t, ana, "auth.passphrase.change", auth.PassphraseAsk{Old: anaFirst, New: second}, nil); err != nil {
		t.Fatal(err)
	}
	var hers auth.NewToken
	if err := f.call(t, ana, "auth.token.create", auth.TokenAsk{Name: "hers", Passphrase: second}, &hers); err != nil {
		t.Fatal(err)
	}
	o := open(t, ss, 1, auth.HostApp)
	app := &auth.SessionCall{Host: auth.HostApp, Cookie: o.Cookie}
	var ts []auth.TokenView
	if err := f.callIn(t, app, "user:1", "auth.token.list", nil, &ts); err != nil || len(ts) != 0 {
		t.Fatalf("an admin's token list from the app host: %+v, %v", ts, err)
	}
	if err := f.callIn(t, app, "user:1", "auth.token.revoke", auth.TokenAsk{ID: hers.ID}, nil); !errors.Is(err, auth.ErrNotOwn) {
		t.Fatalf("another's token revoked from the app host: %v", err)
	}
	if err := f.callIn(t, app, "user:1", "auth.totp.disable", auth.CodeAsk{Name: "ana", Passphrase: rootPass}, nil); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("another's second factor from the app host: %v", err)
	}
	if err := f.call(t, "user:1", "auth.token.list", nil, &ts); err != nil || len(ts) != 1 {
		t.Fatalf("an admin's token list at the console: %+v, %v", ts, err)
	}
}

// TestYourSessions: listed without their ids, the current one marked; one
// ended by its id; another user's is never yours to end.
func TestYourSessions(t *testing.T) {
	f, ss, ana := withSessions(t)
	anaID, _ := strconv.ParseInt(strings.TrimPrefix(ana, "user:"), 10, 64)
	a := open(t, ss, 1, auth.HostApp)
	*f.clock = f.clock.Add(time.Second)
	b := open(t, ss, 1, auth.HostApp)
	theirs := open(t, ss, anaID, auth.HostApp)
	var list []auth.SessionView
	if err := f.callIn(t, &auth.SessionCall{Host: auth.HostApp, Cookie: b.Cookie}, "user:1", "auth.session.list", nil, &list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || !list[0].Current || list[1].Current || len(list[0].ID) != 16 || list[0].Client != "203.0.113.5" {
		t.Fatalf("the list: %+v", list)
	}
	for _, v := range list {
		if strings.Contains(a.Cookie+b.Cookie, v.ID) {
			t.Fatal("a session's id is in the list")
		}
	}
	var mine []auth.SessionView
	_ = f.callIn(t, nil, ana, "auth.session.list", nil, &mine)
	if err := f.call(t, "user:1", "auth.session.end", auth.SessionAsk{ID: mine[0].ID}, nil); !errors.Is(err, auth.ErrNoSuchSession) {
		t.Fatalf("another user's session ended: %v", err)
	}
	if err := f.call(t, "user:1", "auth.session.end", auth.SessionAsk{ID: list[1].ID}, nil); err != nil {
		t.Fatal(err)
	}
	if live(ss, a.Cookie, auth.HostApp) || !live(ss, b.Cookie, auth.HostApp) || !live(ss, theirs.Cookie, auth.HostApp) {
		t.Fatal("the wrong session ended")
	}
	if err := f.call(t, "user:1", "auth.session.end", auth.SessionAsk{ID: "zz"}, nil); !errors.Is(err, auth.ErrNoSuchSession) {
		t.Fatalf("a malformed id: %v", err)
	}
}

// TestSessionVerbs: the self-service verbs are the session's, and nothing
// that manages others is.
func TestSessionVerbs(t *testing.T) {
	f := newFixture(t)
	want := map[string]bool{"auth.whoami": true, "auth.passphrase.change": true, "auth.totp.begin": true, "auth.totp.confirm": true,
		"auth.totp.disable": true, "auth.token.list": true, "auth.token.create": true, "auth.token.revoke": true,
		"auth.session.list": true, "auth.session.end": true}
	for _, v := range f.m.Verbs() {
		if v.Session != want[v.Verb] {
			t.Errorf("%s: session = %v", v.Verb, v.Session)
		}
		if v.Session && v.Public {
			t.Errorf("%s: a session verb a token may call", v.Verb)
		}
	}
}
