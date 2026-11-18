package auth_test

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/yongjohnlee80/autopanel/internal/auth"
	"github.com/yongjohnlee80/autopanel/internal/module"
)

// TestAnAPITokenIsCheckedAtEveryCall: a good token leaves nothing on the audit
// log; a bad one answers the one bad_login whatever was wrong with it; a flood
// of bad ones is audited twenty times and once more for the burst, and never
// stops a good token.
func TestAnAPITokenIsCheckedAtEveryCall(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.login(t, "root", rootPass, ""); err != nil {
		t.Fatal(err)
	}
	var nt auth.NewToken
	if err := f.call(t, "user:1", "auth.token.create", auth.TokenAsk{Name: "monitor"}, &nt); err != nil {
		t.Fatal(err)
	}
	before := len(f.aud.entries)
	for range 100 {
		p, err := f.m.APIToken(ctx, nt.Token, "api 203.0.113.9")
		if err != nil || p != "token:"+strconv.FormatInt(nt.ID, 10) {
			t.Fatalf("a good token: %q, %v", p, err)
		}
	}
	if n := len(f.aud.entries) - before; n != 0 {
		t.Fatalf("a hundred good calls wrote %d audit entries", n)
	}
	for name, bad := range map[string]string{
		"a wrong secret":  wrongSecret(nt.Token),
		"an unknown id":   "apt_99_" + strings.Repeat("a", 43),
		"no token at all": "",
		"not a token":     "Bearer something",
	} {
		if _, err := f.m.APIToken(ctx, bad, "api 203.0.113.9"); !errors.Is(err, auth.ErrBadLogin) {
			t.Errorf("%s: %v; want bad_login", name, err)
		}
	}
	// A flood: the entries stop at the burst, and the good token still works.
	for range 500 {
		_, _ = f.m.APIToken(ctx, "apt_99_"+strings.Repeat("b", 43), "api 198.51.100.1")
	}
	failed, burst := 0, 0
	for _, e := range f.aud.entries[before:] {
		switch {
		case strings.HasPrefix(e, "auth.token.api "):
			failed++
		case strings.HasPrefix(e, "auth.token.burst "):
			burst++
		}
	}
	if failed != 20 || burst != 1 {
		t.Fatalf("504 bad tokens in a minute wrote %d failure entries and %d burst entries; want 20 and 1", failed, burst)
	}
	if _, err := f.m.APIToken(ctx, nt.Token, "api 203.0.113.9"); err != nil {
		t.Fatalf("a good token during a flood of bad ones: %v", err)
	}
	// A minute later failures are on record again.
	*f.clock = f.clock.Add(2 * time.Minute)
	n := len(f.aud.entries)
	_, _ = f.m.APIToken(ctx, "apt_99_"+strings.Repeat("b", 43), "api 198.51.100.1")
	if len(f.aud.entries) != n+1 {
		t.Fatalf("a failure after the minute wrote %d entries", len(f.aud.entries)-n)
	}
	// Revoked, it is a bad token like any other.
	if err := f.call(t, "user:1", "auth.token.revoke", auth.TokenAsk{ID: nt.ID}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.APIToken(ctx, nt.Token, "api 203.0.113.9"); !errors.Is(err, auth.ErrBadLogin) {
		t.Fatalf("a revoked token: %v", err)
	}
}

// TestATokenOfADisabledOrResetOwner: a disabled owner's token is a bad token at
// the next call; an owner told to change its passphrase keeps its tokens, for
// that rule is the passphrase login's.
func TestATokenOfADisabledOrResetOwner(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.login(t, "root", rootPass, ""); err != nil {
		t.Fatal(err)
	}
	first := "a fine long passphrase for Oxp"
	if err := f.call(t, "user:1", "auth.user.add", auth.UserAsk{Name: "op", Role: auth.RoleOperator, Passphrase: first}, nil); err != nil {
		t.Fatal(err)
	}
	u, _ := f.store.User(ctx, "op")
	op := "user:" + strconv.FormatInt(u.ID, 10)
	if err := f.call(t, op, "auth.passphrase.change", auth.PassphraseAsk{Old: first, New: "another long passphrase, number 2"}, nil); err != nil {
		t.Fatal(err)
	}
	var nt auth.NewToken
	if err := f.call(t, op, "auth.token.create", auth.TokenAsk{Name: "ci"}, &nt); err != nil {
		t.Fatal(err)
	}
	read := module.Contract{Verb: "gate.route.list", Discloses: module.Plain}
	p, err := f.m.APIToken(ctx, nt.Token, "api x")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.call(t, "user:1", "auth.user.reset", auth.UserAsk{Name: "op", Passphrase: "a third long passphrase, reset by root"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.Authorize(ctx, op, time.Time{}, read); !errors.Is(err, auth.ErrMustChange) {
		t.Fatalf("the owner itself after a reset: %v; want must change", err)
	}
	if _, err := f.m.Authorize(ctx, p, time.Time{}, read); err != nil {
		t.Fatalf("its token after a reset: %v; want it to work", err)
	}
	if err := f.call(t, "user:1", "auth.user.disable", auth.UserAsk{Name: "op", Disabled: true}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.APIToken(ctx, nt.Token, "api x"); !errors.Is(err, auth.ErrBadLogin) {
		t.Fatalf("a disabled owner's token: %v", err)
	}
}

// wrongSecret is token with one character of its secret changed to another:
// never the token itself, whatever its characters are. (Replacing the last
// character with a fixed one is the same token one time in 64.)
func wrongSecret(token string) string {
	i := len(token) - 10
	c := byte('A')
	if token[i] == c {
		c = 'B'
	}
	return token[:i] + string(c) + token[i+1:]
}
