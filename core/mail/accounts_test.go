package mail

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"testing"

	"github.com/yongjohnlee80/autopanel/internal/module"
)

func ptr[T any](v T) *T { return &v }

func accountOf(t *testing.T, m *Module, address string) AccountView {
	t.Helper()
	list, err := m.accountList(context.Background(), DomainAsk{})
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range list {
		if v.Address == address {
			return v
		}
	}
	t.Fatalf("no account %s in %+v", address, list)
	return AccountView{}
}

// TestADisabledAccountSignsNothingIn: mail.account.set disables an account,
// whose app passwords then sign nothing in and are kept; enabled again they
// work; the list says which is which.
func TestADisabledAccountSignsNothingIn(t *testing.T) {
	m, srv, _ := readyMail(t)
	ctx := context.Background()
	if _, err := m.accountAdd(ctx, AccountAsk{Address: "ana@example.net"}); err != nil {
		t.Fatal(err)
	}
	n, err := m.appPasswordAdd(ctx, AppPasswordAsk{Address: "ana@example.net", Description: "phone"})
	if err != nil {
		t.Fatal(err)
	}
	if !srv.SignIn("ana@example.net", n.Secret) {
		t.Fatal("a new app password does not sign in")
	}
	v, err := m.accountSet(ctx, AccountSet{Address: "ana@example.net", Disabled: ptr(true)})
	if err != nil || !v.Disabled {
		t.Fatalf("disabling: %+v, %v", v, err)
	}
	if srv.SignIn("ana@example.net", n.Secret) {
		t.Fatal("a disabled account's app password signs in")
	}
	if !accountOf(t, m, "ana@example.net").Disabled || len(appPasswordsOf(t, m, "ana@example.net")) != 1 {
		t.Fatal("a disabled account is not listed as disabled, or lost its app password")
	}
	if _, err := m.accountSet(ctx, AccountSet{Address: "ana@example.net", Disabled: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	if !srv.SignIn("ana@example.net", n.Secret) || accountOf(t, m, "ana@example.net").Disabled {
		t.Fatal("an account enabled again does not sign in, or is listed as disabled")
	}
	// Asking for nothing is refused; the server's administrator is never touched.
	if _, err := m.accountSet(ctx, AccountSet{Address: "ana@example.net"}); !errors.Is(err, module.ErrInvalidParams) {
		t.Fatalf("a change of nothing: %v", err)
	}
	srv.AddAdmin("admin", domainIDOf(t, m, "example.net"))
	if _, err := m.accountSet(ctx, AccountSet{Address: "admin@example.net", Disabled: ptr(true)}); !errors.Is(err, ErrAdminAccount) {
		t.Fatalf("disabling the server's administrator: %v", err)
	}
	if _, err := m.accountSet(ctx, AccountSet{Address: "nobody@example.net", Disabled: ptr(true)}); !errors.Is(err, ErrNoAccount) {
		t.Fatalf("disabling no account: %v", err)
	}
}

func domainIDOf(t *testing.T, m *Module, name string) string {
	t.Helper()
	c, err := m.ready(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ds, err := c.Domains(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range ds {
		if d.Name == name {
			return d.ID
		}
	}
	t.Fatalf("no domain %s", name)
	return ""
}

// TestAnAccountsAliases: aliases replace what the account had; each is an
// address of a mail domain, once, and no account's own address or another's
// alias; a refused change changes nothing; an address that is an alias
// cannot become an account.
func TestAnAccountsAliases(t *testing.T) {
	m, srv, _ := readyMail(t)
	ctx := context.Background()
	for _, a := range []string{"ana@example.net", "ben@example.net"} {
		if _, err := m.accountAdd(ctx, AccountAsk{Address: a}); err != nil {
			t.Fatal(err)
		}
	}
	v, err := m.accountSet(ctx, AccountSet{Address: "ana@example.net", Aliases: ptr([]string{"Sales@Example.net", "info@example.net", "sales@example.net"})})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(v.Aliases)
	if !slices.Equal(v.Aliases, []string{"info@example.net", "sales@example.net"}) {
		t.Fatalf("aliases set: %v; want the two, folded and once each", v.Aliases)
	}
	for what, tc := range map[string]struct {
		aliases []string
		want    error
	}{
		"an account's own address":    {[]string{"ben@example.net"}, ErrAddressTaken},
		"its own address":             {[]string{"ana@example.net"}, ErrAddressTaken},
		"a domain that receives none": {[]string{"x@example.org"}, ErrBadAddress},
		"not an address":              {[]string{"sales"}, ErrBadAddress},
		"a bad local part":            {[]string{"-x@example.net"}, ErrBadAddress},
		"another account's alias":     {[]string{"sales@example.net"}, ErrAddressTaken},
	} {
		addr := "ana@example.net"
		if what == "another account's alias" {
			addr = "ben@example.net"
		}
		if _, err := m.accountSet(ctx, AccountSet{Address: addr, Aliases: ptr(tc.aliases)}); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v; want %v", what, err, tc.want)
		}
	}
	many := make([]string, MaxAliases+1)
	for i := range many {
		many[i] = "a" + strconv.Itoa(i) + "@example.net"
	}
	if _, err := m.accountSet(ctx, AccountSet{Address: "ana@example.net", Aliases: ptr(many)}); !errors.Is(err, ErrTooManyAliases) {
		t.Fatalf("too many aliases: %v", err)
	}
	// Nothing refused was changed.
	got := accountOf(t, m, "ana@example.net").Aliases
	slices.Sort(got)
	if !slices.Equal(got, []string{"info@example.net", "sales@example.net"}) {
		t.Fatalf("after refused changes: %v", got)
	}
	// An address that is an alias cannot become an account.
	if _, err := m.accountAdd(ctx, AccountAsk{Address: "sales@example.net"}); !errors.Is(err, ErrAddressTaken) {
		t.Fatalf("an account at an alias's address: %v", err)
	}
	// Set both at once, then clear the aliases.
	if v, err := m.accountSet(ctx, AccountSet{Address: "ana@example.net", Disabled: ptr(true), Aliases: ptr([]string{"info@example.net"})}); err != nil || !v.Disabled || !slices.Equal(v.Aliases, []string{"info@example.net"}) {
		t.Fatalf("both at once: %+v, %v", v, err)
	}
	if v, err := m.accountSet(ctx, AccountSet{Address: "ana@example.net", Aliases: ptr([]string{})}); err != nil || len(v.Aliases) != 0 || !v.Disabled {
		t.Fatalf("clearing the aliases: %+v, %v", v, err)
	}
	if calls := srv.Calls(); !slices.Contains(calls, "SetAliases") || !slices.Contains(calls, "SetDisabled") {
		t.Fatalf("the server was never asked: %v", calls)
	}
}
