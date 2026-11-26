package mail

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
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

// TestADomainHeldByAnAliasIsNotRemoved: an alias in a domain, of an account
// in another, holds the domain as an account would (tifa's review, F1).
func TestADomainHeldByAnAliasIsNotRemoved(t *testing.T) {
	m, st, v, _, _, _ := newTestModule(t)
	st.state = &State{Host: "mail.example.net", CreatedAt: 1, Bootstrapped: 1}
	st.domains = []string{"example.net", "example.org"}
	v.m[sealedKey] = []byte(prod(m).Key)
	srv := mem(m)
	ctx := context.Background()
	for _, d := range st.domains {
		if _, err := srv.AddDomain(ctx, d); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := m.accountAdd(ctx, AccountAsk{Address: "ana@example.net"}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.accountSet(ctx, AccountSet{Address: "ana@example.net", Aliases: ptr([]string{"ana@example.org"})}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.domainRemove(ctx, Name{Name: "example.org"}); !errors.Is(err, ErrDomainHasAccounts) {
		t.Fatalf("removing a domain an alias holds: %v", err)
	}
	if _, err := m.accountSet(ctx, AccountSet{Address: "ana@example.net", Aliases: ptr([]string{})}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.domainRemove(ctx, Name{Name: "example.org"}); err != nil {
		t.Fatalf("removing it once the alias is gone: %v", err)
	}
}

// accountIDOf is the provider's ID of the account at address.
func accountIDOf(t *testing.T, m *Module, address string) string {
	t.Helper()
	c, err := m.ready(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	as, err := c.Accounts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range as {
		if a.Address == address {
			return a.ID
		}
	}
	t.Fatalf("no account %s", address)
	return ""
}

// TestAnAccountsMailIsSentOn: mail.account.set forwards an account's mail to
// an address outside mail's domains, with or without a copy kept, and turns
// it off; the list says where and how many the server sends to; an address
// of mail's own, one that is no address, and more than the server sends to
// are refused before anything changes; an account with a script of its own
// is not changed.
func TestAnAccountsMailIsSentOn(t *testing.T) {
	m, srv, _ := readyMail(t)
	ctx := context.Background()
	if _, err := m.accountAdd(ctx, AccountAsk{Address: "ana@example.net"}); err != nil {
		t.Fatal(err)
	}
	if v := accountOf(t, m, "ana@example.net"); v.Forward != nil || v.ForwardOther || v.ForwardMax != 1 {
		t.Fatalf("a new account: %+v", v)
	}
	v, err := m.accountSet(ctx, AccountSet{Address: "ana@example.net", Forward: &ForwardView{To: []string{" Ana.Home@Example.ORG ", "Ana.Home@example.org"}, Keep: true}})
	if err != nil || v.Forward == nil || !slices.Equal(v.Forward.To, []string{"Ana.Home@example.org"}) || !v.Forward.Keep {
		t.Fatalf("forwarding with a copy kept: %+v, %v", v, err)
	}
	if v, err = m.accountSet(ctx, AccountSet{Address: "ana@example.net", Forward: &ForwardView{To: []string{"other@example.com"}}}); err != nil || v.Forward.Keep || v.Forward.To[0] != "other@example.com" {
		t.Fatalf("replacing it, no copy kept: %+v, %v", v, err)
	}
	// Refused, and what was set stays.
	for what, tc := range map[string]struct {
		to   []string
		want error
	}{
		"an address of mail's own domain":   {[]string{"ben@example.net"}, ErrBadForward},
		"mail's own domain in another case": {[]string{"ben@EXAMPLE.NET"}, ErrBadForward},
		"no address":                        {[]string{"nobody"}, ErrBadForward},
		"a quote":                           {[]string{`a"b@example.org`}, ErrBadForward},
		"a script's command":                {[]string{`a"; discard; redirect "x@evil.example`}, ErrBadForward},
		"a backslash":                       {[]string{`a\b@example.org`}, ErrBadForward},
		"a space":                           {[]string{"a b@example.org"}, ErrBadForward},
		"a newline":                         {[]string{"a\n@example.org"}, ErrBadForward},
		"an address literal":                {[]string{"a@[192.0.2.1]"}, ErrBadForward},
		"an address by number":              {[]string{"a@192.0.2.1"}, ErrBadForward},
		"a domain with no dot":              {[]string{"a@localhost"}, ErrBadForward},
		"a display name":                    {[]string{"Ana <a@example.org>"}, ErrBadForward},
		"an address too long":               {[]string{"a@" + strings.Repeat("a", 250) + ".org"}, ErrBadForward},
		"two addresses, a server that sends to one": {[]string{"a@example.org", "b@example.org"}, ErrTooManyForwards},
		"six addresses": {[]string{"a@example.org", "b@example.org", "c@example.org", "d@example.org", "e@example.org", "f@example.org"}, ErrTooManyForwards},
	} {
		if _, err := m.accountSet(ctx, AccountSet{Address: "ana@example.net", Forward: &ForwardView{To: tc.to, Keep: true}}); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v", what, err)
		}
	}
	if v := accountOf(t, m, "ana@example.net"); v.Forward == nil || v.Forward.To[0] != "other@example.com" {
		t.Fatalf("after refused changes: %+v", v)
	}
	// A refused forward changes nothing else of the same call.
	if _, err := m.accountSet(ctx, AccountSet{Address: "ana@example.net", Aliases: ptr([]string{"sales@example.net"}), Forward: &ForwardView{To: []string{"nobody"}}}); !errors.Is(err, ErrBadForward) {
		t.Fatal(err)
	}
	if v := accountOf(t, m, "ana@example.net"); len(v.Aliases) != 0 {
		t.Fatalf("a refused forward set the aliases: %+v", v)
	}
	// A server set to send to more.
	srv.Redirects = 3
	if v, err = m.accountSet(ctx, AccountSet{Address: "ana@example.net", Forward: &ForwardView{To: []string{"b@example.org", "a@example.org"}, Keep: true}}); err != nil || v.ForwardMax != 3 || !slices.Equal(v.Forward.To, []string{"a@example.org", "b@example.org"}) {
		t.Fatalf("two addresses once the server sends to three: %+v, %v", v, err)
	}
	// Off; and off again.
	for i := 0; i < 2; i++ {
		if v, err = m.accountSet(ctx, AccountSet{Address: "ana@example.net", Forward: &ForwardView{}}); err != nil || v.Forward != nil {
			t.Fatalf("turning it off: %+v, %v", v, err)
		}
	}
	// A script of the owner's own: listed as such, and never changed.
	srv.OwnScript(accountIDOf(t, m, "ana@example.net"), true)
	if v := accountOf(t, m, "ana@example.net"); !v.ForwardOther || v.Forward != nil {
		t.Fatalf("beside a script of the owner's own: %+v", v)
	}
	if _, err := m.accountSet(ctx, AccountSet{Address: "ana@example.net", Forward: &ForwardView{To: []string{"a@example.org"}}}); !errors.Is(err, ErrServer) {
		t.Fatalf("forwarding set over a script of the owner's own: %v", err)
	}
	// And nothing else of the same call is changed.
	if _, err := m.accountSet(ctx, AccountSet{Address: "ana@example.net", Aliases: ptr([]string{"sales@example.net"}), Forward: &ForwardView{}}); !errors.Is(err, ErrServer) {
		t.Fatalf("forwarding turned off over a script of the owner's own: %v", err)
	}
	if v := accountOf(t, m, "ana@example.net"); len(v.Aliases) != 0 {
		t.Fatalf("a refused forward set the aliases: %+v", v)
	}
}
