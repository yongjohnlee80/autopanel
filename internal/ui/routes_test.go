package ui

import (
	"reflect"
	"strings"
	"testing"

	"github.com/yongjohnlee80/golib/tui/decl/decltest"

	"github.com/yongjohnlee80/autopanel/core/gate"
)

// TestFormHost: the host is the subdomain under the domain, the domain alone
// for no subdomain, the subdomain alone for no domain; dots typed at either
// end are dropped.
func TestFormHost(t *testing.T) {
	for _, c := range []struct{ sub, domain, want string }{
		{"www", "example.com", "www.example.com"},
		{"", "example.com", "example.com"},
		{" api. ", ".example.com", "api.example.com"},
		{"a.b", "example.com", "a.b.example.com"},
		{"lone.example.org", "", "lone.example.org"},
	} {
		if got := formHost(c.sub, c.domain); got != c.want {
			t.Errorf("formHost(%q, %q) = %q, want %q", c.sub, c.domain, got, c.want)
		}
	}
}

// TestSplitHost: a stored host is split under the longest domain it is
// under; a host under none is all subdomain.
func TestSplitHost(t *testing.T) {
	domains := []gate.DomainView{{Name: "example.com"}, {Name: "eu.example.com"}}
	for _, c := range []struct{ host, sub, domain string }{
		{"app.example.com", "app", "example.com"},
		{"example.com", "", "example.com"},
		{"x.eu.example.com", "x", "eu.example.com"},
		{"lone.example.org", "lone.example.org", ""},
	} {
		if sub, domain := splitHost(c.host, domains); sub != c.sub || domain != c.domain {
			t.Errorf("splitHost(%q) = %q, %q; want %q, %q", c.host, sub, domain, c.sub, c.domain)
		}
		if got := formHost(splitHost(c.host, domains)); got != c.host {
			t.Errorf("formHost(splitHost(%q)) = %q", c.host, got)
		}
	}
}

// TestTheRouteFormsDomainAndPort: the form's domain box offers the domains,
// the route's own chosen; the host saved is the subdomain under the domain
// chosen; a stack's port fills the upstream. A host under no domain is said
// in the form, which stays.
func TestTheRouteFormsDomainAndPort(t *testing.T) {
	f := withStacks()
	h, s := startHost(t, f)
	openRoutes(t, s)
	s.Keys(t, decltest.Rune('a'))
	s.WaitForText(t, "Add route")
	s.WaitForText(t, "From a stack's port:")
	if got := onLoop(h, func() []portChoice { return h.form.portList }); !reflect.DeepEqual(got, stackPorts(someStacks())) {
		t.Fatalf("the form offers %+v", got)
	}
	run(t, h, func() error { return h.pickUpstream(0) })
	s.WaitForText(t, "http://127.0.0.1:8080")

	// no domain chosen (two to choose from): the host is the subdomain field alone
	s.Keys(t, decltest.Type("lone.example.org")...)
	s.Keys(t, enter)
	s.WaitForText(t, "The host is under no registered domain.")
	run(t, h, func() error { return h.submit("blog", 1, "/", "http://127.0.0.1:8080") }) // example.net
	s.WaitForText(t, "added blog.example.net/")
	added, _, _, _ := f.snapshot()
	if want := (gate.RouteSpec{Host: "blog.example.net", PathPrefix: "/", Upstream: "http://127.0.0.1:8080"}); len(added) != 1 || added[0] != want {
		t.Fatalf("added = %+v, want [%+v]", added, want)
	}
}

// TestTheDomainsPanel: the domains and their routes' counts on the left, the
// selected one and the routes under it on the right. Add asks the name; one
// registered already is refused in the prompt. Remove asks first; a domain a
// route is under alone is refused, and said; another goes.
func TestTheDomainsPanel(t *testing.T) {
	f := newFakeClient()
	s := start(t, f)
	s.WaitForText(t, "CA LE staging")
	s.Keys(t, decltest.Alt('r'))
	s.WaitForText(t, "Domains…")
	s.Keys(t, decltest.Rune('d'))
	for _, part := range []string{"Domains · 2 · read at", "example.com", "example.net", "The routes under it:", "app.example.com/ → http://127.0.0.1:8080"} {
		s.WaitForText(t, part)
	}
	waitFact(t, s, "Routes", "2")
	s.Keys(t, decltest.Rune('j'))
	s.WaitForText(t, "No route is under it.")

	s.Keys(t, decltest.Rune('a'))
	s.WaitForText(t, "Add a domain")
	s.Keys(t, decltest.Type("example.net")...)
	s.Keys(t, enter)
	s.WaitForText(t, "example.net is registered already.")
	for range len("example.net") {
		s.Keys(t, backspace)
	}
	s.Keys(t, decltest.Type("example.org")...)
	s.Keys(t, enter)
	s.WaitForText(t, "domain example.org added")
	gone(t, s, "Add a domain")
	s.WaitForText(t, "Domains · 3 · read at")

	s.Keys(t, decltest.Rune('k')) // example.com: two routes under it
	waitFact(t, s, "Domain", "example.com")
	s.Keys(t, decltest.Rune('r'))
	s.WaitForText(t, "Remove the domain example.com?")
	s.Keys(t, decltest.Rune('y'))
	s.WaitForText(t, "example.com cannot be removed: a route would be left under no domain.")

	s.Keys(t, decltest.Rune('j'))
	waitFact(t, s, "Domain", "example.net")
	s.Keys(t, decltest.Rune('r'))
	s.WaitForText(t, "Remove the domain example.net?")
	s.Keys(t, decltest.Rune('y'))
	s.WaitForText(t, "domain example.net removed")
	s.WaitForText(t, "Domains · 2 · read at")
	f.mu.Lock()
	asks := strings.Join(f.domainAsks, ",")
	f.mu.Unlock()
	if asks != "add example.net,add example.org,remove example.com,remove example.net" {
		t.Fatalf("the domains asked = %s", asks)
	}
}
