package ui

import (
	"github.com/yongjohnlee80/autopanel/core/forward"
	"github.com/yongjohnlee80/autopanel/core/tunnel"
	"reflect"
	"slices"
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

// TestTheAPIsHostForm: System › HTTPS API… opens on the settings in use; a host
// under no registered domain is refused in the prompt; a host and its source
// ranges are set from one line; an empty line turns the API off.
func TestTheAPIsHostForm(t *testing.T) {
	f := newFakeClient()
	h, s := startHost(t, f)
	s.WaitForText(t, "CA LE staging")
	asks := func() []API {
		f.mu.Lock()
		defer f.mu.Unlock()
		return append([]API{}, f.apiAsks...)
	}

	run(t, h, h.setAPI)
	s.WaitForText(t, "The HTTPS API")
	s.WaitForText(t, "Empty turns it off.")
	s.Keys(t, decltest.Type("api.other.net")...)
	s.Keys(t, enter)
	s.WaitForText(t, "api.other.net is under no registered domain")
	for range len("api.other.net") {
		s.Keys(t, backspace)
	}
	s.Keys(t, decltest.Type("api.example.com 203.0.113.0/24")...)
	s.Keys(t, enter)
	s.WaitForText(t, "The HTTPS API is served on api.example.com")
	if got := asks(); len(got) != 2 || got[1].Host != "api.example.com" || len(got[1].Allow) != 1 || got[1].Allow[0] != "203.0.113.0/24" {
		t.Fatalf("what the daemon was asked: %+v", got)
	}

	// It opens on what is set; cleared, the API is off.
	run(t, h, h.setAPI)
	s.WaitForText(t, "api.example.com 203.0.113.0/24")
	for range len("api.example.com 203.0.113.0/24") {
		s.Keys(t, backspace)
	}
	s.Keys(t, enter)
	s.WaitForText(t, "The HTTPS API is off")
	if got := asks(); len(got) != 3 || got[2].Host != "" || len(got[2].Allow) != 0 {
		t.Fatalf("turning it off asked: %+v", got)
	}
}

// TestThePortForwardsPanel: Routes › Port forwarding lists the forwards with
// the selected one's details. Add takes one line; a line that is no forward,
// and one the daemon refuses, are said in the prompt; a good one is shown as
// reviewed, with what adding it does to the firewall, and added on Yes with
// its port opened. Remove asks first.
func TestThePortForwardsPanel(t *testing.T) {
	f := newFakeClient()
	f.blocked = true
	f.forwards = []forward.View{{ID: 1, Name: "nas-ssh", Proto: "tcp", From: 2222, To: 2222, Target: "10.0.0.5:22", Allow: []string{"203.0.113.0/24"}}}
	h, s := startHost(t, f)
	s.WaitForText(t, "CA LE staging")
	run(t, h, h.openForwards)
	for _, part := range []string{"Port forwards · 1 · read at", "nas-ssh", "2222", "10.0.0.5:22", "PROXY header", "not sent", "203.0.113.0/24"} {
		s.WaitForText(t, part)
	}

	s.Keys(t, decltest.Rune('a'))
	s.WaitForText(t, "Add a port forward")
	s.Keys(t, decltest.Type("game")...)
	s.Keys(t, enter)
	s.WaitForText(t, "Give a name, a port and a target")
	for range len("game") {
		s.Keys(t, backspace)
	}
	bad := "mine 2200 127.0.0.1:22"
	s.Keys(t, decltest.Type(bad)...)
	s.Keys(t, enter)
	s.WaitForText(t, "SSH's own port is never forwarded")
	for range len(bad) {
		s.Keys(t, backspace)
	}
	s.Keys(t, decltest.Type("game 25565 127.0.0.1:26000")...)
	s.Keys(t, enter)
	s.WaitForText(t, "Add this port forward?")
	s.WaitForText(t, "game: tcp/25565 → 127.0.0.1:26000")
	s.WaitForText(t, "The firewall blocks tcp/25565 now.")
	if n := len(onLoop(h, func() []forward.View { return h.fwd.list })); n != 1 {
		t.Fatalf("the review changed the list: %d forwards", n)
	}
	s.Keys(t, decltest.Type("y")...)
	s.WaitForText(t, "Forwarding tcp/25565 to 127.0.0.1:26000")
	s.WaitForText(t, "Port forwards · 2 · read at")
	f.mu.Lock()
	adds := slices.Clone(f.forwardAdds)
	f.mu.Unlock()
	if len(adds) != 1 || adds[0].Name != "game" || adds[0].From != 25565 || adds[0].Accept != "review-of-game" || !adds[0].Open {
		t.Fatalf("what the daemon was asked to add: %+v", adds)
	}

	// Remove the selected one (the first row), after a question.
	s.Keys(t, decltest.Rune('r'))
	s.WaitForText(t, "Remove the forward nas-ssh?")
	s.Keys(t, decltest.Type("y")...)
	s.WaitForText(t, "nas-ssh is no longer forwarded")
	s.WaitForText(t, "Port forwards · 1 · read at")
}

// TestAForwardsLine: the one line of the form.
func TestAForwardsLine(t *testing.T) {
	for line, want := range map[string]forward.Spec{
		"game 25565 127.0.0.1:26000":                  {Name: "game", From: 25565, Target: "127.0.0.1:26000", Allow: []string{}},
		"  r   6000-6009  10.0.0.5:7000  10.0.0.0/8 ": {Name: "r", From: 6000, To: 6009, Target: "10.0.0.5:7000", Allow: []string{"10.0.0.0/8"}},
		"dns udp/5353 10.0.0.5:53":                    {Name: "dns", Proto: "udp", From: 5353, Target: "10.0.0.5:53", Allow: []string{}},
		"web tcp/8088 10.0.0.5:80":                    {Name: "web", From: 8088, Target: "10.0.0.5:80", Allow: []string{}},
	} {
		got, ok := forwardSpec(line)
		if got.Allow == nil {
			got.Allow = []string{}
		}
		if !ok || !reflect.DeepEqual(got, want) {
			t.Errorf("%q: %+v, %v; want %+v", line, got, ok, want)
		}
	}
	for _, line := range []string{"", "game", "game 25565", "game port 127.0.0.1:1", "game 6000-x 127.0.0.1:1", "game 25565-0 127.0.0.1:1"} {
		if _, ok := forwardSpec(line); ok {
			t.Errorf("%q was read as a forward", line)
		}
	}
}

// TestTheTunnelsPanel: Routes › Tunnels lists the agents with each one's
// state in a word and the selected one's details: its tunnel, its targets'
// names, the address to write in a route, and the key's fingerprint to
// compare. Add asks for a name, says so when it is no name, and shows the
// token once; Remove asks first.
func TestTheTunnelsPanel(t *testing.T) {
	f := newFakeClient()
	f.agents = []tunnel.View{
		{ID: 1, Name: "attic", State: "enrolled", Fingerprint: "SHA256:atticatticattic", EnrolledFrom: "203.0.113.9", EnrolledAt: 1_800_000_000},
		{ID: 2, Name: "nas", State: "enrolled", Fingerprint: "SHA256:nasnasnasnas", EnrolledFrom: "198.51.100.7", EnrolledAt: 1_800_000_000,
			Status: tunnel.Status{Connected: true, Since: 1_800_000_100, From: "198.51.100.7", Streams: 3, Targets: []string{"photos", "ssh"}}},
		{ID: 3, Name: "old", State: "expired"},
	}
	h, s := startHost(t, f)
	s.WaitForText(t, "CA LE staging")
	run(t, h, h.openTunnels)
	for _, part := range []string{"Tunnel agents · 3 · read at", "attic", "nas", "old", "expired", "SHA256:atticatticattic", "none listed", "tunnel://attic/<target>"} {
		s.WaitForText(t, part)
	}
	run(t, h, func() error { return h.tunnelMoved(1) })
	for _, part := range []string{"198.51.100.7, 3 streams now", "photos, ssh", "tunnel://nas/<target>", "SHA256:nasnasnasnas", "must match"} {
		s.WaitForText(t, part)
	}
	run(t, h, func() error { return h.tunnelMoved(2) })
	s.WaitForText(t, "Its token ran out")

	s.Keys(t, decltest.Rune('a'))
	s.WaitForText(t, "Add a tunnel agent")
	s.Keys(t, decltest.Type("My NAS")...)
	s.Keys(t, enter)
	s.WaitForText(t, "A name is 1 to 32 lower-case")
	for range len("My NAS") {
		s.Keys(t, backspace)
	}
	s.Keys(t, decltest.Type("garage")...)
	s.Keys(t, enter)
	s.WaitForText(t, "Enrolment token")
	s.WaitForText(t, "autopanel-agent enroll")
	s.WaitForText(t, "ape_0123456789abcdef_the-secret-shown-once")
	s.Keys(t, escape) // close the token's dialog: it is gone from the screen
	s.WaitFor(t, "the token left the screen", func(screen string) bool { return !strings.Contains(screen, "the-secret-shown-once") })
	s.WaitForText(t, "Tunnel agents · 4 · read at")

	// Remove the selected one (the first row), after a question.
	s.Keys(t, decltest.Rune('r'))
	s.WaitForText(t, "Remove the agent attic?")
	s.Keys(t, decltest.Type("y")...)
	s.WaitForText(t, "attic is removed")
	s.WaitForText(t, "Tunnel agents · 3 · read at")
}
