package gate

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestCanonicalHost(t *testing.T) {
	good := map[string]string{
		"example.com":           "example.com",
		"Example.COM":           "example.com",
		"example.com.":          "example.com",
		"example.com:443":       "example.com",
		"a-b.example.com:8":     "a-b.example.com",
		"xn--bcher-kva.example": "xn--bcher-kva.example",
	}
	for in, want := range good {
		if got, err := CanonicalHost(in); err != nil || got != want {
			t.Errorf("CanonicalHost(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := []string{"", ".", "example.com:", "example.com:99999x", "[2001:db8::1]:443", "exa mple.com",
		"-example.com", "example-.com", "a..b", "bücher.example", "example.com:443:443",
		strings.Repeat("a", 64) + ".com", strings.Repeat("a.", 127) + "com"}
	for _, in := range bad {
		if got, err := CanonicalHost(in); err == nil {
			t.Errorf("CanonicalHost(%q) = %q; want refused", in, got)
		}
	}
}

// FuzzCanonicalHost holds the parser's contract on any input (R23): it never
// panics, and what it accepts is already canonical and stays fixed.
func FuzzCanonicalHost(f *testing.F) {
	for _, s := range []string{"example.com", "Example.COM:443", "a.b.", "[::1]:80", "\x00", "a:b:c"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		got, err := CanonicalHost(in)
		if err != nil {
			return
		}
		if again, err := CanonicalHost(got); err != nil || again != got {
			t.Fatalf("CanonicalHost(%q) = %q, but that canonicalizes to %q, %v", in, got, again, err)
		}
		if got != strings.ToLower(got) || strings.ContainsAny(got, ":/ ") || len(got) > 253 {
			t.Fatalf("CanonicalHost(%q) = %q is not canonical", in, got)
		}
	})
}

func TestNormalizeRefuses(t *testing.T) {
	ok := Route{Host: "Example.com", Upstream: "http://127.0.0.1:8080"}
	if n, err := ok.Normalize(); err != nil || n.Host != "example.com" || n.PathPrefix != "/" {
		t.Fatalf("Normalize(%+v) = %+v, %v", ok, n, err)
	}
	for what, r := range map[string]Route{
		"a trailing slash":              {Host: "example.com", PathPrefix: "/api/", Upstream: "http://127.0.0.1"},
		"a relative prefix":             {Host: "example.com", PathPrefix: "api", Upstream: "http://127.0.0.1"},
		"a query in the prefix":         {Host: "example.com", PathPrefix: "/a?b", Upstream: "http://127.0.0.1"},
		"a non-http upstream":           {Host: "example.com", Upstream: "file:///etc/passwd"},
		"credentials upstream":          {Host: "example.com", Upstream: "http://user:pw@127.0.0.1"},
		"an upstream with no host":      {Host: "example.com", Upstream: "http:///x"},
		"a tunnel with no target":       {Host: "example.com", Upstream: "tunnel://nas"},
		"a tunnel with an empty target": {Host: "example.com", Upstream: "tunnel://nas/"},
		"a tunnel with no agent":        {Host: "example.com", Upstream: "tunnel:///photos"},
		"a tunnel to an address":        {Host: "example.com", Upstream: "tunnel://nas/127.0.0.1:22"},
		"a tunnel with a port":          {Host: "example.com", Upstream: "tunnel://nas:22/photos"},
		"a tunnel with a path below":    {Host: "example.com", Upstream: "tunnel://nas/photos/admin"},
		"a tunnel with a query":         {Host: "example.com", Upstream: "tunnel://nas/photos?x=1"},
		"a tunnel with credentials":     {Host: "example.com", Upstream: "tunnel://user@nas/photos"},
		"a tunnel in capitals":          {Host: "example.com", Upstream: "tunnel://NAS/Photos"},
		"the agent's reserved name":     {Host: "example.com", Upstream: "tunnel://nas/.targets"},
	} {
		if _, err := r.Normalize(); err == nil {
			t.Errorf("Normalize accepted %s: %+v", what, r)
		}
	}
}

func TestTableMatchesTheLongestPrefixOnASegmentBoundary(t *testing.T) {
	routes := []Route{
		{ID: 1, Host: "example.com", PathPrefix: "/", Upstream: "http://127.0.0.1:1"},
		{ID: 2, Host: "example.com", PathPrefix: "/api", Upstream: "http://127.0.0.1:2"},
		{ID: 3, Host: "example.com", PathPrefix: "/api/v2", Upstream: "http://127.0.0.1:3"},
	}
	snap, err := Build(routes, func(r Route) (RouteID, error) { return r.ID, nil })
	if err != nil {
		t.Fatal(err)
	}
	tbl := NewTable[RouteID]()
	if _, _, ok := tbl.Match("example.com", "/"); ok {
		t.Fatal("an empty table matched")
	}
	tbl.Swap(snap)
	for path, want := range map[string]RouteID{"/": 1, "/apix": 1, "/api": 2, "/api/x": 2, "/api/v2": 3, "/api/v2/y": 3, "/api/v20": 2} {
		if _, got, ok := tbl.Match("example.com", path); !ok || got != want {
			t.Errorf("Match(%q) = %d, %v; want %d", path, got, ok, want)
		}
	}
	if _, _, ok := tbl.Match("other.example", "/"); ok {
		t.Error("a host no route names matched")
	}
	if !tbl.Holds("example.com") || tbl.Holds("other.example") {
		t.Error("Holds disagrees with the routes")
	}
}

func TestBuildRefusesANonCanonicalRouteAndChangesNothing(t *testing.T) {
	tbl := NewTable[RouteID]()
	good, _ := Build([]Route{{ID: 1, Host: "example.com", PathPrefix: "/", Upstream: "http://127.0.0.1"}}, func(r Route) (RouteID, error) { return r.ID, nil })
	tbl.Swap(good)
	if _, err := Build([]Route{{ID: 2, Host: "Example.com", PathPrefix: "/", Upstream: "http://127.0.0.1"}}, func(r Route) (RouteID, error) { return r.ID, nil }); err == nil {
		t.Fatal("Build accepted a host that is not canonical")
	}
	if _, id, ok := tbl.Match("example.com", "/"); !ok || id != 1 {
		t.Fatal("a refused build changed the live table")
	}
}

// memRoutes and memDomains keep routes and domains in memory.
type memRoutes struct{ rs []Route }

func (m *memRoutes) All(context.Context) ([]Route, error) { return m.rs, nil }
func (m *memRoutes) Add(_ context.Context, r Route) (Route, error) {
	r.ID = RouteID(len(m.rs) + 1)
	m.rs = append(m.rs, r)
	return r, nil
}
func (m *memRoutes) Update(_ context.Context, r Route) (Route, error) { return r, nil }
func (m *memRoutes) Remove(context.Context, RouteID) (Route, error)   { return Route{}, nil }

type memDomains struct{ ds []Domain }

func (m *memDomains) All(context.Context) ([]Domain, error) { return m.ds, nil }
func (m *memDomains) Add(_ context.Context, d Domain) error {
	m.ds = append(m.ds, d)
	return nil
}
func (m *memDomains) Remove(_ context.Context, name string) error {
	for i, d := range m.ds {
		if d.Name == name {
			m.ds = append(m.ds[:i], m.ds[i+1:]...)
		}
	}
	return nil
}

// TestAHostAutoPanelServesItselfIsReserved: no route may hold the API's host,
// and its domain cannot be removed while that would leave it under none.
func TestAHostAutoPanelServesItselfIsReserved(t *testing.T) {
	ctx := context.Background()
	ds := &memDomains{ds: []Domain{{Name: "example.com"}, {Name: "api.example.com"}}}
	m := NewModule(&memRoutes{}, ds, func(context.Context) error { return nil })
	reserved := []string{"api.example.com"}
	m.SetReserved(func() []string { return reserved })
	if _, err := m.add(ctx, RouteSpec{Host: "API.example.com", Upstream: "http://127.0.0.1:1"}); !errors.Is(err, ErrHostReserved) {
		t.Fatalf("a route on the reserved host: %v", err)
	}
	if _, err := m.update(ctx, RouteSpec{ID: 1, Host: "api.example.com", Upstream: "http://127.0.0.1:1"}); !errors.Is(err, ErrHostReserved) {
		t.Fatalf("a route moved onto the reserved host: %v", err)
	}
	if _, err := m.add(ctx, RouteSpec{Host: "app.example.com", Upstream: "http://127.0.0.1:1"}); err != nil {
		t.Fatalf("another host: %v", err)
	}
	// The narrower domain can go: the parent still covers the host.
	if _, err := m.domainRemove(ctx, DomainRef{Name: "api.example.com"}); err != nil {
		t.Fatalf("removing a domain the parent covers: %v", err)
	}
	if ok, _ := m.Covered(ctx, "api.example.com"); !ok {
		t.Fatal("the host is no longer covered")
	}
	ds.ds = []Domain{{Name: "example.com"}, {Name: "other.net"}}
	m2 := NewModule(&memRoutes{}, ds, func(context.Context) error { return nil })
	m2.SetReserved(func() []string { return reserved })
	if _, err := m2.domainRemove(ctx, DomainRef{Name: "example.com"}); !errors.Is(err, ErrDomainHoldsHost) {
		t.Fatalf("removing the only domain over the reserved host: %v", err)
	}
	reserved = nil // the API turned off
	if _, err := m2.domainRemove(ctx, DomainRef{Name: "example.com"}); err != nil {
		t.Fatalf("with nothing reserved: %v", err)
	}
}

// A route may lead to a tunnel agent's target, named and nothing more.
func TestARouteMayLeadThroughATunnel(t *testing.T) {
	r, err := Route{Host: "Photos.Example.com", Upstream: "tunnel://nas/photos"}.Normalize()
	if err != nil || r.Upstream != "tunnel://nas/photos" || r.Host != "photos.example.com" {
		t.Fatalf("Normalize = %+v, %v", r, err)
	}
	if again, err := r.Normalize(); err != nil || again != r {
		t.Fatalf("a normalized tunnel route is not canonical: %+v, %v", again, err)
	}
}
