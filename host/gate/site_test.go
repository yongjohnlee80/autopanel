package gate

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	core "github.com/yongjohnlee80/autopanel/core/gate"
)

// A site's route is the core's alone: a stored route (an ID of zero or more)
// cannot name the site's upstream, nor a path of its own.
func TestOnlyTheCoreMakesASitesRoute(t *testing.T) {
	r := core.SiteRoute(3, "blog.example.com")
	if n, err := r.Normalize(); err != nil || n != r || !r.IsSite() || r.ID >= 0 {
		t.Fatalf("the core's route: %+v, %v", n, err)
	}
	for name, bad := range map[string]core.Route{
		"a stored route":     {ID: 7, Host: "blog.example.com", PathPrefix: "/", Upstream: core.SiteUpstream},
		"a route being made": {ID: 0, Host: "blog.example.com", PathPrefix: "/", Upstream: core.SiteUpstream},
		"a path of its own":  {ID: -3, Host: "blog.example.com", PathPrefix: "/x", Upstream: core.SiteUpstream},
		"a socket by name":   {ID: -3, Host: "blog.example.com", PathPrefix: "/", Upstream: "unix:/run/x.sock"},
	} {
		if _, err := bad.Normalize(); !errors.Is(err, core.ErrBadUpstream) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A site with a content host has two routes, of different IDs, both the
// core's and both to the serving process: the gate holds each name (so each
// gets a certificate) and routes each.
func TestASitesContentHostIsRoutedToo(t *testing.T) {
	rs := core.SiteRoutes(3, "blog.example.com", "content.example.com")
	if len(rs) != 2 || rs[0] != core.SiteRoute(3, "blog.example.com") || rs[0].ID == rs[1].ID {
		t.Fatalf("the routes: %+v", rs)
	}
	for _, r := range rs {
		if n, err := r.Normalize(); err != nil || n != r || !r.IsSite() {
			t.Fatalf("%+v: %+v, %v", r, n, err)
		}
	}
	if one := core.SiteRoutes(3, "blog.example.com", ""); len(one) != 1 {
		t.Fatalf("a site with no content host: %+v", one)
	}
	// Two sites' routes never share an ID, a content host's included.
	all := append(rs, core.SiteRoutes(4, "docs.example.com", "files.example.com")...)
	snap, err := Build(all, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	table := core.NewTable[http.Handler]()
	table.Swap(snap)
	seen := map[core.RouteID]bool{}
	for _, r := range all {
		if seen[r.ID] {
			t.Fatalf("an ID twice: %d", r.ID)
		}
		seen[r.ID] = true
		if !table.Holds(r.Host) {
			t.Errorf("the gate does not hold %s", r.Host)
		}
		if got, _, ok := table.Match(r.Host, "/guides/calc/"); !ok || got.ID != r.ID {
			t.Errorf("%s is not routed: %+v, %v", r.Host, got, ok)
		}
	}
}

// The gate serves a site's route from the socket it was told at its start,
// whatever the route says; with none, the answer is 503.
func TestASitesRouteIsServedFromItsSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "site.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "page of "+r.Host)
	})}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })

	snap, err := Build([]core.Route{core.SiteRoute(3, "blog.example.com")}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	table := core.NewTable[http.Handler]()
	table.Swap(snap)
	_, h, ok := table.Match("blog.example.com", "/a/")
	if !ok {
		t.Fatal("no route")
	}
	get := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "https://blog.example.com/a/", nil)
		h.ServeHTTP(rec, req)
		return rec
	}
	SetSiteSocket("")
	if rec := get(); rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("with no socket: %d", rec.Code)
	}
	SetSiteSocket(sock)
	t.Cleanup(func() { SetSiteSocket("") })
	if rec := get(); rec.Code != 200 || rec.Body.String() != "page of blog.example.com" {
		t.Fatalf("from its socket: %d %q", rec.Code, rec.Body.String())
	}
}

// A connection to the serving process is held as an upstream's is: the same
// fixed kernel buffers, small bufio buffers, and an idle pool the ledger
// counts (tifa's review, F1).
func TestASitesConnectionIsBoundedAsAnUpstreams(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "site.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	SetSiteSocket(sock)
	t.Cleanup(func() { SetSiteSocket("") })
	c, err := siteTransport.DialContext(context.Background(), "tcp", "site.local:80")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	raw, err := c.(*net.UnixConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	recv, send, err := socketBuffersOf(raw)
	if err != nil {
		t.Fatal(err)
	}
	// the kernel doubles what is asked for its own bookkeeping
	if recv > 2*upstreamRecvBuffer || send > 2*upstreamSendBuffer {
		t.Fatalf("a site connection's buffers: %d and %d bytes", recv, send)
	}
	if siteTransport.MaxIdleConns != siteIdleConns || siteTransport.WriteBufferSize != 4<<10 || siteTransport.ReadBufferSize != 4<<10 {
		t.Fatalf("the site transport: %+v", siteTransport)
	}
}

// A member's read of a site's document, on the app host, goes to the same
// serving process: its host and its cookie arrive, and the client's address
// is the gate's word.
func TestTheAppHostsDocumentsGoToTheServingProcess(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "site.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _ := r.Cookie("__Host-ap_session")
		value := ""
		if c != nil {
			value = c.Value
		}
		_, _ = io.WriteString(w, r.Host+" "+r.URL.Path+" "+value+" "+r.Header.Get("X-Forwarded-For"))
	})}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	old := siteSocket.Load()
	SetSiteSocket(sock)
	t.Cleanup(func() {
		if old != nil {
			SetSiteSocket(*old)
		} else {
			SetSiteSocket("")
		}
	})
	h := siteDocs(func() Trusted { return Trusted{} })
	req := httptest.NewRequest("GET", "https://app.example.com/s/blog.example.com/plans/", nil)
	req.RemoteAddr = "203.0.113.7:4000"
	req.Header.Set("Cookie", "__Host-ap_session=abc")
	req.Header.Set("X-Forwarded-For", "198.51.100.1") // a client's own claim: dropped
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || rec.Body.String() != "app.example.com /s/blog.example.com/plans/ abc 203.0.113.7" {
		t.Fatalf("through the serving process: %d %q", rec.Code, rec.Body.String())
	}
	SetSiteSocket("")
	siteTransport.CloseIdleConnections() // the connection kept from the request before
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "https://app.example.com/s/blog.example.com/plans/", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("with no serving process: %d", rec.Code)
	}
}
