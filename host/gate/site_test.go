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
