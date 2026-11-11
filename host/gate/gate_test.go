package gate

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	core "github.com/yongjohnlee80/autopanel/core/gate"
)

// upstream echoes what the gate forwarded.
func upstream(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Seen-Host", r.Host)
		w.Header().Set("X-Seen-For", r.Header.Get("X-Forwarded-For"))
		w.Header().Set("X-Seen-CF", r.Header.Get("Cf-Connecting-Ip"))
		_, _ = io.WriteString(w, r.URL.Path)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func serve(t *testing.T, tbl *Table, req *http.Request) *http.Response {
	t.Helper()
	rec := httptest.NewRecorder()
	Handler(tbl).ServeHTTP(rec, req)
	return rec.Result()
}

func TestTheGateProxiesByHostAndRefusesTheRest(t *testing.T) {
	up := upstream(t)
	tbl := core.NewTable[http.Handler]()
	snap, err := Build([]core.Route{{ID: 1, Host: "example.com", PathPrefix: "/", Upstream: up.URL}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tbl.Swap(snap)

	req := httptest.NewRequest("GET", "http://Example.COM:443/hello", nil)
	res := serve(t, tbl, req)
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 || string(body) != "/hello" || res.Header.Get("X-Seen-Host") != "Example.COM:443" {
		t.Fatalf("proxied = %d %q host %q", res.StatusCode, body, res.Header.Get("X-Seen-Host"))
	}
	for _, host := range []string{"other.example", "bad host", "[2001:db8::1]"} {
		req := httptest.NewRequest("GET", "http://example.com/", nil)
		req.Host = host
		if res := serve(t, tbl, req); res.StatusCode != 404 {
			t.Errorf("host %q answered %d; want 404", host, res.StatusCode)
		}
	}
}

func TestCFConnectingIPIsBelievedOnlyFromATrustedPeer(t *testing.T) {
	up := upstream(t)
	trusted := Trusted{netip.MustParsePrefix("198.51.100.0/24")}
	tbl := core.NewTable[http.Handler]()
	snap, err := Build([]core.Route{{ID: 1, Host: "example.com", PathPrefix: "/", Upstream: up.URL}}, trusted)
	if err != nil {
		t.Fatal(err)
	}
	tbl.Swap(snap)

	from := func(peer, cf string) *http.Response {
		req := httptest.NewRequest("GET", "http://example.com/", nil)
		req.RemoteAddr = peer
		req.Header.Set("Cf-Connecting-Ip", cf)
		req.Header.Set("X-Forwarded-For", "203.0.113.66") // a client naming itself: always dropped
		return serve(t, tbl, req)
	}
	res := from("198.51.100.7:4000", "203.0.113.9")
	if got := res.Header.Get("X-Seen-For"); got != "203.0.113.9" {
		t.Errorf("from a trusted peer, X-Forwarded-For = %q; want the CF-Connecting-IP", got)
	}
	res = from("192.0.2.7:4000", "203.0.113.9")
	if got, cf := res.Header.Get("X-Seen-For"), res.Header.Get("X-Seen-CF"); got != "192.0.2.7" || cf != "" {
		t.Errorf("from an untrusted peer, X-Forwarded-For = %q and CF-Connecting-IP = %q; want the peer and none", got, cf)
	}
}
