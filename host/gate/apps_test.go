package gate

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	appTestHost   = "web.example.com"
	adminTestHost = "admin.example.com"
	testCookie    = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" // 43 base64url characters
)

// fakeAppCore answers link.session and link.api as a test says.
type fakeAppCore struct {
	mu       sync.Mutex
	sessions []SessionAsk
	calls    []APIAsk
	answer   SessionAnswer
}

func (f *fakeAppCore) call(_ context.Context, verb string, param, out any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch verb {
	case VerbSession:
		f.sessions = append(f.sessions, param.(SessionAsk))
		*out.(*SessionAnswer) = f.answer
	case VerbAPI:
		f.calls = append(f.calls, param.(APIAsk))
		*out.(*APIAnswer) = APIAnswer{Result: []byte(`"ran"`)}
	}
	return nil
}

type appFixture struct {
	core *fakeAppCore
	api  *apiServer
	h    http.Handler
	now  time.Time
}

func newAppFixture(t *testing.T, c *Apps) *appFixture {
	t.Helper()
	f := &appFixture{core: &fakeAppCore{}, now: time.Unix(1_800_000_000, 0)}
	f.api = newAPIServer(f.core, slog.New(slog.NewTextHandler(io.Discard, nil)), func() Trusted { return Trusted{} }, func() bool { return true })
	f.api.logins = newRateTable(loginPerMinute, loginBurst, loginClients, func() time.Time { return f.now })
	if c == nil {
		c = &Apps{Host: appTestHost, AdminHost: adminTestHost, AdminAllow: []string{"198.51.100.0/24"}}
	}
	if err := f.api.setApps(c); err != nil {
		t.Fatal(err)
	}
	f.h = f.api.or(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "routed") }))
	return f
}

type appReq struct {
	method, path, body, host, from string
	header                         map[string]string
	cookie                         string
}

func (f *appFixture) do(r appReq) *httptest.ResponseRecorder {
	var body io.Reader
	if r.body != "" {
		body = strings.NewReader(r.body)
	}
	host := r.host
	if host == "" {
		host = appTestHost
	}
	req := httptest.NewRequest(r.method, "https://"+host+r.path, body)
	req.RemoteAddr = "192.0.2.1:40000"
	if r.from != "" {
		req.RemoteAddr = r.from
	}
	for k, v := range r.header {
		req.Header.Set(k, v)
	}
	if r.cookie != "" {
		req.Header.Set("Cookie", SessionCookie+"="+r.cookie)
	}
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, req)
	return w
}

func (f *appFixture) asked() ([]SessionAsk, []APIAsk) {
	f.core.mu.Lock()
	defer f.core.mu.Unlock()
	return append([]SessionAsk{}, f.core.sessions...), append([]APIAsk{}, f.core.calls...)
}

// TestASignInSetsTheCookieWithEveryAttribute: the core's id goes into a
// __Host- cookie scripts cannot read, never into the body.
func TestASignInSetsTheCookieWithEveryAttribute(t *testing.T) {
	f := newAppFixture(t, nil)
	f.core.answer = SessionAnswer{Result: []byte(`{"csrf":"x"}`), Cookie: testCookie}
	w := f.do(appReq{method: "POST", path: "/v1/session", body: `{"name":"ana","passphrase":"p","code":""}`, cookie: strings.Repeat("B", 43),
		header: map[string]string{"Content-Type": "application/json", "Origin": "https://" + appTestHost, "Sec-Fetch-Site": "same-origin", "User-Agent": "Firefox\x01"}})
	if w.Code != 200 || strings.Contains(w.Body.String(), testCookie) {
		t.Fatalf("the sign-in: %d %q", w.Code, w.Body.String())
	}
	c := w.Header().Get("Set-Cookie")
	for _, part := range []string{SessionCookie + "=" + testCookie, "Path=/", "Secure", "HttpOnly", "SameSite=Strict"} {
		if !strings.Contains(c, part) {
			t.Fatalf("the cookie %q lacks %s", c, part)
		}
	}
	if strings.Contains(c, "Domain") || strings.Contains(c, "Max-Age") || strings.Contains(c, "Expires") {
		t.Fatalf("the cookie %q outlives the browser or leaves the host", c)
	}
	for k, v := range map[string]string{"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
		"Cross-Origin-Opener-Policy": "same-origin", "Content-Security-Policy": appPolicy} {
		if w.Header().Get(k) != v {
			t.Errorf("%s: %q", k, w.Header().Get(k))
		}
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("a CORS header")
	}
	s, _ := f.asked()
	if len(s) != 1 || s[0].Op != SessionOpen || s[0].Host != HostApp || s[0].Authority != appTestHost || s[0].Origin != "https://"+appTestHost ||
		s[0].FetchSite != "same-origin" || s[0].Session != strings.Repeat("B", 43) || s[0].Agent != "Firefox_" || string(s[0].Param) != `{"name":"ana","passphrase":"p","code":""}` {
		t.Fatalf("what the core was asked: %+v", s)
	}
	// signing out clears it, with every attribute
	f.core.answer = SessionAnswer{Clear: true}
	w = f.do(appReq{method: "DELETE", path: "/v1/session", cookie: testCookie, header: map[string]string{"X-AP-CSRF": "tok", "Origin": "https://" + appTestHost}})
	c = w.Header().Get("Set-Cookie")
	if w.Code != 204 || !strings.Contains(c, SessionCookie+"=;") || !strings.Contains(c, "Max-Age=0") || !strings.Contains(c, "Secure") || !strings.Contains(c, "HttpOnly") {
		t.Fatalf("signing out: %d %q", w.Code, c)
	}
	s, _ = f.asked()
	if s[1].Op != SessionEnd || s[1].CSRF != "tok" || s[1].Method != "DELETE" {
		t.Fatalf("the sign-out asked: %+v", s[1])
	}
}

// TestFiveSignInsAMinuteFromAnAddress: the sixth is 429 before the core
// hears of it, from one address or one /64; another address is apart.
func TestFiveSignInsAMinuteFromAnAddress(t *testing.T) {
	f := newAppFixture(t, nil)
	f.core.answer = SessionAnswer{Result: []byte(`{}`)}
	try := func(from string) int {
		return f.do(appReq{method: "POST", path: "/v1/session", body: `{}`, from: from, header: map[string]string{"Content-Type": "application/json"}}).Code
	}
	for i := range 5 {
		if c := try("[2001:db8:1:2::1]:4000"); c != 200 {
			t.Fatalf("sign-in %d: %d", i+1, c)
		}
	}
	if c := try("[2001:db8:1:2::ffff]:4000"); c != 429 {
		t.Fatalf("a sixth from the same /64: %d", c)
	}
	if c := try("192.0.2.50:4000"); c != 200 {
		t.Fatalf("another address: %d", c)
	}
	s, _ := f.asked()
	if len(s) != 6 {
		t.Fatalf("the core heard %d sign-ins", len(s))
	}
	// the other session paths are not sign-ins
	for range 10 {
		if c := f.do(appReq{method: "GET", path: "/v1/session", from: "[2001:db8:1:2::1]:4000", cookie: testCookie}).Code; c == 429 {
			t.Fatal("asking about a session spent a sign-in")
		}
	}
	f.now = f.now.Add(13 * time.Second)
	if c := try("[2001:db8:1:2::1]:4000"); c != 200 {
		t.Fatalf("after a fifth of a minute: %d", c)
	}
}

// TestTheAdminHostIsNobodysUntilNamed: an empty list keeps everyone out,
// before a body is read; the app host's empty list lets anyone in.
func TestTheAdminHostIsNobodysUntilNamed(t *testing.T) {
	f := newAppFixture(t, &Apps{AdminHost: adminTestHost})
	if w := f.do(appReq{method: "POST", path: "/v1/session", host: adminTestHost, body: `{}`, from: "198.51.100.7:1"}); w.Code != 403 || errName(t, w) != "app.not_allowed" {
		t.Fatalf("the admin host with no sources: %d", w.Code)
	}
	f = newAppFixture(t, nil)
	if w := f.do(appReq{method: "GET", path: "/v1/session", host: adminTestHost, from: "203.0.113.1:1"}); w.Code != 403 {
		t.Fatalf("from outside its sources: %d", w.Code)
	}
	f.core.answer = SessionAnswer{Result: []byte(`{}`)}
	if w := f.do(appReq{method: "GET", path: "/v1/session", host: adminTestHost, from: "198.51.100.7:1", cookie: testCookie}); w.Code != 200 {
		t.Fatalf("from inside: %d", w.Code)
	}
	if w := f.do(appReq{method: "GET", path: "/v1/session", from: "203.0.113.1:1", cookie: testCookie}); w.Code != 200 {
		t.Fatalf("the app host from anywhere: %d", w.Code)
	}
	s, _ := f.asked()
	if len(s) != 2 || s[0].Host != HostAdmin || s[1].Host != HostApp {
		t.Fatalf("what the core heard: %+v", s)
	}
	f = newAppFixture(t, &Apps{Host: appTestHost, Allow: []string{"10.0.0.0/8"}})
	if w := f.do(appReq{method: "GET", path: "/v1/session", from: "203.0.113.1:1"}); w.Code != 403 {
		t.Fatalf("the app host outside its sources: %d", w.Code)
	}
}

// TestOneCredentialAHost: a token is refused on an application's host, and a
// token with a cookie is 400; neither reaches the core.
func TestOneCredentialAHost(t *testing.T) {
	f := newAppFixture(t, nil)
	if w := f.do(appReq{method: "POST", path: "/v1/call/auth.whoami", header: map[string]string{"Authorization": goodBearer}, cookie: testCookie}); w.Code != 400 {
		t.Fatalf("both: %d", w.Code)
	}
	if w := f.do(appReq{method: "POST", path: "/v1/call/auth.whoami", header: map[string]string{"Authorization": goodBearer}}); w.Code != 401 {
		t.Fatalf("a token: %d", w.Code)
	}
	if w := f.do(appReq{method: "POST", path: "/v1/call/auth.whoami"}); w.Code != 401 {
		t.Fatalf("no cookie: %d", w.Code)
	}
	s, c := f.asked()
	if len(s)+len(c) != 0 {
		t.Fatal("a refused request reached the core")
	}
}

// TestASessionCallReachesTheCoreAsItCame: the cookie, the second token and
// what the request says of its origin go to the core as sent.
func TestASessionCallReachesTheCoreAsItCame(t *testing.T) {
	f := newAppFixture(t, nil)
	w := f.do(appReq{method: "POST", path: "/v1/call/auth.token.list", body: `{}`, cookie: testCookie,
		header: map[string]string{"Content-Type": "application/json", "X-AP-CSRF": "tok", "Origin": "https://evil.example.net", "Sec-Fetch-Site": "cross-site"}})
	if w.Code != 200 || w.Body.String() != `"ran"` {
		t.Fatalf("the call: %d %q", w.Code, w.Body.String())
	}
	_, c := f.asked()
	if len(c) != 1 || c[0].Verb != "auth.token.list" || c[0].Session != testCookie || c[0].CSRF != "tok" || c[0].Origin != "https://evil.example.net" ||
		c[0].FetchSite != "cross-site" || c[0].Host != HostApp || c[0].Authority != appTestHost || c[0].Token != "" || c[0].Method != "POST" {
		t.Fatalf("what the core was asked: %+v", c)
	}
	// a cookie of another shape is no session, and still a cookie
	f.do(appReq{method: "POST", path: "/v1/call/auth.whoami", cookie: "short"})
	if _, c = f.asked(); len(c) != 2 || c[1].Session != "" {
		t.Fatalf("a malformed cookie: %+v", c)
	}
	for _, r := range []appReq{
		{method: "GET", path: "/"},
		{method: "GET", path: "/v1/nothing", cookie: testCookie},
		{method: "GET", path: "/v1/call/auth.whoami", cookie: testCookie},
		{method: "PUT", path: "/v1/session", cookie: testCookie},
		{method: "GET", path: "/v1/session/csrf", cookie: testCookie},
	} {
		if w := f.do(r); w.Code != 404 && w.Code != 405 {
			t.Errorf("%s %s: %d", r.method, r.path, w.Code)
		}
	}
	if w := f.do(appReq{method: "GET", path: "/", host: "other.example.com"}); w.Body.String() != "routed" {
		t.Fatal("another host did not reach the routes")
	}
	if !f.api.isHost(appTestHost) || !f.api.isHost(adminTestHost) || f.api.isHost("other.example.com") {
		t.Fatal("the application hosts' certificates")
	}
	if err := f.api.setApps(nil); err != nil || f.api.isHost(appTestHost) {
		t.Fatal("turned off, the app host stays")
	}
	if err := f.api.setApps(&Apps{Host: appTestHost, Allow: []string{"nope"}}); err == nil {
		t.Fatal("a source that is no prefix")
	}
}

// TestTheAppHostPassesASitesDocumentToTheServingProcess: GET and HEAD under
// /s/ on the app host go to the sites' serving process, with the request's
// host and cookies and none of the app host's own headers; nothing reaches
// the core through the link; the admin host has no such path.
func TestTheAppHostPassesASitesDocumentToTheServingProcess(t *testing.T) {
	f := newAppFixture(t, &Apps{Host: appTestHost, Allow: []string{"192.0.2.0/24"}, AdminHost: adminTestHost, AdminAllow: []string{"192.0.2.0/24"}})
	var got *http.Request
	f.api.site = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		w.Header().Set("Cache-Control", "private, no-store")
		_, _ = io.WriteString(w, "the document")
	})
	const doc = "/s/blog.example.com/plans/"
	rec := f.do(appReq{method: "GET", path: doc, cookie: "abc"})
	if rec.Code != 200 || rec.Body.String() != "the document" || got == nil || got.Host != appTestHost || got.URL.Path != doc {
		t.Fatalf("a document on the app host: %d %q", rec.Code, rec.Body.String())
	}
	if c, err := got.Cookie(SessionCookie); err != nil || c.Value != "abc" {
		t.Fatalf("the session cookie did not reach the serving process: %v", err)
	}
	if csp := rec.Header().Values("Content-Security-Policy"); len(csp) != 1 || csp[0] != "default-src 'none'" {
		t.Fatalf("the policy is not the serving process's alone: %v", csp)
	}
	if cc := rec.Header().Values("Cache-Control"); len(cc) != 1 || cc[0] != "private, no-store" {
		t.Fatalf("the caching is not the serving process's alone: %v", cc)
	}
	if rec.Header().Get("Strict-Transport-Security") == "" {
		t.Error("no HSTS on the app host")
	}
	if sessions, calls := f.asked(); len(sessions) != 0 || len(calls) != 0 {
		t.Fatalf("a document's read reached the core's link: %v %v", sessions, calls)
	}
	got = nil
	for what, tc := range map[string]struct {
		r    appReq
		code int
	}{
		"a POST":                  {appReq{method: "POST", path: doc, body: "{}"}, http.StatusMethodNotAllowed},
		"an address not let in":   {appReq{method: "GET", path: doc, from: "203.0.113.9:1"}, http.StatusForbidden},
		"the admin host":          {appReq{method: "GET", path: doc, host: adminTestHost}, http.StatusNotFound},
		"a path that only starts": {appReq{method: "GET", path: "/sx/blog.example.com/"}, http.StatusNotFound},
	} {
		if rec := f.do(tc.r); rec.Code != tc.code || got != nil {
			t.Errorf("%s: %d, reached the serving process: %v", what, rec.Code, got != nil)
		}
	}
	// With no serving process there is nothing under /s/.
	f.api.site = nil
	if rec := f.do(appReq{method: "GET", path: doc}); rec.Code != http.StatusNotFound {
		t.Errorf("no serving process: %d", rec.Code)
	}
}
