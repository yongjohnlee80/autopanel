package gate

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeAPICore answers link.api as a test says.
type fakeAPICore struct {
	mu     sync.Mutex
	asks   []APIAsk
	answer func(APIAsk) (APIAnswer, error)
	hold   chan struct{} // when set, a call waits for it to close
}

func (f *fakeAPICore) call(ctx context.Context, verb string, param, out any) error {
	if verb != VerbAPI {
		return errors.New("the API called " + verb)
	}
	ask := param.(APIAsk)
	f.mu.Lock()
	f.asks = append(f.asks, ask)
	hold, answer := f.hold, f.answer
	f.mu.Unlock()
	if hold != nil {
		select {
		case <-hold:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	ans := APIAnswer{Result: []byte(`{"ok":true}`)}
	if answer != nil {
		var err error
		if ans, err = answer(ask); err != nil {
			return err
		}
	}
	*out.(*APIAnswer) = ans
	return nil
}

func (f *fakeAPICore) asked() []APIAsk {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]APIAsk{}, f.asks...)
}

const (
	apiTestHost = "api.example.com"
	goodBearer  = "Bearer apt_7_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

// apiFixture is an API server on apiTestHost, with a routing table behind it
// that answers "routed".
type apiFixture struct {
	core    *fakeAPICore
	api     *apiServer
	h       http.Handler
	up      bool
	trusted Trusted
}

func newAPIFixture(t *testing.T, c *API) *apiFixture {
	t.Helper()
	f := &apiFixture{core: &fakeAPICore{}, up: true}
	f.api = newAPIServer(f.core, slog.New(slog.NewTextHandler(io.Discard, nil)), func() Trusted { return f.trusted }, func() bool { return f.up })
	if c == nil {
		c = &API{Host: apiTestHost}
	}
	if err := f.api.set(c); err != nil {
		t.Fatal(err)
	}
	f.h = f.api.or(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "routed") }))
	return f
}

type apiReq struct {
	method, path, body string
	header             map[string]string
	from               string // the peer; 192.0.2.1 unless set
	host               string // apiTestHost unless set
}

func (f *apiFixture) do(r apiReq) *httptest.ResponseRecorder {
	var body io.Reader
	if r.body != "" {
		body = strings.NewReader(r.body)
	}
	req := httptest.NewRequest(r.method, "https://"+apiTestHost+r.path, body)
	if r.host != "" {
		req.Host = r.host
	}
	req.RemoteAddr = "192.0.2.1:40000"
	if r.from != "" {
		req.RemoteAddr = r.from
	}
	for k, v := range r.header {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, req)
	return w
}

func errName(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var e struct {
		Error struct {
			Name string `json:"name"`
		} `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil {
		t.Fatalf("a refusal that is not the error shape: %q", w.Body.String())
	}
	return e.Error.Name
}

// TestAnAPICallReachesTheCoreAsItCame: the verb, the body, the token and the
// client go to the core untouched, and its result comes back as it is.
func TestAnAPICallReachesTheCoreAsItCame(t *testing.T) {
	f := newAPIFixture(t, nil)
	w := f.do(apiReq{method: "POST", path: "/v1/call/gate.route.list", body: `{"a":1}`,
		header: map[string]string{"Authorization": goodBearer, "Content-Type": "application/json; charset=utf-8", "X-Request-Id": "req-1_A"}})
	if w.Code != 200 || w.Body.String() != `{"ok":true}` || w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("the answer: %d %q %v", w.Code, w.Body.String(), w.Header())
	}
	asks := f.core.asked()
	if len(asks) != 1 {
		t.Fatalf("the core was asked %d times", len(asks))
	}
	a := asks[0]
	if a.Verb != "gate.route.list" || string(a.Param) != `{"a":1}` || a.Token != strings.TrimPrefix(goodBearer, "Bearer ") || a.Client != "192.0.2.1" || a.RequestID != "req-1_A" {
		t.Fatalf("what the core got: %+v", a)
	}
	if w.Header().Get("X-Request-Id") != "req-1_A" || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("the headers: %v", w.Header())
	}
	// The contracts are a verb of the core's, by GET.
	if w := f.do(apiReq{method: "GET", path: "/v1/contracts", header: map[string]string{"Authorization": goodBearer}}); w.Code != 200 {
		t.Fatalf("/v1/contracts: %d", w.Code)
	}
	if a := f.core.asked()[1]; a.Verb != "api.contracts" || len(a.Param) != 0 {
		t.Fatalf("the contracts ask: %+v", a)
	}
	// An empty result is JSON too.
	f.core.answer = func(APIAsk) (APIAnswer, error) { return APIAnswer{}, nil }
	if w := f.do(apiReq{method: "POST", path: "/v1/call/x", header: map[string]string{"Authorization": goodBearer}}); w.Body.String() != "null" {
		t.Fatalf("an empty result: %q", w.Body.String())
	}
}

// TestWithoutATokenEveryRequestGetsOneAnswer: a missing or malformed token is
// 401 whatever the verb, the method or the size, and the core is never asked:
// nothing about either catalog or any limit is told to a stranger.
func TestWithoutATokenEveryRequestGetsOneAnswer(t *testing.T) {
	f := newAPIFixture(t, &API{Host: apiTestHost, Large: []APIVerb{{Verb: "site.article.put", MaxBody: 1 << 20}}})
	f.api.rate = newRateTable(100000, 100000, 16, time.Now) // the rate is not what this test is about
	big := strings.Repeat("x", 100<<10)
	for _, auth := range []string{"", "Basic abc", "Bearer nope", "Bearer apt_x_" + strings.Repeat("a", 43), "Bearer apt_7_short",
		"Bearer apt_7_" + strings.Repeat("a", 42) + "!", "bearer apt_7_" + strings.Repeat("a", 43), "Bearer apt_7_" + strings.Repeat("a", 300),
		"Bearer apt_0_" + strings.Repeat("a", 43), "Bearer apt_9999999999999999999_" + strings.Repeat("a", 43), "Bearer apt_+7_" + strings.Repeat("a", 43)} {
		for _, r := range []apiReq{
			{method: "POST", path: "/v1/call/sys.status", body: big},
			{method: "POST", path: "/v1/call/site.article.put", body: big},
			{method: "POST", path: "/v1/call/no.such.verb"},
			{method: "GET", path: "/v1/call/sys.status"},
			{method: "GET", path: "/v1/contracts"},
			{method: "GET", path: "/nothing"},
			{method: "POST", path: "/v1/call/BAD%20verb"},
		} {
			r.header = map[string]string{"Authorization": auth, "Content-Type": "application/json", "Cookie": "session=" + strings.TrimPrefix(goodBearer, "Bearer ")}
			if auth == "" {
				delete(r.header, "Authorization")
			}
			w := f.do(r)
			if w.Code != 401 || errName(t, w) != "api.unauthorized" || w.Header().Get("WWW-Authenticate") != "Bearer" {
				t.Errorf("%s %s with %q: %d %s", r.method, r.path, auth, w.Code, w.Body.String())
			}
		}
	}
	if n := len(f.core.asked()); n != 0 {
		t.Fatalf("the core was asked %d times for requests with no token", n)
	}
}

// TestTheGateRefusesByShapeAndSize: with a well-formed token, a path that is
// no verb is 404, a wrong method 405, a body over the verb's limit 413, a body
// that is not JSON 415; none of them reaches the core.
func TestTheGateRefusesByShapeAndSize(t *testing.T) {
	f := newAPIFixture(t, &API{Host: apiTestHost, Large: []APIVerb{{Verb: "site.asset.put", MaxBody: 200 << 10}}})
	auth := map[string]string{"Authorization": goodBearer, "Content-Type": "application/json"}
	over := strings.Repeat("x", apiBody+1)
	for _, c := range []struct {
		r    apiReq
		code int
		name string
	}{
		{apiReq{method: "GET", path: "/"}, 404, "api.not_found"},
		{apiReq{method: "POST", path: "/v1/call/"}, 404, "api.not_found"},
		{apiReq{method: "POST", path: "/v1/call/a/b"}, 404, "api.not_found"},
		{apiReq{method: "POST", path: "/v1/call/Sys.Status"}, 404, "api.not_found"},
		{apiReq{method: "POST", path: "/v1//call/sys.status"}, 404, "api.not_found"},
		{apiReq{method: "POST", path: "/v1/call/../call/sys.status"}, 404, "api.not_found"},
		{apiReq{method: "GET", path: "/v1/call/sys.status"}, 405, "api.method"},
		{apiReq{method: "POST", path: "/v1/contracts"}, 405, "api.method"},
		{apiReq{method: "OPTIONS", path: "/v1/call/sys.status"}, 405, "api.method"},
		{apiReq{method: "POST", path: "/v1/call/sys.status", body: over}, 413, "api.too_large"},
		{apiReq{method: "POST", path: "/v1/call/site.asset.put", body: strings.Repeat("x", 200<<10+1)}, 413, "api.too_large"},
	} {
		c.r.header = auth
		w := f.do(c.r)
		if w.Code != c.code || errName(t, w) != c.name {
			t.Errorf("%s %s: %d %s; want %d %s", c.r.method, c.r.path, w.Code, w.Body.String(), c.code, c.name)
		}
		if loc := w.Header().Get("Location"); loc != "" || w.Code/100 == 3 {
			t.Errorf("%s %s was redirected to %q", c.r.method, c.r.path, loc)
		}
	}
	if w := f.do(apiReq{method: "POST", path: "/v1/call/sys.status", body: `{}`, header: map[string]string{"Authorization": goodBearer, "Content-Type": "text/plain"}}); w.Code != 415 {
		t.Errorf("a body that is not JSON: %d", w.Code)
	}
	if n := len(f.core.asked()); n != 0 {
		t.Fatalf("the core was asked %d times", n)
	}
	// A larger body is taken for the verb that declares it, and only that one.
	if w := f.do(apiReq{method: "POST", path: "/v1/call/site.asset.put", body: `{"data":"` + strings.Repeat("x", 150<<10) + `"}`, header: auth}); w.Code != 200 {
		t.Fatalf("a larger body for the verb that takes one: %d %s", w.Code, w.Body.String())
	}
}

// TestTheCoresRefusalsBecomeStatuses: each kind of refusal has its status, and
// the error crosses as the core wrote it.
func TestTheCoresRefusalsBecomeStatuses(t *testing.T) {
	f := newAPIFixture(t, nil)
	for kind, code := range map[string]int{APIToken: 401, APIForbidden: 403, APINotFound: 404, APIBadParam: 400, APIFailed: 422, APIInternal: 500, "new-kind": 500} {
		f.core.answer = func(APIAsk) (APIAnswer, error) {
			return APIAnswer{Error: &APIError{Kind: kind, Code: -32162, Name: "auth.forbidden", Message: "your role may not do that"}}, nil
		}
		w := f.do(apiReq{method: "POST", path: "/v1/call/sys.status", header: map[string]string{"Authorization": goodBearer}})
		if w.Code != code || !strings.Contains(w.Body.String(), `"code":-32162`) || !strings.Contains(w.Body.String(), `"message":"your role may not do that"`) {
			t.Errorf("%s: %d %s; want %d", kind, w.Code, w.Body.String(), code)
		}
	}
	// A core that does not answer is 503; an answer over the limit is 500 and not sent.
	f.core.answer = func(APIAsk) (APIAnswer, error) { return APIAnswer{}, errors.New("the link is down") }
	if w := f.do(apiReq{method: "POST", path: "/v1/call/sys.status", header: map[string]string{"Authorization": goodBearer}}); w.Code != 503 || errName(t, w) != "api.unavailable" {
		t.Errorf("a core that does not answer: %d %s", w.Code, w.Body.String())
	}
	f.core.answer = func(APIAsk) (APIAnswer, error) { return APIAnswer{Result: make([]byte, apiAnswer+1)}, nil }
	if w := f.do(apiReq{method: "POST", path: "/v1/call/sys.status", header: map[string]string{"Authorization": goodBearer}}); w.Code != 500 || w.Body.Len() > 1024 {
		t.Errorf("an answer over the limit: %d, %d bytes", w.Code, w.Body.Len())
	}
}

// TestTheAPIsHostIsNeverRouted: a request for the API's host is the gate's own
// whatever its path; any other host goes to the table; with the API off, its
// host is a name like any other.
func TestTheAPIsHostIsNeverRouted(t *testing.T) {
	f := newAPIFixture(t, nil)
	if w := f.do(apiReq{method: "GET", path: "/anything", header: map[string]string{"Authorization": goodBearer}}); w.Body.String() == "routed" {
		t.Fatal("the API's host reached the routing table")
	}
	if w := f.do(apiReq{method: "GET", path: "/", host: "API.Example.com:443", header: map[string]string{"Authorization": goodBearer}}); w.Body.String() == "routed" {
		t.Fatal("the API's host, written another way, reached the routing table")
	}
	if w := f.do(apiReq{method: "GET", path: "/v1/health", host: "app.example.com"}); w.Body.String() != "routed" {
		t.Fatalf("another host did not reach the table: %q", w.Body.String())
	}
	if err := f.api.set(nil); err != nil {
		t.Fatal(err)
	}
	if w := f.do(apiReq{method: "GET", path: "/v1/health"}); w.Body.String() != "routed" || f.api.isHost(apiTestHost) {
		t.Fatalf("with the API off its host is still the gate's: %q", w.Body.String())
	}
	// No CORS header is ever sent.
	_ = f.api.set(&API{Host: apiTestHost})
	w := f.do(apiReq{method: "POST", path: "/v1/call/sys.status", header: map[string]string{"Authorization": goodBearer, "Origin": "https://evil.example"}})
	for k := range w.Header() {
		if strings.HasPrefix(k, "Access-Control-") {
			t.Fatalf("a CORS header was sent: %s", k)
		}
	}
}

// TestHealthCostsTheCoreNothing: /v1/health needs no token, says what the gate
// already knows, and never asks the core.
func TestHealthCostsTheCoreNothing(t *testing.T) {
	f := newAPIFixture(t, nil)
	for range 500 { // far past the rate: health is not counted against it
		if w := f.do(apiReq{method: "GET", path: "/v1/health"}); w.Code != 200 || w.Body.String() != `{"status":"ok"}` {
			t.Fatalf("health: %d %q", w.Code, w.Body.String())
		}
	}
	f.up = false
	if w := f.do(apiReq{method: "GET", path: "/v1/health"}); w.Code != 503 {
		t.Fatalf("health with the core away: %d", w.Code)
	}
	if w := f.do(apiReq{method: "POST", path: "/v1/health"}); w.Code != 405 {
		t.Fatalf("POST /v1/health: %d", w.Code)
	}
	if n := len(f.core.asked()); n != 0 {
		t.Fatalf("health asked the core %d times", n)
	}
}

// TestOnlyAllowedSourcesReachTheAPI: with source ranges set, any other address
// is refused first, health included; behind a trusted proxy the client is the
// one the proxy names.
func TestOnlyAllowedSourcesReachTheAPI(t *testing.T) {
	f := newAPIFixture(t, &API{Host: apiTestHost, Allow: []string{"198.51.100.0/24", "2001:db8:1::/48"}})
	auth := map[string]string{"Authorization": goodBearer}
	for from, want := range map[string]int{"198.51.100.9:1": 200, "[2001:db8:1:2::3]:1": 200, "192.0.2.1:1": 403, "[2001:db8:2::1]:1": 403, "[::ffff:198.51.100.9]:1": 200} {
		if w := f.do(apiReq{method: "POST", path: "/v1/call/sys.status", header: auth, from: from}); w.Code != want {
			t.Errorf("from %s: %d; want %d", from, w.Code, want)
		}
	}
	if w := f.do(apiReq{method: "GET", path: "/v1/health", from: "192.0.2.1:1"}); w.Code != 403 || errName(t, w) != "api.not_allowed" {
		t.Errorf("health from outside the ranges: %d", w.Code)
	}
	// CF-Connecting-IP names the client only from a trusted peer.
	named := map[string]string{"Authorization": goodBearer, "Cf-Connecting-Ip": "198.51.100.7"}
	if w := f.do(apiReq{method: "POST", path: "/v1/call/sys.status", header: named, from: "192.0.2.1:1"}); w.Code != 403 {
		t.Errorf("a stranger naming an allowed client: %d", w.Code)
	}
	f.trusted = Trusted{netip.MustParsePrefix("192.0.2.0/24")}
	if w := f.do(apiReq{method: "POST", path: "/v1/call/sys.status", header: named, from: "192.0.2.1:1"}); w.Code != 200 {
		t.Errorf("a trusted proxy naming an allowed client: %d", w.Code)
	}
	if a := f.core.asked(); a[len(a)-1].Client != "198.51.100.7" {
		t.Errorf("the client the core was told: %s", a[len(a)-1].Client)
	}
	if err := f.api.set(&API{Host: apiTestHost, Allow: []string{"not a prefix"}}); err == nil {
		t.Error("a source that is no prefix was accepted")
	}
}

// TestRequestsAreLimitedByClient: one address has a burst and then a rate; an
// IPv6 /64 is one client; another client is not held back.
func TestRequestsAreLimitedByClient(t *testing.T) {
	f := newAPIFixture(t, nil)
	now := time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC)
	f.api.rate = newRateTable(apiPerMinute, apiBurst, apiClients, func() time.Time { return now })
	auth := map[string]string{"Authorization": goodBearer}
	call := func(from string) *httptest.ResponseRecorder {
		return f.do(apiReq{method: "POST", path: "/v1/call/sys.status", header: auth, from: from})
	}
	for i := range apiBurst {
		if w := call("192.0.2.1:1"); w.Code != 200 {
			t.Fatalf("request %d of the burst: %d", i+1, w.Code)
		}
	}
	w := call("192.0.2.1:2")
	if w.Code != 429 || w.Header().Get("Retry-After") == "" || errName(t, w) != "api.rate" {
		t.Fatalf("past the burst: %d %v", w.Code, w.Header())
	}
	if w := call("192.0.2.2:1"); w.Code != 200 {
		t.Fatalf("another client was held back: %d", w.Code)
	}
	now = now.Add(time.Second) // one a second
	if w := call("192.0.2.1:1"); w.Code != 200 {
		t.Fatalf("a second later: %d", w.Code)
	}
	if w := call("192.0.2.1:1"); w.Code != 429 {
		t.Fatalf("and at once again: %d", w.Code)
	}
	for i := range apiBurst {
		if w := call("[2001:db8::" + string(rune('1'+i%9)) + "]:1"); w.Code != 200 {
			t.Fatalf("request %d from one /64: %d", i+1, w.Code)
		}
	}
	if w := call("[2001:db8::ffff]:1"); w.Code != 429 {
		t.Fatalf("another address of the same /64: %d", w.Code)
	}
	if w := call("[2001:db8:0:1::1]:1"); w.Code != 200 {
		t.Fatalf("another /64: %d", w.Code)
	}
}

// TestTheRateTableIsBounded: it remembers a fixed number of clients.
func TestTheRateTableIsBounded(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	rt := newRateTable(60, 20, 8, func() time.Time { return now })
	for i := range 1000 {
		rt.take(netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}).String())
		now = now.Add(time.Millisecond)
	}
	if n := len(rt.buckets); n > 8 {
		t.Fatalf("the table holds %d clients; its bound is 8", n)
	}
}

// TestCallsInFlightAreBounded: at most apiInFlight calls are with the core at
// once, and of those at most apiLargeInFlight to a verb with a larger body;
// one more waits a short while and is refused.
func TestCallsInFlightAreBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for the slot timeout")
	}
	f := newAPIFixture(t, &API{Host: apiTestHost, Large: []APIVerb{{Verb: "site.asset.put", MaxBody: 1 << 20}}})
	f.api.rate = newRateTable(100000, 100000, 16, time.Now)
	f.core.hold = make(chan struct{})
	auth := map[string]string{"Authorization": goodBearer}
	var wg sync.WaitGroup
	codes := make(chan int, 32)
	start := func(verb string) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes <- f.do(apiReq{method: "POST", path: "/v1/call/" + verb, header: auth}).Code
		}()
	}
	waitAsked := func(n int) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for len(f.core.asked()) < n {
			if time.Now().After(deadline) {
				t.Fatalf("only %d calls reached the core; want %d", len(f.core.asked()), n)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	for range apiLargeInFlight {
		start("site.asset.put")
	}
	waitAsked(apiLargeInFlight)
	// A third large call is refused while small ones still get in.
	if w := f.do(apiReq{method: "POST", path: "/v1/call/site.asset.put", header: auth}); w.Code != 503 || errName(t, w) != "api.busy" {
		t.Fatalf("a third large call: %d", w.Code)
	}
	for range apiInFlight - apiLargeInFlight {
		start("sys.status")
	}
	waitAsked(apiInFlight)
	if w := f.do(apiReq{method: "POST", path: "/v1/call/sys.status", header: auth}); w.Code != 503 {
		t.Fatalf("a ninth call: %d", w.Code)
	}
	if n := len(f.core.asked()); n != apiInFlight {
		t.Fatalf("%d calls reached the core; the bound is %d", n, apiInFlight)
	}
	close(f.core.hold)
	wg.Wait()
	close(codes)
	for c := range codes {
		if c != 200 {
			t.Fatalf("a held call ended %d", c)
		}
	}
	if len(f.api.slots) != 0 || len(f.api.large) != 0 {
		t.Fatalf("slots were not given back: %d, %d", len(f.api.slots), len(f.api.large))
	}
}

// TestARequestIDIsValidatedOrMade: an id that is not one is replaced.
func TestARequestIDIsValidatedOrMade(t *testing.T) {
	f := newAPIFixture(t, nil)
	for _, bad := range []string{"", "has space", "a\"b", strings.Repeat("x", 65), "ünï"} {
		w := f.do(apiReq{method: "POST", path: "/v1/call/sys.status", header: map[string]string{"Authorization": goodBearer, "X-Request-Id": bad}})
		got := w.Header().Get("X-Request-Id")
		if got == bad || len(got) != 24 || requestID(got) != got {
			t.Errorf("the id for %q: %q", bad, got)
		}
	}
}

// TestTheAPIIsNotServedWithoutTLS: on the plain listener the API's host is
// refused, not sent on to HTTPS: a token sent in the clear is not asked for again.
func TestTheAPIIsNotServedWithoutTLS(t *testing.T) {
	f := newAPIFixture(t, nil)
	plain := f.api.notPlain(http.HandlerFunc(toHTTPS))
	req := httptest.NewRequest("POST", "http://"+apiTestHost+"/v1/call/sys.status", nil)
	req.Header.Set("Authorization", goodBearer)
	w := httptest.NewRecorder()
	plain.ServeHTTP(w, req)
	if w.Code != 400 || w.Header().Get("Location") != "" {
		t.Fatalf("the API's host without TLS: %d, to %q", w.Code, w.Header().Get("Location"))
	}
	w = httptest.NewRecorder()
	plain.ServeHTTP(w, httptest.NewRequest("GET", "http://app.example.com/x", nil))
	if w.Code != http.StatusPermanentRedirect {
		t.Fatalf("another host without TLS: %d", w.Code)
	}
}
