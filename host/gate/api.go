package gate

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	core "github.com/yongjohnlee80/autopanel/core/gate"
)

// THE HTTPS API — served by the gate on one host of its own, to API tokens.
// The gate decides nothing about who may do what: it checks a request's
// source, rate, shape and size, then passes the verb, the body and the token
// to the core over link.api, and writes back what the core answers. It never
// reads a token beyond its shape, and it keeps none.
//
// Decision: docs/decisions/api.md

// The API's limits. Their sum is held against the gate's memory: at most
// apiInFlight calls, of which apiLargeInFlight may carry a larger body, each
// body and answer held once as JSON and once in the link's framing.
const (
	apiInFlight      = 8
	apiLargeInFlight = 2
	apiBody          = 64 << 10 // a verb that declares no limit
	apiAnswer        = 1 << 20
	apiLargeAnswer   = 64 << 10 // a verb with a larger body answers little
	apiSlotWait      = 2 * time.Second
	apiCallTime      = 30 * time.Second
	apiPerMinute     = 60 // requests a minute from one client
	apiBurst         = 20
	apiClients       = 4096 // clients whose rate is remembered
)

// apiCaller is the link, as the API uses it.
type apiCaller interface {
	call(ctx context.Context, verb string, param, out any) error
}

// apiState is the API's settings as the core last sent them.
type apiState struct {
	host  string
	allow []netip.Prefix
	large map[string]int // a verb's body limit, where it declares one
}

// apiServer serves the API's host.
type apiServer struct {
	link    apiCaller
	log     *slog.Logger
	trusted func() Trusted
	up      func() bool // the link answered last time it was asked

	conf  atomic.Pointer[apiState]
	slots chan struct{} // every call in flight
	large chan struct{} // those with a larger body
	rate  *rateTable
}

func newAPIServer(l apiCaller, log *slog.Logger, trusted func() Trusted, up func() bool) *apiServer {
	return &apiServer{link: l, log: log, trusted: trusted, up: up,
		slots: make(chan struct{}, apiInFlight), large: make(chan struct{}, apiLargeInFlight),
		rate: newRateTable(apiPerMinute, apiBurst, apiClients, time.Now)}
}

// set takes the core's settings; nil turns the API off.
func (a *apiServer) set(c *API) error {
	if c == nil || c.Host == "" {
		a.conf.Store(nil)
		return nil
	}
	st := &apiState{host: c.Host, large: map[string]int{}}
	for _, s := range c.Allow {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return errors.New("gate: the core sent an allowed source that is no prefix: " + strconv.Quote(s))
		}
		st.allow = append(st.allow, p.Masked())
	}
	for _, v := range c.Large {
		st.large[v.Verb] = v.MaxBody
	}
	a.conf.Store(st)
	return nil
}

// isHost reports whether name is the API's host.
func (a *apiServer) isHost(name string) bool {
	st := a.conf.Load()
	return st != nil && st.host == name
}

// or serves the API's host itself and passes every other request to next: a
// request for the API's host never reaches the routing table.
func (a *apiServer) or(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st := a.conf.Load()
		if st != nil {
			if host, err := core.CanonicalHost(r.Host); err == nil && host == st.host {
				a.serve(w, r, st)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// notPlain refuses the API's host on the plain listener: a client that sent
// its token without TLS is not sent on to HTTPS to do it again.
func (a *apiServer) notPlain(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if host, err := core.CanonicalHost(r.Host); err == nil && a.isHost(host) {
			apiError(w, http.StatusBadRequest, 0, "api.https_only", "the API is served over HTTPS only")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *apiServer) serve(w http.ResponseWriter, r *http.Request, st *apiState) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	id := requestID(r.Header.Get("X-Request-Id"))
	h.Set("X-Request-Id", id)

	client := a.client(r)
	if len(st.allow) > 0 && !allowed(st.allow, client) {
		apiError(w, http.StatusForbidden, 0, "api.not_allowed", "this address may not call the API")
		return
	}
	// The path as it was sent: no cleaning, so nothing is ever redirected.
	path := r.URL.EscapedPath()
	if path == "/v1/health" {
		a.health(w, r)
		return
	}
	if wait, ok := a.rate.take(rateKey(client)); !ok {
		h.Set("Retry-After", strconv.Itoa(wait))
		apiError(w, http.StatusTooManyRequests, 0, "api.rate", "too many requests; wait and try again")
		return
	}
	verb, method := "", ""
	switch {
	case path == "/v1/contracts":
		verb, method = "api.contracts", http.MethodGet
	case strings.HasPrefix(path, "/v1/call/"):
		verb, method = path[len("/v1/call/"):], http.MethodPost
	}
	// The token's shape before anything a verb decides (its size limit, a
	// slot): without a well-formed token every request gets this one answer.
	token, ok := bearer(r.Header.Get("Authorization"))
	if !ok {
		h.Set("WWW-Authenticate", "Bearer")
		apiError(w, http.StatusUnauthorized, 0, "api.unauthorized", "no valid API token")
		return
	}
	switch {
	case !validVerb(verb):
		apiError(w, http.StatusNotFound, 0, "api.not_found", "no such verb")
		return
	case r.Method != method:
		h.Set("Allow", method)
		apiError(w, http.StatusMethodNotAllowed, 0, "api.method", "that path takes "+method)
		return
	}
	limit, isLarge := st.large[verb]
	if !isLarge {
		limit = apiBody
	}
	if r.ContentLength > int64(limit) {
		apiError(w, http.StatusRequestEntityTooLarge, 0, "api.too_large", "the body is larger than this verb takes")
		return
	}
	// A slot before the body is read: what is in memory is bounded by the slots.
	release, ok := a.enter(r.Context(), isLarge)
	if !ok {
		h.Set("Retry-After", "2")
		apiError(w, http.StatusServiceUnavailable, 0, "api.busy", "the API is busy; try again")
		return
	}
	defer release()
	var body []byte
	if r.Method == http.MethodPost {
		b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, int64(limit)))
		var tooLarge *http.MaxBytesError
		switch {
		case errors.As(err, &tooLarge):
			apiError(w, http.StatusRequestEntityTooLarge, 0, "api.too_large", "the body is larger than this verb takes")
			return
		case err != nil:
			apiError(w, http.StatusBadRequest, 0, "api.bad_request", "the body could not be read")
			return
		}
		if len(b) > 0 && !isJSON(r.Header.Get("Content-Type")) {
			apiError(w, http.StatusUnsupportedMediaType, 0, "api.not_json", "a body must be application/json")
			return
		}
		body = b
	}
	ctx, cancel := context.WithTimeout(r.Context(), apiCallTime)
	defer cancel()
	var ans APIAnswer
	if err := a.link.call(ctx, VerbAPI, APIAsk{Verb: verb, Param: body, Token: token, Client: client.String(), RequestID: id}, &ans); err != nil {
		if r.Context().Err() == nil {
			a.log.Warn("gate: an API call did not reach the core", "request", id, "err", err)
		}
		apiError(w, http.StatusServiceUnavailable, 0, "api.unavailable", "AutoPanel's core does not answer; try again")
		return
	}
	if e := ans.Error; e != nil {
		if e.Kind == APIToken {
			h.Set("WWW-Authenticate", "Bearer")
		}
		apiError(w, apiStatus(e.Kind), e.Code, e.Name, e.Message)
		return
	}
	most := apiAnswer
	if isLarge {
		most = apiLargeAnswer
	}
	if len(ans.Result) > most {
		a.log.Error("gate: an API answer over its limit was not sent", "verb", verb, "bytes", len(ans.Result), "request", id)
		apiError(w, http.StatusInternalServerError, 0, "api.internal", "internal error")
		return
	}
	h.Set("Content-Type", "application/json")
	if len(ans.Result) == 0 {
		ans.Result = []byte("null")
	}
	_, _ = w.Write(ans.Result)
}

// health says whether the gate reaches the core, from what the gate already
// knows: it costs no call, so it needs no token.
func (a *apiServer) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		apiError(w, http.StatusMethodNotAllowed, 0, "api.method", "that path takes GET")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if !a.up() {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, `{"status":"unavailable"}`)
		return
	}
	_, _ = io.WriteString(w, `{"status":"ok"}`)
}

// enter takes a slot, and one of the larger ones for a verb with a larger
// body, waiting a short while for each. The larger are among the total.
func (a *apiServer) enter(ctx context.Context, isLarge bool) (func(), bool) {
	t := time.NewTimer(apiSlotWait)
	defer t.Stop()
	if isLarge {
		select {
		case a.large <- struct{}{}:
		case <-t.C:
			return nil, false
		case <-ctx.Done():
			return nil, false
		}
	}
	select {
	case a.slots <- struct{}{}:
	case <-t.C:
		if isLarge {
			<-a.large
		}
		return nil, false
	case <-ctx.Done():
		if isLarge {
			<-a.large
		}
		return nil, false
	}
	return func() {
		<-a.slots
		if isLarge {
			<-a.large
		}
	}, true
}

// client is the address a request came from: the connection's peer, or what
// CF-Connecting-IP names when the peer is a proxy the deployment trusts.
func (a *apiServer) client(r *http.Request) netip.Addr {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	peer, _ := netip.ParseAddr(host)
	peer = peer.Unmap()
	if cf := r.Header.Get(cfConnectingIP); cf != "" && a.trusted().holds(r.RemoteAddr) {
		if ip, err := netip.ParseAddr(cf); err == nil {
			return ip.Unmap()
		}
	}
	return peer
}

func allowed(allow []netip.Prefix, ip netip.Addr) bool {
	for _, p := range allow {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// rateKey is whom a rate is kept for: an IPv4 address, an IPv6 /64.
func rateKey(ip netip.Addr) string {
	if ip.Is6() {
		if p, err := ip.Prefix(64); err == nil {
			return p.String()
		}
	}
	return ip.String()
}

// bearer is the token of an Authorization header that has a token's shape:
// "Bearer apt_<id>_<secret>". Whether it is anyone's is the core's to say.
func bearer(h string) (string, bool) {
	t, ok := strings.CutPrefix(h, "Bearer ")
	if !ok || len(t) > 256 {
		return "", false
	}
	rest, ok := strings.CutPrefix(t, "apt_")
	if !ok {
		return "", false
	}
	id, secret, ok := strings.Cut(rest, "_")
	if n, err := strconv.ParseInt(id, 10, 64); !ok || err != nil || n <= 0 || id[0] == '+' || len(secret) < 32 {
		return "", false // an id the core would not read as one never reaches it
	}
	for _, c := range secret {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return "", false
		}
	}
	return t, true
}

// validVerb is a verb's shape: "gate.route.list".
func validVerb(v string) bool {
	if v == "" || len(v) > 64 {
		return false
	}
	for _, c := range v {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_') {
			return false
		}
	}
	return true
}

func isJSON(contentType string) bool {
	t, _, _ := strings.Cut(contentType, ";")
	return strings.EqualFold(strings.TrimSpace(t), "application/json")
}

// requestID is the caller's request id when it is one (at most 64 of
// [A-Za-z0-9-_]), or a new one.
func requestID(s string) string {
	ok := s != "" && len(s) <= 64
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			ok = false
		}
	}
	if ok {
		return s
	}
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func apiStatus(kind string) int {
	switch kind {
	case APIToken:
		return http.StatusUnauthorized
	case APIForbidden:
		return http.StatusForbidden
	case APINotFound:
		return http.StatusNotFound
	case APIBadParam:
		return http.StatusBadRequest
	case APIFailed:
		return http.StatusUnprocessableEntity
	}
	return http.StatusInternalServerError
}

// apiError writes a refusal: {"error": {"code", "name", "message"}}.
func apiError(w http.ResponseWriter, status int, code int64, name, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": code, "name": name, "message": message}})
}

// rateTable keeps a token bucket for each client, for a bounded number of
// clients: when it is full, those idle longest go first.
type rateTable struct {
	mu      sync.Mutex
	perMin  float64
	burst   float64
	max     int
	now     func() time.Time
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	seen   time.Time
}

func newRateTable(perMinute, burst, max int, now func() time.Time) *rateTable {
	return &rateTable{perMin: float64(perMinute), burst: float64(burst), max: max, now: now, buckets: map[string]*bucket{}}
}

// take spends one request of key's. Refused, it answers the seconds to wait.
func (t *rateTable) take(key string) (wait int, ok bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	b := t.buckets[key]
	if b == nil {
		if len(t.buckets) >= t.max {
			t.evict(now)
		}
		b = &bucket{tokens: t.burst, seen: now}
		t.buckets[key] = b
	}
	b.tokens = min(t.burst, b.tokens+now.Sub(b.seen).Minutes()*t.perMin)
	b.seen = now
	if b.tokens < 1 {
		return int((1-b.tokens)/t.perMin*60) + 1, false
	}
	b.tokens--
	return 0, true
}

// evict makes room: every client whose bucket has refilled is forgotten (it
// would start full again anyway), and failing that, the one idle longest.
func (t *rateTable) evict(now time.Time) {
	var oldest string
	var at time.Time
	for k, b := range t.buckets {
		if now.Sub(b.seen).Minutes()*t.perMin >= t.burst {
			delete(t.buckets, k)
			continue
		}
		if oldest == "" || b.seen.Before(at) {
			oldest, at = k, b.seen
		}
	}
	if len(t.buckets) >= t.max && oldest != "" {
		delete(t.buckets, oldest)
	}
}
