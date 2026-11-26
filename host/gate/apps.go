package gate

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// THE APPLICATIONS' HOSTS — the app host (mail and drive) and the admin host
// (the admin application), each served by the gate on a name of its own, so
// every call a page makes is same-origin. A person signs in there and gets a
// session cookie; the gate passes the cookie, the second token and what the
// request says of where it came from to the core, and decides nothing with
// them. What the gate does decide is what it can see: who may reach the host
// at all, how often an address may try to sign in, and the shape and size of
// a request.
//
// Decision: docs/decisions/auth.md#browser-sessions

const (
	// SessionCookie is the session's cookie. __Host-: the browser keeps it to
	// this host, over HTTPS, with Path=/ and no Domain, so no other name under
	// the domain can set or read it.
	SessionCookie = "__Host-ap_session"
	// The sign-ins an address may try (IPv6 by /64): before any reaches the
	// core and its derivation.
	loginPerMinute = 5
	loginBurst     = 5
	loginBody      = 4 << 10 // {name, passphrase, code}
	maxAgent       = 120
	// The headers every answer on these hosts carries.
	appPolicy = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)

// appHost is one application host as the gate serves it.
type appHost struct {
	kind  string // HostApp, HostAdmin
	allow []netip.Prefix
	open  bool // an empty allow lets anyone in: the app host's rule; the admin host's lets nobody
}

// setApps takes the core's settings for the applications' hosts; nil turns
// both off.
func (a *apiServer) setApps(c *Apps) error {
	if c == nil || (c.Host == "" && c.AdminHost == "") {
		a.apps.Store(nil)
		return nil
	}
	hosts := map[string]appHost{}
	for _, h := range []struct {
		name, kind string
		allow      []string
	}{{c.Host, HostApp, c.Allow}, {c.AdminHost, HostAdmin, c.AdminAllow}} {
		if h.name == "" {
			continue
		}
		ah := appHost{kind: h.kind, open: h.kind == HostApp && len(h.allow) == 0}
		for _, s := range h.allow {
			p, err := netip.ParsePrefix(s)
			if err != nil {
				return errors.New("gate: the core sent an allowed source that is no prefix: " + strconv.Quote(s))
			}
			ah.allow = append(ah.allow, p.Masked())
		}
		hosts[h.name] = ah
	}
	a.apps.Store(&hosts)
	return nil
}

// appOf is the application host name names.
func (a *apiServer) appOf(name string) (appHost, bool) {
	hs := a.apps.Load()
	if hs == nil {
		return appHost{}, false
	}
	h, ok := (*hs)[name]
	return h, ok
}

// sitesPrefix is where the app host serves the sites' internal and private
// documents (core/site.AppPrefix): /s/<site host>/<address>/.
const sitesPrefix = "/s/"

// serveSiteDoc passes a member's read of a site's document to the sites'
// serving process, which asks the core whether the session may have it. The
// gate decides nothing here but the method and the rate: it reads no cookie.
// The answer's policy, type and caching are the serving process's.
func (a *apiServer) serveSiteDoc(w http.ResponseWriter, r *http.Request, client netip.Addr) {
	h := w.Header()
	if a.site == nil {
		apiError(w, http.StatusNotFound, 0, "app.not_found", "not found")
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		h.Set("Allow", "GET, HEAD")
		apiError(w, http.StatusMethodNotAllowed, 0, "app.method", "a document is read with GET")
		return
	}
	if wait, ok := a.rate.take(rateKey(client)); !ok {
		h.Set("Retry-After", strconv.Itoa(wait))
		apiError(w, http.StatusTooManyRequests, 0, "api.rate", "too many requests; wait and try again")
		return
	}
	for _, k := range []string{"Cache-Control", "X-Content-Type-Options", "Referrer-Policy", "Content-Security-Policy"} {
		h.Del(k) // the serving process sets its own
	}
	a.site.ServeHTTP(w, r)
}

func (h appHost) admits(ip netip.Addr) bool {
	return h.open || allowed(h.allow, ip)
}

// serveApp serves an application's host. The applications' files are not
// served yet: every path but the API's is 404.
func (a *apiServer) serveApp(w http.ResponseWriter, r *http.Request, app appHost) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Content-Security-Policy", appPolicy)
	h.Set("Strict-Transport-Security", "max-age=31536000")
	id := requestID(r.Header.Get("X-Request-Id"))
	h.Set("X-Request-Id", id)

	// Who may reach the host at all, before anything is read: the admin
	// host lets nobody in until its sources are named.
	client := a.client(r)
	if !app.admits(client) {
		apiError(w, http.StatusForbidden, 0, "app.not_allowed", "this address may not use this host")
		return
	}
	path := r.URL.EscapedPath()
	if app.kind == HostApp && strings.HasPrefix(path, sitesPrefix) {
		a.serveSiteDoc(w, r, client)
		return
	}
	if !strings.HasPrefix(path, "/v1/") {
		apiError(w, http.StatusNotFound, 0, "app.not_found", "not found")
		return
	}
	// One credential a host: a token here is refused, and a token with a
	// cookie is a request no browser of ours makes.
	_, hasToken := r.Header["Authorization"]
	cookie, hasCookie := sessionCookie(r)
	switch {
	case hasToken && hasCookie:
		apiError(w, http.StatusBadRequest, 0, "app.two_credentials", "a request carries a session or a token, not both")
		return
	case hasToken:
		apiError(w, http.StatusUnauthorized, 0, "app.unauthorized", "this host takes a session, not an API token")
		return
	}
	if wait, ok := a.rate.take(rateKey(client)); !ok {
		h.Set("Retry-After", strconv.Itoa(wait))
		apiError(w, http.StatusTooManyRequests, 0, "api.rate", "too many requests; wait and try again")
		return
	}
	ask := SessionAsk{Host: app.kind, Authority: r.Host, Session: cookie, CSRF: r.Header.Get("X-AP-CSRF"), Origin: r.Header.Get("Origin"),
		FetchSite: r.Header.Get("Sec-Fetch-Site"), Method: r.Method, Client: client.String(), RequestID: id}
	switch path {
	case "/v1/session":
		switch r.Method {
		case http.MethodPost:
			if wait, ok := a.logins.take(rateKey(client)); !ok {
				h.Set("Retry-After", strconv.Itoa(wait))
				apiError(w, http.StatusTooManyRequests, 0, "app.login_rate", "too many sign-ins from this address; wait and try again")
				return
			}
			ask.Op = SessionOpen
			ask.Agent = printableAgent(r.Header.Get("User-Agent"))
		case http.MethodGet:
			ask.Op = SessionGet
		case http.MethodDelete:
			ask.Op = SessionEnd
		default:
			h.Set("Allow", "GET, POST, DELETE")
			apiError(w, http.StatusMethodNotAllowed, 0, "api.method", "that path takes GET, POST or DELETE")
			return
		}
		a.session(w, r, ask)
		return
	case "/v1/session/csrf":
		if r.Method != http.MethodPost {
			h.Set("Allow", http.MethodPost)
			apiError(w, http.StatusMethodNotAllowed, 0, "api.method", "that path takes POST")
			return
		}
		ask.Op = SessionCSRF
		a.session(w, r, ask)
		return
	}
	verb, method := "", ""
	switch {
	case path == "/v1/contracts":
		verb, method = "api.contracts", http.MethodGet
	case strings.HasPrefix(path, "/v1/call/"):
		verb, method = path[len("/v1/call/"):], http.MethodPost
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
	if !hasCookie {
		apiError(w, http.StatusUnauthorized, 0, "app.unauthorized", "sign in first")
		return
	}
	if r.ContentLength > apiBody {
		apiError(w, http.StatusRequestEntityTooLarge, 0, "api.too_large", "the body is larger than this verb takes")
		return
	}
	release, ok := a.enter(r.Context(), false)
	if !ok {
		h.Set("Retry-After", "2")
		apiError(w, http.StatusServiceUnavailable, 0, "api.busy", "the API is busy; try again")
		return
	}
	defer release()
	var body []byte
	if r.Method == http.MethodPost {
		if body, ok = readJSON(w, r, apiBody); !ok {
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), apiCallTime)
	defer cancel()
	var ans APIAnswer
	err := a.link.call(ctx, VerbAPI, APIAsk{Verb: verb, Param: body, Client: ask.Client, RequestID: id,
		Host: app.kind, Authority: r.Host, Session: cookie, CSRF: ask.CSRF, Origin: ask.Origin, FetchSite: ask.FetchSite, Method: r.Method}, &ans)
	if err != nil {
		a.unreachable(w, r, id, err)
		return
	}
	if e := ans.Error; e != nil {
		apiError(w, apiStatus(e.Kind), e.Code, e.Name, e.Message)
		return
	}
	if len(ans.Result) > apiAnswer {
		a.log.Error("gate: an application's answer over its limit was not sent", "verb", verb, "bytes", len(ans.Result), "request", id)
		apiError(w, http.StatusInternalServerError, 0, "api.internal", "internal error")
		return
	}
	writeResult(w, ans.Result)
}

// session passes a sign-in, a question about the session, a new second token
// or a sign-out to the core, and sets or clears the cookie as it answers.
func (a *apiServer) session(w http.ResponseWriter, r *http.Request, ask SessionAsk) {
	if r.ContentLength > loginBody {
		apiError(w, http.StatusRequestEntityTooLarge, 0, "api.too_large", "the body is larger than this takes")
		return
	}
	release, ok := a.enter(r.Context(), false)
	if !ok {
		w.Header().Set("Retry-After", "2")
		apiError(w, http.StatusServiceUnavailable, 0, "api.busy", "the API is busy; try again")
		return
	}
	defer release()
	if ask.Op == SessionOpen {
		if ask.Param, ok = readJSON(w, r, loginBody); !ok {
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), apiCallTime)
	defer cancel()
	var ans SessionAnswer
	if err := a.link.call(ctx, VerbSession, ask, &ans); err != nil {
		a.unreachable(w, r, ask.RequestID, err)
		return
	}
	switch {
	case ans.Cookie != "" && validCookie(ans.Cookie):
		http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: ans.Cookie, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	case ans.Clear:
		http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	}
	if e := ans.Error; e != nil {
		apiError(w, apiStatus(e.Kind), e.Code, e.Name, e.Message)
		return
	}
	if len(ans.Result) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if len(ans.Result) > apiLargeAnswer {
		apiError(w, http.StatusInternalServerError, 0, "api.internal", "internal error")
		return
	}
	writeResult(w, ans.Result)
}

// sessionCookie is the session cookie's value when it has the shape of one
// (43 base64url characters), and whether the request carries the cookie at
// all: one of another shape is no session, but it is still a cookie.
func sessionCookie(r *http.Request) (string, bool) {
	c, err := r.Cookie(SessionCookie)
	if err != nil {
		return "", false
	}
	if !validCookie(c.Value) {
		return "", true
	}
	return c.Value, true
}

func validCookie(v string) bool {
	if len(v) != 43 {
		return false
	}
	for _, c := range v {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// printableAgent is a browser's name, cut short and kept printable.
func printableAgent(s string) string {
	if len(s) > maxAgent {
		s = s[:maxAgent]
	}
	return strings.Map(func(r rune) rune {
		if r < ' ' || r > '~' {
			return '_'
		}
		return r
	}, s)
}

// readJSON reads a body up to limit, which must be JSON when there is one. It
// answers the refusal itself.
func readJSON(w http.ResponseWriter, r *http.Request, limit int) ([]byte, bool) {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, int64(limit)))
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		apiError(w, http.StatusRequestEntityTooLarge, 0, "api.too_large", "the body is larger than this verb takes")
		return nil, false
	case err != nil:
		apiError(w, http.StatusBadRequest, 0, "api.bad_request", "the body could not be read")
		return nil, false
	}
	if len(b) > 0 && !isJSON(r.Header.Get("Content-Type")) {
		apiError(w, http.StatusUnsupportedMediaType, 0, "api.not_json", "a body must be application/json")
		return nil, false
	}
	return b, true
}

func (a *apiServer) unreachable(w http.ResponseWriter, r *http.Request, id string, err error) {
	if r.Context().Err() == nil {
		a.log.Warn("gate: a call did not reach the core", "request", id, "err", err)
	}
	apiError(w, http.StatusServiceUnavailable, 0, "api.unavailable", "AutoPanel's core does not answer; try again")
}

func writeResult(w http.ResponseWriter, b []byte) {
	w.Header().Set("Content-Type", "application/json")
	if len(b) == 0 {
		b = []byte("null")
	}
	_, _ = w.Write(b)
}

// loginClients are the addresses whose sign-ins are remembered. One that
// is forgotten starts again with a full burst, which is what a new address
// has anyway.
const loginClients = 1024

// newLoginRate is the sign-ins' table: few a minute.
func newLoginRate(now func() time.Time) *rateTable {
	return newRateTable(loginPerMinute, loginBurst, loginClients, now)
}
