package app

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/yongjohnlee80/golib/server/rpc"

	"github.com/yongjohnlee80/autopanel/core/gate"
	hostgate "github.com/yongjohnlee80/autopanel/host/gate"
	"github.com/yongjohnlee80/autopanel/internal/auth"
	"github.com/yongjohnlee80/autopanel/internal/module"
)

// THE APPLICATIONS' HOSTS, THE CORE'S SIDE — the app host (mail and drive)
// and the admin host (the admin application), each off until sys.app.set
// names it. The gate serves them and decides nothing about who may do what:
// a sign-in, a session's questions and each call come back over the link,
// with the cookie's value, the second token and what the request says of
// where it came from. Here the session is found, the request's origin and
// second token are checked, the role is checked, and the verb is run.
//
// Decision: docs/decisions/auth.md#browser-sessions

// The applications' settings, kept as panel settings.
const (
	appHostSetting    = "app.host"
	appAllowSetting   = "app.allow"
	adminHostSetting  = "app.admin_host"
	adminAllowSetting = "app.admin_allow"
)

var (
	errAppHostTaken = errors.New("app: a route, a site, the mail server or the API uses that host")
	errAppSameHost  = errors.New("app: the app host and the admin host are two names")
)

// AppSettings is sys.app.get's answer and sys.app.set's param.
type AppSettings struct {
	Host       string   `json:"host"`        // "": the app host is off
	Allow      []string `json:"allow"`       // none: any address
	AdminHost  string   `json:"admin_host"`  // "": the admin host is off
	AdminAllow []string `json:"admin_allow"` // none: no address at all
}

// appLogins is what the applications need of the users' module.
type appLogins interface {
	BrowserLogin(ctx context.Context, p auth.Login, client string) (auth.User, error)
	UserByID(ctx context.Context, id int64) (auth.User, error)
}

func (m *apiModule) appVerbs() []module.Verb {
	return []module.Verb{
		module.Handle(module.Contract{Verb: "sys.app.get", Area: "sys.admin", Discloses: module.Plain, Since: 11, Result: "{host, allow, admin_host, admin_allow}",
			Doc: "The browser applications' hosts and the source ranges that may reach each. An empty host is off; an empty allow lets anyone reach the app host, and nobody the admin host."}, m.appGet),
		module.Handle(module.Contract{Verb: "sys.app.set", Area: "sys.admin", Mutates: true, Privileged: true, Since: 11, Param: "{host, allow?, admin_host?, admin_allow?}", Result: "{host, allow, admin_host, admin_allow}",
			Doc: "Serves the browser applications: mail and drive on host, the admin application on admin_host, each a name of its own under a registered domain; an empty name turns one off. allow limits who may reach the app host; admin_allow names who may reach the admin host, and while it is empty nobody may."}, m.appSet),
	}
}

func (m *apiModule) loadApps(ctx context.Context) error {
	var vals [4]string
	for i, key := range []string{appHostSetting, appAllowSetting, adminHostSetting, adminAllowSetting} {
		v, _, err := m.st.Setting(ctx, key)
		if err != nil {
			return err
		}
		vals[i] = v
	}
	m.mu.Lock()
	m.app = AppSettings{Host: vals[0], Allow: strings.Fields(vals[1]), AdminHost: vals[2], AdminAllow: strings.Fields(vals[3])}
	m.mu.Unlock()
	return nil
}

func (m *apiModule) appGet(context.Context, struct{}) (AppSettings, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return copyApps(m.app), nil
}

func copyApps(a AppSettings) AppSettings {
	return AppSettings{Host: a.Host, Allow: append([]string{}, a.Allow...), AdminHost: a.AdminHost, AdminAllow: append([]string{}, a.AdminAllow...)}
}

// appName is a name an application may be served on: "" for off.
func (m *apiModule) appName(ctx context.Context, name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", nil
	}
	h, err := gate.CanonicalHost(name)
	if err != nil {
		return "", err
	}
	ok, err := m.covered(ctx, h)
	switch {
	case err != nil:
		return "", err
	case !ok:
		return "", gate.ErrNoDomain
	case m.taken(h) || h == m.Host():
		return "", errAppHostTaken
	}
	return h, nil
}

func prefixes(in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	for _, a := range in {
		p, err := netip.ParsePrefix(strings.TrimSpace(a))
		if err != nil {
			return nil, errAPIAllow
		}
		out = append(out, p.Masked().String())
	}
	sort.Strings(out)
	return out, nil
}

func (m *apiModule) appSet(ctx context.Context, p AppSettings) (AppSettings, error) {
	host, err := m.appName(ctx, p.Host)
	if err != nil {
		return AppSettings{}, err
	}
	admin, err := m.appName(ctx, p.AdminHost)
	if err != nil {
		return AppSettings{}, err
	}
	if host != "" && host == admin {
		return AppSettings{}, errAppSameHost
	}
	allow, err := prefixes(p.Allow)
	if err != nil {
		return AppSettings{}, err
	}
	adminAllow, err := prefixes(p.AdminAllow)
	if err != nil {
		return AppSettings{}, err
	}
	// Each host with its sources, written so that a stop between two writes
	// never leaves a host on for addresses that were not asked for: turning
	// it on, its sources first; turning it off, the host first. (For the
	// admin host, sources written before its name only narrow it: with no
	// name it is off, and an empty list lets nobody in.)
	write := func(hostKey, host, allowKey string, allow []string) error {
		order := []string{allowKey, hostKey}
		if host == "" {
			order = []string{hostKey, allowKey}
		}
		for _, key := range order {
			value := host
			if key == allowKey {
				value = strings.Join(allow, " ")
			}
			if err := m.st.PutSetting(ctx, key, value); err != nil {
				return err
			}
		}
		return nil
	}
	if err := write(appHostSetting, host, appAllowSetting, allow); err != nil {
		return AppSettings{}, err
	}
	if err := write(adminHostSetting, admin, adminAllowSetting, adminAllow); err != nil {
		return AppSettings{}, err
	}
	next := AppSettings{Host: host, Allow: allow, AdminHost: admin, AdminAllow: adminAllow}
	m.mu.Lock()
	m.app = next
	m.mu.Unlock()
	m.changed() // after the commit only
	return copyApps(next), nil
}

// appHosts are the applications' hosts that are on.
func (m *apiModule) appHosts() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []string
	for _, h := range []string{m.app.Host, m.app.AdminHost} {
		if h != "" {
			out = append(out, h)
		}
	}
	return out
}

// appHostOf is the name of a kind of application host, "" while it is off.
func (m *apiModule) appHostOf(kind string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	switch kind {
	case hostgate.HostApp:
		return m.app.Host
	case hostgate.HostAdmin:
		return m.app.AdminHost
	}
	return ""
}

// forApps is what the gate is sent: nil while both are off.
func (m *apiModule) forApps() *hostgate.Apps {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.app.Host == "" && m.app.AdminHost == "" {
		return nil
	}
	a := copyApps(m.app)
	return &hostgate.Apps{Host: a.Host, Allow: a.Allow, AdminHost: a.AdminHost, AdminAllow: a.AdminAllow}
}

// sameOrigin is a request the browser itself says comes from this host's own
// page: Origin names the host the request was sent to (its port with it, if
// it was sent to one), and Sec-Fetch-Site, when the browser sends it, is
// same-origin. A request with no Origin is not.
func (m *apiModule) sameOrigin(kind, authority, origin, fetchSite string) bool {
	name := m.appHostOf(kind)
	if name == "" || origin == "" {
		return false
	}
	host, port, err := net.SplitHostPort(authority)
	if err != nil {
		host, port = authority, ""
	}
	if h, err := gate.CanonicalHost(host); err != nil || h != name {
		return false
	}
	want := "https://" + name
	if port != "" && port != "443" {
		want += ":" + port
	}
	return origin == want && (fetchSite == "" || fetchSite == "same-origin")
}

// resolve is the live session a cookie names on a kind of host, and its user,
// read from the store now: a disabled user, or one whose role the admin host
// no longer admits, has no session.
func (m *apiModule) resolve(ctx context.Context, cookie, kind string) (auth.Session, auth.User, error) {
	s, err := m.sessions.Resolve(ctx, cookie, kind)
	if err != nil {
		return auth.Session{}, auth.User{}, err
	}
	u, err := m.logins.UserByID(ctx, s.UserID)
	switch {
	case errors.Is(err, auth.ErrNoUser):
		return auth.Session{}, auth.User{}, auth.ErrNoSession
	case err != nil:
		return auth.Session{}, auth.User{}, err
	case u.DisabledAt != 0, !admits(kind, u.Role):
		return auth.Session{}, auth.User{}, auth.ErrNoSession
	}
	return s, u, nil
}

// reachable reports whether client may use a kind of host. The gate refuses
// any other address before it reads a body; the core checks again, taking
// the gate's word only for the address itself. An empty list lets anyone
// reach the app host and nobody the admin host.
func (m *apiModule) reachable(kind, client string) bool {
	m.mu.RLock()
	allow := m.app.Allow
	if kind == hostgate.HostAdmin {
		allow = m.app.AdminAllow
	}
	m.mu.RUnlock()
	if len(allow) == 0 {
		return kind == hostgate.HostApp
	}
	ip, err := netip.ParseAddr(client)
	if err != nil {
		return false
	}
	for _, a := range allow {
		if p, err := netip.ParsePrefix(a); err == nil && p.Contains(ip.Unmap()) {
			return true
		}
	}
	return false
}

// admits reports whether a role may sign in on a kind of host: the admin
// application is the admin's and the operator's.
func admits(kind string, role auth.Role) bool {
	return kind != hostgate.HostAdmin || role == auth.RoleAdmin || role == auth.RoleOperator
}

// SessionUser is a signed-in person, as the applications see them.
type SessionUser struct {
	Name       string    `json:"name"`
	Role       auth.Role `json:"role"`
	MustChange bool      `json:"must_change"`
}

// SessionOpened is POST /v1/session's answer; SessionState is GET's.
type SessionOpened struct {
	CSRF      string      `json:"csrf"`
	User      SessionUser `json:"user"`
	ExpiresAt int64       `json:"expires_at"`
}

type SessionState struct {
	User      SessionUser `json:"user"`
	ExpiresAt int64       `json:"expires_at"`
}

// signIn is POST /v1/session's body.
type signIn struct {
	Name       string `json:"name"`
	Passphrase string `json:"passphrase"`
	Code       string `json:"code"`
}

func sessionRefusal(kind string, code int64, name, message string) hostgate.SessionAnswer {
	return hostgate.SessionAnswer{Error: &hostgate.APIError{Kind: kind, Code: code, Name: name, Message: message}}
}

var (
	noSession   = sessionRefusal(hostgate.APIToken, rpc.CodeAccessDenied, "app.unauthorized", "sign in first")
	badSignIn   = sessionRefusal(hostgate.APIToken, -32160, "auth.bad_login", "wrong user, passphrase or code")
	crossOrigin = sessionRefusal(hostgate.APIForbidden, rpc.CodeAccessDenied, "app.cross_origin", "a change must come from this host's own page, with its token")
	sessionGone = sessionRefusal(hostgate.APIInternal, rpc.CodeInternal, "", "internal error")
)

// session is link.session: a sign-in, a session's state, its second token
// again, or a sign-out.
func (m *apiModule) session(ctx context.Context, ask hostgate.SessionAsk) (ans hostgate.SessionAnswer, _ error) {
	defer func() {
		if r := recover(); r != nil {
			m.log.Error("app: a session call panicked", "op", ask.Op, "panic", r)
			ans = sessionGone
		}
	}()
	if m.appHostOf(ask.Host) == "" || m.sessions == nil {
		return sessionRefusal(hostgate.APINotFound, rpc.CodeMethodNotFound, "app.not_found", "not found"), nil
	}
	if !m.reachable(ask.Host, ask.Client) {
		return sessionRefusal(hostgate.APIForbidden, rpc.CodeAccessDenied, "app.not_allowed", "this address may not use this host"), nil
	}
	client := printable(ask.Client, 64)
	same := m.sameOrigin(ask.Host, ask.Authority, ask.Origin, ask.FetchSite)
	switch ask.Op {
	case hostgate.SessionOpen:
		// A sign-in from another site's page is refused before it costs a
		// derivation, or signs the browser in to an attacker's account.
		if !same {
			return crossOrigin, nil
		}
		var p signIn
		if err := json.Unmarshal(ask.Param, &p); err != nil {
			return sessionRefusal(hostgate.APIBadParam, rpc.CodeInvalidParams, "", "the body is not {name, passphrase, code}"), nil
		}
		u, err := m.logins.BrowserLogin(ctx, auth.Login{User: p.Name, Passphrase: p.Passphrase, Code: p.Code}, client)
		switch {
		case errors.Is(err, auth.ErrBusy):
			return sessionRefusal(hostgate.APIBusy, -32119, "auth.busy", "too many sign-ins are waiting; try again shortly"), nil
		case errors.Is(err, auth.ErrBadLogin), errors.Is(err, auth.ErrThrottled):
			return badSignIn, nil // one answer for every failure, a wait and a lock included
		case err != nil:
			m.log.Error("app: a sign-in failed", "err", err)
			return sessionGone, nil
		}
		if !admits(ask.Host, u.Role) {
			m.note(ctx, u.Name+" (browser "+client+")", "auth.session.open", ask.Host, "refused: the role")
			return badSignIn, nil
		}
		o, err := m.sessions.New(ctx, u.ID, ask.Host, client, printable(ask.Agent, 120), ask.Session)
		if err != nil {
			m.log.Error("app: a session could not be made", "err", err)
			return sessionGone, nil
		}
		m.note(ctx, u.Name+" (browser "+client+")", "auth.session.open", ask.Host, "session "+o.ShortID)
		b, _ := json.Marshal(SessionOpened{CSRF: o.CSRF, User: SessionUser{Name: u.Name, Role: u.Role, MustChange: u.MustChange}, ExpiresAt: o.ExpiresAt})
		return hostgate.SessionAnswer{Result: b, Cookie: o.Cookie}, nil
	case hostgate.SessionGet:
		s, u, err := m.resolve(ctx, ask.Session, ask.Host)
		if err != nil {
			return m.lost(err), nil
		}
		b, _ := json.Marshal(SessionState{User: SessionUser{Name: u.Name, Role: u.Role, MustChange: u.MustChange}, ExpiresAt: m.sessions.ExpiresAt(s)})
		return hostgate.SessionAnswer{Result: b}, nil
	case hostgate.SessionCSRF:
		s, _, err := m.resolve(ctx, ask.Session, ask.Host)
		if err != nil {
			return m.lost(err), nil
		}
		if !same {
			return crossOrigin, nil
		}
		b, _ := json.Marshal(map[string]string{"csrf": m.sessions.Token(s, ask.Session)})
		return hostgate.SessionAnswer{Result: b}, nil
	case hostgate.SessionEnd:
		s, u, err := m.resolve(ctx, ask.Session, ask.Host)
		if errors.Is(err, auth.ErrNoSession) {
			return hostgate.SessionAnswer{Clear: true}, nil // nothing to end: the cookie goes all the same
		}
		if err != nil {
			return sessionGone, nil
		}
		if !same || !m.sessions.CSRF(s, ask.Session, ask.CSRF) {
			return crossOrigin, nil
		}
		if err := m.sessions.End(ctx, ask.Session); err != nil {
			return sessionGone, nil
		}
		m.note(ctx, u.Name+" (browser "+client+")", "auth.session.end", ask.Host, "session "+auth.ShortID(s)+": signed out")
		return hostgate.SessionAnswer{Clear: true}, nil
	}
	return sessionRefusal(hostgate.APINotFound, rpc.CodeMethodNotFound, "app.not_found", "not found"), nil
}

// lost is the answer for a session that is not one: 401 and the cookie
// cleared; or, when the store failed, 500.
func (m *apiModule) lost(err error) hostgate.SessionAnswer {
	if errors.Is(err, auth.ErrNoSession) {
		a := noSession
		a.Clear = true
		return a
	}
	m.log.Error("app: a session could not be read", "err", err)
	return sessionGone
}

// note writes one finished entry to the audit log.
func (m *apiModule) note(ctx context.Context, actor, action, subject, outcome string) {
	id, err := m.aud.AuditAttempt(ctx, actor, action, subject)
	if err == nil {
		_ = m.aud.AuditResult(ctx, id, outcome)
	}
}

// adminAreas are what only the admin host serves: the host's own areas and
// the management of users. A session of the app host never reaches them,
// whatever its role.
var adminAreas = map[string]bool{"sys": true, "sys.admin": true, "gate": true, "certs": true, "firewall": true,
	"services": true, "mail.admin": true, "site.admin": true}

func adminVerb(c module.Contract) bool {
	return adminAreas[c.AreaOf()] || strings.HasPrefix(c.Verb, "auth.user.")
}

// sessionCall is one call of a browser session: link.api on an application's
// host.
func (m *apiModule) sessionCall(ctx context.Context, ask hostgate.APIAsk) hostgate.APIAnswer {
	if ask.Token != "" { // the gate never sends both; the core takes its word for nothing
		return refusal(hostgate.APIBadParam, rpc.CodeInvalidParams, "app.two_credentials", "a request carries a session or a token, not both")
	}
	if m.appHostOf(ask.Host) == "" || m.sessions == nil {
		return refusal(hostgate.APINotFound, rpc.CodeMethodNotFound, "api.not_found", "no such verb")
	}
	if !m.reachable(ask.Host, ask.Client) {
		return refusal(hostgate.APIForbidden, rpc.CodeAccessDenied, "app.not_allowed", "this address may not use this host")
	}
	s, u, err := m.resolve(ctx, ask.Session, ask.Host)
	switch {
	case errors.Is(err, auth.ErrNoSession):
		return refusal(hostgate.APIToken, rpc.CodeAccessDenied, "app.unauthorized", "sign in first")
	case err != nil:
		m.log.Error("app: a session could not be read", "err", err)
		return refusal(hostgate.APIInternal, rpc.CodeInternal, "", "internal error")
	}
	principal := "user:" + strconv.FormatInt(u.ID, 10)
	client := printable(ask.Client, 64)
	ctx = auth.WithSession(ctx, auth.SessionCall{Host: ask.Host, Cookie: ask.Session})
	signIn := refusal(hostgate.APIToken, rpc.CodeAccessDenied, "app.unauthorized", "sign in first")
	if ask.Verb == apiContracts {
		return m.listContracts(ctx, principal, m.sessionSet(ask.Host), signIn)
	}
	v, ok := m.sessionSet(ask.Host)[ask.Verb]
	if !ok {
		return refusal(hostgate.APINotFound, rpc.CodeMethodNotFound, "api.not_found", "no such verb")
	}
	// The cookie alone runs nothing: every call is a POST, and each needs the
	// page's own origin and the second token it holds, reads included, so no
	// verb a session may call is ever reached from another site's page.
	if !m.sameOrigin(ask.Host, ask.Authority, ask.Origin, ask.FetchSite) || !m.sessions.CSRF(s, ask.Session, ask.CSRF) {
		return refusal(hostgate.APIForbidden, rpc.CodeAccessDenied, "app.cross_origin", "a change must come from this host's own page, with its token")
	}
	if u.MustChange && v.Verb != "auth.passphrase.change" {
		return m.declared(hostgate.APIForbidden, auth.ErrMustChange)
	}
	return m.run(ctx, v, principal, func(name string) string {
		return name + " (" + ask.Host + " " + client + ", session " + auth.ShortID(s) + ", request " + printable(ask.RequestID, 64) + ")"
	}, ask.Param, signIn)
}

// sessionSet is the verbs a session of a kind of host may call: the session
// verbs, and on the app host none of the admin host's.
func (m *apiModule) sessionSet(kind string) map[string]module.Verb {
	if kind == hostgate.HostAdmin {
		return m.sessionVerbs
	}
	return m.appVerbSet
}
