package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yongjohnlee80/golib/dao"

	"github.com/yongjohnlee80/autopanel/core/gate"
	hostgate "github.com/yongjohnlee80/autopanel/host/gate"
	"github.com/yongjohnlee80/autopanel/internal/auth"
	"github.com/yongjohnlee80/autopanel/internal/keyslot"
	"github.com/yongjohnlee80/autopanel/internal/module"
	"github.com/yongjohnlee80/autopanel/store"
)

const (
	webHost   = "web.example.com"
	adminHost = "admin.example.com"
	webOrigin = "https://" + webHost
	goodPass  = "the right passphrase"
)

// appUsers signs people in from a store's users, by a passphrase every one of
// them shares, and authorises by their role in the store.
type appUsers struct {
	st     *store.Store
	mu     sync.Mutex
	logins []string // the names a sign-in was checked for
	busy   bool
}

func (u *appUsers) BrowserLogin(ctx context.Context, p auth.Login, _ string) (auth.User, error) {
	u.mu.Lock()
	u.logins = append(u.logins, p.User)
	busy := u.busy
	u.mu.Unlock()
	if busy {
		return auth.User{}, auth.ErrBusy
	}
	usr, err := u.st.Users().User(ctx, p.User)
	if err != nil || p.Passphrase != goodPass {
		return auth.User{}, auth.ErrBadLogin
	}
	if p.Code == "locked" {
		return auth.User{}, auth.ErrThrottled
	}
	return usr, nil
}

func (u *appUsers) UserByID(ctx context.Context, id int64) (auth.User, error) {
	return u.st.Users().UserByID(ctx, id)
}

func (u *appUsers) APIToken(context.Context, string, string) (string, error) {
	return "", auth.ErrBadLogin
}

func (u *appUsers) Authorize(ctx context.Context, principal string, _ time.Time, c module.Contract) (string, error) {
	id, _ := strconv.ParseInt(strings.TrimPrefix(principal, "user:"), 10, 64)
	usr, err := u.st.Users().UserByID(ctx, id)
	if err != nil {
		return "", auth.ErrExpired
	}
	if !auth.Allows(usr.Role, c) {
		return usr.Name, auth.ErrForbidden
	}
	return usr.Name, nil
}

// sessionTestVerbs are session verbs of each kind the core must tell apart.
type sessionTestVerbs struct {
	mu  sync.Mutex
	ran []string
}

func (*sessionTestVerbs) Name() string { return "s" }
func (*sessionTestVerbs) Errors() []module.PublicError {
	return []module.PublicError{{Err: auth.ErrMustChange, Code: -32164, Name: "auth.must_change", Message: "change your passphrase first"}}
}

func (v *sessionTestVerbs) note(name string) {
	v.mu.Lock()
	v.ran = append(v.ran, name)
	v.mu.Unlock()
}

func (v *sessionTestVerbs) Verbs() []module.Verb {
	return []module.Verb{
		module.Handle(module.Contract{Verb: "mail.s.read", Area: "mail", Session: true, Discloses: module.Plain},
			func(context.Context, struct{}) (string, error) { v.note("read"); return "mine", nil }),
		module.Handle(module.Contract{Verb: "mail.s.change", Area: "mail", Session: true, Mutates: true, Privileged: true},
			func(context.Context, struct{}) (string, error) { v.note("change"); return "done", nil }),
		module.Handle(module.Contract{Verb: "mail.s.both", Area: "mail", Session: true, Public: true, Discloses: module.Plain},
			func(context.Context, struct{}) (string, error) { v.note("both"); return "either", nil }),
		module.Handle(module.Contract{Verb: "sys.s.admin", Area: "sys.admin", Session: true, Discloses: module.Plain},
			func(context.Context, struct{}) (string, error) { v.note("admin"); return "the admin's", nil }),
		module.Handle(module.Contract{Verb: "auth.passphrase.change", Area: "auth", Session: true, Mutates: true},
			func(context.Context, struct{}) (string, error) { v.note("passphrase"); return "", nil }),
	}
}

type appFixture struct {
	m     *apiModule
	st    *store.Store
	users *appUsers
	verbs *sessionTestVerbs
	aud   *fakeAudit
	ids   map[string]int64
}

func newAppCore(t *testing.T) *appFixture {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, store.Config{Engine: dao.DialectSQLite, Path: filepath.Join(t.TempDir(), "store.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	f := &appFixture{st: st, users: &appUsers{st: st}, verbs: &sessionTestVerbs{}, aud: &fakeAudit{}, ids: map[string]int64{}}
	for _, p := range []struct {
		name string
		role auth.Role
	}{{"ada", auth.RoleAdmin}, {"vera", auth.RoleViewer}, {"neo", auth.RoleOperator}} {
		var slot *keyslot.PassphraseSlot
		verifier := "v"
		if p.role == auth.RoleAdmin {
			mk, _ := keyslot.NewMasterKey()
			sl, err := keyslot.SealPassphrase(mk, goodPass, keyslot.Params{Time: 1, MemKiB: 64, Threads: 1})
			if err != nil {
				t.Fatal(err)
			}
			slot, verifier = &sl, ""
		}
		u, err := st.Users().AddUser(ctx, p.name, p.role, slot, verifier, false)
		if err != nil {
			t.Fatal(err)
		}
		f.ids[p.name] = u.ID
	}
	settings := &fakeSettings{m: map[string]string{appHostSetting: webHost, adminHostSetting: adminHost, adminAllowSetting: "198.51.100.0/24 203.0.113.0/24"}}
	f.m = &apiModule{st: settings, auth: f.users, logins: f.users, sessions: auth.NewSessions(st.Sessions()), aud: f.aud,
		log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		covered: func(_ context.Context, h string) (bool, error) { return gate.Under(h, "example.com"), nil },
		taken:   func(h string) bool { return h == "mail.example.com" || h == "blog.example.com" },
		changed: func() {}}
	if err := f.m.load(ctx); err != nil {
		t.Fatal(err)
	}
	if err := f.m.serve(f.verbs, f.m); err != nil {
		t.Fatal(err)
	}
	return f
}

// signIn opens a session on the app host as name, with the page's origin.
func (f *appFixture) signIn(t *testing.T, kind, name string) (cookie, csrf string) {
	t.Helper()
	host := webHost
	if kind == hostgate.HostAdmin {
		host = adminHost
	}
	a := f.session(t, hostgate.SessionAsk{Op: hostgate.SessionOpen, Host: kind, Authority: host, Origin: "https://" + host, FetchSite: "same-origin",
		Param: []byte(`{"name":"` + name + `","passphrase":"` + goodPass + `","code":""}`)})
	if a.Error != nil || a.Cookie == "" {
		t.Fatalf("signing %s in: %+v", name, a.Error)
	}
	var o SessionOpened
	if err := json.Unmarshal(a.Result, &o); err != nil || o.CSRF == "" {
		t.Fatalf("the sign-in's answer: %s", a.Result)
	}
	return a.Cookie, o.CSRF
}

func (f *appFixture) session(t *testing.T, ask hostgate.SessionAsk) hostgate.SessionAnswer {
	t.Helper()
	if ask.Method == "" {
		ask.Method = "POST"
	}
	ask.Client, ask.RequestID = "203.0.113.9", "r1"
	a, err := f.m.session(context.Background(), ask)
	if err != nil {
		t.Fatalf("link.session itself failed: %v", err)
	}
	return a
}

// callAs is a session's call with the page's origin and its token.
func (f *appFixture) callAs(t *testing.T, cookie, csrf, verb string) hostgate.APIAnswer {
	t.Helper()
	return f.ask(t, hostgate.APIAsk{Verb: verb, Host: hostgate.HostApp, Authority: webHost, Session: cookie, CSRF: csrf, Origin: webOrigin, FetchSite: "same-origin", Method: "POST"})
}

func (f *appFixture) ask(t *testing.T, ask hostgate.APIAsk) hostgate.APIAnswer {
	t.Helper()
	ask.Client, ask.RequestID = "203.0.113.9", "r2"
	a, err := f.m.call(context.Background(), ask)
	if err != nil {
		t.Fatalf("link.api itself failed: %v", err)
	}
	return a
}

func (f *appFixture) ran() []string {
	f.verbs.mu.Lock()
	defer f.verbs.mu.Unlock()
	return append([]string{}, f.verbs.ran...)
}

// TestTheAppHostsAreSetOnlyWhereTheyCanBeServed: each under a registered
// domain, held by nothing else, the two apart; the sources are prefixes.
func TestTheAppHostsAreSetOnlyWhereTheyCanBeServed(t *testing.T) {
	f := newAPICore(t)
	ctx := context.Background()
	if f.m.forApps() != nil {
		t.Fatal("the applications are on before they were set")
	}
	if _, err := f.m.set(ctx, APISettings{Host: "api.example.com"}); err != nil {
		t.Fatal(err)
	}
	bumps := f.bumps
	for _, c := range []struct {
		ask  AppSettings
		want error
	}{
		{AppSettings{Host: "web.other.net"}, gate.ErrNoDomain},
		{AppSettings{AdminHost: "mail.example.com"}, errAppHostTaken},
		{AppSettings{Host: "api.example.com"}, errAppHostTaken},
		{AppSettings{Host: "web.example.com", AdminHost: "WEB.example.com"}, errAppSameHost},
		{AppSettings{Host: "web.example.com", Allow: []string{"everyone"}}, errAPIAllow},
		{AppSettings{AdminHost: "admin.example.com", AdminAllow: []string{"10.0.0.0/33"}}, errAPIAllow},
		{AppSettings{Host: "bad host"}, gate.ErrBadHost},
	} {
		if _, err := f.m.appSet(ctx, c.ask); !errors.Is(err, c.want) {
			t.Errorf("%+v: %v; want %v", c.ask, err, c.want)
		}
	}
	if f.bumps != bumps || f.m.forApps() != nil {
		t.Fatal("a refused setting changed something")
	}
	got, err := f.m.appSet(ctx, AppSettings{Host: " Web.Example.com", AdminHost: "admin.example.com", AdminAllow: []string{"198.51.100.7/24"}})
	if err != nil || got.Host != webHost || got.AdminHost != adminHost || got.AdminAllow[0] != "198.51.100.0/24" || len(got.Allow) != 0 {
		t.Fatalf("a good setting: %+v, %v", got, err)
	}
	if f.bumps != bumps+1 || !f.m.IsHost(webHost) || !f.m.IsHost(adminHost) || len(f.m.hosts()) != 3 {
		t.Fatalf("after the setting: %d bumps, hosts %v", f.bumps, f.m.hosts())
	}
	if g := f.m.forApps(); g == nil || g.Host != webHost || g.AdminHost != adminHost || len(g.AdminAllow) != 1 {
		t.Fatalf("what the gate is sent: %+v", g)
	}
	if _, err := f.m.set(ctx, APISettings{Host: webHost}); !errors.Is(err, errAPIHostTaken) {
		t.Fatalf("the API on the app host: %v", err)
	}
	again := &apiModule{st: f.st}
	if err := again.load(ctx); err != nil || again.appHostOf(hostgate.HostAdmin) != adminHost || len(again.app.AdminAllow) != 1 {
		t.Fatalf("read back at the next start: %+v %v", again.app, err)
	}
	// Turning the admin host on and stopping half way never opens it wider.
	fs := &failingSettings{fakeSettings: &fakeSettings{m: map[string]string{}}, failAt: 4}
	half := &apiModule{st: fs, covered: f.m.covered, taken: f.m.taken, changed: func() {}}
	if _, err := half.appSet(ctx, AppSettings{AdminHost: adminHost, AdminAllow: []string{"198.51.100.0/24"}}); err == nil {
		t.Fatal("a failed write was not reported")
	}
	if fs.m[adminHostSetting] != "" || fs.m[adminAllowSetting] != "198.51.100.0/24" {
		t.Fatalf("stopped half way: %v", fs.m)
	}
	if _, err := f.m.appSet(ctx, AppSettings{}); err != nil || f.m.forApps() != nil {
		t.Fatalf("turning both off: %v", err)
	}
}

// TestASignIn: from the host's own page only; one answer for every failure;
// a session id planted before it is not the session after it.
func TestASignIn(t *testing.T) {
	f := newAppCore(t)
	good := hostgate.SessionAsk{Op: hostgate.SessionOpen, Host: hostgate.HostApp, Authority: webHost, Origin: webOrigin, FetchSite: "same-origin",
		Param: []byte(`{"name":"vera","passphrase":"` + goodPass + `","code":""}`)}
	for name, mod := range map[string]func(*hostgate.SessionAsk){
		"no origin":         func(a *hostgate.SessionAsk) { a.Origin = "" },
		"another origin":    func(a *hostgate.SessionAsk) { a.Origin = "https://evil.example.net" },
		"plain http":        func(a *hostgate.SessionAsk) { a.Origin = "http://" + webHost },
		"cross-site":        func(a *hostgate.SessionAsk) { a.FetchSite = "cross-site" },
		"same-site":         func(a *hostgate.SessionAsk) { a.FetchSite = "same-site" },
		"another authority": func(a *hostgate.SessionAsk) { a.Authority, a.Origin = "evil.example.net", "https://evil.example.net" },
	} {
		ask := good
		mod(&ask)
		if a := f.session(t, ask); a.Error == nil || a.Error.Name != "app.cross_origin" || a.Cookie != "" {
			t.Errorf("%s: %+v", name, a.Error)
		}
	}
	if len(f.users.logins) != 0 {
		t.Fatalf("a sign-in from another page cost a check: %v", f.users.logins)
	}
	var first *hostgate.APIError
	for _, body := range []string{`{"name":"vera","passphrase":"wrong","code":""}`, `{"name":"nobody","passphrase":"` + goodPass + `"}`,
		`{"name":"vera","passphrase":"` + goodPass + `","code":"locked"}`} {
		ask := good
		ask.Param = []byte(body)
		a := f.session(t, ask)
		if a.Error == nil || a.Error.Kind != hostgate.APIToken || a.Cookie != "" {
			t.Fatalf("%s: %+v", body, a.Error)
		}
		if first == nil {
			first = a.Error
		} else if *a.Error != *first {
			t.Fatalf("%s answers %+v, another failure %+v", body, a.Error, first)
		}
	}
	f.users.busy = true
	if a := f.session(t, good); a.Error == nil || a.Error.Kind != hostgate.APIBusy {
		t.Fatalf("too many waiting: %+v", a.Error)
	}
	f.users.busy = false
	// with the port the page was served on
	ask := good
	ask.Authority, ask.Origin = webHost+":8443", webOrigin+":8443"
	if a := f.session(t, ask); a.Error != nil {
		t.Fatalf("a page on another port: %+v", a.Error)
	}
	planted, _ := f.signIn(t, hostgate.HostApp, "vera")
	ask = good
	ask.Session = planted
	a := f.session(t, ask)
	if a.Error != nil || a.Cookie == "" || a.Cookie == planted {
		t.Fatalf("a sign-in with an id already set: %+v", a.Error)
	}
	if _, err := f.m.sessions.Resolve(context.Background(), planted, hostgate.HostApp); !errors.Is(err, auth.ErrNoSession) {
		t.Fatal("the id set before the sign-in outlived it (fixation)")
	}
	var o SessionOpened
	_ = json.Unmarshal(a.Result, &o)
	if o.User.Name != "vera" || o.User.Role != auth.RoleViewer || o.ExpiresAt == 0 || strings.Contains(string(a.Result), a.Cookie) {
		t.Fatalf("the answer: %s", a.Result)
	}
	if !strings.Contains(strings.Join(f.aud.all(), "\n"), "vera (browser 203.0.113.9) | auth.session.open | app | session ") {
		t.Fatalf("the sign-in is not on record: %v", f.aud.all())
	}
}

// TestTheAdminHostIsTheAdminsAndOperators: a viewer cannot sign in there, and
// a session of one host is none on the other.
func TestTheAdminHostIsTheAdminsAndOperators(t *testing.T) {
	f := newAppCore(t)
	a := f.session(t, hostgate.SessionAsk{Op: hostgate.SessionOpen, Host: hostgate.HostAdmin, Authority: adminHost, Origin: "https://" + adminHost,
		Param: []byte(`{"name":"vera","passphrase":"` + goodPass + `"}`)})
	if a.Error == nil || a.Error.Name != "auth.bad_login" || a.Cookie != "" {
		t.Fatalf("a viewer on the admin host: %+v", a.Error)
	}
	op, _ := f.signIn(t, hostgate.HostAdmin, "neo")
	web, _ := f.signIn(t, hostgate.HostApp, "ada")
	if a := f.session(t, hostgate.SessionAsk{Op: hostgate.SessionGet, Host: hostgate.HostApp, Session: op, Method: "GET"}); a.Error == nil || !a.Clear {
		t.Fatalf("an admin host's session on the app host: %+v", a.Error)
	}
	if a := f.session(t, hostgate.SessionAsk{Op: hostgate.SessionGet, Host: hostgate.HostAdmin, Session: web, Method: "GET"}); a.Error == nil {
		t.Fatalf("an app host's session on the admin host: %+v", a.Error)
	}
	// demoted, the operator's session is none on the admin host
	if err := f.st.Users().SetLogin(context.Background(), f.ids["neo"], auth.RoleViewer, nil, "v", false); err != nil {
		t.Fatal(err)
	}
	if a := f.session(t, hostgate.SessionAsk{Op: hostgate.SessionGet, Host: hostgate.HostAdmin, Session: op, Method: "GET"}); a.Error == nil {
		t.Fatal("a demoted operator keeps the admin host")
	}
}

// TestTheCoreChecksTheAdminHostsSourcesAgain: the gate's word for the
// address, the core's own check of it.
func TestTheCoreChecksTheAdminHostsSourcesAgain(t *testing.T) {
	f := newAppCore(t)
	op, csrf := f.signIn(t, hostgate.HostAdmin, "ada")
	ask := hostgate.SessionAsk{Op: hostgate.SessionGet, Host: hostgate.HostAdmin, Session: op, Method: "GET", Client: "192.0.2.1"}
	if a, _ := f.m.session(context.Background(), ask); a.Error == nil || a.Error.Name != "app.not_allowed" {
		t.Fatalf("the admin host from outside its sources: %+v", a.Error)
	}
	call := hostgate.APIAsk{Verb: "sys.s.admin", Host: hostgate.HostAdmin, Authority: adminHost, Session: op, CSRF: csrf, Origin: "https://" + adminHost, Client: "192.0.2.1"}
	if a, _ := f.m.call(context.Background(), call); kindOf(a) != hostgate.APIForbidden || a.Error.Name != "app.not_allowed" {
		t.Fatalf("a call from outside: %+v", a.Error)
	}
	call.Client = "203.0.113.200"
	if a, _ := f.m.call(context.Background(), call); a.Error != nil {
		t.Fatalf("a call from inside: %+v", a.Error)
	}
	f.m.mu.Lock()
	f.m.app.AdminAllow = nil
	f.m.mu.Unlock()
	if a, _ := f.m.call(context.Background(), call); kindOf(a) != hostgate.APIForbidden {
		t.Fatalf("with no sources at all: %+v", a.Error)
	}
	if a := f.session(t, hostgate.SessionAsk{Op: hostgate.SessionGet, Host: hostgate.HostApp, Method: "GET"}); a.Error.Name == "app.not_allowed" {
		t.Fatal("the app host's empty list keeps people out")
	}
}

// TestASessionsStateTokenAndSignOut: the page asks who it is with the cookie
// alone; its token again from its own origin; signing out is a change.
func TestASessionsStateTokenAndSignOut(t *testing.T) {
	f := newAppCore(t)
	if a := f.session(t, hostgate.SessionAsk{Op: hostgate.SessionGet, Host: hostgate.HostApp, Method: "GET"}); a.Error == nil || a.Error.Kind != hostgate.APIToken || !a.Clear {
		t.Fatalf("no cookie: %+v", a)
	}
	cookie, csrf := f.signIn(t, hostgate.HostApp, "vera")
	a := f.session(t, hostgate.SessionAsk{Op: hostgate.SessionGet, Host: hostgate.HostApp, Session: cookie, Method: "GET"})
	var st SessionState
	if a.Error != nil || json.Unmarshal(a.Result, &st) != nil || st.User.Name != "vera" {
		t.Fatalf("its state: %s %+v", a.Result, a.Error)
	}
	if a := f.session(t, hostgate.SessionAsk{Op: hostgate.SessionCSRF, Host: hostgate.HostApp, Session: cookie, Authority: webHost, Origin: "https://evil.example.net"}); a.Error == nil {
		t.Fatal("the token, to another origin")
	}
	a = f.session(t, hostgate.SessionAsk{Op: hostgate.SessionCSRF, Host: hostgate.HostApp, Session: cookie, Authority: webHost, Origin: webOrigin})
	if a.Error != nil || !strings.Contains(string(a.Result), `"csrf":"`+csrf+`"`) {
		t.Fatalf("the token again: %s %+v; want the same in every tab", a.Result, a.Error)
	}
	end := hostgate.SessionAsk{Op: hostgate.SessionEnd, Host: hostgate.HostApp, Session: cookie, Authority: webHost, Origin: webOrigin, Method: "DELETE"}
	for name, mod := range map[string]func(*hostgate.SessionAsk){
		"without the token": func(a *hostgate.SessionAsk) {},
		"a wrong token":     func(a *hostgate.SessionAsk) { a.CSRF = csrf[:len(csrf)-1] + "x" },
		"another origin":    func(a *hostgate.SessionAsk) { a.CSRF, a.Origin = csrf, "https://evil.example.net" },
	} {
		ask := end
		mod(&ask)
		if a := f.session(t, ask); a.Error == nil || a.Clear {
			t.Fatalf("signing out %s: %+v", name, a)
		}
	}
	end.CSRF = csrf
	if a := f.session(t, end); a.Error != nil || !a.Clear || len(a.Result) != 0 {
		t.Fatalf("signing out: %+v", a)
	}
	if _, err := f.m.sessions.Resolve(context.Background(), cookie, hostgate.HostApp); err == nil {
		t.Fatal("the session outlived its sign-out")
	}
	if a := f.session(t, end); a.Error != nil || !a.Clear {
		t.Fatalf("signing out again: %+v", a)
	}
}

// TestACallNeedsTheSessionTheOriginAndTheToken: the cookie alone runs
// nothing; each missing part is refused and changes nothing.
func TestACallNeedsTheSessionTheOriginAndTheToken(t *testing.T) {
	f := newAppCore(t)
	cookie, csrf := f.signIn(t, hostgate.HostApp, "ada")
	good := hostgate.APIAsk{Verb: "mail.s.change", Host: hostgate.HostApp, Authority: webHost, Session: cookie, CSRF: csrf, Origin: webOrigin, FetchSite: "same-origin", Method: "POST"}
	for name, mod := range map[string]func(*hostgate.APIAsk){
		"no token":             func(a *hostgate.APIAsk) { a.CSRF = "" },
		"a wrong token":        func(a *hostgate.APIAsk) { a.CSRF = strings.Repeat("A", len(csrf)) },
		"another origin":       func(a *hostgate.APIAsk) { a.Origin = "https://evil.example.net" },
		"no origin":            func(a *hostgate.APIAsk) { a.Origin = "" },
		"cross-site":           func(a *hostgate.APIAsk) { a.FetchSite = "cross-site" },
		"a read, cross-origin": func(a *hostgate.APIAsk) { a.Verb, a.Origin = "mail.s.read", "https://evil.example.net" },
		"a token's read too":   func(a *hostgate.APIAsk) { a.Verb, a.CSRF = "mail.s.both", "" },
	} {
		ask := good
		mod(&ask)
		if a := f.ask(t, ask); kindOf(a) != hostgate.APIForbidden || a.Error.Name != "app.cross_origin" {
			t.Errorf("%s: %+v", name, a.Error)
		}
	}
	if r := f.ran(); len(r) != 0 {
		t.Fatalf("a refused call ran: %v", r)
	}
	for name, mod := range map[string]func(*hostgate.APIAsk){
		"no cookie":        func(a *hostgate.APIAsk) { a.Session = "" },
		"an unknown one":   func(a *hostgate.APIAsk) { a.Session = strings.Repeat("A", 43) },
		"the admin host's": func(a *hostgate.APIAsk) { a.Host = hostgate.HostAdmin },
	} {
		ask := good
		mod(&ask)
		if a := f.ask(t, ask); kindOf(a) != hostgate.APIToken {
			t.Errorf("%s: %+v", name, a.Error)
		}
	}
	ask := good
	ask.Token = "apt_1_" + strings.Repeat("a", 43)
	if a := f.ask(t, ask); kindOf(a) != hostgate.APIBadParam || a.Error.Name != "app.two_credentials" {
		t.Fatalf("a token and a session: %+v", a.Error)
	}
	if a := f.ask(t, good); a.Error != nil || string(a.Result) != `"done"` {
		t.Fatalf("a good change: %s %+v", a.Result, a.Error)
	}
	got := f.aud.all()
	if !strings.Contains(strings.Join(got, "\n"), "ada (app 203.0.113.9, session ") {
		t.Fatalf("the change's actor: %v", got)
	}
}

// TestWhatASessionMayCall: session verbs only, none of the admin host's on
// the app host, a token's verbs not at all unless they are a session's too;
// a user who must change the passphrase may do only that; a disabled user
// has no session.
func TestWhatASessionMayCall(t *testing.T) {
	f := newAppCore(t)
	cookie, csrf := f.signIn(t, hostgate.HostApp, "ada")
	for _, verb := range []string{"sys.s.admin", "sys.app.set", "sys.api.get", "t.read", "auth.login"} {
		if a := f.callAs(t, cookie, csrf, verb); kindOf(a) != hostgate.APINotFound {
			t.Errorf("%s from the app host: %+v", verb, a.Error)
		}
	}
	if a := f.callAs(t, cookie, csrf, "mail.s.both"); a.Error != nil {
		t.Fatalf("a verb of both sets: %+v", a.Error)
	}
	a := f.callAs(t, cookie, csrf, apiContracts)
	var cs []module.Contract
	if a.Error != nil || json.Unmarshal(a.Result, &cs) != nil {
		t.Fatalf("the contracts: %+v", a.Error)
	}
	var names []string
	for _, c := range cs {
		names = append(names, c.Verb)
	}
	if strings.Join(names, " ") != "auth.passphrase.change mail.s.both mail.s.change mail.s.read" {
		t.Fatalf("the app host's contracts: %v", names)
	}
	op, opCSRF := f.signIn(t, hostgate.HostAdmin, "ada")
	if a := f.ask(t, hostgate.APIAsk{Verb: "sys.s.admin", Host: hostgate.HostAdmin, Authority: adminHost, Session: op, CSRF: opCSRF, Origin: "https://" + adminHost, Method: "POST"}); a.Error != nil {
		t.Fatalf("an admin's verb on the admin host: %+v", a.Error)
	}
	// a viewer's role is checked as everywhere
	vc, vcsrf := f.signIn(t, hostgate.HostApp, "vera")
	if a := f.callAs(t, vc, vcsrf, "mail.s.change"); kindOf(a) != hostgate.APIForbidden {
		t.Fatalf("a viewer's change: %+v", a.Error)
	}
	ctx := context.Background()
	if err := f.st.Users().SetLogin(ctx, f.ids["vera"], auth.RoleViewer, nil, "v", true); err != nil {
		t.Fatal(err)
	}
	if a := f.callAs(t, vc, vcsrf, "mail.s.read"); kindOf(a) != hostgate.APIForbidden || a.Error.Name != "auth.must_change" {
		t.Fatalf("a read before the passphrase is changed: %+v", a.Error)
	}
	if a := f.callAs(t, vc, vcsrf, "auth.passphrase.change"); a.Error != nil {
		t.Fatalf("the passphrase change itself: %+v", a.Error)
	}
	if err := f.st.Users().SetDisabled(ctx, f.ids["vera"], true); err != nil {
		t.Fatal(err)
	}
	if a := f.callAs(t, vc, vcsrf, "auth.passphrase.change"); kindOf(a) != hostgate.APIToken {
		t.Fatalf("a disabled user's session: %+v", a.Error)
	}
}

// TestTheSessionVerbsAreExactlyThese: the session's public set, listed, so a
// verb joins it only by a change to this test.
func TestTheSessionVerbsAreExactlyThese(t *testing.T) {
	m := &apiModule{}
	var mods []module.Module
	for _, mod := range contractModules() {
		if _, ok := mod.(*apiModule); ok {
			continue
		}
		mods = append(mods, mod)
	}
	if err := m.serve(append(mods, m)...); err != nil {
		t.Fatal(err)
	}
	want := "auth.passphrase.change auth.session.end auth.session.list auth.token.create auth.token.list auth.token.revoke auth.totp.begin auth.totp.confirm auth.totp.disable auth.whoami"
	var got []string
	for v := range m.sessionVerbs {
		got = append(got, v)
		if m.sessionVerbs[v].Public {
			t.Errorf("%s: a session-only verb a token may call", v)
		}
	}
	sort.Strings(got)
	if strings.Join(got, " ") != want {
		t.Fatalf("the session verbs:\n got %s\nwant %s", strings.Join(got, " "), want)
	}
	if len(m.appVerbSet) != len(m.sessionVerbs) {
		t.Fatal("a self-service verb is kept from the app host")
	}
}

// TestTheSitesReadersAreTheAppHostsSessions: the site finds a member by the
// app host's session cookie, as the browser login would: a session of the
// admin host, a cookie nobody has and a disabled user are nobody.
func TestTheSitesReadersAreTheAppHostsSessions(t *testing.T) {
	f := newAppCore(t)
	ctx := context.Background()
	sessions, isAppHost := siteReaders(f.m)
	if !isAppHost(webHost) || isAppHost(adminHost) || isAppHost("") || isAppHost("blog.example.com") {
		t.Fatal("which host is the applications'")
	}
	vera, _ := f.signIn(t, hostgate.HostApp, "vera")
	ada, _ := f.signIn(t, hostgate.HostApp, "ada")
	if u := sessions(ctx, webHost, vera); u == nil || u.ID != f.ids["vera"] || u.Admin {
		t.Fatalf("a member's session: %+v", u)
	}
	if u := sessions(ctx, webHost, ada); u == nil || u.ID != f.ids["ada"] || !u.Admin {
		t.Fatalf("an administrator's session: %+v", u)
	}
	onAdmin, _ := f.signIn(t, hostgate.HostAdmin, "ada")
	for what, cookie := range map[string]string{"no cookie": "", "a cookie nobody has": "nobodys-cookie", "a session of the admin host": onAdmin} {
		if u := sessions(ctx, webHost, cookie); u != nil {
			t.Errorf("%s is a reader: %+v", what, u)
		}
	}
	if err := f.st.Users().SetDisabled(ctx, f.ids["vera"], true); err != nil {
		t.Fatal(err)
	}
	if u := sessions(ctx, webHost, vera); u != nil {
		t.Errorf("a disabled user's session is a reader: %+v", u)
	}
	if s, _ := siteReaders(&apiModule{}); s(ctx, webHost, ada) != nil {
		t.Error("a core with no sessions found a reader")
	}
}
