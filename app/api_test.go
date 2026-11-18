package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yongjohnlee80/autopanel/core/gate"
	hostgate "github.com/yongjohnlee80/autopanel/host/gate"
	"github.com/yongjohnlee80/autopanel/internal/auth"
	"github.com/yongjohnlee80/autopanel/internal/module"
)

// fakeTokens resolves two tokens: an admin's and a viewer's.
type fakeTokens struct {
	mu      sync.Mutex
	expired map[string]bool // principals whose token ended after it was resolved
	bad     int             // failed checks
}

const (
	adminToken  = "apt_1_admin"
	viewerToken = "apt_2_viewer"
)

func (f *fakeTokens) APIToken(_ context.Context, token, _ string) (string, error) {
	switch token {
	case adminToken:
		return "token:1", nil
	case viewerToken:
		return "token:2", nil
	}
	f.mu.Lock()
	f.bad++
	f.mu.Unlock()
	return "", auth.ErrBadLogin
}

func (f *fakeTokens) Authorize(_ context.Context, principal string, _ time.Time, c module.Contract) (string, error) {
	role, name := auth.RoleViewer, "token monitor of vera"
	if principal == "token:1" {
		role, name = auth.RoleAdmin, "token deploy of ada"
	}
	f.mu.Lock()
	gone := f.expired[principal]
	f.mu.Unlock()
	switch {
	case gone:
		return name, auth.ErrExpired
	case !auth.Allows(role, c):
		return name, auth.ErrForbidden
	}
	return name, nil
}

// fakeAudit keeps the privileged entries.
type fakeAudit struct {
	mu      sync.Mutex
	entries []string // "actor | action | subject | outcome"
	fail    bool
}

func (f *fakeAudit) AuditAttempt(_ context.Context, actor, action, subject string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return 0, errors.New("the audit log is full")
	}
	f.entries = append(f.entries, actor+" | "+action+" | "+subject+" | ")
	return int64(len(f.entries)), nil
}

func (f *fakeAudit) AuditResult(_ context.Context, id int64, outcome string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries[id-1] += outcome
	return nil
}

func (f *fakeAudit) all() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.entries...)
}

type fakeSettings struct {
	mu sync.Mutex
	m  map[string]string
}

func (f *fakeSettings) Setting(_ context.Context, key string) (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.m[key]
	return v, ok, nil
}

func (f *fakeSettings) PutSetting(_ context.Context, key, value string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.m[key] = value
	return nil
}

var errTestRefused = errors.New("test: refused")

// apiTestVerbs is a module with one verb of each kind the API must tell apart.
type apiTestVerbs struct {
	changed []string // what t.change was given
}

type nameParam struct {
	Name string `json:"name"`
}

func (*apiTestVerbs) Name() string { return "t" }

func (*apiTestVerbs) Errors() []module.PublicError {
	return []module.PublicError{{Err: errTestRefused, Code: -32299, Name: "t.refused", Message: "the test verb refused"}}
}

func (m *apiTestVerbs) Verbs() []module.Verb {
	return []module.Verb{
		module.Handle(module.Contract{Verb: "t.read", Area: "sys", Public: true, Discloses: module.Plain},
			func(context.Context, struct{}) (map[string]any, error) { return map[string]any{"n": 1}, nil }),
		module.Handle(module.Contract{Verb: "t.admin", Area: "sys.admin", Public: true, Discloses: module.Plain},
			func(context.Context, struct{}) (string, error) { return "the admin's", nil }),
		module.Handle(module.Contract{Verb: "t.change", Area: "sys.admin", Public: true, Mutates: true, Privileged: true, MaxBody: 1 << 20},
			func(_ context.Context, p nameParam) (nameParam, error) {
				m.changed = append(m.changed, p.Name)
				return p, nil
			}),
		module.Handle(module.Contract{Verb: "t.private", Area: "sys", Discloses: module.Plain},
			func(context.Context, struct{}) (string, error) { return "never served", nil }),
		module.Handle(module.Contract{Verb: "t.fail", Area: "sys", Public: true, Discloses: module.Plain},
			func(context.Context, struct{}) (string, error) { return "", errTestRefused }),
		module.Handle(module.Contract{Verb: "t.broken", Area: "sys", Public: true, Discloses: module.Plain},
			func(context.Context, struct{}) (string, error) { return "", errors.New("a secret detail") }),
		module.Handle(module.Contract{Verb: "t.panic", Area: "sys", Public: true, Discloses: module.Plain},
			func(context.Context, struct{}) (string, error) { panic("boom") }),
	}
}

type apiCoreFixture struct {
	m      *apiModule
	tokens *fakeTokens
	aud    *fakeAudit
	verbs  *apiTestVerbs
	st     *fakeSettings
	bumps  int
}

func newAPICore(t *testing.T) *apiCoreFixture {
	t.Helper()
	f := &apiCoreFixture{tokens: &fakeTokens{expired: map[string]bool{}}, aud: &fakeAudit{}, verbs: &apiTestVerbs{}, st: &fakeSettings{m: map[string]string{}}}
	f.m = &apiModule{st: f.st, auth: f.tokens, aud: f.aud, log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		covered: func(_ context.Context, h string) (bool, error) { return gate.Under(h, "example.com"), nil },
		taken:   func(h string) bool { return h == "app.example.com" || h == "mail.example.com" },
		changed: func() { f.bumps++ }}
	if err := f.m.serve(f.verbs, &auth.Module{}, f.m); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *apiCoreFixture) call(t *testing.T, token, verb, body string) hostgate.APIAnswer {
	t.Helper()
	ans, err := f.m.call(context.Background(), hostgate.APIAsk{Verb: verb, Param: []byte(body), Token: token, Client: "203.0.113.9", RequestID: "r1"})
	if err != nil {
		t.Fatalf("link.api itself failed: %v", err)
	}
	return ans
}

func kindOf(a hostgate.APIAnswer) string {
	if a.Error == nil {
		return ""
	}
	return a.Error.Kind
}

// TestWithoutAGoodTokenEveryVerbAnswersAlike: a public verb, a private one and
// one that does not exist cannot be told apart by someone with no token.
func TestWithoutAGoodTokenEveryVerbAnswersAlike(t *testing.T) {
	f := newAPICore(t)
	var first *hostgate.APIError
	for _, verb := range []string{"t.read", "t.private", "t.nothing", "auth.login", apiContracts, "t.change"} {
		a := f.call(t, "apt_9_nobody", verb, `{"name":"x"}`)
		if kindOf(a) != hostgate.APIToken || a.Error.Name != "api.unauthorized" || len(a.Result) != 0 {
			t.Fatalf("%s with a bad token: %+v", verb, a.Error)
		}
		if first == nil {
			first = a.Error
		} else if *a.Error != *first {
			t.Fatalf("%s answers %+v; the first verb answered %+v", verb, a.Error, first)
		}
	}
	if len(f.verbs.changed) != 0 || len(f.aud.all()) != 0 {
		t.Fatalf("a bad token ran or audited a verb: %v %v", f.verbs.changed, f.aud.all())
	}
	// A token that ended between being resolved and being authorised is the same answer.
	f.tokens.expired["token:2"] = true
	if a := f.call(t, viewerToken, "t.read", ""); kindOf(a) != hostgate.APIToken || *a.Error != *first {
		t.Fatalf("a token that just ended: %+v", a.Error)
	}
	if a := f.call(t, viewerToken, apiContracts, ""); kindOf(a) != hostgate.APIToken {
		t.Fatalf("its contracts: %+v", a.Error)
	}
}

// TestOnlyPublicVerbsAreServed: with a good token, a private verb and an
// unknown one are both "no such verb"; the login and the link's verbs are
// private like any other.
func TestOnlyPublicVerbsAreServed(t *testing.T) {
	f := newAPICore(t)
	for _, verb := range []string{"t.private", "t.nothing", "auth.login", "auth.user.add", "sys.api.set", hostgate.VerbAPI} {
		if a := f.call(t, adminToken, verb, ""); kindOf(a) != hostgate.APINotFound {
			t.Errorf("%s: %+v; want not found", verb, a.Error)
		}
	}
	a := f.call(t, viewerToken, "t.read", "")
	if a.Error != nil || string(a.Result) != `{"n":1}` {
		t.Fatalf("a public read: %s %+v", a.Result, a.Error)
	}
}

// TestAReadLeavesNoAuditEntryAndARefusalDoes: a poll writes nothing; a call the
// role may not make is on record, with who, from where and which request.
func TestAReadLeavesNoAuditEntryAndARefusalDoes(t *testing.T) {
	f := newAPICore(t)
	for range 100 {
		if a := f.call(t, viewerToken, "t.read", ""); a.Error != nil {
			t.Fatal(a.Error)
		}
	}
	if got := f.aud.all(); len(got) != 0 {
		t.Fatalf("a hundred reads wrote %d audit entries", len(got))
	}
	a := f.call(t, viewerToken, "t.admin", "")
	if kindOf(a) != hostgate.APIForbidden || a.Error.Name != "auth.forbidden" {
		t.Fatalf("a viewer on an admin's verb: %+v", a.Error)
	}
	got := f.aud.all()
	want := "token monitor of vera (api 203.0.113.9, token #2, request r1) | t.admin |  | auth.forbidden"
	if len(got) != 1 || got[0] != want {
		t.Fatalf("the refusal's entry:\n got %q\nwant %q", got, want)
	}
}

// TestAChangeIsAuditedBeforeItRuns: a privileged public verb leaves its entry
// first, with the token's owner as the actor, and does not run without it.
func TestAChangeIsAuditedBeforeItRuns(t *testing.T) {
	f := newAPICore(t)
	a := f.call(t, adminToken, "t.change", `{"name":"site"}`)
	if a.Error != nil || string(a.Result) != `{"name":"site"}` || len(f.verbs.changed) != 1 {
		t.Fatalf("the change: %s %+v %v", a.Result, a.Error, f.verbs.changed)
	}
	got := f.aud.all()
	if len(got) != 1 || got[0] != `token deploy of ada (api 203.0.113.9, token #1, request r1) | t.change | name "site" | ok` {
		t.Fatalf("the change's entry: %q", got)
	}
	if a := f.call(t, viewerToken, "t.change", `{"name":"x"}`); kindOf(a) != hostgate.APIForbidden || len(f.verbs.changed) != 1 {
		t.Fatalf("a viewer changing: %+v", a.Error)
	}
	f.aud.fail = true
	if a := f.call(t, adminToken, "t.change", `{"name":"y"}`); kindOf(a) != hostgate.APIInternal || len(f.verbs.changed) != 1 {
		t.Fatalf("a change whose entry could not be written ran: %+v %v", a.Error, f.verbs.changed)
	}
}

// TestWhatAVerbRefusesCrossesAsDeclared: a body that is not what the verb takes
// is a bad request; a declared error crosses with its code and name; anything
// else, and a panic, cross as a bare internal error.
func TestWhatAVerbRefusesCrossesAsDeclared(t *testing.T) {
	f := newAPICore(t)
	for body, verb := range map[string]string{`{not json`: "t.change", `{"nam":"x"}`: "t.change", `[1,2]`: "t.change"} {
		if a := f.call(t, adminToken, verb, body); kindOf(a) != hostgate.APIBadParam {
			t.Errorf("%s with %s: %+v", verb, body, a.Error)
		}
	}
	a := f.call(t, viewerToken, "t.fail", "")
	if kindOf(a) != hostgate.APIFailed || a.Error.Code != -32299 || a.Error.Name != "t.refused" || a.Error.Message != "the test verb refused" {
		t.Fatalf("a declared refusal: %+v", a.Error)
	}
	for _, verb := range []string{"t.broken", "t.panic"} {
		a := f.call(t, viewerToken, verb, "")
		if kindOf(a) != hostgate.APIInternal || strings.Contains(a.Error.Message, "secret") || strings.Contains(a.Error.Message, "boom") {
			t.Fatalf("%s: %+v", verb, a.Error)
		}
	}
	// The gate's word for the client and the request cannot break an audit entry.
	ans, _ := f.m.call(context.Background(), hostgate.APIAsk{Verb: "t.admin", Token: viewerToken, Client: "1.2.3.4) | forged | (", RequestID: "a\nb"})
	if kindOf(ans) != hostgate.APIForbidden {
		t.Fatal(ans.Error)
	}
	if e := f.aud.all()[0]; strings.Count(e, "|") != 3 || strings.Contains(e, "\n") || strings.Contains(e, "forged | (") {
		t.Fatalf("the gate's text reached the entry raw: %q", e)
	}
}

// TestContractsAreTheOnesTheRoleMayCall: /v1/contracts lists the public verbs
// this token reaches, and nothing private.
func TestContractsAreTheOnesTheRoleMayCall(t *testing.T) {
	f := newAPICore(t)
	list := func(token string) []string {
		a := f.call(t, token, apiContracts, "")
		if a.Error != nil {
			t.Fatal(a.Error)
		}
		var cs []module.Contract
		if err := json.Unmarshal(a.Result, &cs); err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, c := range cs {
			out = append(out, c.Verb)
		}
		return out
	}
	if got := strings.Join(list(viewerToken), " "); got != "t.broken t.fail t.panic t.read" {
		t.Errorf("a viewer's contracts: %s", got)
	}
	if got := strings.Join(list(adminToken), " "); got != "t.admin t.broken t.change t.fail t.panic t.read" {
		t.Errorf("an admin's contracts: %s", got)
	}
}

// TestAContractThatCannotBePublicStopsTheCore: an open verb or a login made
// public, and a body limit on a private verb or past the most there is, are
// refused when the verbs are gathered.
func TestAContractThatCannotBePublicStopsTheCore(t *testing.T) {
	for name, c := range map[string]module.Contract{
		"a private verb with a body limit": {Verb: "x.a", MaxBody: 1024},
		"a body limit past the most":       {Verb: "x.b", Public: true, MaxBody: MaxAPIBody + 1},
		"an open verb made public":         {Verb: "x.c", Public: true, Open: true},
		"a login made public":              {Verb: "x.d", Public: true, Login: true},
	} {
		m := &apiModule{}
		if err := m.serve(oneVerb{c}); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

type oneVerb struct{ c module.Contract }

func (oneVerb) Name() string                 { return "x" }
func (oneVerb) Errors() []module.PublicError { return nil }
func (o oneVerb) Verbs() []module.Verb       { return []module.Verb{{Contract: o.c}} }

// TestThePublicVerbsAreExactlyThese: the verbs a token may call over HTTPS.
// Adding one is a change to this list, reviewed; each is a read whose answer
// is Plain, and none is of the users' module.
func TestThePublicVerbsAreExactlyThese(t *testing.T) {
	want := []string{"certs.list", "gate.domain.list", "gate.route.list", "services.list", "sys.checks", "sys.firewall.get", "sys.status"}
	var got []string
	for _, m := range contractModules() {
		for _, v := range m.Verbs() {
			if !v.Public {
				if v.MaxBody != 0 {
					t.Errorf("%s is private and declares a body limit", v.Verb)
				}
				continue
			}
			got = append(got, v.Verb)
			if v.Discloses != module.Plain || v.Mutates || v.Privileged || v.Open || v.Login || v.AreaOf() == "auth" {
				t.Errorf("%s is public and is not a plain read outside auth: %+v", v.Verb, v.Contract)
			}
		}
	}
	sort.Strings(got)
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("the public verbs:\n got %v\nwant %v", got, want)
	}
	m := &apiModule{}
	if err := m.serve(contractModules()...); err != nil {
		t.Fatalf("the real contracts: %v", err)
	}
	// A viewer's token reaches all but the firewall, which is the admin's.
	for _, v := range want {
		if ok := auth.Allows(auth.RoleViewer, m.public[v].Contract); ok != (v != "sys.firewall.get") {
			t.Errorf("a viewer calling %s: %v", v, ok)
		}
	}
}

// TestTheAPIsHostIsSetOnlyWhereItCanBeServed: under a registered domain, on a
// host nothing else uses, with sources that are prefixes; an empty host turns
// it off; what was set is read back at the next start.
func TestTheAPIsHostIsSetOnlyWhereItCanBeServed(t *testing.T) {
	f := newAPICore(t)
	ctx := context.Background()
	if f.m.forGate() != nil || f.m.IsHost("") || len(f.m.hosts()) != 0 {
		t.Fatal("the API is on before it was set")
	}
	for host, want := range map[string]error{"api.other.net": gate.ErrNoDomain, "app.example.com": errAPIHostTaken, "mail.example.com": errAPIHostTaken, "bad host": gate.ErrBadHost} {
		if _, err := f.m.set(ctx, APISettings{Host: host}); !errors.Is(err, want) {
			t.Errorf("setting %q: %v; want %v", host, err, want)
		}
	}
	if _, err := f.m.set(ctx, APISettings{Host: "api.example.com", Allow: []string{"203.0.113.0/24", "everyone"}}); !errors.Is(err, errAPIAllow) {
		t.Errorf("a source that is no prefix: %v", err)
	}
	if f.bumps != 0 || f.m.Host() != "" {
		t.Fatalf("a refused setting changed something: %d %q", f.bumps, f.m.Host())
	}
	got, err := f.m.set(ctx, APISettings{Host: " API.Example.com ", Allow: []string{"203.0.113.77/24"}})
	if err != nil || got.Host != "api.example.com" || len(got.Allow) != 1 || got.Allow[0] != "203.0.113.0/24" {
		t.Fatalf("a good setting: %+v, %v", got, err)
	}
	if f.bumps != 1 || !f.m.IsHost("api.example.com") || f.m.hosts()[0] != "api.example.com" {
		t.Fatalf("after the setting: bumps %d, host %q", f.bumps, f.m.Host())
	}
	g := f.m.forGate()
	if g == nil || g.Host != "api.example.com" || g.Allow[0] != "203.0.113.0/24" || len(g.Large) != 1 || g.Large[0] != (hostgate.APIVerb{Verb: "t.change", MaxBody: 1 << 20}) {
		t.Fatalf("what the gate is sent: %+v", g)
	}
	again := &apiModule{st: f.st}
	if err := again.load(ctx); err != nil || again.Host() != "api.example.com" || len(again.allow) != 1 {
		t.Fatalf("read back at the next start: %q %v %v", again.Host(), again.allow, err)
	}
	if _, err := f.m.set(ctx, APISettings{}); err != nil || f.m.forGate() != nil || f.bumps != 2 {
		t.Fatalf("turning it off: %v", err)
	}
}
