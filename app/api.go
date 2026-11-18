package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/yongjohnlee80/golib/server/rpc"

	"github.com/yongjohnlee80/autopanel/core/audit"
	"github.com/yongjohnlee80/autopanel/core/gate"
	hostcontrol "github.com/yongjohnlee80/autopanel/host/control"
	hostgate "github.com/yongjohnlee80/autopanel/host/gate"
	"github.com/yongjohnlee80/autopanel/internal/auth"
	"github.com/yongjohnlee80/autopanel/internal/module"
)

// THE HTTPS API'S CORE SIDE — the gate serves the API and decides nothing: it
// passes each call, with the token as the client sent it, over link.api. Here
// the token is resolved, the verb is looked up among the public ones, the role
// is checked and the verb is run, by the chain the control socket uses. The
// core still listens on no network.
//
// Decision: docs/decisions/api.md

// The API's settings, kept as panel settings.
const (
	apiHostSetting  = "api.host"
	apiAllowSetting = "api.allow"
)

// MaxAPIBody is the largest body any public verb may declare.
const MaxAPIBody = 2<<20 + 64<<10

var (
	errAPIHostTaken = errors.New("api: a route or the mail server uses that host")
	errAPIAllow     = errors.New("api: an allowed source is not an address prefix")
)

// apiTokens is what the API needs of the users' module.
type apiTokens interface {
	APIToken(ctx context.Context, token, from string) (principal string, err error)
	Authorize(ctx context.Context, principal string, since time.Time, c module.Contract) (actor string, err error)
}

// apiSettings is where the API's settings are kept.
type apiSettings interface {
	Setting(ctx context.Context, key string) (string, bool, error)
	PutSetting(ctx context.Context, key, value string) error
}

// apiModule is sys.api.* on the control socket, and link.api's handler.
type apiModule struct {
	st      apiSettings
	auth    apiTokens
	aud     hostcontrol.Auditor
	log     *slog.Logger
	covered func(ctx context.Context, host string) (bool, error) // a registered domain covers it
	taken   func(host string) bool                               // a route or mail holds it
	changed func()                                               // the gate is told

	mu    sync.RWMutex
	host  string
	allow []string

	public map[string]module.Verb
	errs   []module.PublicError
	names  map[int64]string // a declared error's name by its code
}

func (m *apiModule) Name() string { return "api" }

func (m *apiModule) Errors() []module.PublicError {
	return []module.PublicError{
		{Err: errAPIHostTaken, Code: -32240, Name: "sys.api.host_taken", Message: "a route or the mail server uses that host; the API needs one of its own"},
		{Err: errAPIAllow, Code: -32241, Name: "sys.api.bad_allow", Message: "an allowed source must be an address prefix, such as 203.0.113.0/24"},
	}
}

// APISettings is sys.api.get's answer and sys.api.set's param.
type APISettings struct {
	Host  string   `json:"host"`  // "": the API is off
	Allow []string `json:"allow"` // source prefixes; none: any address
}

func (m *apiModule) Verbs() []module.Verb {
	return []module.Verb{
		module.Handle(module.Contract{Verb: "sys.api.get", Area: "sys.admin", Discloses: module.Plain, Since: 8, Result: "{host, allow}",
			Doc: "The HTTPS API's host and the source ranges that may call it. An empty host means the API is off."}, m.get),
		module.Handle(module.Contract{Verb: "sys.api.set", Area: "sys.admin", Mutates: true, Privileged: true, Since: 8, Param: "{host, allow?}", Result: "{host, allow}",
			Doc: "Serves the HTTPS API on a host of its own, under a registered domain, to API tokens; an empty host turns it off. allow limits the callers to source prefixes."}, m.set),
	}
}

// load reads the settings at the core's start.
func (m *apiModule) load(ctx context.Context) error {
	host, _, err := m.st.Setting(ctx, apiHostSetting)
	if err != nil {
		return err
	}
	allow, _, err := m.st.Setting(ctx, apiAllowSetting)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.host, m.allow = host, strings.Fields(allow)
	m.mu.Unlock()
	return nil
}

func (m *apiModule) get(context.Context, struct{}) (APISettings, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return APISettings{Host: m.host, Allow: append([]string{}, m.allow...)}, nil
}

func (m *apiModule) set(ctx context.Context, p APISettings) (APISettings, error) {
	host := ""
	if strings.TrimSpace(p.Host) != "" {
		h, err := gate.CanonicalHost(strings.TrimSpace(p.Host))
		if err != nil {
			return APISettings{}, err
		}
		ok, err := m.covered(ctx, h)
		switch {
		case err != nil:
			return APISettings{}, err
		case !ok:
			return APISettings{}, gate.ErrNoDomain
		case m.taken(h):
			return APISettings{}, errAPIHostTaken
		}
		host = h
	}
	allow := make([]string, 0, len(p.Allow))
	for _, a := range p.Allow {
		pre, err := netip.ParsePrefix(strings.TrimSpace(a))
		if err != nil {
			return APISettings{}, errAPIAllow
		}
		allow = append(allow, pre.Masked().String())
	}
	sort.Strings(allow)
	if err := m.st.PutSetting(ctx, apiHostSetting, host); err != nil {
		return APISettings{}, err
	}
	if err := m.st.PutSetting(ctx, apiAllowSetting, strings.Join(allow, " ")); err != nil {
		return APISettings{}, err
	}
	m.mu.Lock()
	m.host, m.allow = host, allow
	m.mu.Unlock()
	m.changed() // after the commit only
	return APISettings{Host: host, Allow: allow}, nil
}

// Host is the API's host, "" when it is off.
func (m *apiModule) Host() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.host
}

// IsHost reports whether name is the API's host: the certificate manager
// admits it, though no route names it.
func (m *apiModule) IsHost(name string) bool {
	h := m.Host()
	return h != "" && h == name
}

// hosts is the API's host as a list, for whoever reserves it.
func (m *apiModule) hosts() []string {
	if h := m.Host(); h != "" {
		return []string{h}
	}
	return nil
}

// forGate is what the gate is sent: nil while the API is off.
func (m *apiModule) forGate() *hostgate.API {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.host == "" {
		return nil
	}
	out := &hostgate.API{Host: m.host, Allow: append([]string{}, m.allow...), Large: []hostgate.APIVerb{}}
	for name, v := range m.public {
		if v.MaxBody > 0 {
			out.Large = append(out.Large, hostgate.APIVerb{Verb: name, MaxBody: v.MaxBody})
		}
	}
	sort.Slice(out.Large, func(i, j int) bool { return out.Large[i].Verb < out.Large[j].Verb })
	return out
}

// serve takes the public verbs out of the control socket's modules. A verb
// that is open or a login can never be public, and only a public verb may
// declare a larger body: a mistake in a contract stops the core at its start.
func (m *apiModule) serve(mods ...module.Module) error {
	m.public, m.names = map[string]module.Verb{}, map[int64]string{}
	for _, mod := range mods {
		for _, e := range mod.Errors() {
			m.errs = append(m.errs, e)
			m.names[e.Code] = e.Name
		}
		for _, v := range mod.Verbs() {
			switch {
			case v.MaxBody != 0 && !v.Public:
				return fmt.Errorf("api: %s declares a body limit and is not public", v.Verb)
			case v.MaxBody < 0 || v.MaxBody > MaxAPIBody:
				return fmt.Errorf("api: %s declares a body limit outside 0 to %d", v.Verb, MaxAPIBody)
			case v.Public && (v.Open || v.Login):
				return fmt.Errorf("api: %s is open or a login, and cannot be public", v.Verb)
			case v.Public:
				m.public[v.Verb] = v
			}
		}
	}
	return nil
}

// apiContracts is the verb the API answers itself: the public contracts the
// token's role may call.
const apiContracts = "api.contracts"

// call is link.api: one call of the HTTPS API.
func (m *apiModule) call(ctx context.Context, ask hostgate.APIAsk) (ans hostgate.APIAnswer, _ error) {
	defer func() {
		if r := recover(); r != nil {
			m.log.Error("api: a verb panicked", "verb", ask.Verb, "panic", r)
			ans = refusal(hostgate.APIInternal, rpc.CodeInternal, "", "internal error")
		}
	}()
	client := printable(ask.Client, 64)
	// The token first (R13): without a good one every verb answers alike, so
	// neither catalog is disclosed.
	principal, err := m.auth.APIToken(ctx, ask.Token, "api "+client)
	if err != nil {
		return m.noToken(), nil
	}
	if ask.Verb == apiContracts {
		return m.contracts(ctx, principal), nil
	}
	v, ok := m.public[ask.Verb]
	if !ok {
		return refusal(hostgate.APINotFound, rpc.CodeMethodNotFound, "api.not_found", "no such verb"), nil
	}
	name, err := m.auth.Authorize(ctx, principal, time.Time{}, v.Contract)
	actor := name + " (api " + client + ", " + strings.Replace(principal, "token:", "token #", 1) + ", request " + printable(ask.RequestID, 64) + ")"
	var params []any
	if len(ask.Param) > 0 {
		var p any
		if jerr := json.Unmarshal(ask.Param, &p); jerr != nil {
			return refusal(hostgate.APIBadParam, rpc.CodeInvalidParams, "", "the body is not JSON"), nil
		}
		if p != nil {
			params = []any{p}
		}
	}
	switch {
	case errors.Is(err, auth.ErrExpired): // revoked or expired between the two reads
		return m.noToken(), nil
	case err != nil:
		hostcontrol.Refused(ctx, m.aud, actor, v, params, err, m.errs)
		return m.declared(hostgate.APIForbidden, err), nil
	}
	res, err := hostcontrol.Invoke(module.WithPrincipal(audit.WithActor(ctx, actor), principal), v, m.errs, m.log, m.aud, actor, params)
	if err != nil {
		var re *rpc.Error
		switch {
		case errors.As(err, &re) && re.Code == rpc.CodeInvalidParams:
			return refusal(hostgate.APIBadParam, re.Code, "", re.Message), nil
		case errors.As(err, &re) && re.Code != rpc.CodeInternal:
			return refusal(hostgate.APIFailed, re.Code, m.names[re.Code], re.Message), nil
		}
		return refusal(hostgate.APIInternal, rpc.CodeInternal, "", "internal error"), nil
	}
	b, err := json.Marshal(res)
	if err != nil {
		m.log.Error("api: a result that is not JSON", "verb", ask.Verb, "err", err)
		return refusal(hostgate.APIInternal, rpc.CodeInternal, "", "internal error"), nil
	}
	return hostgate.APIAnswer{Result: b}, nil
}

// contracts answers the public contracts principal's role may call.
func (m *apiModule) contracts(ctx context.Context, principal string) hostgate.APIAnswer {
	out := []module.Contract{}
	for _, v := range m.public {
		_, err := m.auth.Authorize(ctx, principal, time.Time{}, v.Contract)
		if errors.Is(err, auth.ErrExpired) {
			return m.noToken()
		}
		if err == nil {
			out = append(out, v.Contract)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Verb < out[j].Verb })
	b, _ := json.Marshal(out)
	return hostgate.APIAnswer{Result: b}
}

// noToken is the one answer for every token failure.
func (m *apiModule) noToken() hostgate.APIAnswer {
	return m.declared(hostgate.APIToken, auth.ErrBadLogin)
}

// declared is a refusal by an error a module declares.
func (m *apiModule) declared(kind string, err error) hostgate.APIAnswer {
	if pe, ok := module.Public(err, m.errs); ok {
		if kind == hostgate.APIToken { // never the login's wording: there is no user or code here
			return refusal(kind, pe.Code, "api.unauthorized", "no valid API token")
		}
		return refusal(kind, pe.Code, pe.Name, pe.Message)
	}
	return refusal(kind, rpc.CodeAccessDenied, "", "refused")
}

func refusal(kind string, code int64, name, message string) hostgate.APIAnswer {
	return hostgate.APIAnswer{Error: &hostgate.APIError{Kind: kind, Code: code, Name: name, Message: message}}
}

// printable is s for the audit log: what the gate sent is cut short and kept
// to characters that cannot break an entry.
func printable(s string, limit int) string {
	if len(s) > limit {
		s = s[:limit]
	}
	return strings.Map(func(r rune) rune {
		if r < '!' || r > '~' || r == '"' || r == '(' || r == ')' || r == '|' {
			return '_'
		}
		return r
	}, s)
}

// apiLink is link.api on the link socket: the gate's way to the API's core
// side. Like the link's other verbs it is open: the kernel's record of the
// peer's user is what admits the gate, and the token in each call is what
// admits the caller.
type apiLink struct{ m *apiModule }

func (apiLink) Name() string { return "link" } // a second module of the link socket

func (apiLink) Errors() []module.PublicError { return nil }

func (l apiLink) Verbs() []module.Verb {
	return []module.Verb{
		module.Handle(module.Contract{Verb: hostgate.VerbAPI, Since: 8, Open: true, Param: "{verb, param, token, client, request_id}", Result: "{result?, error?: {kind, code, name, message}}",
			Doc: "One call of the HTTPS API, passed on by the gate: the token is resolved, the verb looked up among the public ones, the role checked, and the verb run. Link socket only."}, l.m.call),
	}
}
