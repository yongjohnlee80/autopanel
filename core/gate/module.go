package gate

import (
	"context"
	"errors"
	"sync"

	"github.com/yongjohnlee80/autopanel/internal/module"
)

// Routes is where routes are kept. Each write also writes its audit entry, in
// one transaction (R2); the actor comes from the context (audit.Actor).
type Routes interface {
	All(ctx context.Context) ([]Route, error) // the whole set: routes are few, and the table is rebuilt whole
	Add(ctx context.Context, r Route) (Route, error)
	Update(ctx context.Context, r Route) (Route, error)
	Remove(ctx context.Context, id RouteID) (Route, error)
}

var (
	// ErrNotFound is a route id the store doesn't hold.
	ErrNotFound = errors.New("gate: no such route")
	// ErrDuplicate is a second route for one host and path prefix.
	ErrDuplicate = errors.New("gate: a route for this host and path prefix exists")
)

// Module is the gate's verbs. reload rebuilds the live table from the store; it
// runs after every committed change, so a rolled-back change never reaches the
// table (rationale §R9).
type Module struct {
	routes  Routes
	domains Domains
	reload  func(ctx context.Context) error
	users   DomainUsers // nil: no other module holds a domain
	// mu orders write-then-reload pairs: without it, an older reload could swap
	// its snapshot in after a newer one.
	mu sync.Mutex
}

// NewModule returns the gate's verbs over routes and domains; reload swaps a
// new table in.
func NewModule(routes Routes, domains Domains, reload func(ctx context.Context) error) *Module {
	return &Module{routes: routes, domains: domains, reload: reload}
}

func (m *Module) Name() string { return "gate" }

// RouteView is a route as a client sees it.
type RouteView struct {
	ID         int64  `json:"id"`
	Host       string `json:"host"`
	PathPrefix string `json:"path_prefix"`
	Upstream   string `json:"upstream"`
}

func view(r Route) RouteView {
	return RouteView{ID: int64(r.ID), Host: r.Host, PathPrefix: r.PathPrefix, Upstream: r.Upstream}
}

// RouteSpec is a route as a client writes it. ID is set only to update.
type RouteSpec struct {
	ID         int64  `json:"id,omitempty"`
	Host       string `json:"host"`
	PathPrefix string `json:"path_prefix,omitempty"`
	Upstream   string `json:"upstream"`
}

// RouteRef names one route.
type RouteRef struct {
	ID int64 `json:"id"`
}

func (m *Module) Verbs() []module.Verb {
	return []module.Verb{
		module.Handle(module.Contract{Verb: "gate.route.list", Since: 1, Result: "[{id, host, path_prefix, upstream}]",
			Doc: "Every route, by host, then the longest path prefix first."}, m.list),
		module.Handle(module.Contract{Verb: "gate.route.add", Since: 1, Param: "{host, path_prefix?, upstream}", Result: "{id, host, path_prefix, upstream}",
			Doc: "Adds a route and serves it at once. The host may then have a certificate.", Mutates: true}, m.add),
		module.Handle(module.Contract{Verb: "gate.route.update", Since: 1, Param: "{id, host, path_prefix?, upstream}", Result: "{id, host, path_prefix, upstream}",
			Doc: "Replaces a route's host, prefix and upstream.", Mutates: true}, m.update),
		module.Handle(module.Contract{Verb: "gate.route.remove", Since: 1, Param: "{id}", Result: "{id, host, path_prefix, upstream}",
			Doc: "Removes a route; its host stops being served once no route names it.", Mutates: true}, m.remove),
		module.Handle(module.Contract{Verb: "gate.domain.list", Since: 5, Result: "[{name, routes}]",
			Doc: "Every registered domain, by name, with the number of routes under it."}, m.domainList),
		module.Handle(module.Contract{Verb: "gate.domain.add", Since: 5, Param: "{name}", Result: "{name, routes}",
			Doc: "Registers a domain the administrator owns: example.com. A route's host must be a domain or a name under one.", Mutates: true}, m.domainAdd),
		module.Handle(module.Contract{Verb: "gate.domain.remove", Since: 5, Param: "{name}",
			Doc: "Removes a domain. Refused while a route would be left under no domain.", Mutates: true}, m.domainRemove),
	}
}

func (m *Module) Errors() []module.PublicError {
	return []module.PublicError{
		{Err: ErrNotFound, Code: -32150, Name: "gate.not_found", Message: "no such route"},
		{Err: ErrDuplicate, Code: -32151, Name: "gate.duplicate", Message: "a route for this host and path prefix exists"},
		{Err: ErrBadHost, Code: -32152, Name: "gate.bad_host", Message: "not a valid host name (use punycode for an internationalised name)"},
		{Err: ErrBadPrefix, Code: -32153, Name: "gate.bad_prefix", Message: "a path prefix must be \"/\" or an absolute path without a trailing slash"},
		{Err: ErrBadUpstream, Code: -32154, Name: "gate.bad_upstream", Message: "an upstream must be an http or https URL with a host and no credentials"},
		{Err: ErrNoDomain, Code: -32155, Name: "gate.no_domain", Message: "the host is under no registered domain; add the domain first"},
		{Err: ErrDomainExists, Code: -32156, Name: "gate.domain_exists", Message: "the domain is registered already"},
		{Err: ErrDomainInUse, Code: -32157, Name: "gate.domain_in_use", Message: "a route would be left under no domain; remove or move it first"},
		{Err: ErrDomainHasMail, Code: -32159, Name: "gate.domain_has_mail", Message: "the domain receives mail; stop that under Mail → Domains first"},
		{Err: ErrNoSuchDomain, Code: -32158, Name: "gate.no_such_domain", Message: "no such domain"},
	}
}

func (m *Module) list(ctx context.Context, _ struct{}) ([]RouteView, error) {
	rs, err := m.routes.All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]RouteView, 0, len(rs))
	for _, r := range rs {
		out = append(out, view(r))
	}
	return out, nil
}

func (m *Module) write(ctx context.Context, fn func() (Route, error)) (RouteView, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, err := fn()
	if err != nil {
		return RouteView{}, err
	}
	return view(r), m.reload(ctx) // after the commit only
}

func (m *Module) add(ctx context.Context, s RouteSpec) (RouteView, error) {
	r, err := Route{Host: s.Host, PathPrefix: s.PathPrefix, Upstream: s.Upstream}.Normalize()
	if err != nil {
		return RouteView{}, err
	}
	return m.write(ctx, func() (Route, error) {
		if err := m.underADomain(ctx, r.Host); err != nil {
			return Route{}, err
		}
		return m.routes.Add(ctx, r)
	})
}

func (m *Module) update(ctx context.Context, s RouteSpec) (RouteView, error) {
	r, err := Route{ID: RouteID(s.ID), Host: s.Host, PathPrefix: s.PathPrefix, Upstream: s.Upstream}.Normalize()
	if err != nil {
		return RouteView{}, err
	}
	return m.write(ctx, func() (Route, error) {
		if err := m.underADomain(ctx, r.Host); err != nil {
			return Route{}, err
		}
		return m.routes.Update(ctx, r)
	})
}

func (m *Module) remove(ctx context.Context, ref RouteRef) (RouteView, error) {
	return m.write(ctx, func() (Route, error) { return m.routes.Remove(ctx, RouteID(ref.ID)) })
}
