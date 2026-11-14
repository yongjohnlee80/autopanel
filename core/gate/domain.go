package gate

import (
	"context"
	"errors"
	"sort"
	"strings"
)

// DOMAINS. A domain is a name the administrator owns: "example.com". A route's
// host is a domain or a name under one, so routes, certificates and traffic
// attach to the domains they belong to. No public-suffix list is consulted: a
// domain is what the administrator typed.

// Domain is one registered domain.
type Domain struct {
	Name string // canonical (CanonicalHost)
}

// Domains is where domains are kept.
type Domains interface {
	All(ctx context.Context) ([]Domain, error)
	Add(ctx context.Context, d Domain) error // ErrDomainExists
	Remove(ctx context.Context, name string) error
}

var (
	// ErrNoDomain is a route whose host is under no registered domain.
	ErrNoDomain = errors.New("gate: the host is under no registered domain")
	// ErrDomainExists is a domain registered twice.
	ErrDomainExists = errors.New("gate: the domain is registered")
	// ErrDomainInUse is a domain whose removal would leave a route under none.
	ErrDomainInUse = errors.New("gate: a route would be left under no domain")
	// ErrNoSuchDomain is a domain the store doesn't hold.
	ErrNoSuchDomain = errors.New("gate: no such domain")
	// ErrDomainHasMail is a domain whose removal would strand its mail.
	ErrDomainHasMail = errors.New("gate: the domain receives mail")
)

// DomainUsers is another module that holds a registry domain by its exact
// name: mail, for a domain that receives mail. The gate asks it before it
// removes a domain, and imports nothing of it.
type DomainUsers interface {
	// Uses reports whether name is in use, and how.
	Uses(ctx context.Context, name string) (how string, used bool)
}

// Under reports whether host is domain or a name under it.
func Under(host, domain string) bool {
	return host == domain || strings.HasSuffix(host, "."+domain)
}

// covered reports whether host is under one of domains.
func covered(host string, domains []Domain) bool {
	for _, d := range domains {
		if Under(host, d.Name) {
			return true
		}
	}
	return false
}

// DomainView is a domain as a client sees it.
type DomainView struct {
	Name   string `json:"name"`
	Routes int    `json:"routes"` // the routes whose host is under it
}

// DomainRef names one domain.
type DomainRef struct {
	Name string `json:"name"`
}

func (m *Module) domainList(ctx context.Context, _ struct{}) ([]DomainView, error) {
	ds, err := m.domains.All(ctx)
	if err != nil {
		return nil, err
	}
	rs, err := m.routes.All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]DomainView, 0, len(ds))
	for _, d := range ds {
		v := DomainView{Name: d.Name}
		for _, r := range rs {
			if Under(r.Host, d.Name) {
				v.Routes++
			}
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *Module) domainAdd(ctx context.Context, ref DomainRef) (DomainView, error) {
	name, err := CanonicalHost(ref.Name)
	if err != nil {
		return DomainView{}, err
	}
	if !strings.Contains(name, ".") {
		// "localhost" or "com": a domain has a name and a suffix.
		return DomainView{}, ErrBadHost
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.domains.Add(ctx, Domain{Name: name}); err != nil {
		return DomainView{}, err
	}
	return DomainView{Name: name}, nil
}

// domainRemove removes a domain unless a route would then be under none: a
// route under a parent domain that stays keeps it removable.
func (m *Module) domainRemove(ctx context.Context, ref DomainRef) (struct{}, error) {
	name, err := CanonicalHost(ref.Name)
	if err != nil {
		return struct{}{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	ds, err := m.domains.All(ctx)
	if err != nil {
		return struct{}{}, err
	}
	var rest []Domain
	found := false
	for _, d := range ds {
		if d.Name == name {
			found = true
			continue
		}
		rest = append(rest, d)
	}
	if !found {
		return struct{}{}, ErrNoSuchDomain
	}
	if m.users != nil {
		if how, used := m.users.Uses(ctx, name); used {
			return struct{}{}, &usedBy{how: how}
		}
	}
	rs, err := m.routes.All(ctx)
	if err != nil {
		return struct{}{}, err
	}
	for _, r := range rs {
		if Under(r.Host, name) && !covered(r.Host, rest) {
			return struct{}{}, ErrDomainInUse
		}
	}
	return struct{}{}, m.domains.Remove(ctx, name)
}

// underADomain refuses a route whose host no domain covers. The caller holds
// m.mu, so a domain cannot go between the check and the write.
func (m *Module) underADomain(ctx context.Context, host string) error {
	ds, err := m.domains.All(ctx)
	if err != nil {
		return err
	}
	if !covered(host, ds) {
		return ErrNoDomain
	}
	return nil
}

// SetDomainUsers names the module that holds registry domains of its own. It
// is set once, before the verbs are served.
func (m *Module) SetDomainUsers(u DomainUsers) { m.users = u }

// usedBy is ErrDomainHasMail, saying how.
type usedBy struct{ how string }

func (e *usedBy) Error() string        { return ErrDomainHasMail.Error() + ": " + e.how }
func (e *usedBy) Unwrap() error        { return ErrDomainHasMail }
func (e *usedBy) PublicDetail() string { return e.how }
