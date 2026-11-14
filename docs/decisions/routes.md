# Routes and domains

How the gate decides which routes it serves, and how they attach to the domains the administrator owns.

## A route's host is under a registered domain

**Decided:** a domain is a name the administrator owns, registered with `gate.domain.add`:
`example.com`. A route's host must be a domain or a name under one (`app.example.com`); a route
under none is refused (`gate.no_domain`). The panel's route form takes a subdomain and a choice of
the domains, so a host is never typed whole.

**Why:** a route, its certificate and its traffic belong to a domain. Tying routes to domains the
administrator has said are theirs keeps a typo from serving, and certifying, a name nobody owns, and
gives later work (a wildcard certificate, mail's domains, traffic per domain) one place to attach.

**No public-suffix list:** a domain is what the administrator typed, with at least one dot. AutoPanel
does not try to know where a registrable name begins.

**Upgrading keeps every route:** the migration that adds domains makes every host a route already
has into a domain. Once the administrator adds the parent (`example.com`), the child entries can be
removed.

**Removing a domain** is refused only while a route would be left under no domain; a route under a
parent that stays keeps the child removable.

**In the code:** `core/gate/domain.go` (`Under`, `domainRemove`, `underADomain`),
`store/domains.go`, `sql/deployments/*/000004_update_domains_and_sources.sql`.
