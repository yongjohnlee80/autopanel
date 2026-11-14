package ui

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	tuidecl "github.com/yongjohnlee80/golib/tui/decl"

	"github.com/yongjohnlee80/autopanel/core/gate"
	"github.com/yongjohnlee80/autopanel/core/services"
)

// ROUTES AND DOMAINS — Routes › Proxy routes and Routes › Domains, each a
// panel of two panes: the rows on the left, the selected one on the right.
//
// A route's host is under a registered domain (docs/decisions/routes.md), so
// the route form asks for it in two parts: a subdomain, typed, and a domain,
// chosen from the registered ones. The upstream is typed too, or chosen from
// the ports the stacks publish, which fills it.

// routeForm is the route form's models and what it was opened with.
type routeForm struct {
	domains *tuidecl.ListModel // App.formDomains: the domains to choose from
	ports   *tuidecl.ListModel // App.formPorts: the stacks' ports to fill the upstream from

	editID     int64             // the route the form edits; 0 adds one
	domainList []gate.DomainView // the domains, by row
	portList   []portChoice      // the ports, by row

	routeAt  int // the row under the routes list's cursor
	domainAt int // the row under the domains list's cursor
}

// portChoice is a port a stack publishes, as the form offers it.
type portChoice struct {
	label, upstream string
}

func newRouteForm() routeForm {
	return routeForm{
		domains: tuidecl.NewListModel("key", "label"),
		ports:   tuidecl.NewListModel("key", "label"),
	}
}

// state is the route form's part of the App singleton's state.
func (f *routeForm) state() map[string]any {
	return map[string]any{
		"App.formDomains":     f.domains,
		"App.formPorts":       f.ports,
		"App.formTitle":       "",
		"App.formSub":         "",
		"App.formDomainIndex": -1,
		"App.formPath":        "/",
		"App.formUpstream":    "",
		"App.formError":       "",
		"App.formErrorShown":  false,
		"App.formHasPorts":    false,
	}
}

// stackPorts are the TCP ports the stacks publish, each as a loopback
// upstream named <stack>-<service>, in that order. A range is offered by its
// first port.
func stackPorts(views []services.View) []portChoice {
	var out []portChoice
	for _, v := range views {
		for _, c := range v.Containers {
			for _, p := range c.Ports {
				if p.Proto != "tcp" {
					continue
				}
				up := "http://127.0.0.1:" + strconv.Itoa(p.From)
				out = append(out, portChoice{label: v.Name + "-" + c.Service + "  " + up, upstream: up})
			}
		}
	}
	return out
}

// stackOfUpstream names the stack's service an upstream reaches, "" for none.
func stackOfUpstream(upstream string, views []services.View) string {
	for _, p := range stackPorts(views) {
		if strings.TrimRight(upstream, "/") == p.upstream {
			return strings.TrimSpace(strings.TrimSuffix(p.label, p.upstream))
		}
	}
	return ""
}

// routeDetail is a route whole, for the details pane.
func routeDetail(w wording, r gate.RouteView, domains []gate.DomainView, views []services.View) string {
	domain := domainOf(r.Host, domains)
	if domain == "" {
		domain = w.tr("autopanel.value.routes.noDomain")
	}
	return facts(w,
		[2]string{"autopanel.label.route.id", "#" + strconv.FormatInt(r.ID, 10)},
		[2]string{"autopanel.label.route.host", r.Host},
		[2]string{"autopanel.label.route.path", r.PathPrefix},
		[2]string{"autopanel.label.route.upstream", r.Upstream},
		[2]string{"autopanel.label.route.domain", domain},
		[2]string{"autopanel.label.route.stack", orDash(stackOfUpstream(r.Upstream, views))})
}

// domainDetail is a domain whole, for the details pane: its name, its routes'
// count, and each route under it.
func domainDetail(w wording, d gate.DomainView, routes []gate.RouteView) string {
	text := facts(w,
		[2]string{"autopanel.label.domain.name", d.Name},
		[2]string{"autopanel.label.domain.routes", strconv.Itoa(d.Routes)})
	var under []string
	for _, r := range routes {
		if gate.Under(r.Host, d.Name) {
			under = append(under, "  "+r.Host+r.PathPrefix+" → "+r.Upstream)
		}
	}
	if len(under) == 0 {
		return text + "\n\n" + w.tr("autopanel.value.domain.noRoutes")
	}
	sort.Strings(under)
	return text + "\n\n" + w.tr("autopanel.label.domain.under") + "\n" + strings.Join(under, "\n")
}

// renderRoutes puts the routes panel's title and details on screen.
func (h *host) renderRoutes() {
	title := h.trf("autopanel.title.list.count", h.tr("autopanel.title.list.routes"), len(h.routes), time.Now().Format("15:04:05"))
	_ = h.p.SetMany(map[string]any{"App.routesTitle": title, "App.routeDetail": h.routeDetailAt(h.form.routeAt)})
}

func (h *host) routeDetailAt(row int) string {
	r, ok := h.route(row)
	if !ok {
		return ""
	}
	return routeDetail(h, r, h.domains, h.stk.views)
}

// routeMoved is the routes list's cursor moved.
func (h *host) routeMoved(row int) error {
	h.form.routeAt = row
	return h.p.Set("App.routeDetail", h.routeDetailAt(row))
}

// renderDomains puts the domains panel's title and details on screen.
func (h *host) renderDomains() {
	title := h.tr("autopanel.title.list.domains")
	if h.wid.domainErr != nil {
		title = h.trf("autopanel.title.list.failed", title, h.wid.domainErr.Error())
	} else if h.domainsRead {
		title = h.trf("autopanel.title.list.count", title, len(h.domains), time.Now().Format("15:04:05"))
	}
	_ = h.p.SetMany(map[string]any{"App.domainsTitle": title, "App.domainDetail": h.domainDetailAt(h.form.domainAt)})
}

func (h *host) domainDetailAt(row int) string {
	if row < 0 || row >= len(h.domains) {
		return ""
	}
	return domainDetail(h, h.domains[row], h.routes)
}

// domainMoved is the domains list's cursor moved.
func (h *host) domainMoved(row int) error {
	h.form.domainAt = row
	return h.p.Set("App.domainDetail", h.domainDetailAt(row))
}

// openRoutes is Routes › Proxy routes.
func (h *host) openRoutes() error {
	h.refresh()
	return h.openPanel("routes")
}

// openDomains is Routes › Domains.
func (h *host) openDomains() error {
	h.refresh()
	return h.openPanel("domains")
}

// add opens the route form, empty.
func (h *host) add() error {
	h.openForm(0, h.tr("autopanel.title.form.add"), gate.RouteView{})
	return nil
}

// edit opens the route form on the route at row.
func (h *host) edit(row int) error {
	r, ok := h.route(row)
	if !ok {
		h.say(h.tr("autopanel.notice.routes.none"))
		return nil
	}
	h.openForm(r.ID, h.trf("autopanel.title.form.edit", r.ID), r)
	return nil
}

// openForm reads the domains and the stacks the form offers, then fills it
// with r and opens it.
func (h *host) openForm(id int64, title string, r gate.RouteView) {
	var (
		domains []gate.DomainView
		views   []services.View
	)
	h.background(func(ctx context.Context) error {
		var err error
		if domains, err = h.client.Domains(ctx); err != nil {
			return err
		}
		views, _ = h.client.Stacks(ctx) // the ports to offer: none when the stacks cannot be read
		return nil
	}, func(err error) {
		if err != nil {
			h.failed(err)
			return
		}
		h.setDomains(domains)
		f := &h.form
		f.editID, f.domainList, f.portList = id, domains, stackPorts(views)
		rows := make([]tuidecl.Row, 0, len(domains))
		for _, d := range domains {
			rows = append(rows, tuidecl.Row{"key": d.Name, "label": d.Name})
		}
		f.domains.Reset(rows)
		ports := make([]tuidecl.Row, 0, len(f.portList))
		for i, p := range f.portList {
			ports = append(ports, tuidecl.Row{"key": strconv.Itoa(i), "label": p.label})
		}
		f.ports.Reset(ports)
		sub, domain := splitHost(r.Host, domains)
		at := -1
		for i, d := range domains {
			if d.Name == domain {
				at = i
			}
		}
		if at < 0 && id == 0 && len(domains) == 1 {
			at = 0 // a new route under the one domain there is
		}
		prefix := r.PathPrefix
		if prefix == "" {
			prefix = "/"
		}
		if err := h.fill(map[string]any{"App.formSub": sub, "App.formPath": prefix, "App.formUpstream": r.Upstream}); err != nil {
			h.failed(err)
			return
		}
		_ = h.p.Set("App.formDomainIndex", -2) // through another value: the box may show another choice since
		if err := h.p.SetMany(map[string]any{"App.formTitle": title, "App.formDomainIndex": at, "App.formError": "",
			"App.formErrorShown": false, "App.formHasPorts": len(f.portList) > 0}); err != nil {
			h.failed(err)
			return
		}
		if err := h.p.Call("routeDialog", "open"); err != nil {
			h.failed(err)
		}
	})
}

// pickUpstream is a stack's port chosen in the form: it fills the upstream.
func (h *host) pickUpstream(row int) error {
	if row < 0 || row >= len(h.form.portList) {
		return nil
	}
	return h.fill(map[string]any{"App.formUpstream": h.form.portList[row].upstream})
}

// formRefused shows why the form's route was not taken; the form stays open,
// as typed.
func (h *host) formRefused(why string) {
	_ = h.p.SetMany(map[string]any{"App.formError": why, "App.formErrorShown": true})
}

// submit adds or updates the route the form describes, off the loop. On
// success the form closes and the routes are read again; on failure it stays
// open, as typed, with the reason under its fields.
func (h *host) submit(sub string, domainRow int, prefix, upstream string) error {
	if h.busy {
		h.say(h.tr("autopanel.notice.app.busy"))
		return nil
	}
	domain := ""
	if domainRow >= 0 && domainRow < len(h.form.domainList) {
		domain = h.form.domainList[domainRow].Name
	}
	s := formSpec(h.form.editID, formHost(sub, domain), prefix, upstream)
	if s.Host == "" {
		h.formRefused(h.tr("autopanel.notice.form.noHost"))
		return nil
	}
	done, call := "autopanel.notice.routes.added", h.client.Add
	if s.ID != 0 {
		done, call = "autopanel.notice.routes.updated", h.client.Update
	}
	h.busy = true
	h.background(func(ctx context.Context) error { return call(ctx, s) }, func(err error) {
		h.busy = false
		switch {
		case errors.Is(err, gate.ErrNoDomain):
			h.formRefused(h.tr("autopanel.notice.form.noDomain"))
			return
		case err != nil:
			h.formRefused(h.trf("autopanel.notice.app.error", err.Error()))
			return
		}
		_ = h.p.Call("routeDialog", "close")
		h.say(h.trf(done, s.Host+s.PathPrefix))
		h.refresh()
	})
	return nil
}

// remove asks before removing the route at row.
func (h *host) remove(row int) error {
	r, ok := h.route(row)
	if !ok {
		h.say(h.tr("autopanel.notice.routes.none"))
		return nil
	}
	id := r.ID
	return h.ask("autopanel.title.confirm.removeRoute", h.trf("autopanel.question.routes.remove", describe(r)), func() error {
		h.change(func(ctx context.Context) error { return h.client.Remove(ctx, id) }, func() {
			h.say(h.trf("autopanel.notice.routes.removed", id))
			h.refresh()
		})
		return nil
	})
}

// change runs one change off the loop, unless another is in flight; done
// follows a success, and a failure is said on the status bar.
func (h *host) change(call func(ctx context.Context) error, done func()) {
	if h.busy {
		h.say(h.tr("autopanel.notice.app.busy"))
		return
	}
	h.busy = true
	h.background(call, func(err error) {
		h.busy = false
		if err != nil {
			h.failed(err)
			return
		}
		done()
	})
}

// addDomain asks for a domain's name, and registers it.
func (h *host) addDomain() error {
	return h.prompt("autopanel.title.prompt.addDomain", "autopanel.label.prompt.domain", "", func(name string) error {
		name = strings.TrimSpace(name)
		if name == "" {
			h.promptRefused(h.tr("autopanel.notice.domains.noName"))
			return nil
		}
		if h.busy {
			h.promptRefused(h.tr("autopanel.notice.app.busy"))
			return nil
		}
		h.busy = true
		h.background(func(ctx context.Context) error { return h.client.AddDomain(ctx, name) }, func(err error) {
			h.busy = false
			switch {
			case errors.Is(err, gate.ErrDomainExists):
				h.promptRefused(h.trf("autopanel.notice.domains.exists", name))
			case errors.Is(err, gate.ErrBadHost):
				h.promptRefused(h.trf("autopanel.notice.domains.badName", name))
			case err != nil:
				h.promptRefused(h.trf("autopanel.notice.app.error", err.Error()))
			default:
				h.promptDone()
				h.say(h.trf("autopanel.notice.domains.added", name))
				h.refresh()
			}
		})
		return nil
	})
}

// removeDomain asks before removing the domain at row. A domain a route is
// under alone cannot go: the daemon says so, and the panel says which.
func (h *host) removeDomain(row int) error {
	if row < 0 || row >= len(h.domains) {
		h.say(h.tr("autopanel.notice.domains.none"))
		return nil
	}
	name := h.domains[row].Name
	return h.ask("autopanel.title.confirm.removeDomain", h.trf("autopanel.question.domains.remove", name), func() error {
		if h.busy {
			h.say(h.tr("autopanel.notice.app.busy"))
			return nil
		}
		h.busy = true
		h.background(func(ctx context.Context) error { return h.client.RemoveDomain(ctx, name) }, func(err error) {
			h.busy = false
			switch {
			case errors.Is(err, gate.ErrDomainInUse):
				h.say(h.trf("autopanel.notice.domains.inUse", name))
			case errors.Is(err, gate.ErrNoSuchDomain):
				h.say(h.trf("autopanel.notice.domains.gone", name))
				h.refresh()
			case err != nil:
				h.failed(err)
			default:
				h.say(h.trf("autopanel.notice.domains.removed", name))
				h.refresh()
			}
		})
		return nil
	})
}
