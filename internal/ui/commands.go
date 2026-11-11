package ui

import (
	"context"
	"fmt"
	"math"
	"strconv"

	"github.com/yongjohnlee80/golib/decl"
	"github.com/yongjohnlee80/golib/parse/qml"

	"github.com/yongjohnlee80/autopanel/core/gate"
)

// THE APP SINGLETON'S COMMANDS — what the document invokes, and nothing else
// of this package is reachable from it.
func (h *host) commands() map[string]decl.HandlerFunc {
	return map[string]decl.HandlerFunc{
		"App.openRoutes":      none(func() error { return h.openPanel("routes", "routesPanel", "routesTable") }),
		"App.setCA":           oneString("App.setCA", h.setCA),
		"App.panelLeft":       none(h.panelLeft),
		"App.panelChanged":    oneString("App.panelChanged", h.panelChanged),
		"App.openMonitor":     oneString("App.openMonitor", h.openMonitor),
		"App.reloadMonitor":   oneString("App.reloadMonitor", h.reloadMonitor),
		"App.useTheme":        oneString("App.useTheme", h.useTheme),
		"App.setLanguage":     oneString("App.setLanguage", h.setLanguage),
		"App.add":             none(h.add),
		"App.edit":            oneRow("App.edit", h.edit),
		"App.remove":          oneRow("App.remove", h.remove),
		"App.removeConfirmed": none(h.removeConfirmed),
		"App.submit":          threeStrings("App.submit", h.submit),
		"App.refresh":         none(func() error { h.refresh(); return nil }),
		"App.quit":            none(func() error { h.p.Quit(); return nil }),
	}
}

// caNames are the certificate services the Certs menu offers: the message
// that names each.
var caNames = map[string]string{"staging": "autopanel.ca.name.staging", "production": "autopanel.ca.name.production"}

// setCA chooses the certificate service, off the loop, then reads the status
// again: the Certs menu checks what the daemon reports, so a refused change
// leaves the old service checked.
func (h *host) setCA(ca string) error {
	nameID, ok := caNames[ca]
	if !ok {
		return fmt.Errorf("App.setCA takes staging or production, not %q", ca)
	}
	if h.busy {
		h.say(h.tr("autopanel.notice.busy"))
		h.refresh()
		return nil
	}
	h.busy = true
	h.background(func(ctx context.Context) error { return h.client.SetCA(ctx, ca) }, func(err error) {
		h.busy = false
		if err != nil {
			h.say(h.trf("autopanel.notice.error", err.Error()))
		} else {
			h.say(h.trf("autopanel.notice.caNow", h.tr(nameID)))
		}
		h.refresh()
	})
	return nil
}

// add opens the route form, empty.
func (h *host) add() error {
	h.editID = 0
	return h.openForm(h.tr("autopanel.form.add"), gate.RouteView{})
}

// edit opens the route form on the route at row.
func (h *host) edit(row int) error {
	r, ok := h.route(row)
	if !ok {
		h.say(h.tr("autopanel.notice.noRoute"))
		return nil
	}
	h.editID = r.ID
	return h.openForm(h.trf("autopanel.form.edit", r.ID), r)
}

// openForm fills the route form with r and opens it.
func (h *host) openForm(title string, r gate.RouteView) error {
	prefix := r.PathPrefix
	if prefix == "" {
		prefix = "/"
	}
	if err := h.fill(map[string]any{"App.formHost": r.Host, "App.formPath": prefix, "App.formUpstream": r.Upstream}); err != nil {
		return err
	}
	if err := h.p.SetMany(map[string]any{"App.formTitle": title, "App.formHelp": h.tr("autopanel.form.hint")}); err != nil {
		return err
	}
	return h.p.Call("routeDialog", "open")
}

// submit adds or updates the route the form describes, off the loop. On
// success the form closes and the routes are read again; on failure it stays
// open, as typed, with the reason in its help line and the status bar.
func (h *host) submit(host, prefix, upstream string) error {
	if h.busy {
		h.say(h.tr("autopanel.notice.busy"))
		return nil
	}
	s := formSpec(h.editID, host, prefix, upstream)
	done, call := "autopanel.notice.added", h.client.Add
	if s.ID != 0 {
		done, call = "autopanel.notice.updated", h.client.Update
	}
	h.busy = true
	h.background(func(ctx context.Context) error { return call(ctx, s) }, func(err error) {
		h.busy = false
		if err != nil {
			h.say(h.trf("autopanel.notice.error", err.Error()))
			_ = h.p.Set("App.formHelp", h.trf("autopanel.notice.error", err.Error()))
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
		h.say(h.tr("autopanel.notice.noRoute"))
		return nil
	}
	h.removeID = r.ID
	if err := h.p.Set("App.confirmQuestion", h.trf("autopanel.confirm.remove", describe(r))); err != nil {
		return err
	}
	return h.p.Call("confirmDialog", "open")
}

// removeConfirmed removes the route the confirmation named, off the loop.
func (h *host) removeConfirmed() error {
	if h.busy {
		h.say(h.tr("autopanel.notice.busy"))
		return nil
	}
	id := h.removeID
	h.busy = true
	h.background(func(ctx context.Context) error { return h.client.Remove(ctx, id) }, func(err error) {
		h.busy = false
		if err != nil {
			h.say(h.trf("autopanel.notice.error", err.Error()))
			return
		}
		h.say(h.trf("autopanel.notice.removed", id))
		h.refresh()
	})
	return nil
}

// none is a command that takes no arguments, and refuses any it is given.
func none(fn func() error) decl.HandlerFunc {
	return func(args []qml.SpecValue) error {
		if len(args) > 0 {
			return fmt.Errorf("takes no arguments, and was given %d", len(args))
		}
		return fn()
	}
}

// oneRow is a command that takes a view's row: currentIndex, or a signal's index.
func oneRow(name string, fn func(int) error) decl.HandlerFunc {
	return func(args []qml.SpecValue) error {
		if len(args) != 1 || args[0].Kind != qml.SpecValueNumber {
			return fmt.Errorf("%s takes a row number", name)
		}
		f, err := strconv.ParseFloat(args[0].Raw, 64)
		if err != nil || f != math.Trunc(f) {
			return fmt.Errorf("%s takes a row number, not %q", name, args[0].Raw)
		}
		return fn(int(f))
	}
}

// oneString is a command that takes one string.
func oneString(name string, fn func(string) error) decl.HandlerFunc {
	return func(args []qml.SpecValue) error {
		if len(args) != 1 || args[0].Kind != qml.SpecValueString {
			return fmt.Errorf("%s takes one string", name)
		}
		return fn(args[0].Raw)
	}
}

// threeStrings is a command that takes three strings: the form's fields.
func threeStrings(name string, fn func(a, b, c string) error) decl.HandlerFunc {
	return func(args []qml.SpecValue) error {
		if len(args) != 3 {
			return fmt.Errorf("%s takes three strings, and was given %d arguments", name, len(args))
		}
		for _, a := range args {
			if a.Kind != qml.SpecValueString {
				return fmt.Errorf("%s takes three strings", name)
			}
		}
		return fn(args[0].Raw, args[1].Raw, args[2].Raw)
	}
}
