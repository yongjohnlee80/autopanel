package ui

import (
	"context"
	"fmt"
	"math"
	"strconv"

	"github.com/yongjohnlee80/golib/decl"
	"github.com/yongjohnlee80/golib/parse/qml"
)

// THE APP SINGLETON'S COMMANDS — what the document invokes, and nothing else
// of this package is reachable from it.
func (h *host) commands() map[string]decl.HandlerFunc {
	return map[string]decl.HandlerFunc{
		"App.login":         twoStrings("App.login", h.login),
		"App.loginDeclined": none(h.loginDeclined),
		"App.refresh":       none(func() error { h.poll(); return nil }),
		"App.quit":          none(func() error { h.p.Quit(); return nil }),
		"App.nothing":       none(func() error { return nil }),
		"App.openKeys":      none(h.openKeys),

		// the screen: the dock, the widgets, the panels, the status bar
		"App.goDock":          oneString("App.goDock", h.goDock),
		"App.toggleWidget":    oneString("App.toggleWidget", h.toggleWidgetNamed),
		"App.widgetChanged":   none(func() error { h.refreshDock(); return nil }),
		"App.widgetDocked":    twoStrings("App.widgetDocked", h.widgetDocked),
		"App.widgetResized":   stringAndNumber("App.widgetResized", h.widgetResized),
		"App.resetLayout":     none(h.resetLayout),
		"App.toggleStatusBar": none(h.toggleStatusBar),
		"App.panelOpened":     oneString("App.panelOpened", h.panelOpened),
		"App.panelClosed":     oneString("App.panelClosed", h.panelClosed),
		"App.panelChanged":    twoStrings("App.panelChanged", h.panelChanged),
		"App.closePanel":      oneString("App.closePanel", h.closePanel),

		// System, and the preferences
		"App.setCA":         oneString("App.setCA", h.setCA),
		"App.openMonitor":   oneString("App.openMonitor", h.openMonitor),
		"App.reloadMonitor": oneString("App.reloadMonitor", h.reloadMonitor),
		"App.monitorMoved":  stringAndRow("App.monitorMoved", h.monitorMoved),
		"App.useTheme":      oneString("App.useTheme", h.useTheme),
		"App.setLanguage":   oneString("App.setLanguage", h.setLanguage),

		// Routes: the routes, the domains, the form
		"App.openRoutes":   none(h.openRoutes),
		"App.openDomains":  none(h.openDomains),
		"App.routeMoved":   oneRow("App.routeMoved", h.routeMoved),
		"App.domainMoved":  oneRow("App.domainMoved", h.domainMoved),
		"App.add":          none(h.add),
		"App.edit":         oneRow("App.edit", h.edit),
		"App.remove":       oneRow("App.remove", h.remove),
		"App.submit":       formFields("App.submit", h.submit),
		"App.pickUpstream": oneRow("App.pickUpstream", h.pickUpstream),
		"App.addDomain":    none(h.addDomain),
		"App.removeDomain": oneRow("App.removeDomain", h.removeDomain),

		// the dialogs' answers
		"App.confirmed":      none(h.confirm),
		"App.confirmedOther": none(h.confirmOther),
		"App.promptAnswered": oneString("App.promptAnswered", h.promptAnswered),

		// the terminal
		"App.toggleTerminal": none(h.toggleTerminal),
		"App.terminalOpened": none(h.terminalOpened),
		"App.terminalClosed": none(h.terminalClosed),
		"App.newShell":       none(h.newShell),
		"App.stopShells":     none(h.stopShells),
		"App.nextShell":      none(func() error { return h.cycleShell(1) }),
		"App.previousShell":  none(func() error { return h.cycleShell(-1) }),

		// Services: the stacks, the browser, the review
		"App.openStacks":       none(h.openStacks),
		"App.openStackAt":      oneRow("App.openStackAt", h.openStackAt),
		"App.stackMoved":       oneRow("App.stackMoved", h.stackMoved),
		"App.addStack":         none(h.addStack),
		"App.applyStack":       oneRow("App.applyStack", h.applyStack),
		"App.updateFromSource": oneRow("App.updateFromSource", h.updateFromSource),
		"App.pullStack":        oneRow("App.pullStack", h.pullStack),
		"App.startService":     oneRow("App.startService", func(row int) error { return h.stackUnit("start", row) }),
		"App.stopService":      oneRow("App.stopService", func(row int) error { return h.stackUnit("stop", row) }),
		"App.restartService":   oneRow("App.restartService", func(row int) error { return h.stackUnit("restart", row) }),
		"App.removeStack":      oneRow("App.removeStack", h.removeStack),
		"App.logsOf":           oneRow("App.logsOf", h.openLogs),
		"App.reloadLogs":       none(h.reloadLogs),
		"App.reviewMoved":      oneRow("App.reviewMoved", h.reviewMoved),
		"App.reviewAccept":     none(h.reviewAccept),
		"App.reviewPrepare":    none(h.reviewPrepare),
		"App.browseMove":       oneRow("App.browseMove", h.browseMove),
		"App.browseEnter":      oneRow("App.browseEnter", h.browseEnter),
		"App.browseUp":         none(h.browseUp),
		"App.browseGo":         oneString("App.browseGo", h.browseGo),
		"App.browseImport":     none(h.browseImport),
	}
}

// caNames are the certificate services the Certs menu offers: the message
// that names each.
var caNames = map[string]string{"staging": "autopanel.value.ca.nameStaging", "production": "autopanel.value.ca.nameProduction"}

// setCA chooses the certificate service, off the loop, then reads the status
// again: the Certs menu checks what the daemon reports, so a refused change
// leaves the old service checked.
func (h *host) setCA(ca string) error {
	nameID, ok := caNames[ca]
	if !ok {
		return fmt.Errorf("App.setCA takes staging or production, not %q", ca)
	}
	if h.busy {
		h.say(h.tr("autopanel.notice.app.busy"))
		h.refresh()
		return nil
	}
	h.busy = true
	h.background(func(ctx context.Context) error { return h.client.SetCA(ctx, ca) }, func(err error) {
		h.busy = false
		if err != nil {
			h.failed(err)
		} else {
			h.say(h.trf("autopanel.notice.certs.caNow", h.tr(nameID)))
		}
		h.refresh()
	})
	return nil
}

// closePanel is a panel's Close button: q and Escape do the same.
func (h *host) closePanel(key string) error {
	s, ok := panelOf(key)
	if !ok {
		return fmt.Errorf("no panel %q", key)
	}
	return h.p.Call(s.id, "close")
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

// rowOf reads a row number: a view's currentIndex, or a signal's index.
func rowOf(name string, v qml.SpecValue) (int, error) {
	if v.Kind != qml.SpecValueNumber {
		return 0, fmt.Errorf("%s takes a row number", name)
	}
	f, err := strconv.ParseFloat(v.Raw, 64)
	if err != nil || f != math.Trunc(f) {
		return 0, fmt.Errorf("%s takes a row number, not %q", name, v.Raw)
	}
	return int(f), nil
}

// oneRow is a command that takes a view's row.
func oneRow(name string, fn func(int) error) decl.HandlerFunc {
	return func(args []qml.SpecValue) error {
		if len(args) != 1 {
			return fmt.Errorf("%s takes a row number", name)
		}
		row, err := rowOf(name, args[0])
		if err != nil {
			return err
		}
		return fn(row)
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

// twoStrings is a command that takes two strings.
func twoStrings(name string, fn func(a, b string) error) decl.HandlerFunc {
	return func(args []qml.SpecValue) error {
		if len(args) != 2 || args[0].Kind != qml.SpecValueString || args[1].Kind != qml.SpecValueString {
			return fmt.Errorf("%s takes two strings", name)
		}
		return fn(args[0].Raw, args[1].Raw)
	}
}

// stringAndRow is a command that takes a string and a row: a list's name and
// its cursor.
func stringAndRow(name string, fn func(string, int) error) decl.HandlerFunc {
	return func(args []qml.SpecValue) error {
		if len(args) != 2 || args[0].Kind != qml.SpecValueString {
			return fmt.Errorf("%s takes a string and a row number", name)
		}
		row, err := rowOf(name, args[1])
		if err != nil {
			return err
		}
		return fn(args[0].Raw, row)
	}
}

// stringAndNumber is a command that takes a string and a number: a tile's id
// and its size.
func stringAndNumber(name string, fn func(string, float64) error) decl.HandlerFunc {
	return func(args []qml.SpecValue) error {
		if len(args) != 2 || args[0].Kind != qml.SpecValueString || args[1].Kind != qml.SpecValueNumber {
			return fmt.Errorf("%s takes a string and a number", name)
		}
		n, err := strconv.ParseFloat(args[1].Raw, 64)
		if err != nil || math.IsNaN(n) || math.IsInf(n, 0) {
			return fmt.Errorf("%s takes a number, not %q", name, args[1].Raw)
		}
		return fn(args[0].Raw, n)
	}
}

// formFields is the route form's submit: the subdomain, the domain box's
// row, the path prefix and the upstream.
func formFields(name string, fn func(sub string, domain int, prefix, upstream string) error) decl.HandlerFunc {
	return func(args []qml.SpecValue) error {
		if len(args) != 4 || args[0].Kind != qml.SpecValueString || args[2].Kind != qml.SpecValueString || args[3].Kind != qml.SpecValueString {
			return fmt.Errorf("%s takes a string, a row number and two strings", name)
		}
		row, err := rowOf(name, args[1])
		if err != nil {
			return err
		}
		return fn(args[0].Raw, row, args[2].Raw, args[3].Raw)
	}
}
