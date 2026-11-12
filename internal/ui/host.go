package ui

import (
	"context"
	"embed"
	"strconv"
	"strings"

	"github.com/caddyserver/certmagic"
	"github.com/yongjohnlee80/golib/tui"
	tuidecl "github.com/yongjohnlee80/golib/tui/decl"
	"github.com/yongjohnlee80/golib/tui/decl/controls"
	"github.com/yongjohnlee80/golib/tui/decl/themes"
	"github.com/yongjohnlee80/golib/tui/widget/core"

	"github.com/yongjohnlee80/autopanel/core/gate"
)

// THE QML THIS PACKAGE SHIPS, and the modules a document imports it through.
//
//	import autopanel 1.0              the App singleton: state and commands       (declared)
//	import autopanel.theme.<name> 1.0 golib's themes: the Theme singleton         (offered)
//	import autopanel.dialogs 1.0      Login, RouteDialog, TurnDialog, ConfirmDialog (offered)
//	import autopanel.views 1.0        About                                       (offered)
//	import autopanel.panels 1.0       FloatPanel: a floating window with controls (offered)
//
// The text is in catalogs, one per language (qml/i18n/autopanel_<tag>.xml),
// over golib's own.

// qmlFiles are the screen (qml/Main.qml), its dialogs, views and panels, and
// the catalogs.
//
//go:embed qml
var qmlFiles embed.FS

const (
	layoutFile    = "qml/Main.qml"
	moduleVersion = "1.0"
)

// host is the program behind Main.qml: state and behaviour, no widgets.
//
// It holds no state of the daemon's beyond what it last read: the routes the
// table shows, by row, so a row index from the document names its route, and
// the last status and monitoring answers, so a change of language composes
// their text again. Every change goes through the Client, and the routes and
// the status are read again after.
type host struct {
	ctx     context.Context // the client calls'; Run's
	client  Client
	version string // the panel's own version, for About
	p       *tuidecl.Program

	layout   []byte // Main.qml as shipped, importing defaultTheme
	theme    string // the theme on screen
	language string // the language on screen

	// minimized collects the panels minimized from their window controls; the
	// taskbar on the hints row shows them, and a menu row restores its panel.
	minimized *core.MinimizedWindows

	model  *tuidecl.ListModel // App.routes: the table's rows
	routes []gate.RouteView   // the same rows, as the daemon gave them
	facts  *tuidecl.ListModel // App.overview: the running AutoPanel, a fact per row
	status *Status            // the last status read, nil before the first

	themes *tuidecl.ListModel // App.themes: System › Theme's rows
	mon    monitors           // the System panels' models and last answers (monitor.go)
	svc    deployed           // the Services panels' models and last answers (services.go)

	signingIn bool // a login attempt is in flight
	signedIn  bool // a panel user has logged in; nothing is read before

	// The terminal (terminal.go): the shell + starts and, when it is another,
	// root's; and whether the panel is open.
	ownShell      shell
	rootShell     *shell
	terminalShown bool

	editID    int64        // the route the form edits; 0 adds one
	removeID  int64        // the route the confirmation names
	confirmed func() error // what Yes in the confirmation runs
	busy      bool         // a change is in flight
}

func newHost(ctx context.Context, c Client, version string) *host {
	layout, err := qmlFiles.ReadFile(layoutFile)
	if err != nil {
		panic("ui: the embedded layout: " + err.Error()) // embedded: a test catches it first
	}
	h := &host{ctx: ctx, client: c, version: version, layout: layout, theme: defaultTheme, language: defaultLanguage,
		minimized: core.NewMinimizedWindows(),
		model:     tuidecl.NewListModel("key", "id", "host", "path", "upstream"),
		facts:     tuidecl.NewListModel("key", "name", "value"),
		themes:    tuidecl.NewListModel("key", "label", "checked"),
		mon:       newMonitors(),
		svc:       newDeployed()}
	h.themes.Reset(themeRows(h.theme))
	h.ownShell, h.rootShell = hostShells()
	return h
}

// options are everything the program is: the modules, the state, the
// commands, the layout. ONE function: Run builds from it, and so do the tests
// (decltest.Check, decltest.RunWith). sink receives handler errors; nil keeps
// the Program's default (or a test's own).
func (h *host) options(sink func(error), app ...tui.AppOption) []tuidecl.ProgramOption {
	opts := []tuidecl.ProgramOption{
		tuidecl.Singleton("autopanel", moduleVersion, "App"),
		// golib's themes, as autopanel.theme.<name>: the panel keeps no colours of its own
		tuidecl.Themes(themes.FS(), ".", "autopanel.theme", moduleVersion),
		tuidecl.Components(qmlFiles, "qml/dialogs", "autopanel.dialogs", moduleVersion),
		tuidecl.Components(qmlFiles, "qml/views", "autopanel.views", moduleVersion),
		tuidecl.Components(qmlFiles, "qml/panels", "autopanel.panels", moduleVersion),
		tuidecl.Types(controls.Types()...), // TextField
		tuidecl.LayoutSource("Main.qml", withTheme(h.layout, h.theme)),
		tuidecl.Translations(qmlFiles, "qml/i18n", "autopanel"),
		tuidecl.Sources(h.state()),
		tuidecl.Handlers(h.commands()),
		tuidecl.AdapterOptions(tuidecl.WithWindowCollector(h.minimized)), // the panels' minimize
		tuidecl.AppOptions(app...),
	}
	if sink != nil {
		opts = append(opts, tuidecl.ErrorSink(sink))
	}
	return opts
}

// attach binds the host to the program built from its options, and asks for
// the login. The first reads (the routes and status, the kept preferences)
// follow a login that succeeds (auth.go).
func (h *host) attach(p *tuidecl.Program) {
	h.p = p
	h.promptLogin()
}

// state is the App singleton's state, with its starting values. Each is a
// source: changing one repaints the bindings that read it.
func (h *host) state() map[string]any {
	s := map[string]any{
		"App.routes":          h.model,
		"App.overview":        h.facts,
		"App.themes":          h.themes,
		"App.status":          tui.Msg("autopanel.status.signedOut"),
		"App.lastUser":        defaultUser,
		"App.loginError":      "",
		"App.message":         "",
		"App.caStaging":       false,
		"App.caProduction":    false,
		"App.aboutHeadline":   "AutoPanel " + orDash(h.version),
		"App.aboutPanel":      orDash(h.version),
		"App.aboutDaemon":     "-",
		"App.formTitle":       tui.Msg("autopanel.form.add"),
		"App.formHost":        "",
		"App.formPath":        "/",
		"App.formUpstream":    "",
		"App.formHelp":        tui.Msg("autopanel.form.hint"),
		"App.confirmTitle":    tui.Msg("autopanel.confirm.title"),
		"App.confirmQuestion": "",
		"App.terminalShown":   false,
		"App.terminalEmpty":   englishText("autopanel.terminal.empty"),
	}
	for name, v := range languageChecks(h.language) {
		s[name] = v
	}
	for name, v := range h.mon.state() {
		s[name] = v
	}
	for name, v := range h.svc.state() {
		s[name] = v
	}
	return s
}

// background runs fn off the UI loop, then done with its answer on the loop.
func (h *host) background(fn func(ctx context.Context) error, done func(error)) {
	go func() {
		err := fn(h.ctx)
		h.p.Post(func() { done(err) })
	}()
}

// refresh reads the routes and the status again, off the loop. Signed out,
// it reads nothing: the service would refuse.
func (h *host) refresh() {
	if !h.signedIn {
		return
	}
	var (
		routes    []gate.RouteView
		st        Status
		statusErr error
	)
	h.background(func(ctx context.Context) error {
		var err error
		routes, err = h.client.Routes(ctx)
		st, statusErr = h.client.Status(ctx)
		return err
	}, func(err error) {
		if err != nil {
			h.say(h.trf("autopanel.notice.routesError", err.Error()))
		} else {
			h.setRoutes(routes)
		}
		if statusErr != nil {
			_ = h.p.Set("App.status", h.trf("autopanel.status.error", statusErr.Error()))
			return
		}
		h.setStatus(st)
	})
}

// setStatus shows the running AutoPanel as st describes it: the status bar's
// line, the overview's rows, About's daemon line, and which certificate
// service the Certs menu checks.
//
// The two checks go through false first. Choosing a row checks it in the menu
// at once, before the daemon has answered; when the daemon then refuses, the
// sources still hold the old values, and setting a source to the value it
// has repaints nothing. Through false, the menu always ends on what the
// daemon reports.
func (h *host) setStatus(st Status) {
	h.status = &st
	ca := strings.TrimSpace(st.CA)
	rows := make([]tuidecl.Row, 0, 8)
	for _, f := range overview(h, st) {
		rows = append(rows, tuidecl.Row{"key": f[0], "name": f[0], "value": f[1]})
	}
	h.facts.Reset(rows)
	_ = h.p.SetMany(map[string]any{"App.caStaging": false, "App.caProduction": false})
	_ = h.p.SetMany(map[string]any{
		"App.status":       statusLine(h, st),
		"App.aboutDaemon":  h.trf("autopanel.about.daemonLine", orDash(st.Version), orDash(st.Uptime)),
		"App.caStaging":    ca == certmagic.LetsEncryptStagingCA,
		"App.caProduction": ca == certmagic.LetsEncryptProductionCA,
	})
}

// setRoutes makes routes the table's rows. Each row's key is its route's id,
// so the cursor stays on its route across a refresh.
func (h *host) setRoutes(routes []gate.RouteView) {
	h.routes = routes
	rows := make([]tuidecl.Row, 0, len(routes))
	for _, r := range routes {
		rows = append(rows, tuidecl.Row{"key": strconv.FormatInt(r.ID, 10), "id": r.ID,
			"host": r.Host, "path": r.PathPrefix, "upstream": r.Upstream})
	}
	h.model.Reset(rows)
}

// route is the route at a row the document passed, if there is one.
func (h *host) route(row int) (gate.RouteView, bool) {
	if row < 0 || row >= len(h.routes) {
		return gate.RouteView{}, false
	}
	return h.routes[row], true
}

// say puts a line at the status bar's right. On the loop.
func (h *host) say(msg string) {
	if h.p != nil {
		_ = h.p.Set("App.message", msg)
	}
}

// fill sets the route form's sources to vals. Each goes through a different
// value first, so a field the user typed in since the last fill takes the
// value again even when the source would not change (USAGE §10: "a form is
// filled by the host, then opened").
func (h *host) fill(vals map[string]any) error {
	other := make(map[string]any, len(vals))
	for k, v := range vals {
		other[k] = v.(string) + " "
	}
	if err := h.p.SetMany(other); err != nil {
		return err
	}
	return h.p.SetMany(vals)
}

// ask opens the confirmation under title (a message's id) with question; Yes
// runs then. No, Enter and Escape leave it.
func (h *host) ask(title, question string, then func() error) error {
	h.confirmed = then
	if err := h.p.SetMany(map[string]any{"App.confirmTitle": h.tr(title), "App.confirmQuestion": question}); err != nil {
		return err
	}
	return h.p.Call("confirmDialog", "open")
}

// confirm is Yes in the confirmation: what it was opened for, once.
func (h *host) confirm() error {
	then := h.confirmed
	h.confirmed = nil
	if then == nil {
		return nil
	}
	return then()
}

// panelLeft gives the keyboard back once a panel has closed: to the services
// panel when it is on screen, since its log and its secrets open over it, and
// otherwise to the overview, the Window's focus target. Posted: the handler
// runs while the panel is still closing.
func (h *host) panelLeft() error {
	h.p.Post(func() {
		if h.svc.shown && !h.isMinimized("services") && h.p.Call("servicesTable", "forceActiveFocus") == nil {
			return
		}
		_ = h.p.Call("overview", "forceActiveFocus")
	})
	return nil
}

// isMinimized says whether the panel of a window key is minimized.
func (h *host) isMinimized(key string) bool {
	for _, e := range h.minimized.Entries() {
		if e.Key == key {
			return true
		}
	}
	return false
}

// panelChanged is a panel's completed window operation. A minimized panel
// has left the screen, as a closed one has; a move, a resize, a maximize or a
// restore keeps the keyboard where it is.
func (h *host) panelChanged(operation string) error {
	if operation == "minimize" {
		return h.panelLeft()
	}
	return nil
}

// openPanel shows a floating panel and gives its view the keyboard: restored
// when it was minimized, opened otherwise. key is the panel's window key, id
// its id in the document, view the id of the view inside it.
func (h *host) openPanel(key, id, view string) error {
	restored := false
	for _, e := range h.minimized.Entries() {
		if e.Key == key {
			restored = e.Restore()
			break
		}
	}
	if !restored {
		if err := h.p.Call(id, "open"); err != nil {
			return err
		}
	}
	return h.p.Call(view, "forceActiveFocus")
}
