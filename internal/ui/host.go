package ui

import (
	"context"
	"embed"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/yongjohnlee80/golib/tui"
	tuidecl "github.com/yongjohnlee80/golib/tui/decl"
	"github.com/yongjohnlee80/golib/tui/decl/controls"
	"github.com/yongjohnlee80/golib/tui/decl/panels"
	"github.com/yongjohnlee80/golib/tui/decl/themes"
	"github.com/yongjohnlee80/golib/tui/decl/tiles"
	"github.com/yongjohnlee80/golib/tui/widget/core"

	"github.com/yongjohnlee80/autopanel/core/gate"
)

// THE QML THIS PACKAGE SHIPS, and the modules a document imports it through.
//
//	import autopanel 1.0              the App singleton: state and commands       (declared)
//	import autopanel.theme.<name> 1.0 golib's themes: the Theme singleton         (offered)
//	import autopanel.dialogs 1.0      Login, RouteDialog, BrowseDialog,           (offered)
//	                                  ReviewDialog, PromptDialog, ConfirmDialog
//	import autopanel.views 1.0        Keys, About                                 (offered)
//	import tui.panels 1.0             golib's Panel: a docked, floating panel     (offered)
//	import tui.tiles 1.0              golib's TilePanel: a tile of the main screen (offered)
//
// The text is in catalogs, one per language (qml/i18n/autopanel_<tag>.xml),
// over golib's own.

// qmlFiles are the screen (qml/Main.qml), its dialogs and views, and the
// catalogs.
//
//go:embed qml
var qmlFiles embed.FS

const (
	layoutFile    = "qml/Main.qml"
	moduleVersion = "1.0"
)

// pollEvery is how often the widgets shown, and the panels open, are read
// again.
const pollEvery = 5 * time.Second

// host is the program behind Main.qml: state and behaviour, no widgets.
//
// It holds no state of the daemon's beyond what it last read: the rows each
// view shows, so a row index from the document names its record, and the last
// answer of each read, so a change of language composes their text again.
// Every change goes through the Client, and what it changed is read again.
type host struct {
	ctx     context.Context // the client calls'; Run's
	client  Client
	version string // the panel's own version, for About
	p       *tuidecl.Program

	layout   []byte // Main.qml as shipped, importing defaultTheme
	theme    string // the theme on screen
	language string // the language on screen

	// minimized collects the panels and widgets hidden in the dock.
	minimized *core.MinimizedWindows
	dock      *tuidecl.ListModel // App.dock: the menu bar's corner
	panelOpen map[string]bool    // the panels open, hidden or not, by key
	lastPanel []string           // the panels open, the one opened last at the end
	place     map[string]tilePlace

	routesModel *tuidecl.ListModel // App.routes: the routes panel's rows
	routes      []gate.RouteView   // the same rows, as the daemon gave them
	status      *Status            // the last status read, nil before the first

	domainModel *tuidecl.ListModel // App.domains: the domains panel's rows
	domains     []gate.DomainView  // the same rows
	domainsRead bool

	themes *tuidecl.ListModel // App.themes: System › Theme's rows
	mon    monitors           // the System panels' models and last answers (monitor.go)
	stk    stacks             // the stacks panel's models and last answers (services.go)
	wid    widgets            // the main screen's widgets (widgets.go)
	brw    browser            // the file browser (browse.go)
	form   routeForm          // the route form (routes.go)

	signingIn bool // a login attempt is in flight
	signedIn  bool // a panel user has logged in; nothing is read before

	// The terminal (terminal.go): the shell + starts and, when it is another,
	// root's; and whether the panel is open.
	ownShell      shell
	rootShell     *shell
	terminalShown bool

	statusShown bool // the status bar is on screen (View › Status bar)

	pollEvery time.Duration // how often the screen is read again; a test's own
	polling   bool          // a poll is in flight
	polled    bool          // the poller runs

	confirmed func() error       // what Yes in the confirmation runs
	other     func() error       // what its third button runs, when it has one
	prompted  func(string) error // what OK in the prompt runs, with the text
	busy      bool               // a change is in flight
}

func newHost(ctx context.Context, c Client, version string) *host {
	layout, err := qmlFiles.ReadFile(layoutFile)
	if err != nil {
		panic("ui: the embedded layout: " + err.Error()) // embedded: a test catches it first
	}
	h := &host{ctx: ctx, client: c, version: version, layout: layout, theme: defaultTheme, language: defaultLanguage,
		minimized:   core.NewMinimizedWindows(),
		dock:        tuidecl.NewListModel("key", "icon", "title", "hidden"),
		panelOpen:   map[string]bool{},
		place:       defaultPlaces(),
		routesModel: tuidecl.NewListModel("key", "id", "host", "path", "upstream"),
		domainModel: tuidecl.NewListModel("key", "name", "routes"),
		themes:      tuidecl.NewListModel("key", "label", "checked"),
		mon:         newMonitors(),
		stk:         newStacks(),
		wid:         newWidgets(),
		brw:         newBrowser(),
		form:        newRouteForm(),
		statusShown: true,
		pollEvery:   pollEvery,
	}
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
		panels.Offer(),                     // Panel: every panel the menus open
		tiles.Offer(),                      // TilePanel: every widget of the main screen
		tuidecl.Types(controls.Types()...), // TextField
		tuidecl.LayoutSource("Main.qml", withTheme(h.layout, h.theme)),
		tuidecl.Translations(qmlFiles, "qml/i18n", "autopanel"),
		tuidecl.Sources(h.state()),
		tuidecl.Handlers(h.commands()),
		// the panels' and the widgets' hide: the dock lists what this holds
		tuidecl.AdapterOptions(tuidecl.WithWindowCollector(h.minimized)),
		tuidecl.AppOptions(app...),
	}
	if sink != nil {
		opts = append(opts, tuidecl.ErrorSink(sink))
	}
	return opts
}

// attach binds the host to the program built from its options, and asks for
// the login. The first reads follow a login that succeeds (auth.go).
func (h *host) attach(p *tuidecl.Program) {
	h.p = p
	h.minimized.Observe(func() { h.p.Post(h.refreshDock) })
	h.p.Post(func() {
		h.retext()
		h.refreshDock()
	})
	h.promptLogin()
}

// state is the App singleton's state, with its starting values. Each is a
// source: changing one repaints the bindings that read it.
func (h *host) state() map[string]any {
	s := map[string]any{
		"App.routes":           h.routesModel,
		"App.domains":          h.domainModel,
		"App.themes":           h.themes,
		"App.dock":             h.dock,
		"App.status":           tui.Msg("autopanel.status.bar.signedOut"),
		"App.statusCenter":     "",
		"App.statusShown":      true,
		"App.lastUser":         defaultUser,
		"App.loginError":       "",
		"App.loginErrorShown":  false,
		"App.message":          "",
		"App.caStaging":        false,
		"App.caProduction":     false,
		"App.aboutHeadline":    "AutoPanel " + orDash(h.version),
		"App.aboutPanel":       orDash(h.version),
		"App.aboutDaemon":      "-",
		"App.routesTitle":      "",
		"App.routeDetail":      "",
		"App.domainsTitle":     "",
		"App.domainDetail":     "",
		"App.confirmTitle":     "",
		"App.confirmQuestion":  "",
		"App.confirmOther":     "",
		"App.confirmHasOther":  false,
		"App.promptTitle":      "",
		"App.promptLabel":      "",
		"App.promptText":       "",
		"App.promptError":      "",
		"App.promptErrorShown": false,
		"App.terminalShown":    false,
		"App.terminalEmpty":    englishText("autopanel.note.terminal.empty"),
		"App.keysText":         "",
	}
	for name, v := range languageChecks(h.language) {
		s[name] = v
	}
	for _, part := range []map[string]any{h.mon.state(), h.stk.state(), h.wid.state(), h.brw.state(), h.form.state(),
		h.layoutState(), tipState(inEnglish{})} {
		for name, v := range part {
			s[name] = v
		}
	}
	return s
}

// retext composes again what the host composes in Go from the catalogs and
// keeps on screen: the tooltips, Help › Keys, the dock's titles and the
// terminal's empty line. On the loop.
func (h *host) retext() {
	vals := tipState(h)
	vals["App.keysText"] = keysText(h)
	vals["App.terminalEmpty"] = h.tr("autopanel.note.terminal.empty")
	_ = h.p.SetMany(vals)
}

// background runs fn off the UI loop, then done with its answer on the loop.
func (h *host) background(fn func(ctx context.Context) error, done func(error)) {
	go func() {
		err := fn(h.ctx)
		h.p.Post(func() { done(err) })
	}()
}

// refresh reads the routes, the domains and the status again, off the loop.
// Signed out, it reads nothing: the service would refuse.
func (h *host) refresh() {
	if !h.signedIn {
		return
	}
	var (
		routes    []gate.RouteView
		domains   []gate.DomainView
		st        Status
		statusErr error
		domainErr error
	)
	h.background(func(ctx context.Context) error {
		var err error
		routes, err = h.client.Routes(ctx)
		domains, domainErr = h.client.Domains(ctx)
		st, statusErr = h.client.Status(ctx)
		return err
	}, func(err error) {
		if err != nil {
			h.say(h.trf("autopanel.notice.routes.readFailed", err.Error()))
			h.wid.certErr = err
		} else {
			h.setRoutes(routes)
		}
		if domainErr != nil {
			h.wid.domainErr = domainErr
		} else {
			h.setDomains(domains)
		}
		if statusErr != nil {
			h.wid.certErr = statusErr
			_ = h.p.Set("App.status", h.trf("autopanel.status.bar.error", statusErr.Error()))
		} else {
			h.setStatus(st)
		}
		h.renderTraffic()
		h.renderCerts()
		h.renderRoutes()
		h.renderDomains()
	})
}

// setStatus shows the running AutoPanel as st describes it: the status bar's
// line, About's daemon line, and which certificate service the Certs menu
// checks.
//
// The two checks go through false first. Choosing a row checks it in the menu
// at once, before the daemon has answered; when the daemon then refuses, the
// sources still hold the old values, and setting a source to the value it
// has repaints nothing. Through false, the menu always ends on what the
// daemon reports.
func (h *host) setStatus(st Status) {
	h.status = &st
	h.wid.certErr = nil
	ca := strings.TrimSpace(st.CA)
	_ = h.p.SetMany(map[string]any{"App.caStaging": false, "App.caProduction": false})
	_ = h.p.SetMany(map[string]any{
		"App.status":       statusLine(h, st),
		"App.statusCenter": h.trf("autopanel.status.bar.readAt", time.Now().Format("15:04:05")),
		"App.aboutDaemon":  h.trf("autopanel.value.about.daemon", orDash(st.Version), orDash(st.Uptime)),
		"App.caStaging":    ca == certmagic.LetsEncryptStagingCA,
		"App.caProduction": ca == certmagic.LetsEncryptProductionCA,
	})
}

// setRoutes keeps routes as the routes panel's rows. Each row's key is its
// route's id, so the cursor stays on its route across a read.
func (h *host) setRoutes(routes []gate.RouteView) {
	h.routes = routes
	rows := make([]tuidecl.Row, 0, len(routes))
	for _, r := range routes {
		rows = append(rows, tuidecl.Row{"key": strconv.FormatInt(r.ID, 10), "id": r.ID,
			"host": r.Host, "path": r.PathPrefix, "upstream": r.Upstream})
	}
	h.routesModel.Reset(rows)
}

// setDomains keeps domains as the domains panel's rows.
func (h *host) setDomains(domains []gate.DomainView) {
	h.domains, h.domainsRead = domains, true
	h.wid.domainErr = nil
	rows := make([]tuidecl.Row, 0, len(domains))
	for _, d := range domains {
		rows = append(rows, tuidecl.Row{"key": d.Name, "name": d.Name, "routes": d.Routes})
	}
	h.domainModel.Reset(rows)
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

// failed says err on the status bar, as the error line of every action that
// changes nothing on screen when it fails.
func (h *host) failed(err error) { h.say(h.trf("autopanel.notice.app.error", err.Error())) }

// fill sets a form's sources to vals. Each goes through a different value
// first, so a field the user typed in since the last fill takes the value
// again even when the source would not change (USAGE §10: "a form is filled
// by the host, then opened").
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
// runs then. No comes first, so Enter alone answers No; Escape leaves it.
func (h *host) ask(title, question string, then func() error) error {
	return h.askOr(title, question, "", nil, then)
}

// askOr is ask with a third answer: otherLabel (a message's id) runs other.
func (h *host) askOr(title, question, otherLabel string, other, then func() error) error {
	h.confirmed, h.other = then, other
	label := ""
	if otherLabel != "" {
		label = h.tr(otherLabel)
	}
	if err := h.p.SetMany(map[string]any{"App.confirmTitle": h.tr(title), "App.confirmQuestion": question,
		"App.confirmOther": label, "App.confirmHasOther": other != nil}); err != nil {
		return err
	}
	return h.p.Call("confirmDialog", "open")
}

// confirm is Yes in the confirmation: what it was opened for, once.
func (h *host) confirm() error {
	then := h.confirmed
	h.confirmed, h.other = nil, nil
	if then == nil {
		return nil
	}
	return then()
}

// confirmOther is the confirmation's third answer, once.
func (h *host) confirmOther() error {
	then := h.other
	h.confirmed, h.other = nil, nil
	if then == nil {
		return nil
	}
	return then()
}

// prompt opens the one-field dialog: title and label are messages' ids, text
// what the field starts with. OK runs then with the
// field's text; an error then returns is shown in the dialog, which stays.
func (h *host) prompt(title, label, text string, then func(string) error) error {
	h.prompted = then
	if err := h.fill(map[string]any{"App.promptText": text}); err != nil {
		return err
	}
	if err := h.p.SetMany(map[string]any{"App.promptTitle": h.tr(title), "App.promptLabel": h.tr(label),
		"App.promptError": "", "App.promptErrorShown": false}); err != nil {
		return err
	}
	return h.p.Call("promptDialog", "open")
}

// promptAnswered is OK in the prompt.
func (h *host) promptAnswered(text string) error {
	if h.prompted == nil {
		return h.p.Call("promptDialog", "close")
	}
	return h.prompted(text)
}

// promptRefused shows why the prompt's answer was not taken; the dialog stays
// open, as typed.
func (h *host) promptRefused(why string) {
	_ = h.p.SetMany(map[string]any{"App.promptError": why, "App.promptErrorShown": true})
}

// promptDone closes the prompt once its answer is taken.
func (h *host) promptDone() {
	h.prompted = nil
	_ = h.p.Call("promptDialog", "close")
}
