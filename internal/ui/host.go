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

	"github.com/yongjohnlee80/autopanel/core/gate"
)

// THE QML THIS PACKAGE SHIPS, and the modules a document imports it through.
//
//	import autopanel 1.0           the App singleton: state and commands   (declared)
//	import autopanel.dialogs 1.0   RoutesManager, RouteDialog, ConfirmDialog   (offered)
//	import autopanel.views 1.0     About                                       (offered)

// qmlFiles are the screen (qml/Main.qml), its dialogs (qml/dialogs/*.qml) and
// its views (qml/views/*.qml).
//
//go:embed qml
var qmlFiles embed.FS

const (
	layoutFile    = "qml/Main.qml"
	moduleVersion = "1.0"
	// formHint is the route form's help line while nothing has gone wrong.
	formHint = "Tab: next field · Enter: OK · Esc: cancel"
)

// host is the program behind Main.qml: state and behaviour, no widgets.
//
// It holds no state of the daemon's beyond what it last read: the routes the
// table shows, by row, so a row index from the document names its route.
// Every change goes through the Client, and the routes and the status are
// read again after.
type host struct {
	ctx     context.Context // the client calls'; Run's
	client  Client
	version string // the panel's own version, for About
	p       *tuidecl.Program

	model  *tuidecl.ListModel // App.routes: the table's rows
	facts  *tuidecl.ListModel // App.overview: the running AutoPanel, a fact per row
	routes []gate.RouteView   // the same rows, as the daemon gave them

	editID   int64 // the route the form edits; 0 adds one
	removeID int64 // the route the confirmation names
	busy     bool  // a change is in flight
}

func newHost(ctx context.Context, c Client, version string) *host {
	return &host{ctx: ctx, client: c, version: version, facts: tuidecl.NewListModel("key", "name", "value"), model: tuidecl.NewListModel("key", "id", "host", "path", "upstream")}
}

// options are everything the program is: the modules, the state, the
// commands, the layout. ONE function: Run builds from it, and so do the tests
// (decltest.Check, decltest.RunWith). sink receives handler errors; nil keeps
// the Program's default (or a test's own).
func (h *host) options(sink func(error), app ...tui.AppOption) []tuidecl.ProgramOption {
	opts := []tuidecl.ProgramOption{
		tuidecl.Singleton("autopanel", moduleVersion, "App"),
		tuidecl.Components(qmlFiles, "qml/dialogs", "autopanel.dialogs", moduleVersion),
		tuidecl.Components(qmlFiles, "qml/views", "autopanel.views", moduleVersion),
		tuidecl.Types(controls.Types()...), // TextField
		tuidecl.Layout(qmlFiles, layoutFile),
		tuidecl.Sources(h.state()),
		tuidecl.Handlers(h.commands()),
		tuidecl.AppOptions(app...),
	}
	if sink != nil {
		opts = append(opts, tuidecl.ErrorSink(sink))
	}
	return opts
}

// attach binds the host to the program built from its options, and starts
// the first read of the routes and status.
func (h *host) attach(p *tuidecl.Program) {
	h.p = p
	h.refresh()
}

// state is the App singleton's state, with its starting values. Each is a
// source: changing one repaints the bindings that read it.
func (h *host) state() map[string]any {
	return map[string]any{
		"App.routes":          h.model,
		"App.status":          "loading…",
		"App.message":         "",
		"App.overview":        h.facts,
		"App.caStaging":       false,
		"App.caProduction":    false,
		"App.aboutHeadline":   "AutoPanel " + orDash(h.version),
		"App.aboutPanel":      orDash(h.version),
		"App.aboutDaemon":     "-",
		"App.formTitle":       "Add route",
		"App.formHost":        "",
		"App.formPath":        "/",
		"App.formUpstream":    "",
		"App.formHelp":        formHint,
		"App.confirmQuestion": "",
	}
}

// background runs fn off the UI loop, then done with its answer on the loop.
func (h *host) background(fn func(ctx context.Context) error, done func(error)) {
	go func() {
		err := fn(h.ctx)
		h.p.Post(func() { done(err) })
	}()
}

// refresh reads the routes and the status again, off the loop.
func (h *host) refresh() {
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
			h.say("routes: " + err.Error())
		} else {
			h.setRoutes(routes)
		}
		if statusErr != nil {
			_ = h.p.Set("App.status", "status: "+statusErr.Error())
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
	ca := strings.TrimSpace(st.CA)
	rows := make([]tuidecl.Row, 0, 8)
	for _, f := range overview(st) {
		rows = append(rows, tuidecl.Row{"key": f[0], "name": f[0], "value": f[1]})
	}
	h.facts.Reset(rows)
	_ = h.p.SetMany(map[string]any{"App.caStaging": false, "App.caProduction": false})
	_ = h.p.SetMany(map[string]any{
		"App.status":       statusLine(st),
		"App.aboutDaemon":  orDash(st.Version) + " · up " + orDash(st.Uptime),
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
