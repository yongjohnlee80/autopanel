package ui

import (
	"context"
	"embed"
	"strconv"

	"github.com/yongjohnlee80/golib/tui"
	tuidecl "github.com/yongjohnlee80/golib/tui/decl"
	"github.com/yongjohnlee80/golib/tui/decl/controls"

	"github.com/yongjohnlee80/autopanel/core/gate"
)

// THE QML THIS PACKAGE SHIPS, and the modules a document imports it through.
//
//	import autopanel 1.0           the App singleton: state and commands   (declared)
//	import autopanel.dialogs 1.0   RouteDialog, ConfirmDialog              (offered)

// qmlFiles are the screen (qml/Main.qml) and its dialogs (qml/dialogs/*.qml).
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
// Every change goes through the Client, and the routes are read again after.
type host struct {
	ctx    context.Context // the client calls'; Run's
	client Client
	p      *tuidecl.Program

	model  *tuidecl.ListModel // App.routes: the table's rows
	routes []gate.RouteView   // the same rows, as the daemon gave them

	editID   int64 // the route the form edits; 0 adds one
	removeID int64 // the route the confirmation names
	busy     bool  // a change is in flight
}

func newHost(ctx context.Context, c Client) *host {
	return &host{ctx: ctx, client: c, model: tuidecl.NewListModel("key", "id", "host", "path", "upstream")}
}

// options are everything the program is: the modules, the state, the
// commands, the layout. ONE function: Run builds from it, and so do the tests
// (decltest.Check, decltest.RunWith). sink receives handler errors; nil keeps
// the Program's default (or a test's own).
func (h *host) options(sink func(error), app ...tui.AppOption) []tuidecl.ProgramOption {
	opts := []tuidecl.ProgramOption{
		tuidecl.Singleton("autopanel", moduleVersion, "App"),
		tuidecl.Components(qmlFiles, "qml/dialogs", "autopanel.dialogs", moduleVersion),
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
		line := statusLine(st)
		if statusErr != nil {
			line = "status: " + statusErr.Error()
		}
		_ = h.p.Set("App.status", line)
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
