package ui

import (
	"context"
	"fmt"

	"github.com/yongjohnlee80/golib/tui"
	"github.com/yongjohnlee80/golib/tui/style"
	"github.com/yongjohnlee80/golib/tui/widget/core"
	"github.com/yongjohnlee80/golib/tui/widget/table"

	"github.com/yongjohnlee80/autopanel/core/gate"
)

// keyHints is the footer's reminder of the panel's keys.
const keyHints = "a add · e edit · d delete · r refresh · q quit"

// routeSource is the routes as the table's rows: ID, Host, Path, Upstream.
type routeSource struct{ routes []gate.RouteView }

var _ table.TableSource = (*routeSource)(nil)

func (s *routeSource) Fields() []core.TableField {
	return []core.TableField{{Title: "ID"}, {Title: "Host"}, {Title: "Path"}, {Title: "Upstream"}}
}

func (s *routeSource) Len() int { return len(s.routes) }

func (s *routeSource) Cell(row, col int) string {
	if row < 0 || row >= len(s.routes) {
		return ""
	}
	r := s.routes[row]
	switch col {
	case 0:
		return fmt.Sprint(r.ID)
	case 1:
		return r.Host
	case 2:
		return r.PathPrefix
	case 3:
		return r.Upstream
	}
	return ""
}

// routesTable is the table view with the panel's keys taken first: the table's
// own grammar binds r (row cursor) and d (dd), which the panel uses.
type routesTable struct {
	*table.DataTable
	keys func(tui.KeyEvent) bool
}

func (t *routesTable) HandleEvent(ev tui.Event) bool {
	if k, ok := ev.(tui.KeyEvent); ok && t.keys != nil && t.keys(k) {
		return true
	}
	return t.DataTable.HandleEvent(ev)
}

// loaded is a refresh's answer.
type loaded struct {
	routes    []gate.RouteView
	status    Status
	routesErr error
	statusErr error
}

// written is a change's answer: done is the confirmation on success, form the
// dialog to close then (nil for none).
type written struct {
	done string
	err  error
	form *core.Modal
}

// panel is the root controller: it mounts the layout, owns the client calls
// (as App tasks) and answers the keys.
type panel struct {
	client Client
	quit   func()

	root   tui.Component
	src    *routeSource
	tcore  *table.TableCore
	table  *routesTable
	host   *core.OverlayHost
	status *core.StatusBar
	footer *core.StatusBar

	busy bool // a change is in flight
	ctx  *tui.Context
}

// newPanel assembles the layout:
//
//	AutoPanel
//	┌ Routes ────────────────────────────┐
//	│ ID  Host  Path  Upstream           │
//	└────────────────────────────────────┘
//	 status summary             message
//	 key hints
func newPanel(c Client, quit func()) *panel {
	p := &panel{client: c, quit: quit, src: &routeSource{}}
	p.tcore = table.NewTableCore(p.src, table.TableOnActivate(func(int) { p.openForm(true) }))
	p.tcore.SetRowCursor(true)
	dt := table.NewDataTable(p.tcore)
	dt.SetEmptyText("No routes: press a to add one")
	p.table = &routesTable{DataTable: dt, keys: p.key}

	title := core.NewText(" AutoPanel")
	title.SetBold(true)
	p.status = core.NewStatusBar()
	p.footer = core.NewStatusBar()

	dock := tui.NewDock()
	dock.Pin(tui.DockTop, title)
	dock.Pin(tui.DockBottom, p.footer)
	dock.Pin(tui.DockBottom, p.status)
	dock.Add(core.NewBox(p.table, core.WithTitle("Routes")))
	p.host = core.NewOverlayHost(dock)
	p.root = p.host
	return p
}

func (p *panel) Init(ctx *tui.Context) {
	p.ctx = ctx
	ctx.Mount(p.root)
	p.status.SetLeft("loading…")
	p.footer.SetLeft(keyHints)
	p.refresh()
}

func (p *panel) Layout(c tui.Constraints) tui.Size {
	sz := p.ctx.LayoutChild(p.root, c)
	p.ctx.PlaceChild(p.root, tui.Rect{X: 0, Y: 0, W: sz.W, H: sz.H})
	return sz
}

func (p *panel) Render(tui.Surface) {}

// InitialFocus puts the keys in the table.
func (p *panel) InitialFocus() (tui.Component, bool) { return p.table, true }

func (p *panel) HandleEvent(ev tui.Event) bool {
	switch e := ev.(type) {
	case tui.TaskResult:
		p.taskDone(e)
		return true
	case tui.KeyEvent:
		return p.key(e) // a key the table did not see (nothing focused)
	}
	return false
}

// key is the panel's keys. It reports whether it took k.
func (p *panel) key(k tui.KeyEvent) bool {
	if k.Kind == tui.KeyRelease {
		return false
	}
	if k.Code == 'c' && k.Mods.Chord() == tui.ModCtrl {
		p.quit()
		return true
	}
	if k.Mods.Chord() != 0 {
		return false
	}
	switch k.Code {
	case 'q':
		p.quit()
	case 'r':
		p.refresh()
	case 'a':
		p.openForm(false)
	case 'e':
		p.openForm(true)
	case 'd':
		p.confirmRemove()
	default:
		return false
	}
	return true
}

// selected is the route under the cursor.
func (p *panel) selected() (gate.RouteView, bool) {
	if p.src.Len() == 0 {
		return gate.RouteView{}, false
	}
	row := p.tcore.SourceRow(p.tcore.Cursor().Row)
	if row < 0 || row >= len(p.src.routes) {
		return gate.RouteView{}, false
	}
	return p.src.routes[row], true
}

// refresh reads the routes and the status again.
func (p *panel) refresh() {
	c := p.client
	p.ctx.Go(func(ctx context.Context) (any, error) {
		var l loaded
		l.routes, l.routesErr = c.Routes(ctx)
		l.status, l.statusErr = c.Status(ctx)
		return l, nil
	})
}

// change runs one client write; its answer comes back as a TaskResult.
func (p *panel) change(form *core.Modal, done string, fn func(ctx context.Context) error) {
	if p.busy {
		p.say("busy: a change is in flight", true)
		return
	}
	p.busy = true
	p.ctx.Go(func(ctx context.Context) (any, error) {
		return written{done: done, err: fn(ctx), form: form}, nil
	})
}

func (p *panel) taskDone(e tui.TaskResult) {
	switch v := e.Value.(type) {
	case loaded:
		if v.routesErr == nil {
			p.src.routes = v.routes
			p.tcore.Changed()
		} else {
			p.say("routes: "+v.routesErr.Error(), true)
		}
		if v.statusErr == nil {
			p.status.SetLeft(statusLine(v.status))
		} else {
			p.status.SetLeft("status: " + v.statusErr.Error())
		}
	case written:
		p.busy = false
		if v.err != nil {
			p.say(v.err.Error(), true)
			if v.form != nil && v.form.IsOpen() {
				v.form.SetFooter(v.err.Error())
			}
			return
		}
		if v.form != nil {
			v.form.Dismiss(core.DismissAccept)
		}
		p.say(v.done, false)
		p.refresh()
	default:
		if e.Err != nil {
			p.say(e.Err.Error(), true)
		}
	}
}

// say shows msg at the status bar's right, in the error colour when bad.
func (p *panel) say(msg string, bad bool) {
	st := style.New().Background(style.TokenPanel).Foreground(style.TokenSuccess)
	if bad {
		st = style.New().Background(style.TokenPanel).Foreground(style.TokenError)
	}
	p.status.SetRight(msg, st)
}

// openForm opens the route form: empty for a new route, or the selected
// route's to edit it.
func (p *panel) openForm(edit bool) {
	var r gate.RouteView
	if edit {
		var ok bool
		if r, ok = p.selected(); !ok {
			p.say("no route selected", true)
			return
		}
	}
	prefix := r.PathPrefix
	if prefix == "" {
		prefix = "/"
	}
	host := core.NewTextInput(core.WithInitialValue(r.Host), core.WithPlaceholder("example.com"))
	path := core.NewTextInput(core.WithInitialValue(prefix), core.WithPlaceholder("/"))
	upstream := core.NewTextInput(core.WithInitialValue(r.Upstream), core.WithPlaceholder("http://127.0.0.1:8080"))
	body := tui.NewFlex(tui.Vertical)
	for _, f := range []struct {
		label string
		input *core.TextInput
	}{{"Host", host}, {"Path prefix", path}, {"Upstream URL", upstream}} {
		body.AddSized(core.NewText(f.label), 1)
		body.AddSized(f.input, 1)
	}

	title, done := "Add route", "added %s%s"
	if edit {
		title, done = fmt.Sprintf("Edit route #%d", r.ID), "updated %s%s"
	}
	var form *core.Modal
	ok := core.NewButton("OK", core.WithRole(core.ButtonRoleAction), core.WithDefault(true),
		core.WithOnActivate(func() {
			s := formSpec(r.ID, host.Value(), path.Value(), upstream.Value())
			c := p.client
			p.change(form, fmt.Sprintf(done, s.Host, s.PathPrefix), func(ctx context.Context) error {
				if edit {
					return c.Update(ctx, s)
				}
				return c.Add(ctx, s)
			})
		}))
	form = core.NewModal(body, core.WithModalTitle(title), core.WithModalWidth(64),
		core.WithButtons(ok, core.NewStandardButton(core.StandardCancel)),
		core.WithModalFooter("Tab: next field · Enter: OK · Esc: cancel"))
	if err := form.Open(p.host); err != nil {
		p.say(err.Error(), true)
	}
}

// confirmRemove asks before removing the selected route.
func (p *panel) confirmRemove() {
	r, ok := p.selected()
	if !ok {
		p.say("no route selected", true)
		return
	}
	c := p.client
	yes := core.NewStandardButton(core.StandardYes, core.WithOnActivate(func() {
		p.change(nil, "removed "+describe(r), func(ctx context.Context) error { return c.Remove(ctx, r.ID) })
	}))
	no := core.NewStandardButton(core.StandardNo, core.WithDefault(true))
	m := core.NewModal(core.NewText("Remove route "+describe(r)+"?"), core.WithModalTitle("Remove route"),
		core.WithButtons(yes, no))
	if err := m.Open(p.host); err != nil {
		p.say(err.Error(), true)
	}
}
