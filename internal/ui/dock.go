package ui

import (
	"fmt"
	"slices"

	tuidecl "github.com/yongjohnlee80/golib/tui/decl"
	"github.com/yongjohnlee80/golib/tui/widget/core"
)

// THE DOCK — the menu bar's corner, as AutoDoc's: an icon for each widget of
// the main screen, then one for each panel that is open, hidden or not. A
// click hides what is shown and shows what is hidden; a hidden one's icon is
// dimmed. Hidden is golib's window minimize: a panel keeps what it holds and
// its Closed hook does not run; a widget gives its tile to the ones beside it
// and is not read while hidden.
//
// The widgets tile the main screen (golib's TileManager): each is a TilePanel
// at an edge, at a size, which Alt-drags move and resize. Where each is, is
// kept for the session (App.<widget>Edge and App.<widget>Size), so a theme's
// reload keeps it; the daemon's preferences hold only the theme and the
// language.
//
// Decision: docs/decisions/ui.md#the-dock-replaces-the-taskbar

// panelSpec is a panel the menus open: its window key, its id in Main.qml,
// the view in it that takes the keyboard, its dock icon and its title's
// message.
type panelSpec struct {
	key, id, view, icon, title string
}

// panelSpecs are the panels, in the dock's order.
var panelSpecs = []panelSpec{
	{"stacks", "stacksPanel", "stacksTable", "▥", "autopanel.title.panel.stacks"},
	{"routes", "routesPanel", "routesTable", "⇄", "autopanel.title.panel.routes"},
	{"domains", "domainsPanel", "domainsTable", "◎", "autopanel.title.panel.domains"},
	{"metrics", "metricsPanel", "metricsTable", "∿", "autopanel.title.panel.metrics"},
	{"audit", "auditPanel", "auditTable", "☰", "autopanel.title.panel.audit"},
	{"logins", "loginsPanel", "loginsTable", "⊙", "autopanel.title.panel.logins"},
	{"ports", "portsPanel", "portsTable", "⊞", "autopanel.title.panel.ports"},
	{"stackLogs", "stackLogsPanel", "stackLogsTable", "¶", "autopanel.title.panel.stackLog"},
	{"terminal", "terminalPanel", "terminalView", "❯", "autopanel.title.panel.terminal"},
}

// panelOf is the panel of a window key.
func panelOf(key string) (panelSpec, bool) {
	i := slices.IndexFunc(panelSpecs, func(s panelSpec) bool { return s.key == key })
	if i < 0 {
		return panelSpec{}, false
	}
	return panelSpecs[i], true
}

// widgetSpec is a widget of the main screen: its tile's id in Main.qml (its
// key), the view in it that takes the keyboard ("" for none), its dock icon,
// its title's message, its App.<name>* sources' name, and where it is tiled
// first: its edge and its size, a percent of the screen across that edge.
type widgetSpec struct {
	id, view, icon, title, name string
	edge                        string
	size                        int
}

// widgetSpecs are the widgets, in the dock's order: as the screen reads, top
// down. Main.qml declares their tiles in the order they take the screen.
var widgetSpecs = []widgetSpec{
	{"hostWidget", "", "◫", "autopanel.title.widget.host", "host", "top", 16},
	{"stacksWidget", "stackSummaryTable", "▦", "autopanel.title.widget.stacks", "stacksWidget", "left", 45},
	{"networkWidget", "networkTable", "⇅", "autopanel.title.widget.network", "network", "top", 22},
	{"trafficWidget", "trafficTable", "↯", "autopanel.title.widget.traffic", "traffic", "left", 28},
	{"certsWidget", "certsTable", "✓", "autopanel.title.widget.certs", "certs", "center", 0},
	{"portsWidget", "portSummaryTable", "⊡", "autopanel.title.widget.ports", "ports", "top", 22},
	{"activityWidget", "activityTable", "≡", "autopanel.title.widget.activity", "activity", "bottom", 24},
}

// widgetOf is the widget of a tile's id.
func widgetOf(id string) (widgetSpec, bool) {
	i := slices.IndexFunc(widgetSpecs, func(s widgetSpec) bool { return s.id == id })
	if i < 0 {
		return widgetSpec{}, false
	}
	return widgetSpecs[i], true
}

// tilePlace is where a widget is tiled now: its edge and its size.
type tilePlace struct {
	edge string
	size float64
}

func defaultPlaces() map[string]tilePlace {
	m := make(map[string]tilePlace, len(widgetSpecs))
	for _, w := range widgetSpecs {
		m[w.id] = tilePlace{edge: w.edge, size: float64(w.size)}
	}
	return m
}

// layoutState is the widgets' places and whether each is shown, as sources.
func (h *host) layoutState() map[string]any {
	s := map[string]any{}
	for _, w := range widgetSpecs {
		p := h.place[w.id]
		s["App."+w.name+"Edge"] = p.edge
		s["App."+w.name+"Size"] = p.size
		s["App."+w.name+"Shown"] = true
	}
	return s
}

// widgetDocked is a widget's tile re-docked, or swapped: its new edge, kept.
func (h *host) widgetDocked(id, edge string) error {
	w, ok := widgetOf(id)
	if !ok {
		return fmt.Errorf("no widget %q", id)
	}
	p := h.place[id]
	p.edge = edge
	h.place[id] = p
	return h.p.Set("App."+w.name+"Edge", edge)
}

// widgetResized is a widget's border dragged: its new size, kept.
func (h *host) widgetResized(id string, size float64) error {
	w, ok := widgetOf(id)
	if !ok {
		return fmt.Errorf("no widget %q", id)
	}
	p := h.place[id]
	p.size = size
	h.place[id] = p
	return h.p.Set("App."+w.name+"Size", size)
}

// resetLayout is View › Reset the layout: every widget where it starts, and
// shown.
func (h *host) resetLayout() error {
	h.place = defaultPlaces()
	if err := h.p.SetMany(h.layoutState()); err != nil {
		return err
	}
	for _, w := range widgetSpecs {
		if h.hidden(w.id) {
			_ = h.p.Call(w.id, "show")
		}
	}
	h.refreshDock()
	return nil
}

// hidden reports whether the window of a panel or a widget is hidden in the
// dock: minimized.
func (h *host) hidden(id string) bool {
	if h.p == nil {
		return false
	}
	c, ok := h.p.Find(id)
	if !ok {
		return false
	}
	w, ok := c.(interface{ WindowBehavior() *core.WindowCore })
	return ok && w.WindowBehavior() != nil && w.WindowBehavior().State().Minimized
}

// shown reports whether a widget is on the screen: signed in, and not hidden.
func (h *host) shown(id string) bool { return h.signedIn && !h.hidden(id) }

// panelShown reports whether a panel is open and not hidden.
func (h *host) panelShown(key string) bool {
	s, ok := panelOf(key)
	return ok && h.panelOpen[key] && !h.hidden(s.id)
}

// refreshDock lists the dock again: the widgets, then the open panels; and
// checks each widget's row of the View menu while it is shown.
func (h *host) refreshDock() {
	if h.p == nil {
		return
	}
	var rows []tuidecl.Row
	checks := map[string]any{}
	for _, w := range widgetSpecs {
		hid := h.hidden(w.id)
		rows = append(rows, tuidecl.Row{"key": w.id, "icon": w.icon, "title": h.tr(w.title), "hidden": hid})
		checks["App."+w.name+"Shown"] = !hid
	}
	for _, s := range panelSpecs {
		if h.panelOpen[s.key] {
			rows = append(rows, tuidecl.Row{"key": s.key, "icon": s.icon, "title": h.tr(s.title), "hidden": h.hidden(s.id)})
		}
	}
	h.dock.Reset(rows)
	_ = h.p.SetMany(checks)
}

// goDock is a dock icon's click: a widget shown is hidden, a hidden one shown;
// a panel shown is hidden and the keyboard goes back to the screen, a hidden
// one is shown and takes the keyboard.
func (h *host) goDock(key string) error {
	if w, ok := widgetOf(key); ok {
		return h.toggleWidget(w)
	}
	s, ok := panelOf(key)
	if !ok {
		return fmt.Errorf("no dock entry %q", key)
	}
	if h.panelShown(key) {
		if err := h.p.Call(s.id, "minimize"); err != nil {
			return err
		}
		h.refreshDock()
		return h.panelLeft()
	}
	return h.openPanel(key)
}

// toggleWidget hides a widget that is shown, and shows one that is hidden,
// reading it at once.
func (h *host) toggleWidget(w widgetSpec) error {
	if err := h.p.Call(w.id, "toggle"); err != nil {
		return err
	}
	h.refreshDock()
	if !h.hidden(w.id) {
		h.poll()
	} else {
		h.panelLeft()
	}
	return nil
}

// toggleWidgetNamed is View › a widget's row.
func (h *host) toggleWidgetNamed(id string) error {
	w, ok := widgetOf(id)
	if !ok {
		return fmt.Errorf("no widget %q", id)
	}
	return h.toggleWidget(w)
}

// openPanel shows a panel and gives its view the keyboard: restored when it
// was hidden, opened otherwise.
func (h *host) openPanel(key string) error {
	s, ok := panelOf(key)
	if !ok {
		return fmt.Errorf("no panel %q", key)
	}
	restored := false
	for _, e := range h.minimized.Entries() {
		if e.Key == key {
			restored = e.Restore()
			break
		}
	}
	if !restored {
		if err := h.p.Call(s.id, "open"); err != nil {
			return err
		}
	}
	h.raise(key)
	h.refreshDock()
	return h.p.Call(s.view, "forceActiveFocus")
}

// raise moves key to the end of the panels open: the one the keyboard goes
// back to when another closes.
func (h *host) raise(key string) {
	h.lastPanel = append(slices.DeleteFunc(h.lastPanel, func(k string) bool { return k == key }), key)
}

// panelOpened and panelClosed follow a panel; the dock lists it while it is
// open. Closed, the keyboard goes back to the screen.
func (h *host) panelOpened(key string) error {
	if _, ok := panelOf(key); !ok {
		return fmt.Errorf("no panel %q", key)
	}
	h.panelOpen[key] = true
	h.raise(key)
	h.refreshDock()
	return nil
}

func (h *host) panelClosed(key string) error {
	if _, ok := panelOf(key); !ok {
		return fmt.Errorf("no panel %q", key)
	}
	delete(h.panelOpen, key)
	h.lastPanel = slices.DeleteFunc(h.lastPanel, func(k string) bool { return k == key })
	h.refreshDock()
	return h.panelLeft()
}

// panelChanged is a panel's completed window operation. A hidden panel has
// left the screen, as a closed one has; a move, a resize, a maximize or a
// restore keeps the keyboard where it is.
func (h *host) panelChanged(key, operation string) error {
	h.refreshDock()
	if operation == "minimize" {
		return h.panelLeft()
	}
	return nil
}

// panelLeft gives the keyboard back once a panel has closed or hidden: to the
// panel opened last that is still shown, else to the first widget shown that
// has a view. Posted: the handler runs while the panel is still closing.
func (h *host) panelLeft() error {
	h.p.Post(func() {
		for i := len(h.lastPanel) - 1; i >= 0; i-- {
			if s, ok := panelOf(h.lastPanel[i]); ok && h.panelShown(s.key) && h.p.Call(s.view, "forceActiveFocus") == nil {
				return
			}
		}
		for _, w := range widgetSpecs {
			if w.view != "" && !h.hidden(w.id) && h.p.Call(w.view, "forceActiveFocus") == nil {
				return
			}
		}
	})
	return nil
}

// toggleStatusBar is View › Status bar.
func (h *host) toggleStatusBar() error {
	h.statusShown = !h.statusShown
	_ = h.p.Set("App.statusShown", !h.statusShown) // through the other value: the menu checked it already
	return h.p.Set("App.statusShown", h.statusShown)
}
