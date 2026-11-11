package ui

import (
	"errors"
	"os"
	"os/user"
	"strconv"

	"github.com/yongjohnlee80/golib/tui"
	tuidecl "github.com/yongjohnlee80/golib/tui/decl"
	"github.com/yongjohnlee80/golib/tui/widget/core"
	"github.com/yongjohnlee80/golib/tui/widget/terminal"
)

// THE TERMINAL — Go › Terminal: a floating panel of shells, a tab each, on
// golib's TerminalTabs. The shells run in the panel's own process, on this
// host, as children of it: they are not the daemon's, and no verb starts one.
//
// The panel runs as root (sudo autopanel --ui). A new tab is a login shell of
// the user who ran sudo, so nothing typed there is root's until that user asks
// for it; a root shell is its own row of the tab menu, and its tab says so.
// A panel started by root itself has only root's shell.
//
// A shell keeps running while the panel is hidden or minimized. It ends when
// its program exits, when its tab is closed, or when the panel quits.

// shell is what a new tab runs.
type shell struct {
	label string // the tab's name: the user the shell is
	path  string // the program; "" is the user's own shell ($SHELL, else /bin/sh)
	args  []string
	dir   string   // where it starts; "" is where the panel was started
	env   []string // added to the panel's environment
}

// loginTools start a login shell as another user, given "-l" and a name.
var loginTools = []string{"/usr/sbin/runuser", "/sbin/runuser", "/usr/bin/runuser", "/usr/bin/su", "/bin/su"}

// hostShells are the shells this panel offers: the one + starts, and root's
// when that is another. The user who ran sudo is read from SUDO_UID, which
// sudo sets and only root's own environment could have changed.
func hostShells() (own shell, root *shell) {
	own = shell{label: "shell"}
	if u, err := user.Current(); err == nil {
		own.label, own.dir = u.Username, u.HomeDir
		if u.HomeDir != "" {
			own.env = []string{"HOME=" + u.HomeDir} // sudo may have kept the caller's
		}
	}
	if os.Geteuid() != 0 {
		return own, nil
	}
	uid, err := strconv.Atoi(os.Getenv("SUDO_UID"))
	if err != nil || uid <= 0 {
		return own, nil
	}
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return own, nil
	}
	for _, tool := range loginTools {
		if fi, err := os.Stat(tool); err == nil && fi.Mode().IsRegular() {
			mine := own // root's: the panel's own
			return shell{label: u.Username, path: tool, args: []string{"-l", u.Username}}, &mine
		}
	}
	return own, nil
}

var errNoTerminal = errors.New("ui: the document has no terminal view")

// terminalTabs is the terminal's view. It is looked up each time: a reloaded
// layout has a new one.
func (h *host) terminalTabs() (*terminal.TerminalTabs, error) {
	c, ok := h.p.Find("terminalView")
	if !ok {
		return nil, errNoTerminal
	}
	tabs, ok := tuidecl.TerminalTabsOf(c)
	if !ok {
		return nil, errNoTerminal
	}
	return tabs, nil
}

// toggleTerminal is Go › Terminal: the panel shown, with a shell, or hidden
// with its shells running on. A minimized panel is brought back.
func (h *host) toggleTerminal() error {
	for _, e := range h.minimized.Entries() {
		if e.Key == "terminal" {
			return h.openTerminal()
		}
	}
	if h.terminalShown {
		return h.p.Call("terminalPanel", "close")
	}
	return h.openTerminal()
}

// openTerminal shows the panel and gives a shell the keyboard: the one that
// had it, or a new one when none is left.
func (h *host) openTerminal() error {
	if err := h.openPanel("terminal", "terminalPanel", "terminalView"); err != nil {
		return err
	}
	tabs, err := h.terminalTabs()
	if err != nil {
		return err
	}
	tabs.SetMenu(h.shellMenu)
	for _, t := range tabs.Tabs() {
		if !t.Running && !t.Closing { // one that never started
			_ = tabs.ForceRemove(t.ID)
		}
	}
	if len(tabs.Tabs()) == 0 {
		h.startShell(h.ownShell)
		return nil
	}
	return tabs.Select(tabs.Active())
}

// terminalOpened and terminalClosed follow the panel: Go › Terminal is
// checked while it is open. Closed, the keyboard goes back to the overview.
func (h *host) terminalOpened() error {
	h.terminalShown = true
	return h.p.Set("App.terminalShown", true)
}

func (h *host) terminalClosed() error {
	h.terminalShown = false
	if err := h.p.Set("App.terminalShown", false); err != nil {
		return err
	}
	return h.panelLeft()
}

// tabLabel names a new tab after its user: "root", then "root 2", the first
// not on the strip.
func tabLabel(tabs *terminal.TerminalTabs, name string) string {
	for n := 1; ; n++ {
		label := name
		if n > 1 {
			label += " " + strconv.Itoa(n)
		}
		taken := false
		for _, t := range tabs.Tabs() {
			taken = taken || t.Label == label
		}
		if !taken {
			return label
		}
	}
}

// startShell adds a tab running sh, starts it and gives it the keyboard. One
// that cannot start is said; its tab is dropped at the panel's next opening.
func (h *host) startShell(sh shell) {
	tabs, err := h.terminalTabs()
	if err != nil {
		h.say(h.trf("autopanel.notice.shellFailed", err.Error()))
		return
	}
	var id terminal.TerminalTabID
	opts := []terminal.TerminalOption{terminal.WithCommand(sh.path, sh.args...), terminal.WithDir(sh.dir),
		terminal.WithEnv(sh.env...), terminal.WithOnExit(func(code int) { h.shellExited(id, code) })}
	if id, err = tabs.Add(tabLabel(tabs, sh.label), opts...); err != nil {
		h.say(h.trf("autopanel.notice.shellFailed", err.Error()))
		return
	}
	if err := tabs.Start(id); err != nil {
		h.say(h.trf("autopanel.notice.shellFailed", err.Error()))
	}
	_ = tabs.Select(id)
}

// newShell is the strip's +: another shell of the user's own.
func (h *host) newShell() error {
	h.startShell(h.ownShell)
	return nil
}

// afterShell follows a tab that has gone: the keyboard to the shell now in
// front, or the panel closed when none is left.
func (h *host) afterShell(tabs *terminal.TerminalTabs) {
	if len(tabs.Tabs()) > 0 {
		_ = tabs.Select(tabs.Active())
		return
	}
	if h.terminalShown {
		_ = h.p.Call("terminalPanel", "close")
	}
}

// shellExited is a shell gone by itself (exit, Ctrl+D): its tab closes. A
// status that is not 0 is said, since it may be an error.
func (h *host) shellExited(id terminal.TerminalTabID, code int) {
	if code != 0 {
		h.say(h.trf("autopanel.notice.shellExited", code))
	}
	tabs, err := h.terminalTabs()
	if err != nil {
		return
	}
	if _, err := tabs.Remove(id); err != nil {
		return // already closing, or a tab of a layout reloaded since
	}
	h.afterShell(tabs)
}

// closeShell is Close on a tab's menu: the shell hung up, its tab closed.
func (h *host) closeShell(id terminal.TerminalTabID) {
	tabs, err := h.terminalTabs()
	if err != nil || id == "" {
		return
	}
	if _, err := tabs.Remove(id); err != nil {
		h.say(h.trf("autopanel.notice.error", err.Error()))
		return
	}
	h.afterShell(tabs)
}

// stopShells is the strip's x: every shell hung up and the panel closed,
// asked first while any of them runs.
func (h *host) stopShells() error {
	tabs, err := h.terminalTabs()
	if err != nil {
		return err
	}
	running := 0
	for _, t := range tabs.Tabs() {
		if t.Running && !t.Closing {
			running++
		}
	}
	if running == 0 {
		return h.stopShellsNow()
	}
	return h.ask("autopanel.terminal.confirmTitle", h.trf("autopanel.terminal.confirmStop", running), h.stopShellsNow)
}

func (h *host) stopShellsNow() error {
	tabs, err := h.terminalTabs()
	if err != nil {
		return err
	}
	for _, t := range tabs.Tabs() {
		if _, err := tabs.Remove(t.ID); err != nil {
			_ = tabs.ForceRemove(t.ID)
		}
	}
	if h.terminalShown {
		return h.p.Call("terminalPanel", "close")
	}
	return nil
}

// cycleShell moves to the next shell (step 1) or the one before (-1).
func (h *host) cycleShell(step int) error {
	tabs, err := h.terminalTabs()
	if err != nil {
		return err
	}
	all := tabs.Tabs()
	for i, t := range all {
		if t.ID == tabs.Active() {
			return tabs.Select(all[(i+step+len(all))%len(all)].ID)
		}
	}
	return nil
}

// shellMenu is a tab's menu (≡, or a right click on the strip): each shell to
// go to, then New, New root shell where root's is another, Close, Maximize
// and Hide. id is the tab the menu was opened for, "" with none. The rows are
// in the UI's language now; an & marks a row's key.
func (h *host) shellMenu(id terminal.TerminalTabID) []core.MenuItemModel {
	tabs, err := h.terminalTabs()
	if err != nil {
		return nil
	}
	row := func(rid, msg string, run func(terminal.TerminalTabID)) core.MenuItemModel {
		text, key, at := tui.ParseMnemonic(h.tr(msg))
		r := core.NewCommand(core.ItemID(rid), text, terminal.TerminalTabsMenuAction{ID: tui.ActionID(rid), Run: run})
		r.Hotkey, r.HotkeyIdx = key, at
		return r
	}
	var rows []core.MenuItemModel
	for i, t := range tabs.Tabs() {
		target, rid := t.ID, "terminal.goto."+string(t.ID)
		rows = append(rows, core.NewCommand(core.ItemID(rid), strconv.Itoa(i+1)+". "+t.Label,
			terminal.TerminalTabsMenuAction{ID: tui.ActionID(rid), Run: func(terminal.TerminalTabID) { _ = tabs.Select(target) }}))
	}
	if len(rows) > 0 {
		rows = append(rows, core.NewSeparator("terminal.shells"))
	}
	rows = append(rows, row("terminal.new", "autopanel.terminal.menu.new", func(terminal.TerminalTabID) { h.startShell(h.ownShell) }))
	if h.rootShell != nil {
		rows = append(rows, row("terminal.newRoot", "autopanel.terminal.menu.newRoot", func(terminal.TerminalTabID) { h.startShell(*h.rootShell) }))
	}
	closing := row("terminal.close", "autopanel.terminal.menu.close", h.closeShell)
	closing.Enabled = id != ""
	return append(rows, closing, core.NewSeparator("terminal.panel"),
		row("terminal.maximize", "autopanel.terminal.menu.maximize", func(terminal.TerminalTabID) { _ = h.p.Call("terminalPanel", "toggleMaximize") }),
		row("terminal.hide", "autopanel.terminal.menu.hide", func(terminal.TerminalTabID) { _ = h.p.Call("terminalPanel", "close") }))
}
