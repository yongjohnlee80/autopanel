//go:build linux

package ui

import (
	"context"
	"os"
	"strings"
	"testing"

	tuidecl "github.com/yongjohnlee80/golib/tui/decl"
	"github.com/yongjohnlee80/golib/tui/decl/decltest"
	"github.com/yongjohnlee80/golib/tui/widget/terminal"
)

// startTerminalHost runs the panel signed in, with /bin/sh as the shell + starts,
// in an empty home, under a prompt the test can wait for.
func startTerminalHost(t *testing.T) (*host, *decltest.Screen) {
	t.Helper()
	t.Setenv("SHELL", "/bin/sh")
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PS1", "$ ")
	t.Setenv("ENV", "")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	h := newHost(ctx, newFakeClient(), "v0.1.0")
	h.ownShell, h.rootShell = shell{label: "tester"}, nil
	h.brw.start = "/home/ada"
	s := decltest.RunWith(t, 120, 30, func(p *tuidecl.Program) error { h.attach(p); return nil }, h.options(nil)...)
	signIn(t, s)
	s.WaitForText(t, "CA LE staging")
	return h, s
}

// shellTabs are the terminal's tabs, read on the loop.
func shellTabs(t *testing.T, h *host) []terminal.TerminalTab {
	t.Helper()
	return onLoop(h, func() []terminal.TerminalTab {
		tabs, err := h.terminalTabs()
		if err != nil {
			t.Error(err)
			return nil
		}
		return tabs.Tabs()
	})
}

func labels(tabs []terminal.TerminalTab) string {
	var out []string
	for _, tab := range tabs {
		out = append(out, tab.Label)
	}
	return strings.Join(out, ",")
}

// waitTabs waits until the strip holds exactly the tabs named.
func waitTabs(t *testing.T, h *host, s *decltest.Screen, want string) {
	t.Helper()
	s.WaitFor(t, "the tabs to be "+want, func(string) bool { return labels(shellTabs(t, h)) == want })
}

// TestTheTerminalRunsShellsInTabs: Go › Terminal opens a shell that takes the
// keyboard; + adds another, each tab its own program; a shell that exits
// closes its tab and hands the keyboard to the next; hiding the panel keeps
// the shells; the tab menu offers root's shell only where it is another; x
// asks before it stops running shells; and the last shell gone closes the
// panel.
func TestTheTerminalRunsShellsInTabs(t *testing.T) {
	h, s := startTerminalHost(t)

	s.Keys(t, decltest.Alt('g'))
	s.WaitForText(t, "Terminal")
	s.Keys(t, decltest.Rune('t'))
	waitTabs(t, h, s, "tester")
	s.WaitForText(t, "$ ")
	if !onLoop(h, func() bool { return h.terminalShown }) {
		t.Fatal("Go › Terminal is not checked with the panel open")
	}
	s.Keys(t, decltest.Type("echo one-$((40+1))\r")...)
	s.WaitForText(t, "one-41")

	// q, r and Ctrl+C typed into a shell are the shell's, not the panel's.
	s.Keys(t, decltest.Type("echo q-r-$((50+1))\r")...)
	s.WaitForText(t, "q-r-51")

	run(t, h, h.newShell)
	waitTabs(t, h, s, "tester,tester 2")
	s.WaitFor(t, "the second shell to be in front", func(sc string) bool { return !strings.Contains(sc, "one-41") })
	s.Keys(t, decltest.Type("echo two-$((40+2))\r")...)
	s.WaitForText(t, "two-42")

	run(t, h, func() error { return h.cycleShell(-1) })
	s.WaitForText(t, "one-41")
	s.Keys(t, decltest.Type("exit\r")...)
	waitTabs(t, h, s, "tester 2")
	s.WaitForText(t, "two-42")
	s.Keys(t, decltest.Type("echo back-$((40+3))\r")...) // the keyboard went to the shell left
	s.WaitForText(t, "back-43")
	waitTabs(t, h, s, "tester 2") // and to nothing else: no key of that line started a shell

	// Hidden, the shell runs on; shown again, it is as it was.
	run(t, h, h.toggleTerminal)
	s.WaitFor(t, "the terminal to hide", func(sc string) bool { return !strings.Contains(sc, "back-43") })
	if tabs := shellTabs(t, h); len(tabs) != 1 || !tabs[0].Running || onLoop(h, func() bool { return h.terminalShown }) {
		t.Fatalf("hidden, the tabs are %+v", tabs)
	}
	run(t, h, h.toggleTerminal)
	s.WaitForText(t, "back-43")
	s.Keys(t, decltest.Type("echo again-$((40+4))\r")...)
	s.WaitForText(t, "again-44")

	// The tab's menu: root's shell is offered only where it is another.
	menu := func() string {
		return onLoop(h, func() string {
			var out []string
			for _, r := range h.shellMenu(shellTabsNow(h)[0].ID) {
				out = append(out, r.Label)
			}
			return strings.Join(out, "|")
		})
	}
	if got := menu(); !strings.Contains(got, "1. tester 2") || !strings.Contains(got, "New shell") ||
		!strings.Contains(got, "Close this shell") || !strings.Contains(got, "Hide") || strings.Contains(got, "root") {
		t.Fatalf("the tab menu = %s", got)
	}
	onLoop(h, func() bool { h.rootShell = &shell{label: "root"}; return true })
	if got := menu(); !strings.Contains(got, "New root shell") {
		t.Fatalf("with another root shell the tab menu = %s", got)
	}
	onLoop(h, func() bool { h.startShell(*h.rootShell); return true })
	waitTabs(t, h, s, "tester 2,root")

	// x asks while a shell runs; No leaves them, Yes stops them and closes.
	run(t, h, h.stopShells)
	s.WaitForText(t, "Stop the running shells (2)")
	s.Keys(t, decltest.Rune('n'))
	s.WaitFor(t, "the question to close", func(sc string) bool { return !strings.Contains(sc, "Stop the running shells") })
	waitTabs(t, h, s, "tester 2,root")
	run(t, h, h.stopShells)
	s.WaitForText(t, "Stop the running shells (2)")
	s.Keys(t, decltest.Rune('y'))
	waitTabs(t, h, s, "")
	s.WaitFor(t, "the terminal to close", func(string) bool { return !onLoop(h, func() bool { return h.terminalShown }) })

	// A shell that ends in error says so, and the last one gone closes the panel.
	run(t, h, h.toggleTerminal)
	waitTabs(t, h, s, "tester")
	s.WaitForText(t, "$ ")
	s.Keys(t, decltest.Type("exit 4\r")...)
	s.WaitForText(t, "The shell exited with status 4")
	waitTabs(t, h, s, "")
	s.WaitFor(t, "the terminal to close", func(string) bool { return !onLoop(h, func() bool { return h.terminalShown }) })
}

// shellTabsNow is the tabs, for a caller already on the loop.
func shellTabsNow(h *host) []terminal.TerminalTab {
	tabs, err := h.terminalTabs()
	if err != nil {
		return nil
	}
	return tabs.Tabs()
}

// TestAThemeChangeKeepsTheShells: the layout is reloaded for a theme, and a
// running shell is still there after, with what it showed.
func TestAThemeChangeKeepsTheShells(t *testing.T) {
	h, s := startTerminalHost(t)
	run(t, h, h.toggleTerminal)
	waitTabs(t, h, s, "tester")
	s.WaitForText(t, "$ ")
	s.Keys(t, decltest.Type("echo kept-$((40+5))\r")...)
	s.WaitForText(t, "kept-45")
	run(t, h, func() error { return h.useTheme("nord") })
	s.WaitForText(t, "nord")
	if tabs := shellTabs(t, h); len(tabs) != 1 || !tabs[0].Running {
		t.Fatalf("after a theme change the tabs are %+v", tabs)
	}
	s.Keys(t, decltest.Type("echo after-$((40+6))\r")...)
	s.WaitForText(t, "after-46")
}

// TestANewTabIsTheShellOfWhoRanSudo: a panel root runs under sudo starts a
// login shell of the user who ran sudo, and offers root's as another; a panel
// run without sudo, or not as root, has its own shell only.
func TestANewTabIsTheShellOfWhoRanSudo(t *testing.T) {
	t.Setenv("SUDO_UID", "")
	if own, root := hostShells(); root != nil || own.path != "" {
		t.Fatalf("without sudo: own %+v, root %+v; want the panel's own shell only", own, root)
	}
	t.Setenv("SUDO_UID", "0")
	if _, root := hostShells(); root != nil {
		t.Fatal("sudo run by root itself offered a second shell")
	}
	t.Setenv("SUDO_UID", "not a number")
	if _, root := hostShells(); root != nil {
		t.Fatal("a SUDO_UID that is no number offered a second shell")
	}
	if os.Geteuid() != 0 {
		t.Setenv("SUDO_UID", "65534")
		if own, root := hostShells(); root != nil || own.path != "" {
			t.Fatalf("not root: own %+v, root %+v; want the panel's own shell only", own, root)
		}
		return
	}
	defer func(tools []string) { loginTools = tools }(loginTools)
	loginTools = []string{"/nonexistent/runuser", "/bin/sh"} // the first there is the one used
	t.Setenv("SUDO_UID", "65534")
	own, root := hostShells()
	if root == nil || root.label != "root" || root.path != "" {
		t.Fatalf("under sudo, root's shell = %+v", root)
	}
	if own.path != "/bin/sh" || len(own.args) != 2 || own.args[0] != "-l" || own.args[1] != own.label || own.label == "root" {
		t.Fatalf("under sudo, + starts %+v; want a login shell of the user who ran sudo", own)
	}
	loginTools = []string{"/nonexistent/runuser"}
	if own, root := hostShells(); root != nil || own.label != "root" {
		t.Fatalf("with no tool to log a user in: own %+v, root %+v; want root's shell only", own, root)
	}
}
