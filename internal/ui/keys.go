package ui

import (
	"strings"

	"github.com/yongjohnlee80/golib/tui"
)

// HELP › KEYS AND THE TOOLTIPS — the two texts about what a control does.
//
// Help › Keys is the one place the screen's keys are listed: the screen, its
// panels and its dialogs show none. A button carries its own key, as an access
// key in its label, drawn in the accent colour, and says what it does in its
// tooltip. Both texts are the catalogs', composed here in the UI's language
// and composed again when it changes.
//
// Decision: docs/decisions/ui.md#access-keys-replace-the-help-lines

// keyRow is a key and what it does: the key as it is pressed, the same in
// every language, and the message that says what it does.
type keyRow struct{ keys, what string }

// keySection is the keys of one place: its heading's message, and its rows.
type keySection struct {
	heading string
	rows    []keyRow
}

// keySections are every key of the screen, by where it works.
var keySections = []keySection{
	{"autopanel.key.section.everywhere", []keyRow{
		{"F10, Alt+…", "autopanel.key.everywhere.menus"},
		{"Tab, Shift+Tab", "autopanel.key.everywhere.focus"},
		{"r", "autopanel.key.everywhere.refresh"},
		{"F1", "autopanel.key.everywhere.keys"},
		{"q, Ctrl+C", "autopanel.key.everywhere.quit"},
	}},
	{"autopanel.key.section.widgets", []keyRow{
		{"Enter", "autopanel.key.widgets.open"},
		{"Alt+Left drag", "autopanel.key.widgets.move"},
		{"Alt+Right drag", "autopanel.key.widgets.resize"},
		{"◫ ⇅ ▦ …", "autopanel.key.widgets.dock"},
	}},
	{"autopanel.key.section.panels", []keyRow{
		{"q, Esc", "autopanel.key.panels.close"},
		{"j, k, ↑, ↓", "autopanel.key.panels.move"},
		{"Alt+Left drag", "autopanel.key.panels.drag"},
		{"Alt+Right drag", "autopanel.key.panels.resize"},
	}},
	{"autopanel.key.section.stacks", []keyRow{
		{"a", "autopanel.key.stacks.add"},
		{"p, Enter", "autopanel.key.stacks.apply"},
		{"t", "autopanel.key.stacks.start"},
		{"x", "autopanel.key.stacks.stop"},
		{"e", "autopanel.key.stacks.restart"},
		{"o", "autopanel.key.stacks.logs"},
		{"u", "autopanel.key.stacks.pull"},
		{"s", "autopanel.key.stacks.update"},
		{"r", "autopanel.key.stacks.remove"},
	}},
	{"autopanel.key.section.routes", []keyRow{
		{"a", "autopanel.key.routes.add"},
		{"e, Enter", "autopanel.key.routes.edit"},
		{"r", "autopanel.key.routes.remove"},
		{"m", "autopanel.key.routes.domains"},
	}},
	{"autopanel.key.section.domains", []keyRow{
		{"a", "autopanel.key.domains.add"},
		{"r", "autopanel.key.domains.remove"},
	}},
	{"autopanel.key.section.monitors", []keyRow{
		{"r", "autopanel.key.monitors.reload"},
	}},
	{"autopanel.key.section.browser", []keyRow{
		{"Enter", "autopanel.key.browser.enter"},
		{"Backspace, u", "autopanel.key.browser.up"},
		{"i", "autopanel.key.browser.import"},
	}},
	{"autopanel.key.section.review", []keyRow{
		{"a, s", "autopanel.key.review.go"},
		{"p", "autopanel.key.review.prepare"},
		{"q, Esc", "autopanel.key.review.close"},
	}},
	{"autopanel.key.section.dialogs", []keyRow{
		{"y, n", "autopanel.key.dialogs.answer"},
		{"Enter", "autopanel.key.dialogs.enter"},
		{"Esc", "autopanel.key.dialogs.cancel"},
	}},
	{"autopanel.key.section.terminal", []keyRow{
		{"Ctrl+T", "autopanel.key.terminal.mode"},
		{"Ctrl+Tab", "autopanel.key.terminal.next"},
		{"Ctrl+Shift+Tab", "autopanel.key.terminal.previous"},
		{"F11", "autopanel.key.terminal.maximize"},
	}},
}

// keysText is Help › Keys: each place's heading, then its keys, lined up.
func keysText(w wording) string {
	width := 0
	for _, s := range keySections {
		for _, r := range s.rows {
			width = max(width, tui.StringWidth(r.keys))
		}
	}
	var b strings.Builder
	for i, s := range keySections {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString(w.tr(s.heading) + "\n")
		for _, r := range s.rows {
			b.WriteString("  " + r.keys + strings.Repeat(" ", width-tui.StringWidth(r.keys)+3) + w.tr(r.what) + "\n")
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

// openKeys is Help › Keys, and F1.
func (h *host) openKeys() error {
	if err := h.p.Set("App.keysText", keysText(h)); err != nil {
		return err
	}
	return h.p.Call("keysDialog", "open")
}

// tips are the buttons' tooltips: each source the document binds, and its
// message. A tooltip is plain text in golib, so the host gives it in the UI's
// language.
var tips = map[string]string{
	"App.tipPanelClose":    "autopanel.tip.panel.close",
	"App.tipMonitorReload": "autopanel.tip.panel.reload",
	"App.tipLogsReload":    "autopanel.tip.logs.reload",
	"App.tipStacksAdd":     "autopanel.tip.stacks.add",
	"App.tipStacksApply":   "autopanel.tip.stacks.apply",
	"App.tipStacksStart":   "autopanel.tip.stacks.start",
	"App.tipStacksStop":    "autopanel.tip.stacks.stop",
	"App.tipStacksRestart": "autopanel.tip.stacks.restart",
	"App.tipStacksLogs":    "autopanel.tip.stacks.logs",
	"App.tipStacksPull":    "autopanel.tip.stacks.pull",
	"App.tipStacksUpdate":  "autopanel.tip.stacks.update",
	"App.tipStacksRemove":  "autopanel.tip.stacks.remove",
	"App.tipRoutesAdd":     "autopanel.tip.routes.add",
	"App.tipRoutesEdit":    "autopanel.tip.routes.edit",
	"App.tipRoutesRemove":  "autopanel.tip.routes.remove",
	"App.tipRoutesDomains": "autopanel.tip.routes.domains",
	"App.tipDomainsAdd":    "autopanel.tip.domains.add",
	"App.tipDomainsRemove": "autopanel.tip.domains.remove",
	"App.tipLoginSignIn":   "autopanel.tip.login.signIn",
	"App.tipLoginQuit":     "autopanel.tip.login.quit",
	"App.tipFormDomain":    "autopanel.tip.form.domain",
	"App.tipFormPort":      "autopanel.tip.form.port",
	"App.tipFormSave":      "autopanel.tip.form.save",
	"App.tipPromptOK":      "autopanel.tip.prompt.ok",
	"App.tipConfirmNo":     "autopanel.tip.confirm.no",
	"App.tipConfirmYes":    "autopanel.tip.confirm.yes",
	"App.tipConfirmOther":  "autopanel.tip.confirm.other",
	"App.tipReviewGo":      "autopanel.tip.review.go",
	"App.tipReviewPrepare": "autopanel.tip.review.prepare",
	"App.tipBrowseImport":  "autopanel.tip.browse.import",
	"App.tipBrowseUp":      "autopanel.tip.browse.up",
	"App.tipDialogCancel":  "autopanel.tip.dialog.cancel",
	"App.tipDialogClose":   "autopanel.tip.dialog.close",
}

// tipState is every tooltip in w's words, as sources.
func tipState(w wording) map[string]any {
	s := make(map[string]any, len(tips))
	for name, id := range tips {
		s[name] = w.tr(id)
	}
	return s
}
