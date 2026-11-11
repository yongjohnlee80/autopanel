package ui

import (
	"context"
	"regexp"
	"slices"

	tuidecl "github.com/yongjohnlee80/golib/tui/decl"
	"github.com/yongjohnlee80/golib/tui/decl/themes"
)

// THEMES — System › Theme: every theme golib ships.
//
// A theme is chosen by one line of Main.qml, its import
// (`import autopanel.theme.dark 1.0`), so switching theme is that line,
// rewritten, and the layout reloaded. The choice is kept in AutoPanel's store
// (the Client's preferences), so the panel opens in it next time.

// defaultTheme is the theme Main.qml imports as shipped, and the one a panel
// opens in until one is chosen.
const defaultTheme = "dark"

var themeImport = regexp.MustCompile(`(?m)^import autopanel\.theme\.([a-z][a-z0-9_]*) ` + regexp.QuoteMeta(moduleVersion))

// isTheme reports a theme golib ships.
func isTheme(name string) bool { return slices.Contains(themes.Names(), name) }

// withTheme is the layout importing the named theme.
func withTheme(layout []byte, name string) []byte {
	return themeImport.ReplaceAll(layout, []byte("import autopanel.theme."+name+" "+moduleVersion))
}

// themeRows are System › Theme's rows: golib's themes in its menu order, with
// its words and access keys, the one on screen checked.
func themeRows(current string) []tuidecl.Row {
	labels := themes.MenuLabels()
	rows := make([]tuidecl.Row, 0, len(labels))
	for _, l := range labels {
		rows = append(rows, tuidecl.Row{"key": l.Name, "label": l.Text, "checked": l.Name == current})
	}
	return rows
}

// showTheme puts the named theme on screen. It reloads the layout, so it runs
// after the handler that asked: a menu row's signal is still being emitted
// then, and the engine reconciles only between emissions.
func (h *host) showTheme(name string, then func(error)) {
	h.p.Post(func() {
		_, err := h.p.Reload(withTheme(h.layout, name))
		if err == nil {
			h.theme = name
		}
		h.themes.Reset(themeRows(h.theme))
		if then != nil {
			then(err)
		}
	})
}

// useTheme is System › Theme's row: the named theme, shown and kept.
func (h *host) useTheme(name string) error {
	if !isTheme(name) {
		h.say(h.trf("autopanel.notice.noTheme", name))
		h.themes.Reset(themeRows(h.theme))
		return nil
	}
	h.showTheme(name, func(err error) {
		if err != nil {
			h.say(h.trf("autopanel.notice.error", err.Error()))
			return
		}
		h.say(h.trf("autopanel.notice.theme", name))
		h.keepPrefs(Prefs{Theme: name})
	})
	return nil
}

// keepPrefs keeps a preference in AutoPanel's store, off the loop. A failure
// is said: the choice is on screen, but the next panel opens without it.
func (h *host) keepPrefs(p Prefs) {
	h.background(func(ctx context.Context) error { return h.client.SetPrefs(ctx, p) }, func(err error) {
		if err != nil {
			h.say(h.trf("autopanel.notice.notKept", err.Error()))
		}
	})
}

// loadPrefs reads the kept preferences and shows them: the theme and the
// language the panel was last given. One the store holds and this build does
// not offer is left as it is.
func (h *host) loadPrefs() {
	var p Prefs
	h.background(func(ctx context.Context) error {
		var err error
		p, err = h.client.Prefs(ctx)
		return err
	}, func(err error) {
		if err != nil {
			return // the defaults stay; the status line already says when the daemon does not answer
		}
		if slices.Contains(languages, p.Language) {
			h.showLanguage(p.Language)
		}
		if isTheme(p.Theme) && p.Theme != h.theme {
			h.showTheme(p.Theme, nil)
		}
	})
}
