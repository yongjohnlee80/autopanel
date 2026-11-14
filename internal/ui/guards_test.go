package ui

import (
	"io/fs"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// GUARDS — what the screen's design rests on, checked on the QML as shipped
// and on the screens as drawn (docs/decisions/ui.md):
//
//   - no line of help: no key list under a panel or a dialog, no hints row,
//     no Dialog helpText; Help › Keys is the one place keys are listed;
//   - every button carries an access key and a tooltip;
//   - every panel is golib's Panel, every widget a TilePanel;
//   - no panel's key is h, j, k or l, which move its list.

// qmlSources are the QML files the package ships, by name.
func qmlSources(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := fs.WalkDir(qmlFiles, "qml", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".qml") {
			return err
		}
		b, err := qmlFiles.ReadFile(p)
		out[p] = string(b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// blocks are the bodies of every `Type {` block in src, comments dropped.
func blocks(src, typ string) []string {
	var lines []string
	for _, l := range strings.Split(src, "\n") {
		if i := strings.Index(l, "//"); i >= 0 && !strings.Contains(l[:i], `"`) {
			l = l[:i]
		}
		lines = append(lines, l)
	}
	src = strings.Join(lines, "\n")
	re := regexp.MustCompile(`(^|[^A-Za-z.])` + typ + `\s*\{`)
	var out []string
	for _, m := range re.FindAllStringIndex(src, -1) {
		depth, start := 0, m[1]-1
		for i := start; i < len(src); i++ {
			switch src[i] {
			case '{':
				depth++
			case '}':
				depth--
			}
			if depth == 0 {
				out = append(out, src[start+1:i])
				break
			}
		}
	}
	return out
}

// keyHint is a line that lists keys: two or more "key what" pairs apart by
// a middle dot, as "a add · e edit · q close".
var keyHint = regexp.MustCompile(`(^|[\s│(])(?:[a-zA-Z]|F\d{1,2}|Esc|Enter|Tab|Ctrl\+\S+|Alt\+\S+)(?:/\S+)? [a-z][a-z ,'-]{1,30} · (?:[a-zA-Z]|F\d{1,2}|Esc|Enter|Tab|Ctrl\+\S+|Alt\+\S+)(?:/\S+)? [a-z]`)

// oldHints are the lines of help the screen had before; none is ever back.
var oldHints = []string{
	"Menus: Alt and a menu's letter", "r refresh · q quit", "Tab: next field · Enter: OK", "a add · e/Enter edit",
	"r read again · q close", "a add · p review and apply", "Ctrl+T scroll and copy", "Enter reviews the selected folder",
}

// TestKeyHintFindsALineOfKeys: the guard's pattern finds the old lines of
// help, and leaves what the screen shows now.
func TestKeyHintFindsALineOfKeys(t *testing.T) {
	for _, line := range []string{"a add · e/Enter edit · d delete · q close", "r read again · q close · Alt+drag moves",
		"│a add · p review and apply · u pull images│", "Menus: Alt and a menu's letter, or F10 · r refresh · q quit"} {
		if !keyHint.MatchString(line) {
			t.Errorf("the pattern misses %q", line)
		}
	}
	for _, line := range []string{"v0.1.0 · CA LE staging · 2 routes · up 1m0s", "0.50 · 0.25 · 0.10", "Routes · 2 · read at 10:00:01",
		"Definition 3f2a9c41d07b · files: 2 · containers: 1", "web*  deployed · source changed", "apply stopped at: pull · source missing"} {
		if keyHint.MatchString(line) {
			t.Errorf("the pattern takes %q for a line of keys", line)
		}
	}
}

// TestNoHelpTextInTheSource: no QML file has a Dialog's helpText or a hints
// row, and no message is a line of help.
func TestNoHelpTextInTheSource(t *testing.T) {
	for name, src := range qmlSources(t) {
		for _, banned := range []string{"helpText", "WindowTaskbar", ".hints", ".help\""} {
			if strings.Contains(src, banned) {
				t.Errorf("%s has %s", name, banned)
			}
		}
	}
	for _, id := range englishCatalog().IDs("en") {
		if parts := strings.Split(id, "."); len(parts) == 4 && (parts[2] == "help" && parts[1] != "menu" || strings.Contains(id, "hint")) {
			t.Errorf("the catalog has %s, a line of help", id)
		}
		text := englishText(id)
		if strings.HasPrefix(id, "autopanel.key.") {
			continue // Help › Keys: the one place keys are listed
		}
		if keyHint.MatchString(text) {
			t.Errorf("%s lists keys: %q", id, text)
		}
		for _, old := range oldHints {
			if strings.Contains(text, old) {
				t.Errorf("%s is an old line of help: %q", id, text)
			}
		}
	}
}

// TestNoHelpLineOnAnyScreen walks the main screen, every panel and every
// dialog, and fails on any line that lists keys. Help › Keys alone may.
func TestNoHelpLineOnAnyScreen(t *testing.T) {
	f := withStacks()
	h, s := startHost(t, f)
	s.WaitForText(t, "42% of 4 CPUs")
	check := func(what string) {
		t.Helper()
		sc := s.String()
		for i, line := range strings.Split(sc, "\n") {
			if keyHint.MatchString(line) {
				t.Errorf("%s: line %d lists keys: %q\n%s", what, i, line, sc)
			}
		}
		for _, old := range oldHints {
			if strings.Contains(sc, old) {
				t.Errorf("%s shows %q", what, old)
			}
		}
	}
	check("the main screen")
	for _, p := range panelSpecs {
		key := p.key
		switch key {
		case "stackLogs":
			run(t, h, func() error { h.loadStacks(); return nil })
			s.WaitFor(t, "the stacks read", func(string) bool { return onLoop(h, func() bool { return len(h.stk.rows) > 0 }) })
			run(t, h, func() error { return h.openLogs(0) })
		case "terminal":
			continue // a shell's own screen: the terminal test walks it
		default:
			run(t, h, func() error {
				if monitorPanels[key] {
					return h.openMonitor(key)
				}
				return h.openPanel(key)
			})
		}
		s.WaitForText(t, englishText(p.title))
		s.WaitForText(t, "Close (q)")
		check("the " + key + " panel")
		run(t, h, func() error { return h.closePanel(key) })
		gone(t, s, "Close (q)")
	}
	dialogs := []struct {
		name, title string
		open        func() error
	}{
		{"the route form", "Add route", h.add},
		{"the browser", "Add a stack: choose its folder", h.addStack},
		{"the review", "Apply stack web: review", func() error { h.checkStack("web", reviewApply, false); return nil }},
		{"the prompt", "Add a domain", h.addDomain},
		{"the confirmation", "Remove domain", func() error { return h.removeDomain(0) }},
		{"About", "About AutoPanel", func() error { return h.p.Call("aboutDialog", "open") }},
	}
	for _, d := range dialogs {
		run(t, h, d.open)
		s.WaitForText(t, d.title)
		check(d.name)
		s.Keys(t, escape)
		gone(t, s, d.title)
	}
}

// TestEveryButtonHasAnAccessKeyAndATooltip: each Button in the QML has a
// toolTipText, and its text marks a key: a message whose English has an &,
// or a source the host fills from such messages. The dock's icons, flat
// buttons, are the one exception: an icon has no letter.
func TestEveryButtonHasAnAccessKeyAndATooltip(t *testing.T) {
	marked := func(id string) bool { return strings.Contains(englishText(id), "&") }
	bySource := map[string][]string{ // the host's text, and the messages it is
		"App.reviewGo":     {"autopanel.button.review.add", "autopanel.button.review.apply", "autopanel.button.review.start"},
		"App.confirmOther": {"autopanel.button.confirm.purge"},
	}
	textRe := regexp.MustCompile(`text:\s*(qsTrId\("([^"]+)"\)|App\.[A-Za-z]+|model\.[a-z]+)`)
	n := 0
	for name, src := range qmlSources(t) {
		for _, b := range blocks(src, "Button") {
			n++
			if regexp.MustCompile(`flat:\s*true`).MatchString(b) {
				continue
			}
			if !strings.Contains(b, "toolTipText:") {
				t.Errorf("%s: a Button has no toolTipText: %s", name, strings.TrimSpace(b))
			}
			m := textRe.FindStringSubmatch(b)
			switch {
			case m == nil:
				t.Errorf("%s: a Button has no text: %s", name, b)
			case m[2] != "":
				if !marked(m[2]) {
					t.Errorf("%s: %s marks no access key: %q", name, m[2], englishText(m[2]))
				}
			default:
				ids, ok := bySource[m[1]]
				if !ok {
					t.Errorf("%s: a Button's text is %s, which no test knows the messages of", name, m[1])
				}
				for _, id := range ids {
					if !marked(id) {
						t.Errorf("%s: %s marks no access key", name, id)
					}
				}
			}
		}
	}
	if n < 40 {
		t.Fatalf("found %d Buttons; the walk is broken", n)
	}
}

// TestEveryTooltipIsTranslated: each tooltip a Button binds is a source the
// host fills from a message, and each such source is bound.
func TestEveryTooltipIsTranslated(t *testing.T) {
	bound := map[string]bool{}
	for _, src := range qmlSources(t) {
		for _, m := range regexp.MustCompile(`toolTipText:\s*(App\.tip[A-Za-z]+)`).FindAllStringSubmatch(src, -1) {
			bound[m[1]] = true
		}
	}
	for name := range bound {
		if _, ok := tips[name]; !ok {
			t.Errorf("%s is bound and filled by no message", name)
		}
	}
	for name, id := range tips {
		if !bound[name] {
			t.Errorf("%s (%s) is bound by no Button", name, id)
		}
		if englishText(id) == id {
			t.Errorf("%s has no message %s", name, id)
		}
	}
}

// TestEveryPanelIsAPanel: every panel the menus open is golib's Panel, every
// widget a TilePanel; nothing is a Drawer of AutoPanel's own.
func TestEveryPanelIsAPanel(t *testing.T) {
	src := qmlSources(t)["qml/Main.qml"]
	for _, banned := range []string{"Drawer {", "FloatPanel", "WindowButtons", "import autopanel.panels"} {
		if strings.Contains(src, banned) {
			t.Errorf("Main.qml has %s", banned)
		}
	}
	panels := blocks(src, "Panel")
	for _, p := range panelSpecs {
		if !slices.ContainsFunc(panels, func(b string) bool { return regexp.MustCompile(`\bid:\s*` + p.id + `\b`).MatchString(b) }) {
			t.Errorf("the %s panel (%s) is not a Panel", p.key, p.id)
		}
	}
	tiles := blocks(src, "TilePanel")
	for _, w := range widgetSpecs {
		if !slices.ContainsFunc(tiles, func(b string) bool { return regexp.MustCompile(`\bid:\s*` + w.id + `\b`).MatchString(b) }) {
			t.Errorf("the %s widget is not a TilePanel", w.id)
		}
	}
	if len(panels) != len(panelSpecs) || len(tiles) != len(widgetSpecs) {
		t.Errorf("%d Panels and %d TilePanels; the host knows %d and %d", len(panels), len(tiles), len(panelSpecs), len(widgetSpecs))
	}
}

// TestNoPanelKeyMovesAList: a panel's keys are never h, j, k or l: its list
// moves by them.
func TestNoPanelKeyMovesAList(t *testing.T) {
	src := qmlSources(t)["qml/Main.qml"]
	seq := regexp.MustCompile(`Shortcut\s*\{\s*sequence:\s*"([^"]+)"`)
	for _, b := range blocks(src, "Panel") {
		for _, m := range seq.FindAllStringSubmatch(b, -1) {
			switch m[1] {
			case "h", "j", "k", "l", "H", "J", "K", "L":
				t.Errorf("a panel's key is %q", m[1])
			}
		}
	}
}

// TestAButtonsKeyIsItsPanelsKey: in a panel, each button's access key is one
// of the panel's Shortcuts, so the letter on the button is the key that
// presses it (a panel is no Dialog, which would press it by itself).
func TestAButtonsKeyIsItsPanelsKey(t *testing.T) {
	src := qmlSources(t)["qml/Main.qml"]
	seq := regexp.MustCompile(`Shortcut\s*\{\s*sequence:\s*"([^"]+)"`)
	text := regexp.MustCompile(`text:\s*qsTrId\("([^"]+)"\)`)
	for _, b := range blocks(src, "Panel") {
		keys := map[string]bool{"q": true} // closeOnQ
		for _, m := range seq.FindAllStringSubmatch(b, -1) {
			keys[strings.ToLower(m[1])] = true
		}
		for _, btn := range blocks(b, "Button") {
			m := text.FindStringSubmatch(btn)
			if m == nil {
				continue
			}
			en := englishText(m[1])
			if i := strings.Index(en, "&"); i >= 0 && i+1 < len(en) && !keys[strings.ToLower(en[i+1:i+2])] {
				t.Errorf("%q marks %q, which is no key of its panel", en, en[i+1:i+2])
			}
		}
	}
}

// TestALanguageSwitchLeavesNoEnglish: in Korean, no message of the panel's
// on the main screen is left in English.
func TestALanguageSwitchLeavesNoEnglish(t *testing.T) {
	f := withStacks()
	h, s := startHost(t, f)
	s.WaitForText(t, "42% of 4 CPUs")
	run(t, h, func() error { return h.setLanguage("ko_KR") })
	s.WaitFor(t, "Korean", func(string) bool { return onLoop(h, func() string { return h.language }) == "ko_KR" })
	gone(t, s, "42% of 4 CPUs")
	sc := s.String()
	for _, en := range []string{"Host", "Network", "Traffic", "Certificates", "Activity", "Memory", "Uptime", "Since the gate started",
		"Issuer:", "Challenge:", "System", "View", "of 4 CPUs"} {
		if strings.Contains(sc, en) {
			t.Errorf("Korean shows %q:\n%s", en, sc)
		}
	}
}
