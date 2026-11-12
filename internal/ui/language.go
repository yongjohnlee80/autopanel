package ui

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"sync"

	"github.com/yongjohnlee80/golib/tui"
	"github.com/yongjohnlee80/golib/tui/i18n"
)

// LANGUAGES — System › Language: the panel in six languages, on golib's
// localization. AutoPanel's catalogs (qml/i18n/autopanel_<tag>.xml) are layered
// over golib's; a QML label's qsTrId and a Go source's tui.Msg are resolved by
// golib in the App's language. A switch relabels everything in one frame; the
// text this package composes in Go (the status line, the overview, the
// panels' rows) is composed again (languageChanged).

// languages are the languages the panel ships, golib's tags, English first.
var languages = []string{"en", "ko_KR", "ja_JP", "zh_CN", "es", "pt_BR"}

const defaultLanguage = "en"

// languageChecks are System › Language's checks: App.language_<tag>, the one
// in use true.
func languageChecks(tag string) map[string]any {
	m := make(map[string]any, len(languages))
	for _, l := range languages {
		m["App.language_"+l] = l == tag
	}
	return m
}

// showLanguage puts the UI in tag, in one frame. On the loop.
func (h *host) showLanguage(tag string) {
	if tag != h.language {
		h.language = tag
		h.p.App().ApplyLanguage(tag)
		h.languageChanged()
	}
	// through false first, as the certificate checks go: the menu checked the
	// row chosen before this ran
	off := languageChecks("")
	_ = h.p.SetMany(off)
	_ = h.p.SetMany(languageChecks(h.language))
}

// setLanguage is System › Language's row: tag, shown and kept.
func (h *host) setLanguage(tag string) error {
	if !slices.Contains(languages, tag) {
		h.say(h.trf("autopanel.notice.noLanguage", strconv.Quote(tag)))
		h.showLanguage(h.language)
		return nil
	}
	h.showLanguage(tag)
	h.keepPrefs(Prefs{Language: tag})
	return nil
}

// languageChanged composes again the text this package composes in Go and
// keeps on screen: the status line, the overview and About, and the System
// panels' rows, and the services'.
func (h *host) languageChanged() {
	if h.status != nil {
		h.setStatus(*h.status)
	}
	h.mon.render(h)
	h.renderServices()
	_ = h.p.Set("App.terminalEmpty", h.tr("autopanel.terminal.empty"))
}

// wording is a catalog's text for a function that composes it: the host, in
// the UI's language, or inEnglish.
type wording interface {
	tr(id string) string
	trf(id string, args ...any) string
}

// tr is a message's text in the App's language now. Before the program, it is
// English.
func (h *host) tr(id string) string {
	if h.p == nil {
		return englishText(id)
	}
	return h.p.App().Translate(tui.Msg(id))
}

// trf is tr with its %1, %2 … filled with args, as Qt's QString::arg: a
// sentence is translated whole and then filled, so no language sees it
// assembled from fragments.
func (h *host) trf(id string, args ...any) string { return fill(h.tr(id), args...) }

// argRef is a %1 … %9 in a message, which fill fills.
var argRef = regexp.MustCompile(`%[1-9]`)

// fill is s with each %N its argument, in one pass, so an argument that says
// "%1" itself (a host name, an error) is shown as it is. A %N past the
// arguments stays.
func fill(s string, args ...any) string {
	if len(args) == 0 {
		return s
	}
	return argRef.ReplaceAllStringFunc(s, func(ref string) string {
		if n := int(ref[1] - '0'); n <= len(args) {
			return fmt.Sprint(args[n-1])
		}
		return ref
	})
}

// englishCatalog is autopanel_en.xml, for text composed before the program
// has its App, and for tests.
var englishCatalog = sync.OnceValue(func() *i18n.Set {
	s := &i18n.Set{}
	if err := s.LoadDir(qmlFiles, "qml/i18n", "autopanel"); err != nil {
		panic("ui: the English catalog: " + err.Error()) // embedded: a test catches it first
	}
	return s
})

// englishText is id's English, or id when the catalog has none.
func englishText(id string) string {
	if t, ok := englishCatalog().Lookup(i18n.English, id); ok {
		return t
	}
	return id
}

// inEnglish is wording in the English catalog's words.
type inEnglish struct{}

func (inEnglish) tr(id string) string               { return englishText(id) }
func (inEnglish) trf(id string, args ...any) string { return fill(englishText(id), args...) }
