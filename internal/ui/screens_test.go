package ui

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/yongjohnlee80/golib/tui/decl/decltest"
)

// TestScreensForReview writes the screens a reviewer reads, as text, into the
// folder AUTOPANEL_SCREENS names: the main screen at 120×36 and at 80×24, the
// stacks panel, the file browser on a stack's folder with a preview, a review,
// the domains panel, the route form and Help › Keys. With no folder named, it
// is skipped.
func TestScreensForReview(t *testing.T) {
	dir := os.Getenv("AUTOPANEL_SCREENS")
	if dir == "" {
		t.Skip("AUTOPANEL_SCREENS names no folder")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name string, s *decltest.Screen) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(s.String()+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	at := func(w, ht int) (*host, *decltest.Screen) {
		h, s := openHost(t, withStacks(), w, ht)
		signIn(t, s)
		s.WaitForText(t, "42%")
		s.WaitForText(t, "web/app")
		s.WaitForText(t, "route.add")
		return h, s
	}

	_, s := at(120, 36)
	write("main-120x36.txt", s)

	_, s = at(80, 24)
	write("main-80x24.txt", s)

	_, s = at(120, 36)
	openStacks(t, s, "web*")
	s.Keys(t, decltest.Rune('j'), decltest.Rune('j'), decltest.Rune('j'))
	waitFact(t, s, "Service", "app of stack web")
	write("stacks-panel.txt", s)

	s.Keys(t, decltest.Rune('k'), decltest.Rune('p'))
	s.WaitForText(t, "Apply stack web: review")
	write("review.txt", s)

	_, s = at(120, 36)
	openBrowser(t, s)
	s.WaitForText(t, "blog/")
	s.Keys(t, decltest.Rune('j'), enter)
	s.WaitForText(t, "README.md")
	s.Keys(t, decltest.Rune('j'), decltest.Rune('j'), decltest.Rune('j'), decltest.Rune('j'))
	s.WaitForText(t, "image: nginx:1.27")
	write("browser.txt", s)

	_, s = at(120, 36)
	s.Keys(t, decltest.Alt('r'))
	s.WaitForText(t, "Domains…")
	s.Keys(t, decltest.Rune('d'))
	s.WaitForText(t, "The routes under it:")
	write("domains-panel.txt", s)

	_, s = at(120, 36)
	openRoutes(t, s)
	s.Keys(t, enter)
	s.WaitForText(t, "Edit route #1")
	s.WaitForText(t, "From a stack's port:")
	write("route-form.txt", s)

	_, s = at(120, 36)
	s.Keys(t, decltest.Alt('h'))
	s.WaitForText(t, "Keys")
	s.Keys(t, decltest.Rune('k'))
	s.WaitForText(t, "EVERYWHERE")
	write("help-keys.txt", s)
}
