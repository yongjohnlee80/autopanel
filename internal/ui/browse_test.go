package ui

import (
	"strings"
	"testing"

	"github.com/yongjohnlee80/golib/tui"
	"github.com/yongjohnlee80/golib/tui/decl/decltest"

	"github.com/yongjohnlee80/autopanel/core/services"
)

func TestSyntaxOf(t *testing.T) {
	for in, want := range map[string]string{"compose.yaml": "YAML", "x.YML": "YAML", "README.md": "Markdown", "run.sh": "Shell", ".env": "", "logo.png": ""} {
		if got := syntaxOf(in); got != want {
			t.Errorf("syntaxOf(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestBrowseRows: ".." first below the root, a folder with a slash, a
// stack's folder marked, a file with its size, a link with its arrow.
func TestBrowseRows(t *testing.T) {
	l := services.Listing{Path: "/home/ada", Entries: []services.Entry{
		{Name: "blog", Kind: "dir", Stack: true}, {Name: "notes", Kind: "dir"}, {Name: "latest", Kind: "link"}, {Name: "a.txt", Kind: "file", Size: 2048}}}
	rows := browseModelRows(browseRows(l))
	var got []string
	for _, r := range rows {
		got = append(got, strings.TrimSpace(r["mark"].(string)+" "+r["name"].(string)+" "+r["size"].(string)))
	}
	if want := ".. | ◆ blog/ | notes/ | latest → | a.txt 2.0 KiB"; strings.Join(got, " | ") != want {
		t.Errorf("rows = %q, want %q", strings.Join(got, " | "), want)
	}
	if rows := browseRows(services.Listing{Path: "/"}); len(rows) != 0 {
		t.Errorf("the root has a parent row: %+v", rows)
	}
}

// TestImportable: Import takes the stack's folder under the cursor, else the
// folder shown when it holds a compose.yaml, else nothing.
func TestImportable(t *testing.T) {
	b := browser{listing: services.Listing{Path: "/home/ada", Entries: []services.Entry{{Name: "blog", Kind: "dir", Stack: true}, {Name: "notes", Kind: "dir"}}}}
	b.rows = browseRows(b.listing)
	for at, want := range map[int]string{0: "", 1: "/home/ada/blog", 2: ""} {
		b.at = at
		if got := b.importable(); got != want {
			t.Errorf("at %d: importable = %q, want %q", at, got, want)
		}
	}
	b.listing.Stack, b.at = true, 2
	if got := b.importable(); got != "/home/ada" {
		t.Errorf("in a stack's folder: importable = %q", got)
	}
}

// openBrowser opens Services › Add a stack.
func openBrowser(t *testing.T, s *decltest.Screen) {
	t.Helper()
	s.WaitForText(t, "CA LE staging")
	s.Keys(t, decltest.Alt('s'))
	s.WaitForText(t, "Add a stack…")
	s.Keys(t, decltest.Rune('a'))
	s.WaitForText(t, "Add a stack: choose its folder")
}

// TestTheFileBrowser: it opens in the home of who ran sudo, folders first, a
// stack's folder marked. Enter goes into a folder; the preview follows the
// cursor: a compose.yaml as YAML, a .env with its secrets masked and said, a
// file outside a stack's folder with a one-line note, a picture as not text.
// Backspace and ".." go up; a folder the daemon cannot read is said.
func TestTheFileBrowser(t *testing.T) {
	f := withStacks()
	s := start(t, f)
	openBrowser(t, s)
	for _, part := range []string{"/home/ada", "Entries: 3", "◆", "blog/", "notes/", "todo.txt", "[ Import… ]", "[ Up ]", "[ Close (q) ]"} {
		s.WaitForText(t, part)
	}
	s.WaitForText(t, "The parent folder: /home") // ".." under the cursor
	s.Keys(t, decltest.Rune('j'))
	waitFact(t, s, "Kind", "Folder that holds a compose.yaml: Import takes it")
	s.Keys(t, decltest.Rune('j'), decltest.Rune('j')) // todo.txt: in no stack's folder
	s.WaitForText(t, "Only a file inside a stack's folder")

	s.Keys(t, decltest.Rune('k'), decltest.Rune('k'), enter) // into blog
	s.WaitForText(t, "Entries: 5 · holds a compose.yaml")
	s.WaitForText(t, "README.md")
	gone(t, s, "todo.txt")
	s.Keys(t, decltest.Rune('j'), decltest.Rune('j')) // .env
	s.WaitForText(t, "2 secret values are hidden.")
	s.WaitForText(t, "DB_PASSWORD=••••••")
	s.Keys(t, decltest.Rune('j'), decltest.Rune('j')) // compose.yaml
	s.WaitForText(t, "image: nginx:1.27")
	gone(t, s, "secret values are hidden")
	s.Keys(t, decltest.Rune('j')) // logo.png
	s.WaitForText(t, "The file is not text.")

	s.Keys(t, backspace) // up, to the home
	s.WaitForText(t, "Entries: 3")
	s.Keys(t, enter) // ".." at the top: up again
	s.WaitForText(t, "Entries: 1")
	s.WaitForText(t, "ada/")

	s.Keys(t, tui.KeyEvent{Kind: tui.KeyPress, Code: tui.KeyTab, Mods: tui.ModShift}) // the path field, over the list
	s.Keys(t, decltest.Type("/nowhere")...)
	s.Keys(t, enter)
	s.WaitForText(t, "Cannot read /home/nowhere") // typed after the folder shown
	s.Keys(t, escape)
	gone(t, s, "Add a stack: choose its folder")
}

// TestImportFromTheBrowser: Import on a stack's folder asks the stack's name,
// the folder's own first; the definition is copied in, and its review opens,
// which adds it. A name the daemon has is refused in the prompt, as typed.
func TestImportFromTheBrowser(t *testing.T) {
	f := withStacks()
	s := start(t, f)
	openBrowser(t, s)
	s.WaitForText(t, "blog/")
	s.Keys(t, decltest.Rune('j')) // blog
	waitFact(t, s, "Kind", "Folder that holds a compose.yaml: Import takes it")
	s.Keys(t, decltest.Rune('i'))
	s.WaitForText(t, "Import a stack")
	s.WaitForText(t, "blog")

	// a name taken: refused, the prompt stays
	f.mu.Lock()
	f.stacks = append(f.stacks, services.View{Name: "taken"})
	f.mu.Unlock()
	for range 4 {
		s.Keys(t, backspace)
	}
	s.Keys(t, decltest.Type("taken")...)
	s.Keys(t, enter)
	s.WaitForText(t, "A stack named taken exists. Choose another name.")
	for range 5 {
		s.Keys(t, backspace)
	}
	s.Keys(t, decltest.Type("blog")...)
	s.Keys(t, enter)
	s.WaitForText(t, "Add stack blog: review")
	gone(t, s, "Add a stack: choose its folder")
	same(t, "imports", f.asked().imports, []string{"/home/ada/blog as taken", "/home/ada/blog as blog"})
	same(t, "checks", f.asked().checks, []string{"blog"})

	s.Keys(t, decltest.Rune('a'))
	s.WaitForText(t, "blog is added and started")
	same(t, "applies", f.asked().applies, []string{"add blog " + blogSHA})
}

// TestPrepareOnlyFromTheBrowser: "Prepare only" on a new stack's review asks
// the daemon to prepare it; its review in the panel then starts it.
func TestPrepareOnlyFromTheBrowser(t *testing.T) {
	f := withStacks()
	f.stacks = nil
	s := start(t, f)
	openBrowser(t, s)
	s.WaitForText(t, "blog/")
	s.Keys(t, decltest.Rune('j'), enter) // into blog: Import takes the folder shown
	s.WaitForText(t, "holds a compose.yaml")
	s.Keys(t, decltest.Rune('i'))
	s.WaitForText(t, "Import a stack")
	s.Keys(t, enter)
	s.WaitForText(t, "Add stack blog: review")
	s.Keys(t, decltest.Rune('p'))
	s.WaitForText(t, "blog is prepared and not started")
	gone(t, s, "Add stack blog: review")
	same(t, "applies", f.asked().applies, []string{"prepare blog " + blogSHA})
}
