package ui

import (
	"context"
	"errors"
	"os"
	"os/user"
	"path"
	"strings"

	tuidecl "github.com/yongjohnlee80/golib/tui/decl"

	"github.com/yongjohnlee80/autopanel/core/services"
)

// THE FILE BROWSER — Services › Add a stack: the host's folders, in the
// pickers' one layout. On the left a path field over the folder's entries,
// folders first, a folder that holds a compose.yaml marked; on the right the
// entry under the cursor: a file's text, its secrets masked, or a folder's
// summary. Enter on a folder goes into it; Backspace, or the ".." row, goes up.
// Import takes the folder under the cursor, or the one shown, when it holds a
// compose.yaml: it asks the stack's name, copies the definition in, and opens
// its review. Nothing runs before that review is confirmed.
//
// The daemon reads the host (services.browse and services.preview), so the
// browser sees what root sees; it previews only the files inside a stack's
// folder, and says so in one line for any other.
//
// Decision: docs/decisions/ui.md#a-stack-is-added-from-a-file-browser

// browser is the file browser's model and what it shows.
type browser struct {
	model *tuidecl.ListModel // App.browseEntries

	start   string // where it opens: the home of the user who ran sudo, or /
	listing services.Listing
	rows    []browseRow // the list's rows: ".." first below the root, then the entries
	at      int         // the row under the cursor
	seq     int         // the last read asked for: an older answer is dropped
	preview int         // the last preview asked for
}

// browseRow is a row of the list: an entry, or the parent folder.
type browseRow struct {
	entry services.Entry
	up    bool
}

func newBrowser() browser {
	return browser{model: tuidecl.NewListModel("key", "name", "mark", "size"), start: browseHome()}
}

// browseHome is the home of the user who ran sudo, when the host knows it,
// else the root.
func browseHome() string {
	if name := os.Getenv("SUDO_USER"); name != "" && name != "root" {
		if u, err := user.Lookup(name); err == nil && u.HomeDir != "" {
			return u.HomeDir
		}
	}
	return "/"
}

// state is the browser's part of the App singleton's state.
func (b *browser) state() map[string]any {
	return map[string]any{
		"App.browseEntries":      b.model,
		"App.browsePath":         "",
		"App.browseTitle":        "",
		"App.browsePreviewTitle": "",
		"App.browsePreview":      "",
		"App.browseSyntax":       "",
		"App.browseNote":         "",
		"App.browseNoteShown":    false,
		"App.browseCanImport":    false,
		"App.browseAt":           0,
	}
}

// syntaxOf is the highlighting for a file the preview shows, by its name.
func syntaxOf(name string) string {
	switch strings.ToLower(path.Ext(name)) {
	case ".yaml", ".yml":
		return "YAML"
	case ".md", ".markdown":
		return "Markdown"
	case ".sh":
		return "Shell"
	}
	return ""
}

// browseRows are a listing's rows: the parent first, below the root, then the
// entries as the daemon gave them, folders first.
func browseRows(l services.Listing) []browseRow {
	var rows []browseRow
	if l.Path != "/" && l.Path != "" {
		rows = append(rows, browseRow{up: true})
	}
	for _, e := range l.Entries {
		rows = append(rows, browseRow{entry: e})
	}
	return rows
}

// browseModelRows are the list's rows as the table shows them: a folder's
// name with a slash, a stack's folder marked, a file's size.
func browseModelRows(rows []browseRow) []tuidecl.Row {
	out := make([]tuidecl.Row, 0, len(rows))
	for _, r := range rows {
		if r.up {
			out = append(out, tuidecl.Row{"key": "..", "name": "..", "mark": "", "size": ""})
			continue
		}
		e := r.entry
		name, mark, size := e.Name, "", ""
		switch e.Kind {
		case "dir":
			name += "/"
			if e.Stack {
				mark = "◆"
			}
		case "link":
			name += " →"
		case "file":
			size = bytesText(uint64(max(e.Size, 0)))
		}
		out = append(out, tuidecl.Row{"key": e.Name, "name": name, "mark": mark, "size": size})
	}
	return out
}

// importable is the folder Import takes: the one under the cursor when it
// holds a compose.yaml, else the folder shown when it does; "" for none.
func (b *browser) importable() string {
	if b.at >= 0 && b.at < len(b.rows) {
		if r := b.rows[b.at]; !r.up && r.entry.Kind == "dir" && r.entry.Stack {
			return path.Join(b.listing.Path, r.entry.Name)
		}
	}
	if b.listing.Stack {
		return b.listing.Path
	}
	return ""
}

// addStack is Services › Add a stack: the browser, where it was left, or at
// its start.
func (h *host) addStack() error {
	at := h.brw.listing.Path
	if at == "" {
		at = h.brw.start
	}
	h.browse(at, true)
	return nil
}

// browse reads a folder and shows it; open opens the browser once it is
// read. A folder the daemon cannot read is said in the note, and the list
// stays as it was.
func (h *host) browse(at string, open bool) {
	h.brw.seq++
	seq := h.brw.seq
	var l services.Listing
	h.background(func(ctx context.Context) (err error) {
		l, err = h.client.Browse(ctx, at)
		return err
	}, func(err error) {
		if seq != h.brw.seq {
			return // a later read was asked for
		}
		if err != nil {
			h.browseNote(h.trf("autopanel.notice.browse.cannotRead", at, err.Error()))
			_ = h.fill(map[string]any{"App.browsePath": h.brw.listing.Path})
			if open {
				_ = h.p.Call("browseDialog", "open")
			}
			return
		}
		b := &h.brw
		b.listing, b.rows, b.at = l, browseRows(l), 0
		b.model.Reset(browseModelRows(b.rows))
		_ = h.fill(map[string]any{"App.browsePath": l.Path})
		_ = h.p.Set("App.browseAt", -1)
		_ = h.p.Set("App.browseAt", 0)
		h.renderBrowse()
		h.browseMoved(0)
		if open {
			if err := h.p.Call("browseDialog", "open"); err != nil {
				h.failed(err)
			}
		}
	})
}

// renderBrowse puts the list's title and Import's state on screen.
func (h *host) renderBrowse() {
	b := &h.brw
	title := h.trf("autopanel.title.browse.entries", len(b.listing.Entries))
	if b.listing.Stack {
		title = h.trf("autopanel.title.browse.stackEntries", len(b.listing.Entries))
	}
	if b.listing.Truncated {
		title = h.trf("autopanel.title.browse.truncated", title)
	}
	_ = h.p.SetMany(map[string]any{"App.browseTitle": title, "App.browseCanImport": b.importable() != ""})
}

// browseNote shows one line over the preview, or none for "".
func (h *host) browseNote(note string) {
	_ = h.p.SetMany(map[string]any{"App.browseNote": note, "App.browseNoteShown": note != ""})
}

// showPreview puts a preview's title, text and highlighting on screen.
func (h *host) showPreview(title, text, syntax string) {
	_ = h.p.SetMany(map[string]any{"App.browsePreviewTitle": title, "App.browsePreview": text, "App.browseSyntax": syntax})
}

// browseMoved is the list's cursor moved: the preview follows. A folder is
// summarised; a file is read, its secrets masked.
func (h *host) browseMoved(row int) {
	b := &h.brw
	b.at = row
	b.preview++
	seq := b.preview
	_ = h.p.Set("App.browseCanImport", b.importable() != "")
	if row < 0 || row >= len(b.rows) {
		h.browseNote("")
		h.showPreview("", "", "")
		return
	}
	r := b.rows[row]
	if r.up {
		h.browseNote("")
		h.showPreview("..", h.trf("autopanel.value.browse.parent", path.Dir(b.listing.Path)), "")
		return
	}
	e := r.entry
	full := path.Join(b.listing.Path, e.Name)
	switch e.Kind {
	case "dir":
		h.browseNote("")
		kind := h.tr("autopanel.value.browse.folder")
		if e.Stack {
			kind = h.tr("autopanel.value.browse.stackFolder")
		}
		h.showPreview(e.Name+"/", facts(h,
			[2]string{"autopanel.label.browse.path", full},
			[2]string{"autopanel.label.browse.kind", kind}), "")
		return
	case "file":
	default:
		h.browseNote("")
		h.showPreview(e.Name, facts(h,
			[2]string{"autopanel.label.browse.path", full},
			[2]string{"autopanel.label.browse.kind", h.tr("autopanel.value.browse.other")}), "")
		return
	}
	var p services.PreviewText
	h.background(func(ctx context.Context) (err error) {
		p, err = h.client.Preview(ctx, full)
		return err
	}, func(err error) {
		if seq != h.brw.preview {
			return // the cursor has moved on
		}
		switch {
		case errors.Is(err, services.ErrNotInStack):
			h.browseNote(h.tr("autopanel.note.browse.notInStack"))
			h.showPreview(e.Name, "", "")
			return
		case errors.Is(err, services.ErrNotText):
			h.browseNote(h.tr("autopanel.note.browse.notText"))
			h.showPreview(e.Name, "", "")
			return
		case err != nil:
			h.browseNote(h.trf("autopanel.notice.browse.cannotRead", full, err.Error()))
			h.showPreview(e.Name, "", "")
			return
		}
		var notes []string
		if p.Masked > 0 {
			notes = append(notes, h.trf("autopanel.note.browse.masked", p.Masked))
		}
		if p.Cut {
			notes = append(notes, h.tr("autopanel.note.browse.cut"))
		}
		h.browseNote(strings.Join(notes, " "))
		h.showPreview(e.Name, p.Text, syntaxOf(e.Name))
	})
}

// browseMove is the list's cursor moved, from the document.
func (h *host) browseMove(row int) error {
	h.browseMoved(row)
	return nil
}

// browseEnter is Enter on a row: a folder is gone into, ".." goes up; a file
// stays previewed.
func (h *host) browseEnter(row int) error {
	b := &h.brw
	if row < 0 || row >= len(b.rows) {
		return nil
	}
	r := b.rows[row]
	switch {
	case r.up:
		return h.browseUp()
	case r.entry.Kind == "dir":
		h.browse(path.Join(b.listing.Path, r.entry.Name), false)
	}
	return nil
}

// browseUp is Backspace, or Up: the parent folder.
func (h *host) browseUp() error {
	if p := h.brw.listing.Path; p != "" && p != "/" {
		h.browse(path.Dir(p), false)
	}
	return nil
}

// browseGo is Enter in the path field: that folder.
func (h *host) browseGo(at string) error {
	at = strings.TrimSpace(at)
	if at == "" {
		return nil
	}
	if !path.IsAbs(at) {
		at = path.Join(h.brw.listing.Path, at)
	}
	h.browse(path.Clean(at), false)
	return nil
}

// browseImport is Import: the stack's name asked, its folder's name first;
// then the definition copied in, the browser closed, and the review opened.
func (h *host) browseImport() error {
	from := h.brw.importable()
	if from == "" {
		h.browseNote(h.tr("autopanel.notice.browse.noStack"))
		return nil
	}
	return h.prompt("autopanel.title.prompt.import", "autopanel.label.prompt.stackName", path.Base(from), func(name string) error {
		name = strings.TrimSpace(name)
		if name == "" {
			name = path.Base(from)
		}
		if !services.ValidName(name) {
			h.promptRefused(h.trf("autopanel.notice.import.badName", name))
			return nil
		}
		if h.busy {
			h.promptRefused(h.tr("autopanel.notice.app.busy"))
			return nil
		}
		h.busy = true
		var got services.Imported
		h.background(func(ctx context.Context) (err error) {
			got, err = h.client.ImportStack(ctx, from, name)
			return err
		}, func(err error) {
			h.busy = false
			switch {
			case errors.Is(err, services.ErrDuplicate):
				h.promptRefused(h.trf("autopanel.notice.import.exists", name))
				return
			case err != nil:
				h.promptRefused(h.trf("autopanel.notice.app.error", err.Error()))
				return
			}
			h.promptDone()
			_ = h.p.Call("browseDialog", "close")
			h.say(h.trf("autopanel.notice.import.done", got.Name, len(got.Files)))
			h.checkStack(got.Name, reviewAdd, false)
			h.loadStacks()
		})
		return nil
	})
}
