package services

import (
	"context"
	"errors"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// IMPORTING A STACK. The file browser reads the host; choosing a folder that
// holds a compose.yaml imports it: its definition is copied into the stacks'
// directory, root's alone, and where it came from is recorded. What root runs
// is then a copy no other user can change, and the stack runs on if its source
// is moved or deleted. Data folders are not copied.
//
// Decision: docs/decisions/services.md#a-stack-is-imported-from-anywhere

var (
	ErrBadPath    = errors.New("services: not a path the browser can read")
	ErrNotInStack = errors.New("services: the file is in no stack's folder")
	ErrNotText    = errors.New("services: the file is not text")
	ErrNoSource   = errors.New("services: the stack was not imported")
)

// Listing is a folder of the host, as the browser shows it.
type Listing struct {
	Path      string  `json:"path"`
	Stack     bool    `json:"stack"` // it holds a compose.yaml: it can be imported
	Entries   []Entry `json:"entries"`
	Truncated bool    `json:"truncated"` // the folder has more entries than a listing answers
}

// Entry is one entry of a folder.
type Entry struct {
	Name  string `json:"name"`
	Kind  string `json:"kind"`  // "dir", "file", "link" or "other"
	Size  int64  `json:"size"`  // for a file
	Stack bool   `json:"stack"` // for a folder: it holds a compose.yaml
}

// PreviewText is a file's text for the browser's preview, its secrets masked.
type PreviewText struct {
	Path   string `json:"path"`
	Text   string `json:"text"`
	Masked int    `json:"masked"` // the values hidden
	Cut    bool   `json:"cut"`    // the file is longer than the preview
}

// Source is where a stack's definition was imported from.
type Source struct {
	Path       string    `json:"path"`
	ImportedAt time.Time `json:"imported_at"`
	SHA256     string    `json:"sha256"` // the manifest as it was imported
}

// SourceView is a stack's source as a client sees it.
type SourceView struct {
	Path       string `json:"path"`
	ImportedAt int64  `json:"imported_at"` // Unix seconds
	State      string `json:"state"`       // "same", "changed" or "missing"
}

// Browse is services.browse's param.
type Browse struct {
	Path string `json:"path"`
}

// Import is services.import's param.
type Import struct {
	From string `json:"from"`           // the source folder, absolute
	Name string `json:"name,omitempty"` // the stack's name; the folder's own when empty
}

// Imported is services.import's and services.reimport's answer.
type Imported struct {
	Name   string  `json:"name"`
	From   string  `json:"from"`
	SHA256 string  `json:"sha256"` // the manifest of what was copied: a review answers the same while nothing changes
	Files  []Input `json:"files"`
}

func (m *Module) browse(ctx context.Context, b Browse) (Listing, error) {
	return m.host.Browse(ctx, b.Path)
}

func (m *Module) preview(ctx context.Context, b Browse) (PreviewText, error) {
	text, cut, err := m.host.Preview(ctx, b.Path)
	if err != nil {
		return PreviewText{}, err
	}
	masked, n := Mask(path.Base(b.Path), string(text))
	return PreviewText{Path: b.Path, Text: masked, Masked: n, Cut: cut}, nil
}

var (
	// envLine is "KEY=value", with an optional "export ".
	envLine = regexp.MustCompile(`^(\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_.-]*\s*=\s*)(.*)$`)
	// secretLine is a key that names a secret, then = or :, then its value.
	secretLine = regexp.MustCompile(`(?i)^(\s*-?\s*"?[A-Za-z0-9_.-]*(?:secret|passw|token|private|credential|api[_-]?key|auth)[A-Za-z0-9_.-]*"?\s*[:=]\s*)(\S.*)$`)
)

// Mask hides what a preview must not show: every value of a .env file (or of
// any file named "*.env"), and in every other file the value of each line whose
// key names a secret. It answers the text and the number of values hidden.
func Mask(name, text string) (string, int) {
	env := name == ".env" || strings.HasSuffix(name, ".env")
	n := 0
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), "#") && !env {
			// A comment can still hold a secret someone commented out.
			if m := secretLine.FindStringSubmatch(strings.TrimLeft(strings.TrimSpace(l), "# ")); m != nil {
				lines[i] = l[:strings.Index(l, "#")+1] + " " + m[1] + "••••••"
				n++
			}
			continue
		}
		var m []string
		if env {
			m = envLine.FindStringSubmatch(l)
		} else {
			m = secretLine.FindStringSubmatch(l)
		}
		if m != nil && strings.TrimSpace(m[2]) != "" {
			lines[i] = m[1] + "••••••"
			n++
		}
	}
	return strings.Join(lines, "\n"), n
}

// sourceFiles reads a source folder's compose file and answers the managed
// paths an import copies beside compose.yaml and .env.
func (m *Module) sourceFiles(ctx context.Context, from string) ([]string, error) {
	compose, envText, err := m.host.ReadSource(ctx, from)
	if err != nil {
		return nil, err
	}
	env, bad := ParseEnv(envText)
	if len(bad) > 0 {
		return nil, with(ErrRefused, "bad-env-line: .env line "+strconv.Itoa(bad[0]))
	}
	st, findings := Parse(compose, env)
	for _, f := range findings {
		if f.Severity == Refused {
			return nil, with(ErrRefused, strings.TrimSpace(f.ID+" "+f.Service+" "+f.Detail))
		}
	}
	return managedPaths(st), nil
}

// importFrom copies from into the stacks' directory as name, and records it.
func (m *Module) importFrom(ctx context.Context, from, name string, replace bool) (Imported, error) {
	if m.guard != nil && m.guard.Owns(name) {
		return Imported{}, ErrReserved
	}
	paths, err := m.sourceFiles(ctx, from)
	if err != nil {
		return Imported{}, err
	}
	files, missing, links, err := m.host.Import(ctx, from, name, paths, replace)
	switch {
	case err != nil:
		return Imported{}, err
	case len(missing) > 0:
		return Imported{}, with(ErrRefused, "missing-file "+missing[0])
	case len(links) > 0:
		return Imported{}, with(ErrRefused, "symlink "+links[0])
	}
	man := NewManifest(files)
	if err := m.store.SetSource(ctx, name, Source{Path: from, ImportedAt: time.Now(), SHA256: man.SHA256}); err != nil {
		return Imported{}, err
	}
	return Imported{Name: name, From: from, SHA256: man.SHA256, Files: man.Files}, nil
}

func (m *Module) importVerb(ctx context.Context, p Import) (Imported, error) {
	name := p.Name
	if name == "" {
		name = path.Base(p.From)
	}
	if !ValidName(name) {
		return Imported{}, ErrBadName
	}
	defer m.lock(name)()
	if _, err := m.store.Get(ctx, name); err == nil {
		return Imported{}, ErrDuplicate
	} else if !errors.Is(err, ErrNotFound) {
		return Imported{}, err
	}
	return m.importFrom(ctx, p.From, name, false)
}

// reimport copies a stack's definition from its source again. What runs does
// not change until an apply, which shows the review first.
func (m *Module) reimport(ctx context.Context, r Ref) (Imported, error) {
	if !ValidName(r.Name) {
		return Imported{}, ErrBadName
	}
	defer m.lock(r.Name)()
	src, ok, err := m.store.Source(ctx, r.Name)
	if err != nil {
		return Imported{}, err
	}
	if !ok {
		return Imported{}, ErrNoSource
	}
	return m.importFrom(ctx, src.Path, r.Name, true)
}

// sourceView says whether a stack's source still matches what was imported.
func (m *Module) sourceView(ctx context.Context, src Source) *SourceView {
	v := &SourceView{Path: src.Path, ImportedAt: src.ImportedAt.Unix(), State: "missing"}
	paths, err := m.sourceFiles(ctx, src.Path)
	if err != nil {
		if errors.Is(err, ErrRefused) {
			v.State = "changed" // it changed into something the policy refuses
		}
		return v
	}
	files, missing, links, err := m.host.SourceManifest(ctx, src.Path, paths)
	switch {
	case err != nil:
	case len(missing) > 0 || len(links) > 0 || NewManifest(files).SHA256 != src.SHA256:
		v.State = "changed"
	default:
		v.State = "same"
	}
	return v
}
