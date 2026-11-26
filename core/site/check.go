package site

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"slices"
	"strings"
	"syscall"
	"unicode/utf8"
)

// What a build wrote is untrusted: a theme is code, and the container ran it.
// CheckOutput is the core's look at a build's output before anything of it is
// served (docs/decisions/site.md, "What comes out of a build"). It parses; it
// does not search text, so prose about <script> passes and markup hidden
// behind entities does not. It reads through a root-scoped handle and never
// follows a link. The caller has already taken the directory away from the
// builder's user, so nothing changes under it.

// CheckOptions are what the core knows of the build, never what the build said
// of itself.
type CheckOptions struct {
	// MaxBytes is the site's total; 0 is DefaultSiteBytes.
	MaxBytes int64
	// Mermaid reports whether a page (its path in the output) holds a Mermaid
	// diagram, by the renderer's word checked against the core's record. Only
	// such a page may carry the kit's scripts. nil: no page may.
	Mermaid func(page string) bool
	// KitScripts are the scripts a diagram page may load: the kit's own, by
	// path and integrity.
	KitScripts []KitScript
	// ContentHost is where an active .html document is served from; "" when
	// the site has none.
	ContentHost string
	// Active are the site's active .html documents by the core's record: a
	// document's address → its source's SHA-256, in hex. Each must be in the
	// output under ActiveDir, byte for byte; nothing else may be there.
	Active map[string]string
}

// ActiveDir is where a build puts the active .html documents: each as
// <ActiveDir>/<address>/index.html, its source as it was published. The
// serving process answers the content host from this directory alone, and
// never serves it on the site's own host.
const ActiveDir = "_active"

// KitScript is one script the kit ships: its path on the site and its
// Subresource Integrity value.
type KitScript struct{ Path, Integrity string }

// CheckReport counts what passed.
type CheckReport struct {
	Files, Pages int
	Bytes        int64
}

// The bounds of a build's output.
const (
	DefaultSiteBytes = 200 << 20
	checkMaxDepth    = 16
	checkMaxFiles    = 20000
	checkMaxFile     = 10 << 20 // the builder's own file-size limit
	checkMaxName     = 255
)

// ErrOutput is every refusal of a build's output; an *OutputError says which
// file and why.
var ErrOutput = errors.New("site: the build's output was refused")

// OutputError names the file a build failed on, and the rule.
type OutputError struct{ Path, Reason string }

func (e *OutputError) Error() string {
	return "site: the build's output was refused: " + e.Path + ": " + e.Reason
}
func (e *OutputError) Unwrap() error { return ErrOutput }

func refuse(p, format string, a ...any) error {
	return &OutputError{Path: p, Reason: fmt.Sprintf(format, a...)}
}

// CheckOutput walks dir, the output of one build, and refuses it whole at the
// first file a page may not hold. First every entry is looked at without
// being opened: anything but a plain directory or a plain file fails the
// build before any file is read. Then each file is read and checked by its
// type.
func CheckOutput(dir string, opt CheckOptions) (CheckReport, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return CheckReport{}, err
	}
	defer root.Close()
	c := &checker{root: root, opt: opt, files: map[string]int64{}}
	if c.opt.MaxBytes <= 0 {
		c.opt.MaxBytes = DefaultSiteBytes
	}
	if err := c.walk(".", 0); err != nil {
		return CheckReport{}, err
	}
	names := make([]string, 0, len(c.files))
	for name := range c.files {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		if err := c.check(name); err != nil {
			return CheckReport{}, err
		}
	}
	for doc := range c.opt.Active {
		if !c.exists(activeFile(doc)) {
			return CheckReport{}, refuse(activeFile(doc), "an active document the build did not make")
		}
	}
	return c.report, nil
}

type checker struct {
	root   *os.Root
	opt    CheckOptions
	files  map[string]int64 // path → size, from the walk
	report CheckReport
}

const noFollow = os.O_RDONLY | syscall.O_NOFOLLOW

func (c *checker) walk(dir string, depth int) error {
	if depth > checkMaxDepth {
		return refuse(dir, "deeper than %d directories", checkMaxDepth)
	}
	d, err := c.root.OpenFile(dir, noFollow|syscall.O_DIRECTORY, 0)
	if err != nil {
		return refuse(dir, "not a directory that can be read: %v", err)
	}
	defer d.Close()
	for {
		entries, err := d.ReadDir(256)
		for _, e := range entries {
			name := e.Name()
			rel := name
			if dir != "." {
				rel = dir + "/" + name
			}
			if why := badName(name); why != "" {
				return refuse(rel, "%s", why)
			}
			info, err := c.root.Lstat(rel)
			if err != nil {
				return refuse(rel, "%v", err)
			}
			switch {
			case info.IsDir():
				if err := c.walk(rel, depth+1); err != nil {
					return err
				}
			case info.Mode().IsRegular():
				if len(c.files) >= checkMaxFiles {
					return refuse(rel, "more than %d files", checkMaxFiles)
				}
				if info.Size() > checkMaxFile {
					return refuse(rel, "larger than %d bytes", checkMaxFile)
				}
				c.report.Bytes += info.Size()
				if c.report.Bytes > c.opt.MaxBytes {
					return refuse(rel, "the site would hold more than %d bytes", c.opt.MaxBytes)
				}
				c.files[rel] = info.Size()
			default:
				return refuse(rel, "not a plain file or directory (%s)", info.Mode().Type())
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return refuse(dir, "%v", err)
		}
	}
}

// badName says why a name in the output may not be served, or "".
func badName(name string) string {
	switch {
	case len(name) == 0 || len(name) > checkMaxName:
		return "a name's length"
	case !utf8.ValidString(name):
		return "a name that is not UTF-8"
	case strings.HasPrefix(name, "."):
		return "a hidden name"
	case strings.ContainsAny(name, "\\"):
		return "a backslash in a name"
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return "a control character in a name"
		}
	}
	return ""
}

func (c *checker) read(rel string) ([]byte, error) {
	// Non-blocking: were a pipe to stand where the walk saw a file, opening it
	// would wait for a writer. A plain file ignores the flag.
	f, err := c.root.OpenFile(rel, noFollow|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, refuse(rel, "%v", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != c.files[rel] {
		return nil, refuse(rel, "changed during the check")
	}
	data, err := io.ReadAll(io.LimitReader(f, checkMaxFile+1))
	if err != nil {
		return nil, refuse(rel, "%v", err)
	}
	if int64(len(data)) != c.files[rel] {
		return nil, refuse(rel, "changed during the check")
	}
	return data, nil
}

// The file types a site serves, by extension. Anything else fails the build.
func (c *checker) check(rel string) error {
	ext := strings.ToLower(path.Ext(rel))
	data, err := c.read(rel)
	if err != nil {
		return err
	}
	c.report.Files++
	if rel == ActiveDir || strings.HasPrefix(rel, ActiveDir+"/") {
		return c.checkActive(rel, data)
	}
	switch ext {
	case ".html":
		c.report.Pages++
		return c.checkHTML(rel, data)
	case ".css":
		if err := checkCSS(string(data)); err != nil {
			return refuse(rel, "%v", err)
		}
	case ".xml":
		if err := checkXML(data); err != nil {
			return refuse(rel, "%v", err)
		}
	case ".txt":
		if !utf8.Valid(data) {
			return refuse(rel, "text that is not UTF-8")
		}
	case ".png", ".jpg", ".jpeg", ".webp", ".gif":
		want := map[string]string{".png": mimePNG, ".jpg": mimeJPEG, ".jpeg": mimeJPEG, ".webp": mimeWebP, ".gif": mimeGIF}[ext]
		if sniffImage(data) != want {
			return refuse(rel, "an image whose content is not what its name says")
		}
	case ".js":
		// Only the kit's own scripts, at their paths, with the bytes their
		// integrity names: the one script a site may serve.
		if !c.kitScript(rel, data) {
			return refuse(rel, "a script that is not one of the kit's, with its integrity")
		}
	case ".woff2", ".woff":
		magic := map[string]string{".woff2": "wOF2", ".woff": "wOFF"}[ext]
		if !bytes.HasPrefix(data, []byte(magic)) {
			return refuse(rel, "a font whose content is not what its name says")
		}
	default:
		return refuse(rel, "a type of file a site does not serve")
	}
	return nil
}

// kitScript reports whether rel is one of the kit's scripts and data is what
// its integrity value names (sha256, base64, as Subresource Integrity has it).
func (c *checker) kitScript(rel string, data []byte) bool {
	sum := sha256.Sum256(data)
	got := "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
	for _, k := range c.opt.KitScripts {
		if strings.TrimPrefix(k.Path, "/") == rel && k.Integrity == got {
			return true
		}
	}
	return false
}

// exists reports whether the walk found rel: once the walk is done, the disk
// is not asked again.
func (c *checker) exists(rel string) bool { _, ok := c.files[rel]; return ok }

func activeFile(doc string) string { return ActiveDir + "/" + doc + "/index.html" }

// checkActive passes a file under ActiveDir only when it is an active
// document of the core's record, as it was published: the one place a build
// may put markup the check does not read, so it must be the bytes the core
// already holds, and nothing a build made.
func (c *checker) checkActive(rel string, data []byte) error {
	doc, ok := strings.CutSuffix(strings.TrimPrefix(rel, ActiveDir+"/"), "/index.html")
	if !ok || c.opt.ContentHost == "" {
		return refuse(rel, "a file among the active documents that is none")
	}
	want, ok := c.opt.Active[doc]
	if !ok {
		return refuse(rel, "an active document the site does not have")
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != want {
		return refuse(rel, "an active document that is not what was published")
	}
	return nil
}
