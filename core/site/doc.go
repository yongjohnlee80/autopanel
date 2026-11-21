// Package site is AutoPanel's own site: the documents published to it, who
// may read each, and what a document's files may be called. The rules are
// here; the store keeps the records, a builder makes the pages, and a serving
// process hands them out.
//
// A document has one of four levels and is private when nothing is said. The
// core owns a document's identity: its ID, its owner, its level and the names
// of its resources. Nothing a build writes is believed about them.
//
// Decision: docs/decisions/site.md
package site

import (
	"errors"
	"slices"
	"strings"
	"unicode/utf8"
)

// A document's level: who may read it.
const (
	Public    = "public"    // anyone
	Protected = "protected" // anyone holding a grant for it (a passphrase was given)
	Internal  = "internal"  // every enabled member
	Private   = "private"   // its owner, and the members it is shared with
)

// A node is a folder or a document: a site is a tree of them.
const (
	KindFolder = "folder"
	KindDoc    = "doc"
)

// A document's format, as AutoDoc wrote it.
const (
	Markdown = "md"
	XMD      = "xmd" // Markdown with a resources folder
	HTML     = "html"
)

// The limits of a document.
const (
	MaxSlug          = 80
	MaxShare         = 64   // members a private document is shared with
	MaxResources     = 64   // files of one document
	MaxResourceName  = 200  // bytes
	MaxResourceDepth = 6    // path segments
	MaxDepth         = 8    // folders below the root
	MaxChildren      = 1000 // nodes in one folder
	MaxPath          = 255  // bytes of a node's address, its slugs joined by /
)

// Refusals. Each says what was wrong and nothing of any other document.
var (
	ErrBadLevel     = errors.New("site: a document's level is public, protected, internal or private")
	ErrBadFormat    = errors.New("site: a document's format is md, xmd or html")
	ErrBadSlug      = errors.New("site: a slug is 1 to 80 lower-case letters, digits and hyphens, starting and ending with a letter or a digit")
	ErrNotAFolder   = errors.New("site: that is no folder")
	ErrNotEmpty     = errors.New("site: a folder is removed only when it is empty")
	ErrCycle        = errors.New("site: a folder cannot move into itself or anything under it")
	ErrTooDeep      = errors.New("site: folders nest at most 8 deep")
	ErrPathTooLong  = errors.New("site: an address is at most 255 bytes")
	ErrTooManyNodes = errors.New("site: a folder holds at most 1000 folders and documents")
	ErrBadPath      = errors.New("site: a path is slugs joined by /, with no empty part")
	ErrRoot         = errors.New("site: the site's root folder is not changed, moved or removed")
	ErrBadShare     = errors.New("site: only a private document has a share list, of at most 64 members, each once, and never its owner")
	ErrActiveHeld   = errors.New("site: only a public html document may run its scripts")
	ErrBadResource  = errors.New("site: a resource's name is a relative path of at most six parts, with no empty part, no . or .. part, no backslash and no control character")
	ErrReservedName = errors.New("site: a resource's name may not start with an underscore or be index.html: those are the site's own")
	ErrSameName     = errors.New("site: two of the document's resources have the same name, or names that differ only by case")
	ErrTooMany      = errors.New("site: a document has at most 64 resources")
)

// Doc is a node of a site's tree, as the core records it: a folder or a
// published document (Kind). Every node but the site's root folder has a
// parent folder; what a reader may do with a node is what May allows for it
// and every folder above it.
type Doc struct {
	ID         int64   // the core's; never reused: every path and grant names it
	Site       int64   // the site it belongs to
	Parent     int64   // its folder; 0 for the root folder alone
	Kind       string  // KindFolder or KindDoc
	Slug       string  // its part of the address; may be used again after a removal, by a node with a new ID
	Format     string  // a document's; "" for a folder
	Owner      int64   // the user who made it; never changed; 0 for the root folder
	Visibility string  // one of the four levels
	Share      []int64 // private only: the users who may read it besides its owner
	Order      int     // its place among its siblings
	Active     bool    // html only: its scripts run; only when public
	Generation int64   // raised when the level, the share list or the protection changes
	Version    int64   // raised when the content changes
}

// ValidLevel reports whether level is one of the four.
func ValidLevel(level string) bool {
	return level == Public || level == Protected || level == Internal || level == Private
}

// Level resolves the level a publish asks for. A first publish that names
// none is private. An update that names none keeps the level the document
// has: silence never changes who may read. An unknown level is refused.
func Level(asked string, existing *Doc) (string, error) {
	switch {
	case asked == "" && existing != nil:
		return existing.Visibility, nil
	case asked == "":
		return Private, nil
	case !ValidLevel(asked):
		return "", ErrBadLevel
	}
	return asked, nil
}

// Lowers reports whether a change from one level to another takes the
// document from readers who had it: any move away from public. (Between the
// held levels the readers change too, but nothing held is ever a public file.)
func Lowers(from, to string) bool { return from == Public && to != Public }

// Check refuses a document whose fields break the rules. It does not look at
// the store: that a slug is free, and that the shared users exist and are
// enabled, is the caller's to check.
func (d Doc) Check() error {
	if !ValidLevel(d.Visibility) {
		return ErrBadLevel
	}
	switch d.Kind {
	case KindDoc:
		if d.Format != Markdown && d.Format != XMD && d.Format != HTML {
			return ErrBadFormat
		}
	case KindFolder:
		if d.Format != "" || d.Active {
			return ErrBadFormat
		}
	default:
		return ErrBadFormat
	}
	if !validName(d.Slug, MaxSlug) {
		return ErrBadSlug
	}
	if len(d.Share) > 0 && d.Visibility != Private || len(d.Share) > MaxShare || slices.Contains(d.Share, d.Owner) {
		return ErrBadShare
	}
	seen := map[int64]bool{}
	for _, u := range d.Share {
		if u <= 0 || seen[u] {
			return ErrBadShare
		}
		seen[u] = true
	}
	if d.Active && (d.Format != HTML || d.Visibility != Public) {
		return ErrActiveHeld
	}
	return nil
}

// validName reports whether s is lower-case letters, digits and hyphens, at
// most max long, starting and ending with a letter or a digit.
func validName(s string, max int) bool {
	if s == "" || len(s) > max || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// ResourceName checks the name an author gave one of a document's files, as
// it will be stored and asked for: a relative path. The name is taken as it
// is, byte for byte: it is never cleaned into another name, so the name that
// was checked is the name that is served.
//
// Refused: an absolute path; an empty, "." or ".." part; a backslash; a
// control character or text that is not UTF-8; more than six parts or 200
// bytes; a first part that starts with an underscore (the site's generated
// files: _doc.html, _unlock, _kit, _frame); and index.html, the page itself.
func ResourceName(name string) error {
	if name == "" || len(name) > MaxResourceName || !utf8.ValidString(name) || strings.Contains(name, `\`) {
		return ErrBadResource
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f || r == utf8.RuneError {
			return ErrBadResource
		}
	}
	parts := strings.Split(name, "/")
	if len(parts) > MaxResourceDepth {
		return ErrBadResource
	}
	for _, p := range parts {
		if p == "" || p == "." || p == ".." {
			return ErrBadResource
		}
	}
	if strings.HasPrefix(parts[0], "_") || strings.EqualFold(name, "index.html") {
		return ErrReservedName
	}
	return nil
}

// ResourceNames checks a document's whole set of names: each by ResourceName,
// at most MaxResources, and no two the same or differing only by case, so a
// file system that folds case cannot serve one as the other.
func ResourceNames(names []string) error {
	if len(names) > MaxResources {
		return ErrTooMany
	}
	seen := map[string]bool{}
	for _, n := range names {
		if err := ResourceName(n); err != nil {
			return err
		}
		k := strings.ToLower(n)
		if seen[k] {
			return ErrSameName
		}
		seen[k] = true
	}
	return nil
}

// IsFolder reports whether the node is a folder.
func (d Doc) IsFolder() bool { return d.Kind == KindFolder }

// IsRoot reports whether the node is its site's root folder.
func (d Doc) IsRoot() bool { return d.Parent == 0 }

// SplitPath reads a node's path, its slugs joined by "/": "" is the root.
// Leading and trailing slashes are allowed; an empty part, or one that is no
// slug, is refused.
func SplitPath(p string) ([]string, error) {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil, nil
	}
	if len(p) > MaxPath {
		return nil, ErrPathTooLong
	}
	parts := strings.Split(p, "/")
	if len(parts) > MaxDepth+1 {
		return nil, ErrTooDeep
	}
	for _, part := range parts {
		if !validName(part, MaxSlug) {
			return nil, ErrBadPath
		}
	}
	return parts, nil
}
