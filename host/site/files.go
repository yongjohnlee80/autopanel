//go:build linux

// Package site is the host's side of AutoPanel's site: the directories a
// build reads and writes, and the live pages it replaces. The core is root
// and the build's output was written by code it does not trust (a theme), so
// nothing here follows a link or trusts a path the build made.
//
// Decision: docs/decisions/site.md
package site

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"strings"

	"golang.org/x/sys/unix"
)

// Owner is a user and a group, by number.
type Owner struct{ UID, GID int }

// Files is the site's directories:
//
//	<Dir>/<host>/                the live pages of a site; the serving process reads them
//	<Dir>/<content host>         a link to <host>: where its active .html documents are served from
//	<Dir>/.held/<host>/…         the held documents' files (held.go)
//	<Dir>/.work/<host>/content/  a build's input, the core's, read-only to the build
//	<Dir>/.work/<host>/out/      a build's output, the builder's user's until TakeAway
//
// The work directory is on the same file system as the live ones, so the swap
// is one rename.
type Files struct {
	Dir     string
	Owner   Owner // who owns what is served: root
	Builder Owner // the builder's user: ap-site
	Reader  Owner // the serving process's user: its group reads the held files
}

// Work is one build's directories.
type Work struct {
	Host, Dir, Content, Out string
}

const (
	workDir = ".work"
	downDir = ".down" // <host>: an empty marker; the site's pages were taken down
)

// ErrBadHost is a host name the files cannot be named by.
var ErrBadHost = errors.New("site: not a host name")

func hostName(h string) error {
	if h == "" || len(h) > 253 || strings.HasPrefix(h, ".") || strings.HasPrefix(h, "-") {
		return ErrBadHost
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.') {
			return ErrBadHost
		}
	}
	if strings.Contains(h, "..") {
		return ErrBadHost
	}
	return nil
}

// Fresh makes host's work directories, empty: anything an earlier build left
// is removed first, so a build never sees another's input, output or
// scratch. content is the core's; out is the builder's.
func (f Files) Fresh(host string) (Work, error) {
	if err := hostName(host); err != nil {
		return Work{}, err
	}
	if err := f.ensureDir(f.Dir, 0o755); err != nil {
		return Work{}, err
	}
	work := path.Join(f.Dir, workDir)
	// 0711: the builder may pass through to its own out, and list nothing
	if err := f.ensureDir(work, 0o711); err != nil {
		return Work{}, err
	}
	w := Work{Host: host, Dir: path.Join(work, host)}
	w.Content, w.Out = path.Join(w.Dir, "content"), path.Join(w.Dir, "out")
	if err := os.RemoveAll(w.Dir); err != nil { // unlinkat, never following a link
		return Work{}, err
	}
	for _, d := range []string{w.Dir, w.Content, w.Out} {
		if err := os.Mkdir(d, 0o755); err != nil {
			return Work{}, err
		}
		owner := f.Owner
		if d == w.Out {
			owner = f.Builder
		}
		if err := os.Lchown(d, owner.UID, owner.GID); err != nil {
			return Work{}, err
		}
		if err := os.Chmod(d, 0o755); err != nil {
			return Work{}, err
		}
	}
	return w, nil
}

// ensureDir makes dir if it is missing, and holds it to the owner and mode
// whatever it was. A link where the directory should be is refused.
func (f Files) ensureDir(dir string, mode fs.FileMode) error {
	info, err := os.Lstat(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := os.Mkdir(dir, mode); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
	case err != nil:
		return err
	case !info.IsDir():
		return fmt.Errorf("site: %s is not a directory", dir)
	}
	if err := os.Lchown(dir, f.Owner.UID, f.Owner.GID); err != nil {
		return err
	}
	return os.Chmod(dir, mode)
}

// WriteContent writes the build's input: name is a relative path under
// content, which it may not leave.
func (f Files) WriteContent(w Work, name string, data []byte) error {
	root, err := os.OpenRoot(w.Content)
	if err != nil {
		return err
	}
	defer root.Close()
	// The modes are set, not asked for: the core's unit runs with a umask
	// that would leave the input readable by root alone, and the builder,
	// another user, must read it.
	var dirs error
	if dir := path.Dir(name); dir != "." {
		if err := root.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		made := ""
		for _, part := range strings.Split(dir, "/") {
			made = path.Join(made, part)
			dirs = errors.Join(dirs, root.Chmod(made, 0o755))
		}
	}
	return errors.Join(dirs, writeFile(root, name, data, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|unix.O_NOFOLLOW))
}

// writeFile writes data to name under root and sets its mode to 0644,
// whatever the process's umask: a file another user must read.
func writeFile(root *os.Root, name string, data []byte, flag int) error {
	file, err := root.OpenFile(name, flag, 0o644)
	if err != nil {
		return err
	}
	_, werr := file.Write(data)
	return errors.Join(werr, file.Chmod(0o644), file.Close())
}

// TakeAway ends the builder's hold on the work directory once the build has
// exited: the directory becomes the core's, 0700, so no path reaches the
// output for anyone else. It runs before anything in the output is looked
// at. The builder's processes must have ended: the build runs as a unit that
// is collected, its control group killed.
func (f Files) TakeAway(w Work) error {
	if err := os.Lchown(w.Dir, f.Owner.UID, f.Owner.GID); err != nil {
		return err
	}
	if err := os.Chmod(w.Dir, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(w.Out)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("site: the build's output is not a directory")
	}
	return nil
}

// Normalize makes every entry of the output the core's: directories 0755,
// files 0644. It runs after the output check, which has refused anything that
// is not a plain file or directory; it refuses one too, and never follows a
// link.
func (f Files) Normalize(w Work) error {
	root, err := os.OpenRoot(w.Out)
	if err != nil {
		return err
	}
	defer root.Close()
	return normalize(root, ".", f.Owner)
}

func normalize(root *os.Root, dir string, owner Owner) error {
	if err := root.Lchown(dir, owner.UID, owner.GID); err != nil {
		return err
	}
	if err := root.Chmod(dir, 0o755); err != nil {
		return err
	}
	d, err := root.OpenFile(dir, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil {
		return err
	}
	entries, err := d.ReadDir(-1)
	d.Close()
	if err != nil {
		return err
	}
	for _, e := range entries {
		rel := path.Join(dir, e.Name())
		info, err := root.Lstat(rel)
		if err != nil {
			return err
		}
		switch {
		case info.IsDir():
			if err := normalize(root, rel, owner); err != nil {
				return err
			}
		case info.Mode().IsRegular():
			if err := root.Lchown(rel, owner.UID, owner.GID); err != nil {
				return err
			}
			if err := root.Chmod(rel, 0o644); err != nil {
				return err
			}
		default:
			return fmt.Errorf("site: %s is not a plain file or directory", rel)
		}
	}
	return nil
}

// Swap makes the checked output host's live pages in one system call: the
// new directory and the live one exchange names, so a reader gets the old
// site or the new one, never a missing directory or a mix. The first build of
// a site is a rename onto a name nothing holds. The input is removed after;
// the old pages are left where the output was, under the work directory that
// TakeAway closed, so a request that opened them a moment before still reads
// them whole. They are removed when the next build begins (Fresh).
func (f Files) Swap(w Work) (first bool, err error) {
	if err := hostName(w.Host); err != nil {
		return false, err
	}
	sites, err := os.Open(f.Dir)
	if err != nil {
		return false, err
	}
	defer sites.Close()
	work, err := os.Open(w.Dir)
	if err != nil {
		return false, err
	}
	defer work.Close()
	err = unix.Renameat2(int(work.Fd()), "out", int(sites.Fd()), w.Host, unix.RENAME_NOREPLACE)
	switch {
	case err == nil:
		first = true
	case errors.Is(err, unix.EEXIST):
		info, lerr := os.Lstat(path.Join(f.Dir, w.Host))
		if lerr != nil {
			return false, lerr
		}
		if !info.IsDir() {
			return false, fmt.Errorf("site: %s is not a directory", path.Join(f.Dir, w.Host))
		}
		if err := unix.Renameat2(int(work.Fd()), "out", int(sites.Fd()), w.Host, unix.RENAME_EXCHANGE); err != nil {
			return false, fmt.Errorf("site: the swap: %w", err)
		}
	default:
		return false, fmt.Errorf("site: the first swap: %w", err)
	}
	if err := os.RemoveAll(w.Content); err != nil {
		return first, err
	}
	// The site is up again.
	if err := os.Remove(path.Join(f.Dir, downDir, w.Host)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return first, err
	}
	return first, nil
}

// LinkContent makes content the name by which the serving process answers
// host's active documents: a link <Dir>/<content> to host's pages, made in
// one rename. Any other link to host is removed, so a content host a site no
// longer has stops answering. content "" removes them all. A name that is a
// site's own pages is never replaced.
func (f Files) LinkContent(host, content string) error {
	if err := hostName(host); err != nil {
		return err
	}
	entries, err := os.ReadDir(f.Dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.Type()&fs.ModeSymlink == 0 || e.Name() == content {
			continue
		}
		if target, err := os.Readlink(path.Join(f.Dir, e.Name())); err == nil && target == host {
			if err := os.Remove(path.Join(f.Dir, e.Name())); err != nil {
				return err
			}
		}
	}
	if content == "" {
		return nil
	}
	if err := hostName(content); err != nil || content == host {
		return ErrBadHost
	}
	link := path.Join(f.Dir, content)
	if info, err := os.Lstat(link); err == nil {
		if info.Mode()&fs.ModeSymlink == 0 {
			return fmt.Errorf("site: %s is a site's pages, not a content host", link)
		}
		if target, err := os.Readlink(link); err == nil && target == host {
			return nil
		}
	}
	if err := os.MkdirAll(path.Join(f.Dir, workDir, host), 0o755); err != nil {
		return err
	}
	tmp := path.Join(f.Dir, workDir, host, "content-link")
	if err := os.Remove(tmp); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.Symlink(host, tmp); err != nil {
		return err
	}
	return os.Rename(tmp, link)
}

// TakeDown withdraws host's live pages at once: one rename moves them off
// the name the serving process reads, then they are deleted, and an empty
// marker is left by which the serving process answers 503 for every path of
// the site until the next swap. It is safe to call again.
func (f Files) TakeDown(host string) error {
	if err := hostName(host); err != nil {
		return err
	}
	down := path.Join(f.Dir, downDir)
	if err := f.ensureDir(f.Dir, 0o755); err != nil {
		return err
	}
	if err := f.ensureDir(down, 0o755); err != nil {
		return err
	}
	marker := path.Join(down, host)
	if err := os.RemoveAll(marker); err != nil {
		return err
	}
	err := os.Rename(path.Join(f.Dir, host), marker)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := os.Mkdir(marker, 0o755); err != nil {
			return err
		}
	case err != nil:
		return err
	}
	// The withdrawn pages go; the marker stays, empty.
	entries, err := os.ReadDir(marker)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := os.RemoveAll(path.Join(marker, e.Name())); err != nil {
			return err
		}
	}
	return os.Chmod(marker, 0o755)
}

// IsDown reports whether host's pages were taken down and not yet replaced.
func (f Files) IsDown(host string) bool {
	if hostName(host) != nil {
		return false
	}
	info, err := os.Lstat(path.Join(f.Dir, downDir, host))
	return err == nil && info.IsDir()
}

// Remove deletes a site's live pages and any work it has.
func (f Files) Remove(host string) error {
	if err := hostName(host); err != nil {
		return err
	}
	for _, p := range []string{path.Join(f.Dir, workDir, host), path.Join(f.Dir, downDir, host), path.Join(f.Dir, heldDir, host)} {
		if err := os.RemoveAll(p); err != nil {
			return err
		}
	}
	if err := f.LinkContent(host, ""); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return os.RemoveAll(path.Join(f.Dir, host))
}
