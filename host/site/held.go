package site

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// HELD FILES — what is built of a document that is not public is kept apart
// from the pages anyone may read:
//
//	<Dir>/.held/<host>/<node id>/<build>/   one held document's files
//
// The directory is the core's (root) and the serving process's group's, 0750,
// its files 0640: no other user of the host reads them. The serving process
// opens a file here only after the core has answered that the reader may
// have it (auth.go); no request's path names one.

const heldDir = ".held"

// HeldRoot is where the held files of every site are.
func (f Files) HeldRoot() string { return path.Join(f.Dir, heldDir) }

// HeldName is a held file as the core names it to the serving process: the
// path under HeldRoot of name, among node's files of build.
func HeldName(host string, node, build int64, name string) string {
	return path.Join(host, strconv.FormatInt(node, 10), strconv.FormatInt(build, 10), name)
}

// heldOwned holds p to root and the readers' group, with mode.
func (f Files) heldOwned(p string, mode fs.FileMode) error {
	if err := os.Lchown(p, f.Owner.UID, f.Reader.GID); err != nil {
		return err
	}
	return os.Chmod(p, mode)
}

func (f Files) heldMkdir(p string) error {
	info, err := os.Lstat(p)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := os.Mkdir(p, 0o750); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
	case err != nil:
		return err
	case !info.IsDir():
		return fmt.Errorf("site: %s is not a directory", p)
	}
	return f.heldOwned(p, 0o750)
}

// PublishHeld makes the named files of w's checked output, and the named
// directories whole, node's held files of build. Nothing else the job wrote
// is copied. A file that is missing, or is no plain file, fails it; a
// directory that is missing is none. The files appear under their final name
// in one rename, so a reader never sees half of them.
func (f Files) PublishHeld(w Work, node, build int64, files, dirs []string) error {
	if err := hostName(w.Host); err != nil {
		return err
	}
	if node <= 0 || build <= 0 {
		return errors.New("site: a held build needs its node and its number")
	}
	if err := f.ensureDir(f.Dir, 0o755); err != nil {
		return err
	}
	nodeDir := path.Join(f.HeldRoot(), w.Host, strconv.FormatInt(node, 10))
	for _, d := range []string{f.HeldRoot(), path.Join(f.HeldRoot(), w.Host), nodeDir} {
		if err := f.heldMkdir(d); err != nil {
			return err
		}
	}
	final := path.Join(nodeDir, strconv.FormatInt(build, 10))
	tmp := final + ".new"
	if err := os.RemoveAll(tmp); err != nil {
		return err
	}
	if err := f.heldMkdir(tmp); err != nil {
		return err
	}
	defer os.RemoveAll(tmp) // gone once renamed; what a failure left, removed
	src, err := os.OpenRoot(w.Out)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.OpenRoot(tmp)
	if err != nil {
		return err
	}
	defer dst.Close()
	for _, name := range files {
		if err := f.copyHeld(src, dst, tmp, name); err != nil {
			return err
		}
	}
	for _, dir := range dirs {
		err := fs.WalkDir(src.FS(), dir, func(name string, e fs.DirEntry, err error) error {
			if err != nil || e.IsDir() {
				return err
			}
			return f.copyHeld(src, dst, tmp, name)
		})
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	if err := os.RemoveAll(final); err != nil {
		return err
	}
	return os.Rename(tmp, final)
}

// copyHeld copies one plain file of the output to the same name under to.
func (f Files) copyHeld(src, dst *os.Root, to, name string) error {
	if !fs.ValidPath(name) || name == "." || strings.HasPrefix(path.Base(name), ".") {
		return fmt.Errorf("site: %q is no name of a held file", name)
	}
	in, err := src.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("site: a held build's %s: %w", name, err)
	}
	defer in.Close()
	if info, err := in.Stat(); err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("site: a held build's %s is no plain file", name)
	}
	if dir := path.Dir(name); dir != "." {
		made := ""
		for _, part := range strings.Split(dir, "/") {
			made = path.Join(made, part)
			if err := dst.Mkdir(made, 0o750); err != nil && !errors.Is(err, fs.ErrExist) {
				return err
			}
			if err := f.heldOwned(path.Join(to, made), 0o750); err != nil {
				return err
			}
		}
	}
	out, err := dst.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0o640)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return f.heldOwned(path.Join(to, name), 0o640)
}

// SweepHeld removes every held directory of host that is not a kept node's
// build: a node that is gone or public now, and a node's older builds.
func (f Files) SweepHeld(host string, keep map[int64]int64) error {
	if err := hostName(host); err != nil {
		return err
	}
	base := path.Join(f.HeldRoot(), host)
	nodes, err := os.ReadDir(base)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, n := range nodes {
		id, perr := strconv.ParseInt(n.Name(), 10, 64)
		build, kept := keep[id]
		if perr != nil || !kept {
			if err := os.RemoveAll(path.Join(base, n.Name())); err != nil {
				return err
			}
			continue
		}
		builds, err := os.ReadDir(path.Join(base, n.Name()))
		if err != nil {
			return err
		}
		for _, b := range builds {
			if b.Name() != strconv.FormatInt(build, 10) {
				if err := os.RemoveAll(path.Join(base, n.Name(), b.Name())); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
