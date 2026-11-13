package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yongjohnlee80/autopanel/core/services"
	"github.com/yongjohnlee80/autopanel/internal/sysinfo"
)

// A STACK'S FILES. Its definition is the administrator's, in a folder only
// root writes. A review and an apply read each of its files once, into a
// staging folder that is root's too; an apply then moves the staged files
// into the stack user's own folder. What a container wrote there is never
// written again.

const (
	composeFile = "compose.yaml"
	envFile     = ".env"
	// maxText bounds the two files the core reads itself.
	maxText = 256 << 10
	// maxFiles and maxBytes bound a definition.
	maxFiles = 1000
	maxBytes = 64 << 20
)

// Available are the folders that hold a stack's definition.
func (h *Host) Available(context.Context) ([]string, error) {
	entries, err := os.ReadDir(h.defs)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() || !services.ValidName(e.Name()) {
			continue
		}
		if st, err := os.Lstat(filepath.Join(h.defs, e.Name(), composeFile)); err == nil && st.Mode().IsRegular() {
			out = append(out, e.Name())
		}
	}
	return out, nil
}

// definition opens a stack's definition folder as a root no path can leave.
func (h *Host) definition(name string) (*os.Root, error) {
	dir := filepath.Join(h.defs, name)
	if st, err := os.Lstat(dir); err != nil || !st.IsDir() {
		return nil, services.ErrNoDefinition
	}
	return os.OpenRoot(dir)
}

// Stage starts a fresh staged copy with the stack's compose.yaml and .env,
// and answers the two.
func (h *Host) Stage(_ context.Context, name string) (compose, env []byte, err error) {
	def, err := h.definition(name)
	if err != nil {
		return nil, nil, err
	}
	defer def.Close()
	dir := h.staging(name)
	if err := os.RemoveAll(dir); err != nil {
		return nil, nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, err
	}
	if err := os.Chmod(filepath.Dir(dir), 0o700); err != nil {
		return nil, nil, err
	}
	stage, err := os.OpenRoot(dir)
	if err != nil {
		return nil, nil, err
	}
	defer stage.Close()
	read := func(file string) ([]byte, error) {
		st, err := def.Lstat(file)
		if err != nil {
			return nil, err
		}
		if !st.Mode().IsRegular() {
			return nil, fmt.Errorf("services: %s is not a file", file)
		}
		if st.Size() > maxText {
			return nil, services.ErrTooLarge
		}
		if err := stageFile(def, stage, file, 0o400); err != nil {
			return nil, err
		}
		return stage.ReadFile(file)
	}
	compose, err = read(composeFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, services.ErrNoDefinition
	}
	if err != nil {
		return nil, nil, err
	}
	env, err = read(envFile)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	return compose, env, nil
}

// copyFile copies src of one root to dst of another, with mode. dst's folder
// must be there.
func copyFile(from, to *os.Root, src, dst string, mode fs.FileMode) error {
	in, err := from.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	_ = to.Remove(dst)
	out, err := to.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if err == nil {
		err = out.Chmod(mode)
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	return err
}

// stageFile copies one file of the definition into the staged copy, making
// the folders on its way.
func stageFile(def, stage *os.Root, file string, mode fs.FileMode) error {
	if dir := path.Dir(file); dir != "." {
		if err := stage.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return copyFile(def, stage, file, file, mode)
}

// linked reports whether file, or a directory on its way, is a symbolic link
// in root; absent says the path is not there.
func linked(root *os.Root, file string) (link, absent bool, err error) {
	at := ""
	for _, part := range strings.Split(file, "/") {
		at = path.Join(at, part)
		st, err := root.Lstat(at)
		switch {
		case errors.Is(err, os.ErrNotExist):
			return false, true, nil
		case err != nil:
			return false, false, err
		case st.Mode()&fs.ModeSymlink != 0:
			return true, false, nil
		}
	}
	return false, false, nil
}

// keptMode is the mode a managed file has in the stack's folder: its own,
// without the right to write. A file a container's own user must read is
// readable by all in the definition; .env never is.
func keptMode(file string, m fs.FileMode) fs.FileMode {
	if file == envFile || file == composeFile {
		return 0o400
	}
	return m.Perm()&0o555 | 0o400
}

// StagePaths adds the files at paths, each a file or a folder of them, to the
// staged copy, and answers every staged file.
func (h *Host) StagePaths(_ context.Context, name string, paths []string) (files []services.Input, missing, links []string, err error) {
	def, err := h.definition(name)
	if err != nil {
		return nil, nil, nil, err
	}
	defer def.Close()
	stage, err := os.OpenRoot(h.staging(name))
	if err != nil {
		return nil, nil, nil, err
	}
	defer stage.Close()
	count, total := 0, int64(0)
	one := func(file string, st fs.FileInfo) error {
		if count++; count > maxFiles {
			return services.ErrTooLarge
		}
		if total += st.Size(); total > maxBytes {
			return services.ErrTooLarge
		}
		return stageFile(def, stage, file, keptMode(file, st.Mode()))
	}
	for _, p := range paths {
		link, absent, err := linked(def, p)
		switch {
		case err != nil:
			return nil, nil, nil, err
		case absent:
			missing = append(missing, p)
			continue
		case link:
			links = append(links, p)
			continue
		}
		st, err := def.Lstat(p)
		if err != nil {
			return nil, nil, nil, err
		}
		if st.Mode().IsRegular() {
			if err := one(p, st); err != nil {
				return nil, nil, nil, err
			}
			continue
		}
		err = fs.WalkDir(def.FS(), p, func(file string, d fs.DirEntry, err error) error {
			switch {
			case err != nil:
				return err
			case d.IsDir():
				return stage.MkdirAll(file, 0o755)
			case !d.Type().IsRegular():
				// A link, a socket, a device: nothing a stack is given.
				links = append(links, file)
				return nil
			}
			st, err := d.Info()
			if err != nil {
				return err
			}
			return one(file, st)
		})
		if err != nil {
			return nil, nil, nil, err
		}
	}
	// What was staged, read back from the staged copy: the manifest is of the
	// bytes an apply will move, not of the definition as it may be by now.
	err = fs.WalkDir(stage.FS(), ".", func(file string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		st, err := d.Info()
		if err != nil {
			return err
		}
		f, err := stage.Open(file)
		if err != nil {
			return err
		}
		defer f.Close()
		sum := sha256.New()
		if _, err := io.Copy(sum, f); err != nil {
			return err
		}
		files = append(files, services.Input{Path: file, Mode: uint32(st.Mode().Perm()), Size: st.Size(), SHA256: hex.EncodeToString(sum.Sum(nil))})
		return nil
	})
	return files, missing, links, err
}

// Look says which of paths are in the stack's own folder already, and which
// of those are, or pass through, a symbolic link.
func (h *Host) Look(_ context.Context, name string, paths []string) (map[string]bool, []string, error) {
	present := map[string]bool{}
	root, err := os.OpenRoot(filepath.Join(h.home(name), "stack"))
	if errors.Is(err, os.ErrNotExist) {
		return present, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	defer root.Close()
	var links []string
	for _, p := range paths {
		link, absent, err := linked(root, p)
		switch {
		case err != nil:
			return nil, nil, err
		case link:
			links = append(links, p)
		case !absent:
			present[p] = true
		}
	}
	return present, links, nil
}

// Changed reports whether the definition differs from m, by each file's size,
// mode and time, and by the time of each folder that holds one.
func (h *Host) Changed(_ context.Context, name string, m services.Manifest, since time.Time) bool {
	def, err := h.definition(name)
	if err != nil {
		return true
	}
	defer def.Close()
	dirs := map[string]bool{}
	for _, f := range m.Files {
		st, err := def.Lstat(f.Path)
		if err != nil || !st.Mode().IsRegular() || st.Size() != f.Size || st.ModTime().After(since) ||
			uint32(keptMode(f.Path, st.Mode())) != f.Mode {
			return true
		}
		if dir := path.Dir(f.Path); dir != "." {
			dirs[dir] = true
		}
	}
	for dir := range dirs {
		if st, err := def.Lstat(dir); err != nil || st.ModTime().After(since) {
			return true
		}
	}
	// A .env that was not there when the stack was applied.
	has := false
	for _, f := range m.Files {
		has = has || f.Path == envFile
	}
	if _, err := def.Lstat(envFile); err == nil && !has {
		return true
	}
	return false
}

// Commit moves the staged files into the stack's own folder, removes the
// managed files the definition no longer has, makes the data paths that are
// not there, and writes the files the core generates. A data path that
// exists is not touched.
func (h *Host) Commit(_ context.Context, name string, c services.Commit) error {
	_, uid, gid, err := stackUser(name)
	if err != nil {
		return err
	}
	return commit(h.staging(name), h.home(name), uid, gid, c)
}

func commit(staging, home string, uid, gid int, c services.Commit) error {
	root, err := os.OpenRoot(home)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := mkdir(root, "stack", 0o700, uid, gid, true); err != nil {
		return err
	}
	stage, err := os.OpenRoot(staging)
	if err != nil {
		return err
	}
	defer stage.Close()

	for _, p := range c.Stale {
		file, err := inStack(p)
		if err != nil {
			return err
		}
		// A file, or a folder the definition mounted read-only: the core put
		// every file of it there.
		if err := root.RemoveAll(file); err != nil {
			return err
		}
		// And the folders it leaves empty, up to the stack's own.
		for dir := path.Dir(file); dir != "stack"; dir = path.Dir(dir) {
			if root.Remove(dir) != nil {
				break
			}
		}
	}
	for _, p := range c.Managed {
		file, err := inStack(p)
		if err != nil {
			return err
		}
		st, err := stage.Lstat(p)
		if err != nil {
			return err
		}
		if err := mkdirs(root, path.Dir(file), uid, gid, true); err != nil {
			return err
		}
		// Written beside its place, then moved into it: a container reads the
		// old file or the new one, never half of either.
		tmp := file + ".autopanel-new"
		if err := copyFile(stage, root, p, tmp, 0o600); err != nil {
			return err
		}
		if err := finish(root, tmp, file, st.Mode().Perm(), uid, gid); err != nil {
			return err
		}
	}
	for _, p := range c.Data {
		file, err := inStack(p)
		if err != nil {
			return err
		}
		if _, err := root.Lstat(file); err == nil {
			continue // the stack's data: never written
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := mkdirs(root, file, uid, gid, false); err != nil {
			return err
		}
	}
	// The core's own folder holds what this apply generated, and nothing else.
	gen := "stack/" + services.Generated
	keep := map[string]bool{}
	for _, f := range c.Generated {
		keep[path.Clean(f.Path)] = true
	}
	if entries, err := fs.ReadDir(root.FS(), gen); err == nil {
		for _, e := range entries {
			if !keep[gen+"/"+e.Name()] {
				if err := root.RemoveAll(gen + "/" + e.Name()); err != nil {
					return err
				}
			}
		}
	}
	if err := writeFiles(home, uid, gid, c.Generated); err != nil {
		return err
	}
	return os.RemoveAll(staging)
}

// inStack is a path of the definition as the stack's home holds it.
func inStack(p string) (string, error) {
	c := path.Clean(p)
	if c == "." || path.IsAbs(c) || c == ".." || strings.HasPrefix(c, "../") {
		return "", fmt.Errorf("services: %q is not a path inside the stack's folder", p)
	}
	return "stack/" + c, nil
}

// mkdir makes dir, the stack user's, with mode whatever the core's umask is.
// One that is there is left as it is, unless own says it is the core's to
// keep: a managed folder's mode is set again, a data folder's never.
func mkdir(root *os.Root, dir string, mode fs.FileMode, uid, gid int, own bool) error {
	err := root.Mkdir(dir, mode)
	switch {
	case errors.Is(err, os.ErrExist):
		if !own {
			return nil
		}
		if st, err := root.Lstat(dir); err != nil || !st.IsDir() {
			return fmt.Errorf("services: %s is not a folder", dir)
		}
	case err != nil:
		return err
	}
	if err := root.Lchown(dir, uid, gid); err != nil {
		return err
	}
	return root.Chmod(dir, mode)
}

// mkdirs makes dir and the folders on its way, below "stack", each the stack
// user's and open to read: a container's own user reads a mounted folder by
// its mode. The stack's own folder above them is its user's alone, so no
// other user of the host reaches them.
func mkdirs(root *os.Root, dir string, uid, gid int, own bool) error {
	at := ""
	for _, part := range strings.Split(dir, "/") {
		at = path.Join(at, part)
		if at == "stack" {
			continue
		}
		if err := mkdir(root, at, 0o755, uid, gid, own); err != nil {
			return err
		}
	}
	return nil
}

func finish(root *os.Root, tmp, file string, mode fs.FileMode, uid, gid int) error {
	err := root.Lchown(tmp, uid, gid)
	if err == nil {
		err = root.Chmod(tmp, mode)
	}
	if err == nil {
		err = root.Rename(tmp, file)
	}
	if err != nil {
		_ = root.Remove(tmp)
	}
	return err
}

// Listening are the host's listening sockets that the stack's own user, and
// the ids under it, do not hold: what a stack's ports must not collide with.
// A container of the stack that is not root inside holds its sockets as one
// of the user's sub-ids.
func (h *Host) Listening(ctx context.Context, name string) ([]services.PortUse, error) {
	ls, err := sysinfo.Listeners(ctx)
	if errors.Is(err, sysinfo.ErrUnsupported) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	usr := services.UserOf(name)
	own := func(int) bool { return false }
	if uid, _, ok, err := ids(usr); err != nil {
		return nil, err
	} else if ok {
		table, _ := os.ReadFile(h.subuid)
		first, count := subRange(usr, string(table))
		own = func(id int) bool { return id == uid || (id >= first && id < first+count) }
	}
	var out []services.PortUse
	for _, l := range ls {
		if l.UID != sysinfo.NoUID && own(l.UID) {
			continue
		}
		out = append(out, services.PortUse{Proto: l.Proto, From: l.Port, To: l.Port})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].From < out[j].From })
	return out, nil
}

// subRange is usr's range in a sub-id table.
func subRange(usr, table string) (first, count int) {
	for _, line := range strings.Split(table, "\n") {
		f := strings.Split(strings.TrimSpace(line), ":")
		if len(f) == 3 && f[0] == usr {
			first, _ = strconv.Atoi(f[1])
			count, _ = strconv.Atoi(f[2])
			return first, count
		}
	}
	return 0, 0
}
