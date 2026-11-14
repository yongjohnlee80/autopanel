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
	"unicode/utf8"

	"github.com/yongjohnlee80/autopanel/core/services"
)

// THE FILE BROWSER AND THE IMPORT. A stack's definition may be written anywhere
// on the host; an import copies it into the stacks' directory, root's alone, so
// what root runs is a copy no other user can change. The browser reads the
// host: a folder's entries, and a file's text for its preview.

const (
	maxEntries = 2000      // a folder's entries a listing answers
	maxPreview = 64 << 10  // the bytes a preview reads
	importDir  = ".import" // beside the definitions: an import is built here, then moved into place
)

// cleanAbs is p when it is an absolute, clean path.
func cleanAbs(p string) (string, error) {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p || strings.ContainsRune(p, 0) {
		return "", fmt.Errorf("%w: %q is not an absolute, clean path", services.ErrBadPath, short(p))
	}
	return p, nil
}

func short(s string) string {
	if r := []rune(s); len(r) > 120 {
		return string(r[:120])
	}
	return s
}

// Browse lists a folder of the host: its entries, folders first. A link is
// listed as a link and never followed.
func (h *Host) Browse(_ context.Context, dir string) (services.Listing, error) {
	dir, err := cleanAbs(dir)
	if err != nil {
		return services.Listing{}, err
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return services.Listing{}, fmt.Errorf("%w: %s", services.ErrBadPath, short(err.Error()))
	}
	if !st.IsDir() {
		return services.Listing{}, fmt.Errorf("%w: %s is not a folder", services.ErrBadPath, short(dir))
	}
	f, err := os.Open(dir)
	if err != nil {
		return services.Listing{}, fmt.Errorf("%w: %s", services.ErrBadPath, short(err.Error()))
	}
	defer f.Close()
	names, err := f.Readdirnames(maxEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return services.Listing{}, err
	}
	out := services.Listing{Path: dir, Stack: isStack(dir), Entries: []services.Entry{}}
	if len(names) > maxEntries {
		names, out.Truncated = names[:maxEntries], true
	}
	for _, n := range names {
		e := services.Entry{Name: n}
		st, err := os.Lstat(filepath.Join(dir, n))
		switch {
		case err != nil:
			e.Kind = "other"
		case st.Mode()&fs.ModeSymlink != 0:
			e.Kind = "link"
		case st.IsDir():
			e.Kind = "dir"
			e.Stack = isStack(filepath.Join(dir, n))
		case st.Mode().IsRegular():
			e.Kind, e.Size = "file", st.Size()
		default:
			e.Kind = "other"
		}
		out.Entries = append(out.Entries, e)
	}
	sort.Slice(out.Entries, func(i, j int) bool {
		a, b := out.Entries[i], out.Entries[j]
		if (a.Kind == "dir") != (b.Kind == "dir") {
			return a.Kind == "dir"
		}
		return a.Name < b.Name
	})
	return out, nil
}

// isStack reports whether dir holds a compose.yaml, a file and not a link.
func isStack(dir string) bool {
	st, err := os.Lstat(filepath.Join(dir, composeFile))
	return err == nil && st.Mode().IsRegular()
}

// Preview reads a file for the browser's preview: a regular file, not a link,
// inside a stack's folder (one of its parents holds a compose.yaml), text, and
// at most maxPreview bytes. The core masks what it holds before a client sees it.
func (h *Host) Preview(_ context.Context, file string) ([]byte, bool, error) {
	file, err := cleanAbs(file)
	if err != nil {
		return nil, false, err
	}
	st, err := os.Lstat(file)
	if err != nil {
		return nil, false, fmt.Errorf("%w: %s", services.ErrBadPath, short(err.Error()))
	}
	if !st.Mode().IsRegular() {
		return nil, false, fmt.Errorf("%w: %s is not a file", services.ErrBadPath, short(file))
	}
	inside := false
	for dir := filepath.Dir(file); ; dir = filepath.Dir(dir) {
		if isStack(dir) {
			inside = true
			break
		}
		if dir == "/" {
			break
		}
	}
	if !inside {
		return nil, false, services.ErrNotInStack
	}
	f, err := os.Open(file)
	if err != nil {
		return nil, false, fmt.Errorf("%w: %s", services.ErrBadPath, short(err.Error()))
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxPreview+1))
	if err != nil {
		return nil, false, err
	}
	cut := len(b) > maxPreview
	if cut {
		b = b[:maxPreview]
	}
	if strings.ContainsRune(string(b), 0) || !utf8.Valid(b) {
		return nil, false, services.ErrNotText
	}
	return b, cut, nil
}

// ReadSource reads a source folder's compose.yaml and .env, as Stage reads a
// definition's: files, not links, and bounded.
func (h *Host) ReadSource(_ context.Context, from string) (compose, env []byte, err error) {
	from, err = cleanAbs(from)
	if err != nil {
		return nil, nil, err
	}
	root, err := os.OpenRoot(from)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %s", services.ErrBadPath, short(err.Error()))
	}
	defer root.Close()
	read := func(file string) ([]byte, error) {
		st, err := root.Lstat(file)
		if err != nil {
			return nil, err
		}
		if !st.Mode().IsRegular() {
			return nil, fmt.Errorf("services: %s is not a file", file)
		}
		if st.Size() > maxText {
			return nil, services.ErrTooLarge
		}
		return root.ReadFile(file)
	}
	if compose, err = read(composeFile); errors.Is(err, os.ErrNotExist) {
		return nil, nil, services.ErrNoDefinition
	} else if err != nil {
		return nil, nil, err
	}
	if env, err = read(envFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	return compose, env, nil
}

// SourceManifest hashes a source folder's definition files (compose.yaml, .env
// and paths) as an import would copy them, and copies nothing.
func (h *Host) SourceManifest(_ context.Context, from string, paths []string) ([]services.Input, []string, []string, error) {
	from, err := cleanAbs(from)
	if err != nil {
		return nil, nil, nil, err
	}
	root, err := os.OpenRoot(from)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: %s", services.ErrBadPath, short(err.Error()))
	}
	defer root.Close()
	return walkDefinition(root, paths, func(string, fs.FileMode) error { return nil })
}

// walkDefinition visits compose.yaml, .env when there is one, and each file
// under paths, in root: each is hashed and given to visit with the mode it is
// kept with. A path the folder does not have is missing; one that is, or holds,
// a link is a link, and is not visited.
func walkDefinition(root *os.Root, paths []string, visit func(file string, mode fs.FileMode) error) (files []services.Input, missing, links []string, err error) {
	count, total := 0, int64(0)
	one := func(file string) error {
		st, err := root.Lstat(file)
		if err != nil {
			return err
		}
		if count++; count > maxFiles {
			return services.ErrTooLarge
		}
		if total += st.Size(); total > maxBytes {
			return services.ErrTooLarge
		}
		f, err := root.Open(file)
		if err != nil {
			return err
		}
		sum := sha256.New()
		n, err := io.Copy(sum, f)
		f.Close()
		if err != nil {
			return err
		}
		mode := keptMode(file, st.Mode())
		files = append(files, services.Input{Path: file, Mode: uint32(mode), Size: n, SHA256: hex.EncodeToString(sum.Sum(nil))})
		return visit(file, mode)
	}
	all := []string{composeFile}
	if _, err := root.Lstat(envFile); err == nil {
		all = append(all, envFile)
	}
	for _, p := range append(all, paths...) {
		link, absent, err := linked(root, p)
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
		st, err := root.Lstat(p)
		if err != nil {
			return nil, nil, nil, err
		}
		if st.Mode().IsRegular() {
			if err := one(p); err != nil {
				return nil, nil, nil, err
			}
			continue
		}
		err = fs.WalkDir(root.FS(), p, func(file string, d fs.DirEntry, err error) error {
			switch {
			case err != nil:
				return err
			case d.IsDir():
				return nil
			case !d.Type().IsRegular():
				links = append(links, file)
				return nil
			}
			return one(file)
		})
		if err != nil {
			return nil, nil, nil, err
		}
	}
	return files, missing, links, nil
}

// Import copies a source folder's definition into the stacks' directory as
// name: built beside it, then moved into place, so a definition is never seen
// half-copied. With replace, it takes the place of the definition there; without,
// a definition of that name is refused. Nothing is copied when a path is
// missing, or is or holds a link.
func (h *Host) Import(_ context.Context, from, name string, paths []string, replace bool) ([]services.Input, []string, []string, error) {
	from, err := cleanAbs(from)
	if err != nil {
		return nil, nil, nil, err
	}
	if !services.ValidName(name) {
		return nil, nil, nil, services.ErrBadName
	}
	src, err := os.OpenRoot(from)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: %s", services.ErrBadPath, short(err.Error()))
	}
	defer src.Close()
	if err := os.MkdirAll(h.defs, 0o700); err != nil {
		return nil, nil, nil, err
	}
	final := filepath.Join(h.defs, name)
	if _, err := os.Lstat(final); err == nil && !replace {
		return nil, nil, nil, services.ErrDuplicate
	}
	work := filepath.Join(h.defs, importDir)
	if err := os.MkdirAll(work, 0o700); err != nil {
		return nil, nil, nil, err
	}
	build := filepath.Join(work, name+"."+strconv.FormatInt(time.Now().UnixNano(), 36))
	if err := os.Mkdir(build, 0o700); err != nil {
		return nil, nil, nil, err
	}
	defer os.RemoveAll(build)
	dst, err := os.OpenRoot(build)
	if err != nil {
		return nil, nil, nil, err
	}
	defer dst.Close()
	files, missing, links, err := walkDefinition(src, paths, func(file string, mode fs.FileMode) error {
		if dir := path.Dir(file); dir != "." {
			if err := dst.MkdirAll(dir, 0o755); err != nil {
				return err
			}
		}
		return copyFile(src, dst, file, file, mode)
	})
	if err != nil || len(missing) > 0 || len(links) > 0 {
		return files, missing, links, err
	}
	if err := os.Chmod(build, 0o700); err != nil {
		return nil, nil, nil, err
	}
	// Into place: the old definition aside, the new one in, the old one gone.
	old := build + ".old"
	if _, err := os.Lstat(final); err == nil {
		if err := os.Rename(final, old); err != nil {
			return nil, nil, nil, err
		}
	}
	if err := os.Rename(build, final); err != nil {
		_ = os.Rename(old, final)
		return nil, nil, nil, err
	}
	return files, nil, nil, os.RemoveAll(old)
}
