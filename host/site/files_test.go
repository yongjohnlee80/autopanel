//go:build linux

package site

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// files is a Files in a temporary directory, owned by the test's user in
// both roles: the tests run unprivileged.
func files(t *testing.T) Files {
	me := Owner{os.Getuid(), os.Getgid()}
	return Files{Dir: filepath.Join(t.TempDir(), "site"), Owner: me, Builder: me}
}

func mode(t *testing.T, p string) fs.FileMode {
	t.Helper()
	info, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode()
}

// build makes one build's output for host, as a builder would, and makes it
// live.
func build(t *testing.T, f Files, host, page string) bool {
	t.Helper()
	w, err := f.Fresh(host)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(w.Out, "a"), 0o777); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"index.html", "a/index.html"} {
		if err := os.WriteFile(filepath.Join(w.Out, name), []byte(page), 0o666); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.TakeAway(w); err != nil {
		t.Fatal(err)
	}
	if err := f.Normalize(w); err != nil {
		t.Fatal(err)
	}
	first, err := f.Swap(w)
	if err != nil {
		t.Fatal(err)
	}
	return first
}

func TestAFreshWorkDirectoryHoldsNothingOfTheLast(t *testing.T) {
	f := files(t)
	w, err := f.Fresh("blog.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.WriteContent(w, "docs/a.md", []byte("# a")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(w.Out, "left.html"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	w2, err := f.Fresh("blog.example.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{filepath.Join(w2.Content, "docs/a.md"), filepath.Join(w2.Out, "left.html")} {
		if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s survived: %v", p, err)
		}
	}
	if m := mode(t, filepath.Join(f.Dir, workDir)); m.Perm() != 0o711 {
		t.Errorf("the work directory is %v: the builder may pass through it, and list nothing", m)
	}
	for _, d := range []string{w2.Dir, w2.Content, w2.Out} {
		if m := mode(t, d); !m.IsDir() || m.Perm() != 0o755 {
			t.Errorf("%s is %v", d, m)
		}
	}
}

func TestContentStaysUnderItsDirectory(t *testing.T) {
	f := files(t)
	w, err := f.Fresh("blog.example.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"../escape.md", "/etc/x.md", "a/../../escape.md"} {
		if err := f.WriteContent(w, name, []byte("x")); err == nil {
			t.Errorf("%s was written", name)
		}
	}
	// A link in the content cannot carry a write out of it.
	outside := filepath.Join(t.TempDir(), "target")
	if err := os.Symlink(outside, filepath.Join(w.Content, "link.md")); err != nil {
		t.Fatal(err)
	}
	if err := f.WriteContent(w, "link.md", []byte("x")); err == nil {
		t.Error("a write through a link")
	}
	if _, err := os.Lstat(outside); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the link's target was written: %v", err)
	}
}

func TestBadHostNamesNameNoDirectory(t *testing.T) {
	f := files(t)
	for _, h := range []string{"", ".", "..", "../x", "a/b", ".work", "a..b", "A.example", "-x.example"} {
		if _, err := f.Fresh(h); !errors.Is(err, ErrBadHost) {
			t.Errorf("Fresh(%q): %v", h, err)
		}
		if err := f.Remove(h); !errors.Is(err, ErrBadHost) {
			t.Errorf("Remove(%q): %v", h, err)
		}
	}
}

// Once the build has exited, its output is the core's: the work directory is
// 0700, then every entry is set to 0755 or 0644.
func TestTheOutputIsTakenAwayThenNormalized(t *testing.T) {
	f := files(t)
	w, err := f.Fresh("blog.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(w.Out, "d"), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(w.Out, "d", "f.html"), []byte("x"), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(w.Out, "d"), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := f.TakeAway(w); err != nil {
		t.Fatal(err)
	}
	if m := mode(t, w.Dir); m.Perm() != 0o700 {
		t.Fatalf("taken away, the work directory is %v", m)
	}
	if err := f.Normalize(w); err != nil {
		t.Fatal(err)
	}
	if m := mode(t, filepath.Join(w.Out, "d")); m.Perm() != 0o755 {
		t.Errorf("a directory is %v", m)
	}
	if m := mode(t, filepath.Join(w.Out, "d", "f.html")); m.Perm() != 0o644 {
		t.Errorf("a file is %v", m)
	}
}

// A link in the output is refused, and what it points at is left alone.
func TestNormalizeFollowsNoLink(t *testing.T) {
	f := files(t)
	w, err := f.Fresh("blog.example.com")
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "host-file")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(w.Out, "a.html")); err != nil {
		t.Fatal(err)
	}
	if err := f.TakeAway(w); err != nil {
		t.Fatal(err)
	}
	if err := f.Normalize(w); err == nil {
		t.Fatal("a link was normalized")
	}
	if m := mode(t, target); m.Perm() != 0o600 {
		t.Fatalf("the link's target became %v", m)
	}
}

// An output that is itself a link is refused before it is looked into.
func TestAnOutputThatIsALinkIsRefused(t *testing.T) {
	f := files(t)
	w, err := f.Fresh("blog.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(w.Out); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), w.Out); err != nil {
		t.Fatal(err)
	}
	if err := f.TakeAway(w); err == nil {
		t.Fatal("an output that is a link was taken")
	}
}

// The swap: the first build is a rename, every later one an exchange, and a
// reader reading all the while never misses a page or reads a mix.
func TestTheSwapIsAtomic(t *testing.T) {
	f := files(t)
	if !build(t, f, "blog.example.com", "v0") {
		t.Fatal("the first build was not a first")
	}
	live := filepath.Join(f.Dir, "blog.example.com")
	var stop atomic.Bool
	const gap = 10 * time.Millisecond // builds are seconds apart; a page view is not
	var misses, mixes, reads atomic.Int64
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				// one directory handle per page view, as the serving process holds one per request
				start := time.Now()
				root, err := os.OpenRoot(live)
				if err != nil {
					misses.Add(1) // the live name always names a directory
					t.Logf("open: %v", err)
					continue
				}
				a, err1 := root.ReadFile("index.html")
				b, err2 := root.ReadFile("a/index.html")
				root.Close()
				reads.Add(1)
				held := time.Since(start)
				switch {
				case err1 == nil && err2 == nil && string(a) != string(b):
					mixes.Add(1) // two generations in one view: never
				case err1 != nil || err2 != nil:
					// An old generation is removed when the next build begins. A
					// view that held its directory longer than the gap between
					// builds may lose it; a faster one may not.
					if held < gap {
						misses.Add(1)
						t.Logf("held %v: %v / %v", held, err1, err2)
					}
				}
			}
		}()
	}
	for i := 1; i <= 100; i++ {
		if build(t, f, "blog.example.com", "v"+string(rune('0'+i%10))) {
			t.Fatal("a later build was a first")
		}
		time.Sleep(gap)
	}
	stop.Store(true)
	wg.Wait()
	if misses.Load() != 0 || mixes.Load() != 0 || reads.Load() == 0 {
		t.Fatalf("of %d views, %d missed a page and %d read two generations", reads.Load(), misses.Load(), mixes.Load())
	}
	// The old pages wait, closed off, for the next build; the input is gone.
	old := filepath.Join(f.Dir, workDir, "blog.example.com")
	if m := mode(t, old); m.Perm() != 0o700 {
		t.Errorf("the old pages' directory is %v", m)
	}
	if _, err := os.Lstat(filepath.Join(old, "content")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the input is left: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(old, "out", "index.html")); err != nil {
		t.Errorf("the old pages: %v", err)
	}
	if m := mode(t, live); !m.IsDir() || m.Perm() != 0o755 {
		t.Errorf("the live directory is %v", m)
	}
	if err := f.Remove("blog.example.com"); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{live, old} {
		if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("removed, %s is left: %v", p, err)
		}
	}
}

// A swap onto a live name that is not a directory is refused.
func TestASwapOntoSomethingElseIsRefused(t *testing.T) {
	f := files(t)
	w, err := f.Fresh("blog.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(f.Dir, "blog.example.com")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Swap(w); err == nil {
		t.Fatal("swapped onto a link")
	}
}

// TestTheCoresUmaskDoesNotCloseABuild: the core's unit runs with a umask of
// 0077. What a build reads (the builder is another user) and what the serving
// process reads (another again) must be open to them all the same: the work
// directories, the input and its directories, the pages, the manifest and the
// marker of a site taken down.
func TestTheCoresUmaskDoesNotCloseABuild(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	f := files(t)
	w, err := f.Fresh("blog.example.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"build.json", "docs/guides/install/index.md", "docs/guides/install/img/flow.png"} {
		if err := f.WriteContent(w, name, []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	want := map[string]fs.FileMode{
		f.Dir: 0o755, w.Dir: 0o755, w.Content: 0o755, w.Out: 0o755,
		filepath.Join(w.Content, "build.json"):                       0o644,
		filepath.Join(w.Content, "docs"):                             0o755,
		filepath.Join(w.Content, "docs/guides"):                      0o755,
		filepath.Join(w.Content, "docs/guides/install"):              0o755,
		filepath.Join(w.Content, "docs/guides/install/index.md"):     0o644,
		filepath.Join(w.Content, "docs/guides/install/img"):          0o755,
		filepath.Join(w.Content, "docs/guides/install/img/flow.png"): 0o644,
	}
	for p, m := range want {
		if got := mode(t, p).Perm(); got != m {
			t.Errorf("%s: mode %v; want %v", p, got, m)
		}
	}
	// The builder's part: a page, written under a umask of its own.
	if err := os.WriteFile(filepath.Join(w.Out, "index.html"), []byte("<h1>x</h1>"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := f.TakeAway(w); err != nil {
		t.Fatal(err)
	}
	if err := f.Normalize(w); err != nil {
		t.Fatal(err)
	}
	if err := f.WriteManifest(w, Manifest{Build: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Swap(w); err != nil {
		t.Fatal(err)
	}
	live := filepath.Join(f.Dir, "blog.example.com")
	for p, m := range map[string]fs.FileMode{live: 0o755, filepath.Join(live, "index.html"): 0o644, filepath.Join(live, ManifestName): 0o644} {
		if got := mode(t, p).Perm(); got != m {
			t.Errorf("%s: mode %v; want %v", p, got, m)
		}
	}
	if err := f.TakeDown("blog.example.com"); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{filepath.Join(f.Dir, downDir), filepath.Join(f.Dir, downDir, "blog.example.com")} {
		if got := mode(t, p).Perm(); got != 0o755 {
			t.Errorf("%s: mode %v; want 0755", p, got)
		}
	}
}
