//go:build linux

package site

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	hostservices "github.com/yongjohnlee80/autopanel/host/services"
)

const testDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// fakeHost records what the builder asks of the host.
type fakeHost struct {
	users  []string
	has    bool
	pulled string
	digest string
	props  []string
	argv   []string
}

func (f *fakeHost) EnsureUser(_ context.Context, name string) error {
	f.users = append(f.users, name)
	return nil
}
func (f *fakeHost) HasImage(context.Context, string, string) (bool, error) { return f.has, nil }
func (f *fakeHost) Pull(_ context.Context, _, ref string) (string, error) {
	f.pulled = ref
	return f.digest, nil
}
func (f *fakeHost) Transient(_ context.Context, name string, props []string, argv ...string) ([]byte, error) {
	f.props, f.argv = props, argv
	return []byte("line 1\nline 2\n"), nil
}

func TestTheBuildRunsWithEveryLimit(t *testing.T) {
	h := &fakeHost{}
	b := Builder{Host: h, Image: "ghcr.io/example/kit@" + testDigest}
	w := Work{Host: "blog.example.com", Dir: "/w", Content: "/w/content", Out: "/w/out"}
	log, err := b.Build(context.Background(), w, "/themes/mine")
	if err != nil || log != "line 1\nline 2" {
		t.Fatalf("%q, %v", log, err)
	}
	for _, want := range []string{"--rm", "--pull=never", "--network=none", "--read-only", "--cap-drop=all",
		"--security-opt=no-new-privileges", "--memory=512m", "--memory-swap=512m", "--pids-limit=256",
		"--timeout=120", "--ulimit=fsize=10485760:10485760", "--user=0:0", "--env=ASTRO_TELEMETRY_DISABLED=1",
		"--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m",
		"--volume=/w/content:/site/src/content:ro,nosuid,nodev,noexec",
		"--volume=/w/out:/site/dist:rw,nosuid,nodev,noexec",
		"--volume=/themes/mine:/site/src/theme:ro,nosuid,nodev,noexec"} {
		if !slices.Contains(h.argv, want) {
			t.Errorf("the build lacks %s:\n%s", want, strings.Join(h.argv, " "))
		}
	}
	if h.argv[len(h.argv)-1] != b.Image {
		t.Errorf("the image is not last: %v", h.argv)
	}
	if !slices.Contains(h.props, "MemoryMax="+unitMemoryMax) || !slices.Contains(h.props, "MemorySwapMax=0") {
		t.Errorf("the unit's limits: %v", h.props)
	}
	// No theme: no theme mount.
	if _, err := b.Build(context.Background(), w, ""); err != nil {
		t.Fatal(err)
	}
	for _, a := range h.argv {
		if strings.Contains(a, "/site/src/theme") {
			t.Errorf("a theme mount with no theme: %s", a)
		}
	}
}

func TestTheImageIsNamedByItsDigest(t *testing.T) {
	for _, img := range []string{"kit:latest", "kit", "kit@sha256:abc", "kit:1@sha256:" + strings.Repeat("A", 64), "--privileged@" + testDigest} {
		h := &fakeHost{}
		b := Builder{Host: h, Image: img}
		if err := b.Prepare(context.Background()); !errors.Is(err, ErrImage) {
			t.Errorf("Prepare(%q): %v", img, err)
		}
		if _, err := b.Build(context.Background(), Work{}, ""); !errors.Is(err, ErrImage) {
			t.Errorf("Build(%q): %v", img, err)
		}
		if len(h.users) != 0 || h.argv != nil {
			t.Errorf("%q reached the host", img)
		}
	}
}

func TestPrepareMakesTheUserAndPullsByDigest(t *testing.T) {
	img := "ghcr.io/example/kit@" + testDigest
	h := &fakeHost{digest: testDigest}
	if err := (Builder{Host: h, Image: img}).Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(h.users, []string{"site"}) || h.pulled != img {
		t.Fatalf("users %v, pulled %q", h.users, h.pulled)
	}
	h = &fakeHost{digest: "sha256:" + strings.Repeat("f", 64)}
	if err := (Builder{Host: h, Image: img}).Prepare(context.Background()); err == nil {
		t.Fatal("an image that resolved to another digest")
	}
	h = &fakeHost{has: true}
	if err := (Builder{Host: h, Image: img}).Prepare(context.Background()); err != nil || h.pulled != "" {
		t.Fatalf("an image held is pulled again: %q, %v", h.pulled, err)
	}
}

// TestARealBuild runs a build as the builder's own user on the test VM, as
// root (AUTOPANEL_TEST_BUILDER=1, with sudo). The image is a small public
// one by digest (AUTOPANEL_TEST_BUILDER_IMAGE); its command tries what a
// hostile theme would: the network, a write outside the output, a file over
// the limit. Never run on a workstation.
func TestARealBuild(t *testing.T) {
	if os.Getenv("AUTOPANEL_TEST_BUILDER") != "1" || os.Getuid() != 0 {
		t.Skip("the builder's own test: AUTOPANEL_TEST_BUILDER=1, as root, on the test VM")
	}
	img := os.Getenv("AUTOPANEL_TEST_BUILDER_IMAGE")
	h := hostservices.New("/var/lib/autopanel-services", t.TempDir())
	b := Builder{Host: h, Image: img, Command: []string{"/bin/sh", "-c", `
		set -u
		cat /site/src/content/in.md > /site/dist/index.html || echo "READ FAILED"
		echo "<p>built</p>" >> /site/dist/index.html
		if wget -q -T 3 -O /tmp/x http://1.1.1.1/ 2>/dev/null; then echo "NETWORK REACHED"; else echo "no network"; fi
		if touch /etc/x 2>/dev/null; then echo "ROOT WRITABLE"; else echo "root read-only"; fi
		if touch /site/src/content/x 2>/dev/null; then echo "INPUT WRITABLE"; else echo "input read-only"; fi
		if dd if=/dev/zero of=/site/dist/big bs=1M count=11 2>/dev/null; then echo "BIG FILE WRITTEN"; else echo "file size bounded"; fi
		rm -f /site/dist/big
		echo "uid $(id -u)"
	`}}
	ctx := context.Background()
	if err := b.Prepare(ctx); err != nil {
		t.Fatal(err)
	}
	usr, err := exec.Command("id", "-u", "ap-site").Output()
	if err != nil {
		t.Fatal(err)
	}
	var uid, gid int
	if _, err := fmtSscan(strings.TrimSpace(string(usr)), &uid); err != nil {
		t.Fatal(err)
	}
	grp, _ := exec.Command("id", "-g", "ap-site").Output()
	if _, err := fmtSscan(strings.TrimSpace(string(grp)), &gid); err != nil {
		t.Fatal(err)
	}
	base, err := os.MkdirTemp("/var/tmp", "ap-site-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	if err := os.Chmod(base, 0o755); err != nil { // the builder passes through to its output
		t.Fatal(err)
	}
	f := Files{Dir: filepath.Join(base, "site"), Owner: Owner{0, 0}, Builder: Owner{uid, gid}}
	w, err := f.Fresh("blog.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.WriteContent(w, "in.md", []byte("<h1>in</h1>\n")); err != nil {
		t.Fatal(err)
	}
	log, err := b.Build(ctx, w, "")
	t.Logf("the build said:\n%s", log)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"no network", "root read-only", "input read-only", "file size bounded"} {
		if !strings.Contains(log, want) {
			t.Errorf("the build did not report %q", want)
		}
	}
	for _, bad := range []string{"NETWORK REACHED", "ROOT WRITABLE", "INPUT WRITABLE", "BIG FILE WRITTEN", "READ FAILED"} {
		if strings.Contains(log, bad) {
			t.Errorf("the build reported %q", bad)
		}
	}
	if err := f.TakeAway(w); err != nil {
		t.Fatal(err)
	}
	if err := f.Normalize(w); err != nil {
		t.Fatal(err)
	}
	page, err := os.ReadFile(filepath.Join(w.Out, "index.html"))
	if err != nil || string(page) != "<h1>in</h1>\n<p>built</p>\n" {
		t.Fatalf("the page: %q, %v", page, err)
	}
	if _, err := f.Swap(w); err != nil {
		t.Fatal(err)
	}
}

func fmtSscan(s string, v *int) (int, error) { return fmt.Sscan(s, v) }
