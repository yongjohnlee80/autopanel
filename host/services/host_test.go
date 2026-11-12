package services

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/yongjohnlee80/autopanel/core/services"
)

func TestParsing(t *testing.T) {
	for out, want := range map[string][2]int{
		"podman version 5.4.2\n":      {5, 4},
		"podman version 4.3.1":        {4, 3},
		"podman version 4.9.4-rhel\n": {4, 9},
	} {
		if major, minor, ok := parseVersion(out); !ok || [2]int{major, minor} != want {
			t.Errorf("parseVersion(%q) = %d.%d, %v", out, major, minor, ok)
		}
	}
	for _, out := range []string{"", "podman", "podman version five"} {
		if _, _, ok := parseVersion(out); ok {
			t.Errorf("parseVersion(%q) read a version", out)
		}
	}

	r := parseShow("MemoryCurrent=9437184\nActiveState=active\nSubState=running\n")
	if r != (services.Running{Active: "active", Sub: "running", MemoryBytes: 9437184}) {
		t.Errorf("parseShow = %+v", r)
	}
	if r := parseShow("MemoryCurrent=[not set]\nActiveState=failed\nSubState=failed\n"); r.Active != "failed" || r.MemoryBytes != 0 {
		t.Errorf("parseShow of a failed unit = %+v", r)
	}

	got := logLines("2026-11-12T10:00:00+00:00 host turn[9]: started\n\x1b[31mred\x1b[0m\tx\n\n")
	if want := []string{"2026-11-12T10:00:00+00:00 host turn[9]: started", "[31mred[0m x"}; !reflect.DeepEqual(got, want) {
		t.Errorf("logLines = %q", got)
	}
}

func TestSubIDsAreGivenAboveEveryRange(t *testing.T) {
	uids := "johno:100000:65536\nap-mail:165536:65536\n# a comment\nbroken\n"
	gids := "johno:100000:65536\nap-mail:231072:65536\n"
	if start, has := nextSubID("ap-turn", uids, gids); has || start != 296608 {
		t.Errorf("a new user = %d, %v; want the first id above both tables", start, has)
	}
	if _, has := nextSubID("ap-mail", uids, gids); !has {
		t.Error("a user in both tables was given a second range")
	}
	if start, has := nextSubID("ap-turn", "", ""); has || start != 100000 {
		t.Errorf("empty tables = %d, %v", start, has)
	}
}

// TestFilesStayInsideTheServicesDirectory: the directory is the service's
// own, so a link planted in it must not send a write by root elsewhere.
func TestFilesStayInsideTheServicesDirectory(t *testing.T) {
	home, outside := t.TempDir(), t.TempDir()
	uid, gid := os.Getuid(), os.Getgid()
	files := []services.File{
		{Path: "config/turnserver.conf", Mode: 0o400, Body: []byte("one")},
		{Path: ".config/containers/systemd/turn.container", Mode: 0o600, Body: []byte("unit")},
	}
	if err := writeFiles(home, uid, gid, files); err != nil {
		t.Fatal(err)
	}
	files[0].Body = []byte("two") // a second deploy replaces a read-only file
	if err := writeFiles(home, uid, gid, files); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(home, "config/turnserver.conf"))
	fi, _ := os.Stat(filepath.Join(home, "config/turnserver.conf"))
	if err != nil || string(b) != "two" || fi.Mode().Perm() != 0o400 {
		t.Fatalf("the file = %q, %v, mode %v", b, err, fi.Mode().Perm())
	}
	if di, _ := os.Stat(filepath.Join(home, ".config/containers")); di.Mode().Perm() != 0o700 {
		t.Fatalf("a directory on the way is %v", di.Mode().Perm())
	}
	if entries, _ := os.ReadDir(filepath.Join(home, "config")); len(entries) != 1 {
		t.Fatalf("the directory holds %d entries; a temporary file was left", len(entries))
	}

	for _, bad := range []string{"../escape", "/etc/passwd", ".", "config/../../escape"} {
		if err := writeFiles(home, uid, gid, []services.File{{Path: bad, Mode: 0o600}}); err == nil {
			t.Errorf("a file at %q was written", bad)
		}
	}
	// The service replaces its config directory with a link to somewhere else.
	if err := os.RemoveAll(filepath.Join(home, "config")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(home, "config")); err != nil {
		t.Fatal(err)
	}
	if err := writeFiles(home, uid, gid, files[:1]); err == nil {
		t.Error("a write through a link out of the directory succeeded")
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Fatalf("the write landed outside: %v", entries)
	}
	// And a link in place of the file itself is replaced, not followed.
	if err := os.Remove(filepath.Join(home, "config")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(home, "config"), 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(outside, "victim")
	if err := os.WriteFile(target, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(home, "config/turnserver.conf")); err != nil {
		t.Fatal(err)
	}
	if err := writeFiles(home, uid, gid, files[:1]); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(target); string(b) != "untouched" {
		t.Fatalf("the link's target now holds %q", b)
	}
	if fi, err := os.Lstat(filepath.Join(home, "config/turnserver.conf")); err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("the file after the write: %v, %v", fi, err)
	}
}
