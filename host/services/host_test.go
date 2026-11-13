package services

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

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

	// systemctl show answers one block per unit, with a blank line between.
	show := "Id=chat-synapse.service\nMemoryCurrent=9437184\nActiveState=active\nSubState=running\nNRestarts=2\nActiveEnterTimestamp=@1700000000\nCPUUsageNSec=801710000\n" +
		"\nId=chat-element.service\nMemoryCurrent=[not set]\nActiveState=failed\nSubState=failed\nNRestarts=0\nActiveEnterTimestamp=\nCPUUsageNSec=[not set]\n"
	units := parseShow(show)
	if r := units["chat-synapse.service"]; r != (services.Running{Active: "active", Sub: "running", MemoryBytes: 9437184, Restarts: 2, Since: 1700000000, CPUNanos: 801710000}) {
		t.Errorf("parseShow of a running unit = %+v", r)
	}
	if r := units["chat-element.service"]; len(units) != 2 || r != (services.Running{Active: "failed", Sub: "failed"}) {
		t.Errorf("parseShow of a unit that never ran = %+v; a property with no value reads as zero", r)
	}

	health := parseHealth("chat-synapse\tUp 2 minutes (healthy)\nchat-element\tUp 3 seconds (starting)\nchat-db\tUp 2 hours\nchat-x\tExited (1) 2 hours ago\nchat-y\tUp 1 minute (unhealthy)\n")
	if want := map[string]string{"chat-synapse": "healthy", "chat-element": "starting", "chat-y": "unhealthy"}; !reflect.DeepEqual(health, want) {
		t.Errorf("parseHealth = %v; want %v", health, want)
	}

	if first, count := subRange("ap-chat", "johno:100000:65536\nap-chat:165536:65536\n"); first != 165536 || count != 65536 {
		t.Errorf("subRange = %d, %d", first, count)
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

// tree writes files under dir, each with its mode.
func tree(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for file, text := range files {
		p := filepath.Join(dir, file)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		return "<" + err.Error() + ">"
	}
	return string(b)
}

// TestADefinitionIsStagedThenCommitted: the files an apply moves are the ones
// the review hashed, and what a container wrote is never written again.
func TestADefinitionIsStagedThenCommitted(t *testing.T) {
	ctx := context.Background()
	root, defs := filepath.Join(t.TempDir(), "services"), filepath.Join(t.TempDir(), "stacks")
	h := New(root, defs)
	tree(t, defs, map[string]string{
		"chat/compose.yaml": "services: {}\n", "chat/.env": "TOKEN=secret\n",
		"chat/element-config.json": "{}\n", "chat/conf/a.conf": "a\n", "chat/conf/sub/b.conf": "b\n",
		"chat/not-mounted.txt": "left alone\n",
		"empty/readme.txt":     "no compose file here\n",
	})
	if err := os.Mkdir(filepath.Join(defs, "Not-A-Name"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(defs, "chat/.env"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := h.Available(ctx); err != nil || !reflect.DeepEqual(got, []string{"chat"}) {
		t.Fatalf("Available = %v, %v; want the one folder with a compose.yaml", got, err)
	}
	if _, _, err := h.Stage(ctx, "empty"); !errors.Is(err, services.ErrNoDefinition) {
		t.Fatalf("staging a folder with no compose.yaml = %v", err)
	}
	if _, _, err := h.Stage(ctx, "nothing"); !errors.Is(err, services.ErrNoDefinition) {
		t.Fatalf("staging a folder that is not there = %v", err)
	}

	compose, env, err := h.Stage(ctx, "chat")
	if err != nil || string(compose) != "services: {}\n" || string(env) != "TOKEN=secret\n" {
		t.Fatalf("Stage = %q, %q, %v", compose, env, err)
	}
	// The definition changes after it was staged: the staged copy does not.
	tree(t, defs, map[string]string{"chat/compose.yaml": "services: {changed: {}}\n"})
	files, missing, links, err := h.StagePaths(ctx, "chat", []string{"element-config.json", "conf", "gone.txt"})
	if err != nil || !reflect.DeepEqual(missing, []string{"gone.txt"}) || len(links) != 0 {
		t.Fatalf("StagePaths: missing %v, links %v, %v", missing, links, err)
	}
	m := services.NewManifest(files)
	var paths []string
	modes := map[string]uint32{}
	for _, f := range m.Files {
		paths = append(paths, f.Path)
		modes[f.Path] = f.Mode
	}
	if want := []string{".env", "compose.yaml", "conf/a.conf", "conf/sub/b.conf", "element-config.json"}; !reflect.DeepEqual(paths, want) {
		t.Fatalf("the staged files = %v; want %v", paths, want)
	}
	if modes[".env"] != 0o400 || modes["compose.yaml"] != 0o400 || modes["element-config.json"] != 0o444 {
		t.Errorf("the modes = %v; .env is its user's alone, and no managed file can be written", modes)
	}
	if st, _ := os.Stat(h.staging("chat")); st.Mode().Perm() != 0o700 {
		t.Errorf("the staging folder is %v; it is root's alone", st.Mode().Perm())
	}
	if got := read(t, filepath.Join(h.staging("chat"), "compose.yaml")); got != "services: {}\n" {
		t.Errorf("the staged compose file = %q; it is what was read, not what the folder holds now", got)
	}

	// The stack's own folder: a container wrote its database there.
	home := h.home("chat")
	tree(t, home, map[string]string{"stack/synapse/homeserver.db": "the history", "stack/old.conf": "stale", "stack/.autopanel/gone.env": "X=1\n"})
	present, links, err := h.Look(ctx, "chat", []string{"synapse", "old.conf", "new"})
	if err != nil || !present["synapse"] || !present["old.conf"] || present["new"] || len(links) != 0 {
		t.Fatalf("Look = %v, %v, %v", present, links, err)
	}
	// The core runs with a umask that takes every right from group and others.
	defer syscall.Umask(syscall.Umask(0o077))
	c := services.Commit{Managed: paths, Stale: []string{"old.conf"}, Data: []string{"synapse", "media"},
		Generated: []services.File{{Path: "stack/.autopanel/web.env", Mode: 0o400, Body: []byte("TOKEN=secret\n")}}}
	if err := commit(h.staging("chat"), home, os.Getuid(), os.Getgid(), c); err != nil {
		t.Fatal(err)
	}
	stack := filepath.Join(home, "stack")
	for file, want := range map[string]string{
		"compose.yaml": "services: {}\n", ".env": "TOKEN=secret\n", "element-config.json": "{}\n", "conf/sub/b.conf": "b\n",
		"synapse/homeserver.db": "the history", ".autopanel/web.env": "TOKEN=secret\n",
	} {
		if got := read(t, filepath.Join(stack, file)); got != want {
			t.Errorf("%s = %q; want %q", file, got, want)
		}
	}
	for _, gone := range []string{"old.conf", ".autopanel/gone.env", "not-mounted.txt"} {
		if _, err := os.Lstat(filepath.Join(stack, gone)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s is in the stack's folder: %v", gone, err)
		}
	}
	if st, err := os.Stat(filepath.Join(stack, "media")); err != nil || !st.IsDir() {
		t.Errorf("a data path that was not there was not made: %v", err)
	}
	// A container's own user reads a mounted folder by its mode, whatever the
	// core's umask was when it made the folder; the stack's folder itself is
	// its user's alone.
	for dir, want := range map[string]os.FileMode{"conf": 0o755, "conf/sub": 0o755, "media": 0o755, "": 0o700} {
		if st, err := os.Stat(filepath.Join(stack, dir)); err != nil || st.Mode().Perm() != want {
			t.Errorf("the folder %q is %v, %v; want %v", dir, st.Mode().Perm(), err, want)
		}
	}
	if st, _ := os.Stat(filepath.Join(stack, ".env")); st.Mode().Perm() != 0o400 {
		t.Errorf(".env is %v in the stack's folder", st.Mode().Perm())
	}
	if _, err := os.Lstat(h.staging("chat")); !errors.Is(err, os.ErrNotExist) {
		t.Error("the staged copy, with its .env, was left after the commit")
	}

	// A second commit replaces a managed file that cannot be written, and
	// still leaves the data as it is.
	tree(t, defs, map[string]string{"chat/element-config.json": "{\"v\": 2}\n"})
	if _, _, err := h.Stage(ctx, "chat"); err != nil {
		t.Fatal(err)
	}
	files, _, _, err = h.StagePaths(ctx, "chat", []string{"element-config.json"})
	if err != nil {
		t.Fatal(err)
	}
	if next := services.NewManifest(files); next.SHA256 == m.SHA256 {
		t.Fatal("a changed file left the manifest's hash as it was")
	} else if err := commit(h.staging("chat"), home, os.Getuid(), os.Getgid(), services.Commit{Managed: []string{"compose.yaml", ".env", "element-config.json"}, Data: []string{"synapse"}}); err != nil {
		t.Fatal(err)
	}
	if got := read(t, filepath.Join(stack, "element-config.json")); got != "{\"v\": 2}\n" {
		t.Errorf("the replaced file = %q", got)
	}
	if got := read(t, filepath.Join(stack, "synapse/homeserver.db")); got != "the history" {
		t.Errorf("the data after a second commit = %q", got)
	}
	if !h.Changed(ctx, "chat", m, time.Now().Add(time.Hour)) {
		t.Error("Changed does not see a file whose size differs from the manifest's")
	}
}

// TestALinkInADefinitionIsNotFollowed: a link is named, and nothing it points
// at is staged. One planted in the stack's own folder is not written through.
func TestALinkInADefinitionIsNotFollowed(t *testing.T) {
	ctx := context.Background()
	root, defs, outside := filepath.Join(t.TempDir(), "services"), filepath.Join(t.TempDir(), "stacks"), t.TempDir()
	h := New(root, defs)
	tree(t, outside, map[string]string{"shadow": "root:x\n", "dir/inner": "x\n"})
	tree(t, defs, map[string]string{"s/compose.yaml": "services: {}\n", "s/conf/ok.conf": "ok\n"})
	for link, target := range map[string]string{"s/passwd": filepath.Join(outside, "shadow"), "s/conf/evil": filepath.Join(outside, "shadow"), "s/linkdir": filepath.Join(outside, "dir")} {
		if err := os.Symlink(target, filepath.Join(defs, link)); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := h.Stage(ctx, "s"); err != nil {
		t.Fatal(err)
	}
	files, missing, links, err := h.StagePaths(ctx, "s", []string{"passwd", "conf", "linkdir/inner"})
	if err != nil || len(missing) != 0 {
		t.Fatalf("StagePaths = missing %v, %v", missing, err)
	}
	sort.Strings(links)
	if want := []string{"conf/evil", "linkdir/inner", "passwd"}; !reflect.DeepEqual(links, want) {
		t.Errorf("the links = %v; want %v", links, want)
	}
	for _, f := range files {
		if f.Path != "compose.yaml" && f.Path != "conf/ok.conf" {
			t.Errorf("%s was staged", f.Path)
		}
	}

	home := h.home("s")
	tree(t, home, map[string]string{"stack/keep": "x"})
	if err := os.Symlink(outside, filepath.Join(home, "stack/conf")); err != nil {
		t.Fatal(err)
	}
	if _, links, err := h.Look(ctx, "s", []string{"conf/ok.conf", "keep"}); err != nil || !reflect.DeepEqual(links, []string{"conf/ok.conf"}) {
		t.Errorf("Look through a planted link = %v, %v", links, err)
	}
	if _, _, err := h.Stage(ctx, "s"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := h.StagePaths(ctx, "s", []string{"conf"}); err != nil {
		t.Fatal(err)
	}
	if err := commit(h.staging("s"), home, os.Getuid(), os.Getgid(), services.Commit{Managed: []string{"compose.yaml", "conf/ok.conf"}}); err == nil {
		t.Error("a commit through a link out of the stack's folder succeeded")
	}
	if _, err := os.Lstat(filepath.Join(outside, "ok.conf")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the commit wrote outside the stack's folder")
	}
}

func TestADefinitionIsBounded(t *testing.T) {
	ctx := context.Background()
	root, defs := filepath.Join(t.TempDir(), "services"), filepath.Join(t.TempDir(), "stacks")
	h := New(root, defs)
	files := map[string]string{"big/compose.yaml": "services: {}\n"}
	for i := 0; i < maxFiles+1; i++ {
		files["big/conf/"+strconv.Itoa(i)] = "x"
	}
	tree(t, defs, files)
	if _, _, err := h.Stage(ctx, "big"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := h.StagePaths(ctx, "big", []string{"conf"}); !errors.Is(err, services.ErrTooLarge) {
		t.Errorf("a definition of %d files = %v; want ErrTooLarge", maxFiles+1, err)
	}
	tree(t, defs, map[string]string{"huge/compose.yaml": strings.Repeat("#", maxText+1)})
	if _, _, err := h.Stage(ctx, "huge"); !errors.Is(err, services.ErrTooLarge) {
		t.Errorf("a compose file over the bound = %v; want ErrTooLarge", err)
	}
}
