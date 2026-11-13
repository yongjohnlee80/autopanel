package ui

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/yongjohnlee80/golib/tui/decl/decltest"

	"github.com/yongjohnlee80/autopanel/core/services"
)

// The hashes the fake reviews answer: the first 12 digits are what a review
// shows.
const (
	blogSHA  = "3f2a9c41d07b8e55aa10c3d2e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3"
	blogSHA2 = "77c0ffee1234aa10c3d2e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5"
	webSHA   = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
	cacheSHA = "0c0ffee0c0ffee0c0ffee0c0ffee0c0ffee0c0ffee0c0ffee0c0ffee0c0ffee0"
)

// someStacks are three stacks in three states: web runs two containers, one
// of which a person stopped, and its definition changed since; cache is
// prepared; old has an apply that stopped at its pull.
func someStacks() []services.View {
	return []services.View{
		{Name: "web", State: "deployed", User: "ap-web", SHA256: webSHA, Changed: true, Containers: []services.Container{
			{Service: "app", Image: "docker.io/library/nginx:1.27", Health: "healthy",
				Ports:   []services.PortUse{{Proto: "tcp", From: 8080, To: 8080}},
				Running: services.Running{Active: "active", Sub: "running", MemoryBytes: 21 << 20, Restarts: 2}},
			// systemd calls a container that was stopped by hand failed
			{Service: "db", Image: "docker.io/library/postgres:16", Stopped: true, Ports: []services.PortUse{},
				Running: services.Running{Active: "failed", Sub: "failed"}},
		}},
		{Name: "cache", State: "prepared", User: "ap-cache", Containers: []services.Container{}},
		{Name: "old", State: "incomplete", Step: "pull", User: "ap-old", Containers: []services.Container{}},
	}
}

// warned is a review with warnings and no refusal.
func warned(sha string) services.Review {
	return services.Review{
		SHA256: sha,
		Files:  []services.Input{{Path: ".env"}, {Path: "compose.yaml"}},
		Containers: []services.Planned{{Service: "app", Image: "docker.io/library/nginx:1.27", Network: "private",
			Ports: []string{"127.0.0.1:8080:80/tcp"}, Mounts: []string{"site:/srv:ro"}}},
		Findings: []services.Finding{
			{ID: "image-by-tag", Severity: services.Warning, Service: "app", Detail: "docker.io/library/nginx:1.27"},
			{ID: "no-memory-limit", Severity: services.Warning, Service: "app"},
			{ID: "reach", Severity: services.Warning},
		},
		Removes: []string{},
	}
}

// withStacks is a fake client whose daemon has someStacks, one folder to add
// a stack from, and a review of each.
func withStacks() *fakeClient {
	f := newFakeClient()
	f.stacks = someStacks()
	f.folders = []services.Folder{{Name: "blog"}}
	web := warned(webSHA)
	web.Removes = []string{"worker"}
	f.reviews = map[string]services.Review{"blog": warned(blogSHA), "web": web, "cache": warned(cacheSHA)}
	return f
}

func (f *fakeClient) Stacks(context.Context) ([]services.View, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]services.View(nil), f.stacks...), nil
}

func (f *fakeClient) AvailableStacks(context.Context) ([]services.Folder, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]services.Folder(nil), f.folders...), nil
}

func (f *fakeClient) CheckStack(_ context.Context, name string) (services.Review, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checks = append(f.checks, name)
	r, ok := f.reviews[name]
	if !ok {
		return services.Review{}, services.ErrNoDefinition
	}
	return r, nil
}

// ApplyStack records the ask. A new stack it adds or prepares is then in the
// list, and a prepared one it adds is deployed.
func (f *fakeClient) ApplyStack(_ context.Context, verb, name, accept string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applies = append(f.applies, verb+" "+name+" "+accept)
	if len(f.applyErrs) > 0 {
		err := f.applyErrs[0]
		f.applyErrs = f.applyErrs[1:]
		return err
	}
	state := map[string]string{"prepare": "prepared", "add": "deployed", "apply": "deployed"}[verb]
	for i := range f.stacks {
		if f.stacks[i].Name == name {
			f.stacks[i].State = state
			return nil
		}
	}
	f.stacks = append(f.stacks, services.View{Name: name, State: state, User: "ap-" + name, Containers: []services.Container{}})
	return nil
}

func (f *fakeClient) PullStack(_ context.Context, name, service string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pulls = append(f.pulls, unitName(name, service))
	return nil
}

func (f *fakeClient) StackUnit(_ context.Context, action, name, service string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unitAsks = append(f.unitAsks, action+" "+unitName(name, service))
	return nil
}

func (f *fakeClient) RemoveStack(_ context.Context, name string, purge bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	ask := name
	if purge {
		ask += " purge"
	}
	f.removals = append(f.removals, ask)
	for i, s := range f.stacks {
		if s.Name == name {
			f.stacks = append(f.stacks[:i], f.stacks[i+1:]...)
			break
		}
	}
	return nil
}

func (f *fakeClient) StackLogs(_ context.Context, name, service string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	who := unitName(name, service)
	f.logAsks = append(f.logAsks, who)
	return []string{"Nov 12 09:00:01 host " + who + "[812]: listening on 0.0.0.0:8080", "Nov 12 09:00:02 host " + who + "[812]: ready"}, nil
}

// asked is what the fake daemon was asked to do to stacks.
type asked struct {
	checks, applies, pulls, units, removals, logs []string
}

func (f *fakeClient) asked() asked {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := func(s []string) []string { return append([]string{}, s...) }
	return asked{checks: c(f.checks), applies: c(f.applies), pulls: c(f.pulls), units: c(f.unitAsks), removals: c(f.removals), logs: c(f.logAsks)}
}

// same fails the test unless got is want; nil and empty are the same.
func same(t *testing.T, what string, got, want []string) {
	t.Helper()
	if len(got) == 0 && len(want) == 0 {
		return
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s = %q, want %q", what, got, want)
	}
}

// openStacks opens the stacks panel through the menu bar: Alt+S opens
// Services, s is "Stacks…".
func openStacks(t *testing.T, s *decltest.Screen, want string) {
	t.Helper()
	s.WaitForText(t, "CA LE staging")
	s.Keys(t, decltest.Alt('s'))
	s.WaitForText(t, "Stacks…")
	s.Keys(t, decltest.Rune('s'))
	s.WaitForText(t, want)
}

// openAdd opens "Add a stack…" through the menu bar: Alt+S, then a.
func openAdd(t *testing.T, s *decltest.Screen) {
	t.Helper()
	s.WaitForText(t, "CA LE staging")
	s.Keys(t, decltest.Alt('s'))
	s.WaitForText(t, "Add a stack…")
	s.Keys(t, decltest.Rune('a'))
}

// gone waits for text to leave the screen.
func gone(t *testing.T, s *decltest.Screen, text string) {
	t.Helper()
	s.WaitFor(t, "\""+text+"\" to leave the screen", func(sc string) bool { return !strings.Contains(sc, text) })
}

func TestPortsText(t *testing.T) {
	got := portsText([]services.PortUse{{Proto: "udp", From: 3478, To: 3478}, {Proto: "udp", From: 49152, To: 49999}})
	if got != "udp 3478, udp 49152-49999" {
		t.Errorf("portsText = %q", got)
	}
	if got := portsText(nil); got != "-" {
		t.Errorf("portsText(nil) = %q", got)
	}
}

// TestShortImage: Docker Hub's prefix goes, the tag stays, another registry
// stays, and a digest is cut short.
func TestShortImage(t *testing.T) {
	for in, want := range map[string]string{
		"docker.io/library/nginx:1.27":              "nginx:1.27",
		"docker.io/example/app:4.6":                 "example/app:4.6",
		"registry.example.com/team/app:v2":          "registry.example.com/team/app:v2",
		"docker.io/library/redis@sha256:" + blogSHA: "redis@sha256:3f2a9c41d07b",
		"registry.example.com/library/tool:1":       "registry.example.com/library/tool:1",
		"":                                          "-",
	} {
		if got := shortImage(in); got != want {
			t.Errorf("shortImage(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestStackRows: a row per container; one row, with its state in words, for a
// stack that has no container yet; "stopped" for a container a person
// stopped, whatever systemd says; a mark on a stack whose definition changed.
func TestStackRows(t *testing.T) {
	views := append(someStacks(),
		services.View{Name: "relay", State: "legacy", Containers: []services.Container{}},
		services.View{Name: "new", State: "deploying", Containers: []services.Container{}},
		services.View{Name: "going", State: "removing", Containers: []services.Container{
			{Service: "app", Image: "registry.example.com/app:1", Running: services.Running{Active: "active", Sub: "running"}}}})
	rows, names := stackRows(inEnglish{}, views)
	want := []map[string]string{
		{"key": "web/app", "stack": "web*", "service": "app", "state": "active (running)", "health": "healthy", "memory": "21.0 MiB",
			"restarts": "2", "ports": "tcp 8080", "image": "nginx:1.27"},
		{"key": "web/db", "stack": "web*", "service": "db", "state": "stopped", "health": "-", "memory": "-",
			"restarts": "0", "ports": "-", "image": "postgres:16"},
		{"key": "cache/", "stack": "cache", "service": "-", "state": "prepared, not started", "image": "-"},
		{"key": "old/", "stack": "old", "service": "-", "state": "apply stopped at: pull"},
		{"key": "relay/", "stack": "relay", "service": "-", "state": "from a template"},
		{"key": "new/", "stack": "new", "service": "-", "state": "being applied"},
		{"key": "going/app", "stack": "going", "service": "app", "state": "being removed · active (running)"},
	}
	if len(rows) != len(want) || len(names) != len(want) {
		t.Fatalf("%d rows and %d names, want %d: %v", len(rows), len(names), len(want), rows)
	}
	for i, roles := range want {
		for role, w := range roles {
			if got := fmt.Sprint(rows[i][role]); got != w {
				t.Errorf("row %d %s = %q, want %q", i, role, got, w)
			}
		}
	}
	wantNames := []stackRow{{0, "app"}, {0, "db"}, {1, ""}, {2, ""}, {3, ""}, {4, ""}, {5, "app"}}
	if !reflect.DeepEqual(names, wantNames) {
		t.Errorf("names = %+v, want %+v", names, wantNames)
	}
}

// findingIDs are the findings the daemon's review can say.
var findingIDs = []string{
	// refusals
	"bad-yaml", "unsupported-key", "no-services", "bad-volume-name", "bad-service-name", "too-many-services",
	"bad-value", "unset-variable", "unit-text", "unsupported-value", "user-not-numeric", "no-image", "absolute-path",
	"path-leaves-folder", "whole-folder", "reserved-path", "undeclared-volume", "unsupported-dependency", "env-no-value",
	"bad-port", "host-network-port", "bad-env-line", "missing-file", "unit-name-taken", "data-overlap", "symlink",
	"capability", "unknown-dependency", "privileged-port", "port-twice", "port-taken", "port-in-use", "dependency-cycle",
	// warnings
	"public-port", "image-by-tag", "host-network", "host-network-no-ports", "no-memory-limit",
	"writable-root", "image-user", "capability-added", "reach",
}

// TestEveryFindingHasItsSentence: each finding the daemon can say has a
// message, so none is shown by its id; and the catalog has a sentence for no
// other.
func TestEveryFindingHasItsSentence(t *testing.T) {
	known := map[string]bool{}
	for _, id := range findingIDs {
		known[id] = true
		if got := findingText(inEnglish{}, services.Finding{ID: id}); got == id {
			t.Errorf("the finding %s has no sentence", id)
		}
	}
	const prefix = "autopanel.finding."
	for _, id := range englishCatalog().IDs("en") {
		if strings.HasPrefix(id, prefix) && !known[strings.TrimPrefix(id, prefix)] {
			t.Errorf("the catalog has %s, a finding the daemon does not say", id)
		}
	}
}

// TestFindingText: a finding is its sentence, then its service and its
// detail; one the panel does not know is shown by its id.
func TestFindingText(t *testing.T) {
	for _, c := range []struct {
		f    services.Finding
		want string
	}{
		{services.Finding{ID: "no-memory-limit", Service: "app"}, "It has no memory limit [app]"},
		{services.Finding{ID: "port-taken", Service: "app", Detail: "tcp 8080 is stack web's"}, "Another stack has this port [app]: tcp 8080 is stack web's"},
		{services.Finding{ID: "bad-yaml", Detail: "line 3"}, "The compose file is not valid YAML: line 3"},
		{services.Finding{ID: "a-new-finding", Service: "app", Detail: "x"}, "a-new-finding [app]: x"},
	} {
		if got := findingText(inEnglish{}, c.f); got != c.want {
			t.Errorf("findingText(%+v) = %q, want %q", c.f, got, c.want)
		}
	}
}

// TestFindingRows: the refusals come first, then the warnings, each in the
// daemon's order.
func TestFindingRows(t *testing.T) {
	rows, texts := findingRows(inEnglish{}, []services.Finding{
		{ID: "reach", Severity: services.Warning},
		{ID: "no-image", Severity: services.Refused, Service: "app"},
		{ID: "no-memory-limit", Severity: services.Warning, Service: "app"},
		{ID: "symlink", Severity: services.Refused, Detail: "site/link"},
	})
	var got []string
	for _, r := range rows {
		got = append(got, fmt.Sprint(r["level"])+": "+fmt.Sprint(r["text"]))
	}
	want := []string{
		"refused: The service names no image [app]",
		"refused: A symbolic link is not allowed in the definition: site/link",
		"warning: Containers can reach what the host and other stacks publish; the private network keeps other stacks out of this one, not this one out of the host",
		"warning: It has no memory limit [app]",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("findingRows = %q, want %q", got, want)
	}
	if len(texts) != len(rows) || texts[1] != "A symbolic link is not allowed in the definition: site/link" {
		t.Errorf("texts = %q", texts)
	}
}

// TestTheStacksPanel: the stacks, a row per container. A small letter acts on
// the row's service and its capital on the whole stack; a stop asks first,
// and says what else stops; the images are pulled for the stack; the log is
// the row's service's, or the stack's on a row with no service; a removal
// asks first, and says whether the directory goes too.
func TestTheStacksPanel(t *testing.T) {
	f := withStacks()
	s := start(t, f)
	openStacks(t, s, "active (running)")
	// The rows are by stack name: cache, old, web/app, web/db.
	for _, part := range []string{"prepared, not started", "apply stopped at: pull", "web*", "healthy", "21.0 MiB", "tcp 8080",
		"nginx:1.27", "postgres:16", "stopped", "4 rows", "* after a name"} {
		s.WaitForText(t, part)
	}
	if strings.Contains(s.String(), "failed") {
		t.Fatalf("a container a person stopped is shown as failed:\n%s", s)
	}

	// On cache's row, which has no service: the service keys say so, and ask
	// the daemon for nothing.
	s.Keys(t, decltest.Rune('s'))
	s.WaitForText(t, "cache has no service at this row")

	s.Keys(t, decltest.Rune('j'), decltest.Rune('j')) // web/app
	s.Keys(t, decltest.Rune('t'))
	s.WaitForText(t, "web/app restarted")
	s.Keys(t, decltest.Rune('s'))
	s.WaitForText(t, "web/app started")

	s.Keys(t, decltest.Rune('x'))
	s.WaitForText(t, "Stop app of web, and every service that depends on it?")
	s.Keys(t, escape)
	gone(t, s, "every service that depends on it")
	same(t, "the asks after a stop that was not confirmed", f.asked().units, []string{"restart web/app", "start web/app"})
	s.Keys(t, decltest.Rune('x'))
	s.WaitForText(t, "every service that depends on it")
	s.Keys(t, decltest.Rune('y'))
	s.WaitForText(t, "web/app stopped")

	s.Keys(t, decltest.Rune('T'))
	s.WaitForText(t, "web restarted")
	s.Keys(t, decltest.Rune('S'))
	s.WaitForText(t, "web started")
	s.Keys(t, decltest.Rune('X'))
	s.WaitForText(t, "Stop every service of web?")
	s.Keys(t, decltest.Rune('y'))
	s.WaitForText(t, "web stopped")

	s.Keys(t, decltest.Rune('u'))
	s.WaitForText(t, "the images of web are pulled")

	s.Keys(t, decltest.Rune('o'))
	s.WaitForText(t, "web/app[812]: ready")
	s.WaitForText(t, "web/app: 2 lines")
	s.Keys(t, decltest.Rune('q'))
	gone(t, s, "[812]: ready")
	s.Keys(t, decltest.Rune('k')) // old: no service, so the whole stack's log
	s.Keys(t, decltest.Rune('o'))
	s.WaitForText(t, "old[812]: ready")
	s.WaitForText(t, "old: 2 lines")
	s.Keys(t, decltest.Rune('q'))
	gone(t, s, "[812]: ready")

	s.Keys(t, decltest.Rune('d'))
	s.WaitForText(t, "Remove old?")
	s.WaitForText(t, "kept, owned by root")
	s.Keys(t, escape)
	gone(t, s, "Remove old?")
	same(t, "the removals without a yes", f.asked().removals, nil)

	s.Keys(t, decltest.Rune('D'))
	s.WaitForText(t, "Remove old and delete its directory?")
	s.Keys(t, decltest.Rune('y'))
	s.WaitForText(t, "old removed, with its directory")
	gone(t, s, "apply stopped at: pull")
	s.Keys(t, decltest.Rune('k'), decltest.Rune('k'), decltest.Rune('k')) // the first row: cache
	s.Keys(t, decltest.Rune('d'))
	s.WaitForText(t, "Remove cache?")
	s.Keys(t, decltest.Rune('y'))
	s.WaitForText(t, "cache removed; its directory is kept")

	// Closed, the panel hands the keyboard back to the main screen: q quits.
	s.Keys(t, decltest.Rune('q'))
	gone(t, s, "u pull images")
	s.Keys(t, decltest.Rune('q'))
	select {
	case <-s.Quit():
	case <-time.After(decltest.WaitTimeout):
		t.Fatalf("q on the main screen did not quit:\n%s", s)
	}

	a := f.asked()
	same(t, "unit asks", a.units, []string{"restart web/app", "start web/app", "stop web/app", "restart web", "start web", "stop web"})
	same(t, "pulls", a.pulls, []string{"web"})
	same(t, "log asks", a.logs, []string{"web/app", "old"})
	same(t, "removals", a.removals, []string{"old purge", "cache"})
	same(t, "applies", a.applies, nil)
}

// TestAddAStackWithNoFolder: with no definition folder to add, the dialog
// says so, and where a compose file goes.
func TestAddAStackWithNoFolder(t *testing.T) {
	f := newFakeClient()
	s := start(t, f)
	openAdd(t, s)
	s.WaitForText(t, "No folder holds a new stack")
	s.WaitForText(t, "/etc/autopanel/stacks/<name>/compose.yaml")
	if strings.Contains(s.String(), "FOLDER") {
		t.Fatalf("an empty table is shown:\n%s", s)
	}
	s.Keys(t, decltest.Rune('r')) // Review is disabled: there is nothing to review
	s.Keys(t, escape)
	gone(t, s, "No folder holds a new stack")
	same(t, "checks", f.asked().checks, nil)
}

// TestAddAStack: the folders are listed, and Enter reviews one, which changes
// nothing. The review shows what the stack would run and the warnings; "Add
// and start" then asks the daemon to add it, with the review's hash.
func TestAddAStack(t *testing.T) {
	f := withStacks()
	s := start(t, f)
	openAdd(t, s)
	s.WaitForText(t, "FOLDER")
	s.WaitForText(t, "blog")
	s.WaitForText(t, "Enter reviews the selected folder")
	s.Keys(t, enter)

	for _, part := range []string{"Add stack blog: review", "Definition 3f2a9c41d07b · 2 files", "nginx:1.27", "image's own", "private",
		"127.0.0.1:8080:80/tcp", "site:/srv:ro", "none", "warning", "The image is named by a tag", "It has no memory limit [app]",
		"Add and start", "Prepare only", "Confirming accepts the warnings"} {
		s.WaitForText(t, part)
	}
	if sc := s.String(); strings.Contains(sc, blogSHA[:13]) || strings.Contains(sc, "stops and removes") {
		t.Fatalf("the review shows the whole hash, or services to remove when there are none:\n%s", s)
	}
	a := f.asked()
	same(t, "checks", a.checks, []string{"blog"})
	same(t, "applies before the review is confirmed", a.applies, nil)

	s.Keys(t, decltest.Rune('a'))
	s.WaitForText(t, "blog is added and started")
	gone(t, s, "Add stack blog: review")
	same(t, "applies", f.asked().applies, []string{"add blog " + blogSHA})
}

// TestPrepareOnly: "Prepare only" on a new stack's review asks the daemon to
// prepare it, and the stack is then in the panel, prepared. Its review there
// has Start, which asks the daemon to add it.
func TestPrepareOnly(t *testing.T) {
	f := withStacks()
	f.stacks = nil
	f.folders = []services.Folder{{Name: "blog"}, {Name: "cache"}}
	s := start(t, f)
	openAdd(t, s)
	s.WaitForText(t, "cache")
	s.Keys(t, decltest.Rune('j'), enter)
	s.WaitForText(t, "Add stack cache: review")
	s.Keys(t, decltest.Rune('p'))
	s.WaitForText(t, "cache is prepared and not started")
	gone(t, s, "Add stack cache: review")
	same(t, "applies", f.asked().applies, []string{"prepare cache " + cacheSHA})

	openStacks(t, s, "prepared, not started")
	s.Keys(t, decltest.Rune('p'))
	s.WaitForText(t, "Start stack cache: review")
	if strings.Contains(s.String(), "Prepare only") {
		t.Fatalf("a prepared stack's review offers to prepare it:\n%s", s)
	}
	s.Keys(t, decltest.Rune('s'))
	s.WaitForText(t, "cache started")
	same(t, "applies", f.asked().applies, []string{"prepare cache " + cacheSHA, "add cache " + cacheSHA})
}

// TestApplyAStack: p reviews the row's stack as it is defined now, with the
// services the apply would remove; Apply asks the daemon to apply it, with
// the review's hash. A registered stack's review has no "Prepare only".
func TestApplyAStack(t *testing.T) {
	f := withStacks()
	s := start(t, f)
	openStacks(t, s, "active (running)")
	s.Keys(t, decltest.Rune('j'), decltest.Rune('j')) // web/app
	s.Keys(t, decltest.Rune('p'))
	s.WaitForText(t, "Apply stack web: review")
	s.WaitForText(t, "Applying stops and removes: worker")
	s.WaitForText(t, "Definition a1b2c3d4e5f6 · 2 files")
	if strings.Contains(s.String(), "Prepare only") {
		t.Fatalf("a registered stack's review offers to prepare it:\n%s", s)
	}
	s.Keys(t, decltest.Rune('p')) // no such button: nothing is prepared
	s.Keys(t, decltest.Rune('a'))
	s.WaitForText(t, "web is applied")
	gone(t, s, "Apply stack web: review")
	a := f.asked()
	same(t, "checks", a.checks, []string{"web"})
	same(t, "applies", a.applies, []string{"apply web " + webSHA})
}

// TestARefusedStackCannotBeApplied: a review with a refusal lists it first,
// says the stack was refused, and its buttons that would apply it do nothing.
func TestARefusedStackCannotBeApplied(t *testing.T) {
	f := withStacks()
	r := warned(blogSHA)
	r.Findings = append(r.Findings, services.Finding{ID: "privileged-port", Severity: services.Refused, Service: "app", Detail: "tcp 80"})
	f.reviews["blog"] = r
	s := start(t, f)
	openAdd(t, s)
	s.WaitForText(t, "blog")
	s.Keys(t, enter)
	s.WaitForText(t, "Add stack blog: review")
	s.WaitForText(t, "The stack was refused")
	s.WaitForText(t, "A port below 1024 is not allowed [app]: tcp 80")
	sc := s.String()
	if refusal, warning := strings.Index(sc, "refused "), strings.Index(sc, "warning "); refusal < 0 || warning < refusal {
		t.Fatalf("the refusal is not listed before the warnings:\n%s", s)
	}

	s.Keys(t, decltest.Rune('a'), decltest.Rune('p'))
	// The review is still open: its findings still move, and the line under
	// them shows the selected one whole, which its row has no room for.
	s.Keys(t, tab, decltest.Rune('j'))
	s.WaitForText(t, "between pulls [app]: docker.io/library/nginx:1.27")
	if !strings.Contains(s.String(), "Add stack blog: review") {
		t.Fatalf("a disabled button closed the review:\n%s", s)
	}
	s.Keys(t, escape)
	gone(t, s, "Add stack blog: review")
	same(t, "applies of a refused stack", f.asked().applies, nil)
}

// TestADefinitionThatChangedIsReviewedAgain: when the daemon says the
// definition changed since its review, nothing was done. The panel checks it
// again and shows the new review, saying why; confirming that one gives the
// daemon the new hash.
func TestADefinitionThatChangedIsReviewedAgain(t *testing.T) {
	f := withStacks()
	f.applyErrs = []error{fmt.Errorf("%w (review it again)", services.ErrChanged)}
	s := start(t, f)
	openAdd(t, s)
	s.WaitForText(t, "blog")
	s.Keys(t, enter)
	s.WaitForText(t, "Definition 3f2a9c41d07b")

	f.mu.Lock()
	f.reviews["blog"] = warned(blogSHA2)
	f.mu.Unlock()
	s.Keys(t, decltest.Rune('a'))
	s.WaitForText(t, "Definition 77c0ffee1234")
	s.WaitForText(t, "The definition changed since it was shown. This is its new review.")
	s.WaitForText(t, "Add stack blog: review")

	s.Keys(t, decltest.Rune('a'))
	s.WaitForText(t, "blog is added and started")
	a := f.asked()
	same(t, "checks", a.checks, []string{"blog", "blog"})
	same(t, "applies", a.applies, []string{"add blog " + blogSHA, "add blog " + blogSHA2})
}

// TestAFailedApplyIsSaid: an apply the daemon could not finish is said on
// the status bar, and the review does not come back: the stack's row says
// where it stopped.
func TestAFailedApplyIsSaid(t *testing.T) {
	f := withStacks()
	f.applyErrs = []error{errors.New("services: pulling nginx: no route to the registry")}
	s := start(t, f)
	openStacks(t, s, "active (running)")
	s.Keys(t, decltest.Rune('p')) // cache, prepared: its review starts it
	s.WaitForText(t, "Start stack cache: review")
	s.Keys(t, decltest.Rune('s'))
	s.WaitForText(t, "error: services: pulling nginx")
	gone(t, s, "Start stack cache: review")
	same(t, "applies", f.asked().applies, []string{"add cache " + cacheSHA})
}
