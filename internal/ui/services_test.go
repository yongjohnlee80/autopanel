package ui

import (
	"context"
	"errors"
	"fmt"
	"path"
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
// of which a person stopped, its definition changed since it was applied, and
// the folder it was imported from changed since; cache is prepared; old has
// an apply that stopped at its pull.
func someStacks() []services.View {
	return []services.View{
		{Name: "web", State: "deployed", User: "ap-web", SHA256: webSHA, Changed: true,
			Source: &services.SourceView{Path: "/home/ada/web", ImportedAt: 1794211200, State: "changed"},
			Containers: []services.Container{
				{Service: "app", Image: "docker.io/library/nginx:1.27", Digest: "sha256:9e1f0c", Health: "healthy",
					Ports:   []services.PortUse{{Proto: "tcp", From: 8080, To: 8080}},
					Running: services.Running{Active: "active", Sub: "running", MemoryBytes: 21 << 20, Restarts: 2, Since: 1794211300, CPUNanos: 12_400_000_000}},
				// systemd calls a container that was stopped by hand failed
				{Service: "db", Image: "docker.io/library/postgres:16", Stopped: true, Ports: []services.PortUse{},
					Running: services.Running{Active: "failed", Sub: "failed"}},
			}},
		{Name: "cache", State: "prepared", User: "ap-cache", Containers: []services.Container{}},
		{Name: "old", State: "incomplete", Step: "pull", User: "ap-old", Containers: []services.Container{},
			Source: &services.SourceView{Path: "/srv/old", State: "missing"}},
	}
}

// warned is a review with warnings and no refusal.
func warned(sha string) services.Review {
	return services.Review{
		SHA256: sha,
		Files:  []services.Input{{Path: ".env"}, {Path: "compose.yaml"}},
		Containers: []services.Planned{{Service: "app", Image: "docker.io/library/nginx:1.27", Network: "private",
			Ports: []string{"127.0.0.1:8080:80/tcp"}, Mounts: []string{"site:/srv:ro"}, Restart: "always"}},
		Findings: []services.Finding{
			{ID: "image-by-tag", Severity: services.Warning, Service: "app", Detail: "docker.io/library/nginx:1.27"},
			{ID: "no-memory-limit", Severity: services.Warning, Service: "app"},
			{ID: "reach", Severity: services.Warning},
		},
		Removes: []string{},
	}
}

// withStacks is a fake client whose daemon has someStacks, a home with a
// stack's folder to import, and a review of each.
func withStacks() *fakeClient {
	f := newFakeClient()
	f.stacks = someStacks()
	web := warned(webSHA)
	web.Removes = []string{"worker"}
	f.reviews = map[string]services.Review{"blog": warned(blogSHA), "web": web, "cache": warned(cacheSHA)}
	f.folders = map[string]services.Listing{
		"/home/ada": {Path: "/home/ada", Entries: []services.Entry{
			{Name: "blog", Kind: "dir", Stack: true}, {Name: "notes", Kind: "dir"}, {Name: "todo.txt", Kind: "file", Size: 120}}},
		"/home/ada/blog": {Path: "/home/ada/blog", Stack: true, Entries: []services.Entry{
			{Name: "site", Kind: "dir"}, {Name: ".env", Kind: "file", Size: 40}, {Name: "README.md", Kind: "file", Size: 30},
			{Name: "compose.yaml", Kind: "file", Size: 210}, {Name: "logo.png", Kind: "file", Size: 4096}}},
		"/home": {Path: "/home", Entries: []services.Entry{{Name: "ada", Kind: "dir"}}},
		"/":     {Path: "/", Entries: []services.Entry{{Name: "home", Kind: "dir"}, {Name: "srv", Kind: "dir"}}},
	}
	f.files = map[string]services.PreviewText{
		"/home/ada/blog/compose.yaml": {Path: "/home/ada/blog/compose.yaml", Text: "services:\n  app:\n    image: nginx:1.27\n    ports: [\"127.0.0.1:8080:80\"]\n"},
		"/home/ada/blog/.env":         {Path: "/home/ada/blog/.env", Text: "DB_PASSWORD=••••••\nAPI_TOKEN=••••••\n", Masked: 2},
		"/home/ada/blog/README.md":    {Path: "/home/ada/blog/README.md", Text: "# Blog\n\nA small site.\n"},
	}
	return f
}

func (f *fakeClient) Stacks(context.Context) ([]services.View, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]services.View(nil), f.stacks...), nil
}

func (f *fakeClient) Browse(_ context.Context, p string) (services.Listing, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if l, ok := f.folders[p]; ok {
		return l, nil
	}
	return services.Listing{}, fmt.Errorf("%w (the browser cannot read that path)", services.ErrBadPath)
}

// Preview answers a file inside a stack's folder; any other is not in a
// stack, and the picture is not text.
func (f *fakeClient) Preview(_ context.Context, p string) (services.PreviewText, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if t, ok := f.files[p]; ok {
		return t, nil
	}
	if l, ok := f.folders[path.Dir(p)]; ok && l.Stack {
		return services.PreviewText{}, services.ErrNotText
	}
	return services.PreviewText{}, services.ErrNotInStack
}

func (f *fakeClient) ImportStack(_ context.Context, from, name string) (services.Imported, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.imports = append(f.imports, from+" as "+name)
	for _, s := range f.stacks {
		if s.Name == name {
			return services.Imported{}, services.ErrDuplicate
		}
	}
	return services.Imported{Name: name, From: from, SHA256: blogSHA, Files: []services.Input{{Path: ".env"}, {Path: "compose.yaml"}}}, nil
}

func (f *fakeClient) ReimportStack(_ context.Context, name string) (services.Imported, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reimports = append(f.reimports, name)
	for i := range f.stacks {
		if f.stacks[i].Name == name && f.stacks[i].Source != nil {
			f.stacks[i].Source.State = "same"
			return services.Imported{Name: name, From: f.stacks[i].Source.Path, SHA256: webSHA}, nil
		}
	}
	return services.Imported{}, services.ErrNoSource
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
	checks, applies, pulls, units, removals, logs, imports, reimports []string
}

func (f *fakeClient) asked() asked {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := func(s []string) []string { return append([]string{}, s...) }
	return asked{checks: c(f.checks), applies: c(f.applies), pulls: c(f.pulls), units: c(f.unitAsks), removals: c(f.removals),
		logs: c(f.logAsks), imports: c(f.imports), reimports: c(f.reimports)}
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
	s.WaitForText(t, "Stacks · 3 · read at")
	s.WaitForText(t, want)
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

// TestStackRows: each stack's row, its state in words and its source's when
// that changed or went, then its containers indented; "stopped" for a
// container a person stopped, whatever systemd says; a mark on a stack whose
// definition changed since it was applied.
func TestStackRows(t *testing.T) {
	views := append(someStacks(),
		services.View{Name: "relay", State: "legacy", Containers: []services.Container{}},
		services.View{Name: "going", State: "removing", Containers: []services.Container{
			{Service: "app", Image: "registry.example.com/app:1", Running: services.Running{Active: "active", Sub: "running"}}}})
	rows, names := stackRows(inEnglish{}, views)
	want := []map[string]string{
		{"key": "web/", "name": "web*", "state": "deployed · source changed"},
		{"key": "web/app", "name": "  app", "state": "active (running)", "health": "healthy"},
		{"key": "web/db", "name": "  db", "state": "stopped", "health": "-"},
		{"key": "cache/", "name": "cache", "state": "prepared, not started"},
		{"key": "old/", "name": "old", "state": "apply stopped at: pull · source missing"},
		{"key": "relay/", "name": "relay", "state": "from a template"},
		{"key": "going/", "name": "going", "state": "being removed"},
		{"key": "going/app", "name": "  app", "state": "being removed · active (running)"},
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
	wantNames := []stackRow{{0, ""}, {0, "app"}, {0, "db"}, {1, ""}, {2, ""}, {3, ""}, {4, ""}, {4, "app"}}
	if !reflect.DeepEqual(names, wantNames) {
		t.Errorf("names = %+v, want %+v", names, wantNames)
	}
}

// TestStackDetail: a container's row is shown whole: its image, digest,
// ports, state, health, restarts, since, CPU, memory and its stack's source;
// a stack's row its state, user, definition and source.
func TestStackDetail(t *testing.T) {
	web := someStacks()[0]
	got := stackDetail(inEnglish{}, web, "app")
	for _, part := range []string{"Service       app of stack web", "Image         docker.io/library/nginx:1.27", "Digest        sha256:9e1f0c",
		"Ports         tcp 8080", "State         active (running)", "Health        healthy", "Restarts      2", "Since         ",
		"CPU time      12.4 s", "Memory        21.0 MiB", "Source        /home/ada/web", "Source state  source changed"} {
		if !strings.Contains(got, part) {
			t.Errorf("the container's details lack %q:\n%s", part, got)
		}
	}
	got = stackDetail(inEnglish{}, web, "")
	for _, part := range []string{"Stack         web", "State         deployed", "User          ap-web",
		"Definition    a1b2c3d4e5f6 · changed since it was applied", "Containers    2", "Imported      "} {
		if !strings.Contains(got, part) {
			t.Errorf("the stack's details lack %q:\n%s", part, got)
		}
	}
	if got := stackDetail(inEnglish{}, someStacks()[1], ""); !strings.Contains(got, "not imported from a folder") {
		t.Errorf("a stack not imported:\n%s", got)
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
	const prefix = "autopanel.finding.review."
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

// TestReviewList: the review's list is its containers, then its findings,
// the refusals first, each kind in the daemon's order.
func TestReviewList(t *testing.T) {
	r := warned(blogSHA)
	r.Findings = []services.Finding{
		{ID: "reach", Severity: services.Warning},
		{ID: "no-image", Severity: services.Refused, Service: "app"},
		{ID: "no-memory-limit", Severity: services.Warning, Service: "app"},
		{ID: "symlink", Severity: services.Refused, Detail: "site/link"},
	}
	rows, names, _, texts := reviewList(inEnglish{}, r)
	var got []string
	for _, row := range rows {
		got = append(got, fmt.Sprint(row["kind"])+": "+fmt.Sprint(row["name"])+" "+fmt.Sprint(row["text"]))
	}
	want := []string{
		"container: app nginx:1.27",
		"refused:  The service names no image [app]",
		"refused:  A symbolic link is not allowed in the definition: site/link",
		"warning:  Containers can reach what the host and other stacks publish; the private network keeps other stacks out of this one, not this one out of the host",
		"warning:  It has no memory limit [app]",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("reviewList = %q, want %q", got, want)
	}
	if names[0] != (reviewRow{container: 0, finding: -1}) || names[2] != (reviewRow{container: -1, finding: 1}) || len(texts) != 4 {
		t.Errorf("names = %+v, texts = %q", names, texts)
	}
}

// TestTheStacksPanel: two panes, each stack and its containers on the left,
// the selected row whole on the right. A button acts on the row: a
// container's acts on its service, a stack's on the whole stack. A stop asks
// first; the log is the row's; a removal asks No, Remove, or Remove with its
// directory.
func TestTheStacksPanel(t *testing.T) {
	f := withStacks()
	s := start(t, f)
	openStacks(t, s, "prepared, not started")
	// The rows by stack name: cache, old, web, its app and its db.
	for _, part := range []string{"apply stopped at", "web*", "deployed · source", "  app", "healthy", "Details", "Update from source"} {
		s.WaitForText(t, part)
	}
	waitFact(t, s, "Stack", "cache")
	if strings.Contains(s.String(), "failed") {
		t.Fatalf("a container a person stopped is shown as failed:\n%s", s)
	}

	s.Keys(t, decltest.Rune('t')) // cache's row: the whole stack
	s.WaitForText(t, "cache started")

	s.Keys(t, decltest.Rune('j'), decltest.Rune('j'), decltest.Rune('j')) // web/app
	waitFact(t, s, "Service", "app of stack web")
	s.Keys(t, decltest.Rune('e'))
	s.WaitForText(t, "web/app restarted")
	s.Keys(t, decltest.Rune('t'))
	s.WaitForText(t, "web/app started")

	s.Keys(t, decltest.Rune('x'))
	s.WaitForText(t, "Stop app of web, and every service that depends on it?")
	s.Keys(t, escape)
	gone(t, s, "every service that depends on it")
	same(t, "the asks after a stop that was not confirmed", f.asked().units, []string{"start cache", "restart web/app", "start web/app"})
	s.Keys(t, decltest.Rune('x'))
	s.WaitForText(t, "every service that depends on it")
	s.Keys(t, decltest.Rune('y'))
	s.WaitForText(t, "web/app stopped")

	s.Keys(t, decltest.Rune('k')) // web's own row: the whole stack
	waitFact(t, s, "Stack", "web")
	s.Keys(t, decltest.Rune('x'))
	s.WaitForText(t, "Stop every service of web?")
	s.Keys(t, decltest.Rune('y'))
	s.WaitForText(t, "web stopped")

	s.Keys(t, decltest.Rune('u'))
	s.WaitForText(t, "the images of web are pulled")

	s.Keys(t, decltest.Rune('j'), decltest.Rune('o')) // web/app's log
	s.WaitForText(t, "web/app[812]: ready")
	s.WaitForText(t, "web/app · 2 lines · read at")
	s.Keys(t, decltest.Rune('q'))
	gone(t, s, "[812]: ready")
	s.Keys(t, decltest.Rune('k'), decltest.Rune('k')) // old: the whole stack's log
	waitFact(t, s, "Stack", "old")
	s.Keys(t, decltest.Rune('o'))
	s.WaitForText(t, "old[812]: ready")
	s.Keys(t, decltest.Rune('q'))
	gone(t, s, "[812]: ready")

	s.Keys(t, decltest.Rune('r'))
	s.WaitForText(t, "Remove old?")
	s.WaitForText(t, "Remove with its directory")
	s.Keys(t, escape)
	gone(t, s, "Remove old?")
	same(t, "the removals without a yes", f.asked().removals, nil)

	s.Keys(t, decltest.Rune('r'))
	s.WaitForText(t, "Remove old?")
	s.Keys(t, decltest.Rune('d')) // Remove with its directory
	s.WaitForText(t, "old removed, with its directory")
	gone(t, s, "apply stopped at")
	s.Keys(t, decltest.Rune('k'), decltest.Rune('k'), decltest.Rune('k')) // the first row: cache
	waitFact(t, s, "Stack", "cache")
	s.Keys(t, decltest.Rune('r'))
	s.WaitForText(t, "Remove cache?")
	s.Keys(t, decltest.Rune('y'))
	s.WaitForText(t, "cache removed; its directory is kept")

	// Closed, the panel hands the keyboard back to the main screen: q quits.
	s.Keys(t, decltest.Rune('q'))
	gone(t, s, "Update from source")
	s.Keys(t, decltest.Rune('q'))
	select {
	case <-s.Quit():
	case <-time.After(decltest.WaitTimeout):
		t.Fatalf("q on the main screen did not quit:\n%s", s)
	}

	a := f.asked()
	same(t, "unit asks", a.units, []string{"start cache", "restart web/app", "start web/app", "stop web/app", "stop web"})
	same(t, "pulls", a.pulls, []string{"web"})
	same(t, "log asks", a.logs, []string{"web/app", "old"})
	same(t, "removals", a.removals, []string{"old purge", "cache"})
	same(t, "applies", a.applies, nil)
}

// TestUpdateFromSource: a stack whose source changed is marked, and Update
// from source copies its definition again, then opens its review, which
// applies it; a stack whose source is missing says so and asks nothing.
func TestUpdateFromSource(t *testing.T) {
	f := withStacks()
	s := start(t, f)
	openStacks(t, s, "web*")
	s.Keys(t, decltest.Rune('j')) // old: its source is missing
	waitFact(t, s, "Stack", "old")
	s.Keys(t, decltest.Rune('s'))
	s.WaitForText(t, "The source folder of old is gone: /srv/old")
	same(t, "reimports of a missing source", f.asked().reimports, nil)

	s.Keys(t, decltest.Rune('j'))
	waitFact(t, s, "Stack", "web")
	s.Keys(t, decltest.Rune('s'))
	s.WaitForText(t, "Apply stack web: review")
	s.WaitForText(t, "Applying stops and removes: worker")
	same(t, "reimports", f.asked().reimports, []string{"web"})
	s.Keys(t, decltest.Rune('a'))
	s.WaitForText(t, "web is applied")
	same(t, "applies", f.asked().applies, []string{"apply web " + webSHA})
	gone(t, s, "deployed · source") // read again: the source is as imported now
}

// TestTheStacksWidgetOpensThePanel: Enter on a container of the main
// screen's stacks widget opens the panel on that container.
func TestTheStacksWidgetOpensThePanel(t *testing.T) {
	f := withStacks()
	s := start(t, f)
	s.WaitForText(t, "web/app")
	s.Keys(t, decltest.Rune('j'), decltest.Rune('j')) // cache, old, web/app
	s.Keys(t, enter)
	s.WaitForText(t, "Stacks · 3 · read at")
	waitFact(t, s, "Service", "app of stack web")
}

// TestApplyAStack: p reviews the row's stack as it is defined now, with the
// services the apply would remove; Apply asks the daemon to apply it, with
// the review's hash. A registered stack's review has no "Prepare only".
func TestApplyAStack(t *testing.T) {
	f := withStacks()
	s := start(t, f)
	openStacks(t, s, "web*")
	s.Keys(t, decltest.Rune('j'), decltest.Rune('j')) // web
	waitFact(t, s, "Stack", "web")
	s.Keys(t, decltest.Rune('p'))
	s.WaitForText(t, "Apply stack web: review")
	s.WaitForText(t, "Applying stops and removes: worker")
	s.WaitForText(t, "Definition a1b2c3d4e5f6 · files: 2 · containers: 1")
	waitFact(t, s, "Image", "docker.io/library/nginx:1.27") // the first row, whole
	if strings.Contains(s.String(), "Prepare only") {
		t.Fatalf("a registered stack's review offers to prepare it:\n%s", s)
	}
	s.Keys(t, decltest.Rune('a'))
	s.WaitForText(t, "web is applied")
	gone(t, s, "Apply stack web: review")
	a := f.asked()
	same(t, "checks", a.checks, []string{"web"})
	same(t, "applies", a.applies, []string{"apply web " + webSHA})
}

// TestTheReviewIsTwoPanes: the containers and the findings on the left, the
// selected one whole on the right: a finding's whole sentence, which its row
// has no room for.
func TestTheReviewIsTwoPanes(t *testing.T) {
	f := withStacks()
	s := start(t, f)
	openStacks(t, s, "web*")
	s.Keys(t, decltest.Rune('j'), decltest.Rune('j'), decltest.Rune('p'))
	s.WaitForText(t, "Containers and findings")
	for _, f := range [][2]string{{"Network", "private"}, {"Ports", "127.0.0.1:8080:80/tcp"}, {"Mounts", "site:/srv:ro"}, {"Restart", "always"}} {
		waitFact(t, s, f[0], f[1])
	}
	s.Keys(t, decltest.Rune('j'), decltest.Rune('j'), decltest.Rune('j')) // the list has the keyboard
	waitFact(t, s, "Level", "warning")
	s.WaitForText(t, "out of the host")
}

// TestARefusedStackCannotBeApplied: a review with a refusal lists it first,
// says the stack was refused, and its buttons that would apply it do nothing.
func TestARefusedStackCannotBeApplied(t *testing.T) {
	f := withStacks()
	r := warned(webSHA)
	r.Findings = append(r.Findings, services.Finding{ID: "privileged-port", Severity: services.Refused, Service: "app", Detail: "tcp 80"})
	f.reviews["web"] = r
	s := start(t, f)
	openStacks(t, s, "web*")
	s.Keys(t, decltest.Rune('j'), decltest.Rune('j'), decltest.Rune('p'))
	s.WaitForText(t, "Apply stack web: review")
	s.WaitForText(t, "The stack was refused")
	sc := s.String()
	if refusal, warning := strings.Index(sc, "refused "), strings.Index(sc, "warning "); refusal < 0 || warning < refusal {
		t.Fatalf("the refusal is not listed before the warnings:\n%s", s)
	}
	s.Keys(t, decltest.Rune('a'))
	s.Keys(t, decltest.Rune('j')) // the first finding: the refusal, whole on the right
	s.WaitForText(t, "A port below 1024 is not allowed [app]: tcp 80")
	if !strings.Contains(s.String(), "Apply stack web: review") {
		t.Fatalf("a disabled button closed the review:\n%s", s)
	}
	s.Keys(t, escape)
	gone(t, s, "Apply stack web: review")
	same(t, "applies of a refused stack", f.asked().applies, nil)
}

// TestADefinitionThatChangedIsReviewedAgain: when the daemon says the
// definition changed since its review, nothing was done. The panel checks it
// again and shows the new review, saying why; confirming that one gives the
// daemon the new hash.
func TestADefinitionThatChangedIsReviewedAgain(t *testing.T) {
	f := withStacks()
	f.applyErrs = []error{fmt.Errorf("%w (review it again)", services.ErrChanged)}
	h, s := startHost(t, f)
	s.WaitForText(t, "CA LE staging")
	onLoop(h, func() bool { h.checkStack("blog", reviewAdd, false); return true })
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
// the status bar, and the review does not come back.
func TestAFailedApplyIsSaid(t *testing.T) {
	f := withStacks()
	f.applyErrs = []error{errors.New("services: pulling nginx: no route to the registry")}
	s := start(t, f)
	openStacks(t, s, "prepared, not started")
	s.Keys(t, decltest.Rune('p')) // cache, prepared: its review starts it
	s.WaitForText(t, "Start stack cache: review")
	s.Keys(t, decltest.Rune('s'))
	s.WaitForText(t, "error: services: pulling nginx")
	gone(t, s, "Start stack cache: review")
	same(t, "applies", f.asked().applies, []string{"add cache " + cacheSHA})
}

// TestStackPortsFillTheUpstream: the route form offers each TCP port a stack
// publishes as a loopback upstream named after its stack and service.
func TestStackPortsFillTheUpstream(t *testing.T) {
	got := stackPorts(someStacks())
	want := []portChoice{{label: "web-app  http://127.0.0.1:8080", upstream: "http://127.0.0.1:8080"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("stackPorts = %+v, want %+v", got, want)
	}
	if got := stackOfUpstream("http://127.0.0.1:8080/", someStacks()); got != "web-app" {
		t.Errorf("stackOfUpstream = %q", got)
	}
}
