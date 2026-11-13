package services

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// machine is a Host that makes no user and starts no unit: definitions,
// staged copies, each stack's folder and its unit files are maps, and what
// was asked of systemd and Podman is a log.
type machine struct {
	mu     sync.Mutex
	podman [2]int
	defs   map[string]map[string]string // stack → file → text: the administrator's folders
	staged map[string]map[string]string
	folder map[string]map[string]string // stack → path → text; a data folder is "<dir>"
	units  map[string]map[string]string // stack → unit file → body
	users  map[string]bool
	// registry is what each image reference resolves to; held is what each
	// stack's user has pulled.
	registry map[string]string
	held     map[string]map[string]bool
	offline  bool
	listen   []PortUse
	changed  bool
	fail     map[string]error // a method's name → the error its next call answers
	log      []string
}

func newMachine() *machine {
	return &machine{podman: [2]int{4, 9}, defs: map[string]map[string]string{}, staged: map[string]map[string]string{},
		folder: map[string]map[string]string{}, units: map[string]map[string]string{}, users: map[string]bool{},
		registry: map[string]string{}, held: map[string]map[string]bool{}, fail: map[string]error{}}
}

// failing answers the error set for method, once.
func (h *machine) failing(method string) error {
	err := h.fail[method]
	delete(h.fail, method)
	return err
}

func (h *machine) said(format string, a ...any) { h.log = append(h.log, fmt.Sprintf(format, a...)) }

// calls are the log's lines that start with prefix, and clears the log.
func (h *machine) calls(prefix string) []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []string
	for _, l := range h.log {
		if strings.HasPrefix(l, prefix) {
			out = append(out, l)
		}
	}
	h.log = nil
	return out
}

func (h *machine) Podman(context.Context) (int, int, error) {
	if h.podman == [2]int{} {
		return 0, 0, ErrNoPodman
	}
	return h.podman[0], h.podman[1], nil
}

func (h *machine) Available(context.Context) ([]string, error) {
	var out []string
	for name, files := range h.defs {
		if _, ok := files["compose.yaml"]; ok {
			out = append(out, name)
		}
	}
	return out, nil
}

func (h *machine) Stage(_ context.Context, name string) ([]byte, []byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	def, ok := h.defs[name]
	if !ok || def["compose.yaml"] == "" {
		return nil, nil, ErrNoDefinition
	}
	h.staged[name] = map[string]string{"compose.yaml": def["compose.yaml"]}
	if env, ok := def[".env"]; ok {
		h.staged[name][".env"] = env
	}
	return []byte(def["compose.yaml"]), []byte(def[".env"]), nil
}

func (h *machine) StagePaths(_ context.Context, name string, paths []string) ([]Input, []string, []string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var missing []string
	for _, p := range paths {
		found := false
		for file, text := range h.defs[name] {
			if within(file, p) {
				h.staged[name][file], found = text, true
			}
		}
		if !found {
			missing = append(missing, p)
		}
	}
	var files []Input
	for file, text := range h.staged[name] {
		files = append(files, Input{Path: file, Mode: 0o400, Size: int64(len(text)), SHA256: hash([]byte(text))})
	}
	return files, missing, nil, nil
}

func (h *machine) Look(_ context.Context, name string, paths []string) (map[string]bool, []string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	present := map[string]bool{}
	for _, p := range paths {
		for file := range h.folder[name] {
			if within(file, p) {
				present[p] = true
			}
		}
	}
	return present, nil, nil
}

func (h *machine) Changed(context.Context, string, Manifest, time.Time) bool { return h.changed }

func (h *machine) EnsureUser(_ context.Context, name string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.failing("EnsureUser"); err != nil {
		return err
	}
	h.users[name] = true
	return nil
}

func (h *machine) Commit(_ context.Context, name string, c Commit) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.failing("Commit"); err != nil {
		return err
	}
	if h.folder[name] == nil {
		h.folder[name] = map[string]string{}
	}
	f := h.folder[name]
	for _, p := range c.Stale {
		for file := range f {
			if within(file, p) {
				delete(f, file)
			}
		}
	}
	for _, p := range c.Managed {
		f[p] = h.staged[name][p]
	}
	for _, p := range c.Data {
		has := false
		for file := range f {
			has = has || within(file, p)
		}
		if !has {
			f[p] = "<dir>"
		}
	}
	for file := range f {
		if strings.HasPrefix(file, Generated+"/") {
			delete(f, file)
		}
	}
	for _, g := range c.Generated {
		f[strings.TrimPrefix(g.Path, "stack/")] = string(g.Body)
	}
	h.said("commit %s", name)
	return nil
}

func (h *machine) Install(_ context.Context, u Unit) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.failing("Install"); err != nil {
		return err
	}
	if !h.users[u.Name] {
		return errors.New("no user")
	}
	if h.units[u.Name] == nil {
		h.units[u.Name] = map[string]string{}
	}
	for _, f := range u.Files {
		h.units[u.Name][f.Path] = string(f.Body)
	}
	return nil
}

func (h *machine) DeleteUnits(_ context.Context, name string, paths []string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, p := range paths {
		delete(h.units[name], p)
	}
	h.said("delete %s %s", name, strings.Join(paths, " "))
	return nil
}

func (h *machine) HasImage(_ context.Context, name, ref string) (bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.held[name][ref], nil
}

func (h *machine) Pull(_ context.Context, name, ref string) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.failing("Pull"); err != nil {
		return "", err
	}
	d, ok := h.registry[ref]
	if h.offline || !ok {
		return "", errors.New("the registry did not answer")
	}
	if h.held[name] == nil {
		h.held[name] = map[string]bool{}
	}
	repo, _ := ImageRef(ref)
	h.held[name][repo+"@"+d] = true
	h.said("pull %s %s", name, ref)
	return d, nil
}

func (h *machine) act(verb, name string, units []string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.failing(verb); err != nil {
		return err
	}
	units = append([]string{}, units...)
	sort.Strings(units)
	h.said("%s %s %s", verb, name, strings.Join(units, " "))
	return nil
}

func (h *machine) Start(_ context.Context, n string, u []string) error { return h.act("start", n, u) }
func (h *machine) Stop(_ context.Context, n string, u []string) error  { return h.act("stop", n, u) }
func (h *machine) Restart(_ context.Context, n string, u []string) error {
	return h.act("restart", n, u)
}

func (h *machine) Uninstall(_ context.Context, name string, purge bool) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.units, name)
	delete(h.users, name)
	if purge {
		delete(h.folder, name)
	}
	return nil
}

func (h *machine) Running(_ context.Context, name string, units []string) (map[string]Running, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := map[string]Running{}
	for _, u := range units {
		out[u] = Running{Active: "active", Sub: "running", MemoryBytes: 1 << 20}
	}
	return out, nil
}

func (h *machine) Health(_ context.Context, name string) (map[string]string, error) {
	return map[string]string{name + "-web": "healthy"}, nil
}

func (h *machine) Logs(_ context.Context, name, container string, limit int) ([]string, error) {
	return []string{fmt.Sprintf("%s %q %d", name, container, limit)}, nil
}

func (h *machine) Listening(context.Context, string) ([]PortUse, error) { return h.listen, nil }

// rows is a Store in memory.
type rows struct {
	mu  sync.Mutex
	all map[string]Service
}

func (r *rows) All(context.Context) ([]Service, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []Service{}
	for _, s := range r.all {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (r *rows) Get(_ context.Context, name string) (Service, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.all[name]
	if !ok {
		return Service{}, ErrNotFound
	}
	return s, nil
}

func (r *rows) Add(_ context.Context, name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.all[name]; ok {
		return ErrDuplicate
	}
	r.all[name] = Service{Name: name, State: Deploying}
	return nil
}

func (r *rows) set(name string, fn func(*Service)) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.all[name]
	if !ok {
		return ErrNotFound
	}
	fn(&s)
	r.all[name] = s
	return nil
}

func (r *rows) SetState(_ context.Context, name string, st State) error {
	return r.set(name, func(s *Service) { s.State = st })
}

func (r *rows) SetPending(_ context.Context, name string, p Pending) error {
	return r.set(name, func(s *Service) { s.Pending = &p })
}

func (r *rows) SetApplied(_ context.Context, name string, a Applied) error {
	return r.set(name, func(s *Service) { s.Applied, s.Pending, s.State, s.AppliedAt = a, nil, Deployed, time.Now() })
}

func (r *rows) SetStopped(_ context.Context, name string, stopped []string) error {
	return r.set(name, func(s *Service) { s.Stopped = stopped })
}

func (r *rows) Remove(_ context.Context, name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.all[name]; !ok {
		return ErrNotFound
	}
	delete(r.all, name)
	return nil
}

const (
	digestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// site is a stack of two services: web reads a configuration file and a
// variable from .env, and needs db, whose data is in a folder.
const site = `services:
  db:
    image: example.com/db:1
    volumes: ["./data:/var/lib/db"]
  web:
    image: example.com/web:1
    depends_on: [db]
    environment: {TOKEN: "${TOKEN}"}
    volumes: ["./web.conf:/etc/web.conf:ro"]
    ports: ["127.0.0.1:8080:8080"]
`

type fixture struct {
	t *testing.T
	m *Module
	h *machine
	s *rows
}

func setup(t *testing.T) fixture {
	t.Helper()
	h, s := newMachine(), &rows{all: map[string]Service{}}
	h.registry["example.com/db:1"], h.registry["example.com/web:1"] = digestA, digestA
	h.defs["site"] = map[string]string{"compose.yaml": site, ".env": "TOKEN=t0ken\n", "web.conf": "listen 8080\n"}
	return fixture{t: t, m: NewModule(s, h), h: h, s: s}
}

// accept is the hash a review of name answers now.
func (f fixture) accept(name string) string {
	f.t.Helper()
	r, err := f.m.check(context.Background(), Ref{Name: name})
	if err != nil {
		f.t.Fatalf("check %s: %v", name, err)
	}
	return r.SHA256
}

func (f fixture) add(name string) View {
	f.t.Helper()
	v, err := f.m.add(context.Background(), Accept{Name: name, Accept: f.accept(name)})
	if err != nil {
		f.t.Fatalf("add %s: %v", name, err)
	}
	f.h.calls("")
	return v
}

func (f fixture) apply(name string) (View, error) {
	f.t.Helper()
	return f.m.applyVerb(context.Background(), Accept{Name: name, Accept: f.accept(name)})
}

func (f fixture) unitNames(name string) []string {
	out := []string{}
	for p := range f.h.units[name] {
		out = append(out, strings.TrimPrefix(p, unitDir))
	}
	sort.Strings(out)
	return out
}

func TestAStackIsReviewedThenAdded(t *testing.T) {
	f := setup(t)
	ctx := context.Background()

	av, err := f.m.available(ctx, struct{}{})
	if err != nil || len(av) != 1 || av[0].Name != "site" {
		t.Fatalf("available = %+v, %v", av, err)
	}
	r, err := f.m.check(ctx, Ref{Name: "site"})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Files) != 3 || len(r.Containers) != 2 || refused(r.Findings) || r.Containers[1].Mounts[0] != "web.conf → /etc/web.conf (read-only)" || r.Containers[0].Mounts[0] != "data → /var/lib/db (data)" {
		t.Fatalf("the review = %+v", r)
	}
	if len(f.h.users) != 0 || len(f.s.all) != 0 {
		t.Fatal("a review made a user or a row")
	}

	// An apply names what was reviewed. Anything else is refused, with nothing done.
	if _, err := f.m.add(ctx, Accept{Name: "site", Accept: "not-the-hash"}); !errors.Is(err, ErrChanged) {
		t.Fatalf("add with another hash = %v; want ErrChanged", err)
	}
	// An edit of .env alone, after the review, changes what an apply must be given.
	f.h.defs["site"][".env"] = "TOKEN=another\n"
	if _, err := f.m.add(ctx, Accept{Name: "site", Accept: r.SHA256}); !errors.Is(err, ErrChanged) {
		t.Fatalf("add after .env changed = %v; want ErrChanged", err)
	}
	f.h.defs["site"]["web.conf"] = "listen 8081\n"
	if got := f.accept("site"); got == r.SHA256 {
		t.Fatal("a changed configuration file left the review's hash as it was")
	}
	if len(f.h.users) != 0 || len(f.s.all) != 0 {
		t.Fatal("a refused add made a user or a row")
	}

	v := f.add("site")
	if v.State != string(Deployed) || v.User != "ap-site" || len(v.Containers) != 2 || v.Containers[1].Service != "web" || v.Containers[1].Health != "healthy" || v.Containers[1].Active != "active" {
		t.Fatalf("the view = %+v", v)
	}
	if got, want := f.unitNames("site"), []string{"site-db.container", "site-web.container", "site.network"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("the units = %v; want %v", got, want)
	}
	web := f.h.units["site"][unitDir+"site-web.container"]
	if !strings.Contains(web, "Image=example.com/web@"+digestA+"\n") || strings.Contains(web, "another") {
		t.Errorf("web's unit runs its image by another name than its digest, or holds the secret:\n%s", web)
	}
	folder := f.h.folder["site"]
	if folder["web.conf"] != "listen 8081\n" || folder[".autopanel/web.env"] != "TOKEN=another\n" || folder["data"] != "<dir>" || folder["compose.yaml"] == "" {
		t.Errorf("the stack's folder = %q", folder)
	}
	if _, err := f.m.add(ctx, Accept{Name: "site", Accept: f.accept("site")}); !errors.Is(err, ErrDuplicate) {
		t.Errorf("a second add = %v; want ErrDuplicate", err)
	}
	if got, err := f.m.available(ctx, struct{}{}); err != nil || len(got) != 0 {
		t.Errorf("available after the add = %+v, %v; want none", got, err)
	}
	users, err := f.m.Users(ctx)
	if err != nil || users["ap-site"] != "site" {
		t.Errorf("Users = %v, %v", users, err)
	}
}

func TestAStackThatIsRefusedChangesNothing(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	f.h.defs["site"]["compose.yaml"] = "services:\n  web: {image: example.com/web:1, privileged: true}\n"
	r, err := f.m.check(ctx, Ref{Name: "site"})
	if err != nil || !refused(r.Findings) {
		t.Fatalf("the review = %+v, %v; want a refusal", r, err)
	}
	_, err = f.m.add(ctx, Accept{Name: "site", Accept: r.SHA256})
	var d interface{ PublicDetail() string }
	if !errors.Is(err, ErrRefused) || !errors.As(err, &d) || !strings.Contains(d.PublicDetail(), "privileged") {
		t.Fatalf("add = %v; want ErrRefused naming the key", err)
	}
	if len(f.h.users) != 0 || len(f.s.all) != 0 || len(f.h.units) != 0 {
		t.Fatal("a refused stack made a user, a row or a unit")
	}

	for what, c := range map[string]struct {
		name string
		want error
	}{"a bad name": {"../site", ErrBadName}, "no folder": {"nothing", ErrNoDefinition}} {
		if _, err := f.m.check(ctx, Ref{Name: c.name}); !errors.Is(err, c.want) {
			t.Errorf("check of %s = %v; want %v", what, err, c.want)
		}
	}
	f.h.podman = [2]int{4, 4}
	if _, err := f.m.add(ctx, Accept{Name: "site", Accept: r.SHA256}); !errors.Is(err, ErrOldPodman) {
		t.Errorf("add on Podman 4.4 = %v; want ErrOldPodman", err)
	}
	f.h.podman = [2]int{}
	if _, err := f.m.add(ctx, Accept{Name: "site", Accept: r.SHA256}); !errors.Is(err, ErrNoPodman) {
		t.Errorf("add with no Podman = %v; want ErrNoPodman", err)
	}
}

// TestAnApplyRestartsWhatItsChangeTouches: a changed configuration file
// leaves the unit's text as it was, and the container must still restart.
func TestAnApplyRestartsWhatItsChangeTouches(t *testing.T) {
	f := setup(t)
	f.add("site")

	// Nothing changed: nothing restarts, and no image is asked for again.
	f.h.offline = true
	if _, err := f.apply("site"); err != nil {
		t.Fatalf("an apply of the same definition, with no registry: %v", err)
	}
	if got := f.h.calls("restart"); len(got) != 0 {
		t.Errorf("an apply that changed nothing restarted %v", got)
	}
	f.h.offline = false

	f.h.defs["site"]["web.conf"] = "listen 9090\n"
	if _, err := f.apply("site"); err != nil {
		t.Fatal(err)
	}
	if got := f.h.calls("restart"); !reflect.DeepEqual(got, []string{"restart site site-web.service"}) {
		t.Errorf("after a change to web's file, restarted = %v; want web alone", got)
	}
	if f.h.folder["site"]["web.conf"] != "listen 9090\n" {
		t.Error("the changed file was not committed")
	}

	// A key of .env that web uses: its generated file changes, and so it restarts.
	f.h.defs["site"][".env"] = "TOKEN=rotated\n"
	if _, err := f.apply("site"); err != nil {
		t.Fatal(err)
	}
	if got := f.h.calls("restart"); !reflect.DeepEqual(got, []string{"restart site site-web.service"}) {
		t.Errorf("after a change to .env, restarted = %v; want web alone", got)
	}

	// An apply does not move a tag: the registry now answers another digest,
	// and the unit still runs the one that was pulled.
	f.h.registry["example.com/web:1"] = digestB
	if _, err := f.apply("site"); err != nil {
		t.Fatal(err)
	}
	if got := f.h.calls("pull"); len(got) != 0 {
		t.Errorf("an apply pulled %v", got)
	}
	// services.pull does.
	v, err := f.m.pull(context.Background(), Ref{Name: "site"})
	if err != nil {
		t.Fatal(err)
	}
	if v.Containers[1].Digest != digestB || !strings.Contains(f.h.units["site"][unitDir+"site-web.container"], "@"+digestB+"\n") {
		t.Errorf("after a pull, web = %+v", v.Containers[1])
	}
	if got := f.h.calls("restart"); !reflect.DeepEqual(got, []string{"restart site site-web.service"}) {
		t.Errorf("after a pull, restarted = %v; want the one whose image changed", got)
	}
}

// TestAFolderMountedReadOnlyIsManaged: its files are the definition's, an
// apply after the first takes it for what it is, and it goes when the
// definition no longer mounts it.
func TestAFolderMountedReadOnlyIsManaged(t *testing.T) {
	f := setup(t)
	f.h.defs["site"]["compose.yaml"] = strings.Replace(site, `"./web.conf:/etc/web.conf:ro"`, `"./web.conf:/etc/web.conf:ro", "./pages:/pages:ro"`, 1)
	f.h.defs["site"]["pages/index.html"], f.h.defs["site"]["pages/img/logo.svg"] = "one", "<svg/>"
	f.add("site")
	if _, err := f.apply("site"); err != nil {
		t.Fatalf("a second apply of a stack with a read-only folder: %v", err)
	}
	f.h.defs["site"]["pages/index.html"] = "two"
	delete(f.h.defs["site"], "pages/img/logo.svg")
	f.h.calls("")
	if _, err := f.apply("site"); err != nil {
		t.Fatal(err)
	}
	folder := f.h.folder["site"]
	if _, has := folder["pages/img/logo.svg"]; has || folder["pages/index.html"] != "two" {
		t.Errorf("the folder after a file changed and another left the definition = %q", folder)
	}
	if got := f.h.calls("restart"); !reflect.DeepEqual(got, []string{"restart site site-web.service"}) {
		t.Errorf("restarted = %v; want web, which mounts the folder", got)
	}
	f.h.defs["site"]["compose.yaml"] = site
	if _, err := f.apply("site"); err != nil {
		t.Fatal(err)
	}
	for file := range f.h.folder["site"] {
		if strings.HasPrefix(file, "pages") {
			t.Errorf("%s is left of a folder the definition no longer mounts", file)
		}
	}
}

// TestAnApplyNeverWritesData: the folder a container writes to is made once.
func TestAnApplyNeverWritesData(t *testing.T) {
	f := setup(t)
	f.add("site")
	f.h.folder["site"]["data/db.sqlite"] = "the family's history"
	delete(f.h.folder["site"], "data")

	f.h.defs["site"]["web.conf"] = "listen 9090\n"
	if _, err := f.apply("site"); err != nil {
		t.Fatal(err)
	}
	if f.h.folder["site"]["data/db.sqlite"] != "the family's history" {
		t.Fatal("an apply touched the stack's data")
	}

	// The same folder, now mounted read-only, would make it a managed file
	// that an apply replaces. Refused: data stays data.
	for what, compose := range map[string]string{
		"the data mount turned read-only": strings.Replace(site, `"./data:/var/lib/db"`, `"./data:/var/lib/db:ro"`, 1),
		"a folder inside it mounted read-only": strings.Replace(site, `volumes: ["./web.conf:/etc/web.conf:ro"]`,
			`volumes: ["./web.conf:/etc/web.conf:ro", "./data/conf:/c:ro"]`, 1),
	} {
		f.h.defs["site"]["compose.yaml"] = compose
		f.h.defs["site"]["data/db.sqlite"] = "a seed"
		f.h.defs["site"]["data/conf/x"] = "x"
		r, err := f.m.check(context.Background(), Ref{Name: "site"})
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, fd := range r.Findings {
			found = found || (fd.ID == "data-overlap" && fd.Severity == Refused)
		}
		if !found {
			t.Errorf("%s was not refused: %v", what, refusals(r.Findings))
		}
		if _, err := f.m.applyVerb(context.Background(), Accept{Name: "site", Accept: r.SHA256}); !errors.Is(err, ErrRefused) {
			t.Errorf("%s was applied: %v", what, err)
		}
	}
	if f.h.folder["site"]["data/db.sqlite"] != "the family's history" {
		t.Fatal("a refused apply touched the stack's data")
	}
}

// TestAnApplyRemovesWhatTheFileNoLongerHas, a failed apply's leftovers
// included: its unit is on disk though nothing applied names it.
func TestAnApplyRemovesWhatTheFileNoLongerHas(t *testing.T) {
	f := setup(t)
	f.add("site")
	withCache := strings.Replace(site, "services:\n", "services:\n  cache:\n    image: example.com/web:1\n", 1)

	// An apply that adds a service fails after its units are written.
	f.h.defs["site"]["compose.yaml"] = withCache
	f.h.fail["start"] = errors.New("systemd did not answer")
	_, err := f.apply("site")
	var d interface{ PublicDetail() string }
	if !errors.Is(err, ErrIncomplete) || !errors.As(err, &d) || d.PublicDetail() != "start: systemd did not answer" {
		t.Fatalf("a failed apply = %v; want ErrIncomplete, naming its step and why", err)
	}
	if _, has := f.h.units["site"][unitDir+"site-cache.container"]; !has {
		t.Fatal("the test's premise: the failed apply wrote the new unit")
	}
	list, _ := f.m.list(context.Background(), struct{}{})
	if list[0].State != Incomplete || list[0].Step != "start" {
		t.Fatalf("after a failed apply the stack is %q at %q; want incomplete, at start", list[0].State, list[0].Step)
	}

	// The administrator takes the service out again. A second apply fails
	// too, earlier: the record must still hold what the first one left.
	f.h.defs["site"]["compose.yaml"] = site
	for _, attempt := range []string{"second", "third"} {
		f.h.fail["EnsureUser"] = errors.New("the host did not answer")
		if _, err := f.apply("site"); err == nil {
			t.Fatalf("the %s apply did not fail", attempt)
		}
		if _, has := f.h.units["site"][unitDir+"site-cache.container"]; !has {
			t.Fatal("the test's premise: these applies fail before anything is removed")
		}
	}

	// And one that fails later, at the moment it stops what is to go: what it
	// records then must still name the unit it has not deleted yet.
	f.h.fail["stop"] = errors.New("systemd did not answer")
	if _, err := f.apply("site"); err == nil {
		t.Fatal("the fourth apply did not fail")
	}
	if _, has := f.h.units["site"][unitDir+"site-cache.container"]; !has {
		t.Fatal("the test's premise: the unit is still there after the stop failed")
	}

	f.h.calls("")
	v, err := f.apply("site")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := f.unitNames("site"), []string{"site-db.container", "site-web.container", "site.network"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("the units = %v; want %v: a unit a failed apply wrote would start at the next boot", got, want)
	}
	if v.State != string(Deployed) || len(v.Containers) != 2 {
		t.Errorf("the view = %+v", v)
	}

	// A service the file drops: stopped, and its unit deleted.
	f.h.defs["site"]["compose.yaml"] = strings.Split(site, "  web:")[0]
	r, _ := f.m.check(context.Background(), Ref{Name: "site"})
	if !reflect.DeepEqual(r.Removes, []string{"web"}) {
		t.Errorf("the review's removes = %v; want web", r.Removes)
	}
	f.h.calls("")
	if _, err := f.apply("site"); err != nil {
		t.Fatal(err)
	}
	if got := f.h.calls("stop"); !reflect.DeepEqual(got, []string{"stop site site-web.service"}) {
		t.Errorf("stopped = %v; want web", got)
	}
	if got, want := f.unitNames("site"), []string{"site-db.container", "site.network"}; !reflect.DeepEqual(got, want) {
		t.Errorf("the units = %v; want %v", got, want)
	}
	if _, has := f.h.folder["site"]["web.conf"]; has {
		t.Error("a managed file the definition no longer has was left in the stack's folder")
	}
	if _, has := f.h.folder["site"][".autopanel/web.env"]; has {
		t.Error("a generated file of a service that is gone was left")
	}
}

// TestARetryRestartsWhatChanged: after a failure the folder already holds the
// new files, so "changed" is measured against what was applied.
func TestARetryRestartsWhatChanged(t *testing.T) {
	f := setup(t)
	f.add("site")
	f.h.defs["site"]["web.conf"] = "listen 9090\n"
	f.h.fail["Install"] = errors.New("no space")
	if _, err := f.apply("site"); err == nil {
		t.Fatal("the apply did not fail")
	}
	if f.h.folder["site"]["web.conf"] != "listen 9090\n" {
		t.Fatal("the test's premise: the failed apply committed the new file")
	}
	f.h.calls("")
	if _, err := f.apply("site"); err != nil {
		t.Fatal(err)
	}
	if got := f.h.calls("restart"); !reflect.DeepEqual(got, []string{"restart site site-web.service"}) {
		t.Errorf("the retry restarted %v; want web, whose file changed since the last apply that finished", got)
	}
}

// TestPrepareStartsNothing, and the add after it needs no registry.
func TestPrepareStartsNothing(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	v, err := f.m.prepare(ctx, Accept{Name: "site", Accept: f.accept("site")})
	if err != nil {
		t.Fatal(err)
	}
	if v.State != Prepared || len(v.Containers) != 0 {
		t.Fatalf("the view = %+v; want prepared, with no container", v)
	}
	if len(f.h.units["site"]) != 0 || len(f.h.calls("start")) != 0 {
		t.Fatal("prepare wrote a unit or started one")
	}
	if !f.h.users["site"] || f.h.folder["site"]["web.conf"] == "" || !f.h.held["site"]["example.com/web@"+digestA] {
		t.Fatal("prepare left no user, no files or no image")
	}
	// The data is put in by hand, between the two.
	f.h.folder["site"]["data/db.sqlite"] = "restored"
	delete(f.h.folder["site"], "data")

	// The files prepare itself put there are not taken for data, and no image
	// is pulled again: the network may be cut by now.
	f.h.offline = true
	f.h.registry["example.com/web:1"] = digestB
	v, err = f.m.add(ctx, Accept{Name: "site", Accept: f.accept("site")})
	if err != nil {
		t.Fatalf("add after prepare: %v", err)
	}
	if v.State != string(Deployed) || len(v.Containers) != 2 || v.Containers[1].Digest != digestA {
		t.Fatalf("the view = %+v; want it deployed, on the digests prepare pulled", v)
	}
	if got := f.h.calls("start"); !reflect.DeepEqual(got, []string{"start site site-db.service site-web.service"}) {
		t.Errorf("started = %v", got)
	}
	if f.h.folder["site"]["data/db.sqlite"] != "restored" {
		t.Error("the add touched the data put in after prepare")
	}
}

// TestAStopIsRememberedAndCoversWhatDependsOnIt: a dependant that starts
// would start what it needs.
func TestAStopIsRememberedAndCoversWhatDependsOnIt(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	f.add("site")
	db, web := unitDir+"site-db.container", unitDir+"site-web.container"

	v, err := f.m.stop(ctx, Ref{Name: "site", Service: "db"})
	if err != nil {
		t.Fatal(err)
	}
	if !v.Containers[0].Stopped || !v.Containers[1].Stopped {
		t.Fatalf("after stopping db: %+v; want db and web, which needs it, both stopped", v.Containers)
	}
	if got := f.h.calls("stop"); !reflect.DeepEqual(got, []string{"stop site site-db.service site-web.service"}) {
		t.Errorf("stopped = %v", got)
	}
	for _, u := range []string{db, web} {
		if strings.Contains(f.h.units["site"][u], "[Install]") {
			t.Errorf("%s keeps its [Install] section: a boot would start it", u)
		}
	}

	if _, err := f.m.start(ctx, Ref{Name: "site", Service: "web"}); !errors.Is(err, ErrStoppedNeed) {
		t.Fatalf("starting web while db is stopped = %v; want ErrStoppedNeed", err)
	}
	if _, err := f.m.restart(ctx, Ref{Name: "site"}); err != nil || len(f.h.calls("restart")) != 0 {
		t.Errorf("a restart of the stack started what was stopped (%v)", err)
	}

	// An apply keeps them stopped, and so a service it adds that needs one.
	f.h.defs["site"]["compose.yaml"] = site + "  worker:\n    image: example.com/web:1\n    depends_on: [web]\n"
	f.h.defs["site"]["web.conf"] = "listen 9090\n"
	f.h.calls("")
	v, err = f.apply("site")
	if err != nil {
		t.Fatal(err)
	}
	if got := append(f.h.calls("start"), f.h.calls("restart")...); len(got) != 0 {
		t.Errorf("the apply started or restarted %v; every service is stopped, or needs one that is", got)
	}
	for _, c := range v.Containers {
		if !c.Stopped {
			t.Errorf("%s is not recorded as stopped", c.Service)
		}
	}
	if strings.Contains(f.h.units["site"][unitDir+"site-worker.container"], "[Install]") {
		t.Error("the added service keeps its [Install] section: at boot it would start, and db with it")
	}

	if _, err := f.m.start(ctx, Ref{Name: "site", Service: "db"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.h.units["site"][db], "[Install]") || strings.Contains(f.h.units["site"][web], "[Install]") {
		t.Error("after starting db: db has its [Install] section back, and web, still stopped, has not")
	}
	f.h.calls("")
	v, err = f.m.start(ctx, Ref{Name: "site"})
	if err != nil {
		t.Fatal(err)
	}
	if got := f.h.calls("start"); !reflect.DeepEqual(got, []string{"start site site-db.service site-web.service site-worker.service"}) {
		t.Errorf("starting the stack started %v", got)
	}
	for _, c := range v.Containers {
		if c.Stopped {
			t.Errorf("%s is still recorded as stopped", c.Service)
		}
	}
}

func TestStacksDoNotShareAPort(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	f.add("site")
	f.h.defs["blog"] = map[string]string{"compose.yaml": "services:\n  web: {image: example.com/web:1, ports: [\"127.0.0.1:8080:80\"]}\n"}
	r, err := f.m.check(ctx, Ref{Name: "blog"})
	if err != nil {
		t.Fatal(err)
	}
	if got := refusals(r.Findings); len(got) != 1 || !strings.HasPrefix(got[0], "port-taken web 8080/tcp is stack site's") {
		t.Errorf("a second stack on the first one's port: %q", got)
	}
	f.h.listen = []PortUse{{Proto: "tcp", From: 9000, To: 9000}}
	f.h.defs["blog"]["compose.yaml"] = "services:\n  web: {image: example.com/web:1, ports: [\"9000:80\"]}\n"
	r, _ = f.m.check(ctx, Ref{Name: "blog"})
	if got := refusals(r.Findings); len(got) != 1 || !strings.HasPrefix(got[0], "port-in-use web 9000/tcp") {
		t.Errorf("a port another program listens on: %q", got)
	}
}

func TestRemoveLogsAndTheVerbsOfAStackThatIsNotThere(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	for what, err := range map[string]error{
		"start":  func() error { _, err := f.m.start(ctx, Ref{Name: "site"}); return err }(),
		"pull":   func() error { _, err := f.m.pull(ctx, Ref{Name: "site"}); return err }(),
		"apply":  func() error { _, err := f.m.applyVerb(ctx, Accept{Name: "site", Accept: "x"}); return err }(),
		"remove": func() error { _, err := f.m.remove(ctx, Remove{Name: "site"}); return err }(),
		"logs":   func() error { _, err := f.m.logs(ctx, LogsAsk{Name: "site"}); return err }(),
	} {
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("%s of a stack that is not registered = %v; want ErrNotFound", what, err)
		}
	}
	f.add("site")
	if _, err := f.m.stop(ctx, Ref{Name: "site", Service: "nothing"}); !errors.Is(err, ErrNoService) {
		t.Errorf("stop of a service the stack has not = %v; want ErrNoService", err)
	}
	l, err := f.m.logs(ctx, LogsAsk{Name: "site", Service: "web", Limit: 9999})
	if err != nil || !reflect.DeepEqual(l.Lines, []string{`site "site-web" 500`}) {
		t.Errorf("logs = %v, %v; want web's container, 500 lines at most", l.Lines, err)
	}
	if _, err := f.m.remove(ctx, Remove{Name: "site", Purge: true}); err != nil {
		t.Fatal(err)
	}
	if len(f.s.all) != 0 || f.h.users["site"] || f.h.folder["site"] != nil {
		t.Error("a purge left a row, a user or the folder")
	}
	if got, _ := f.m.available(ctx, struct{}{}); len(got) != 1 {
		t.Errorf("after the removal the definition is offered again: %v", got)
	}

	// A row an older AutoPanel made from a template: shown, and only removed.
	f.s.all["turn"] = Service{Name: "turn", State: Deployed, Legacy: true}
	list, _ := f.m.list(ctx, struct{}{})
	if len(list) != 1 || list[0].State != LegacyRow {
		t.Fatalf("the list = %+v", list)
	}
	if _, err := f.m.start(ctx, Ref{Name: "turn"}); !errors.Is(err, ErrLegacy) {
		t.Errorf("start of a templated service = %v; want ErrLegacy", err)
	}
	if _, err := f.m.remove(ctx, Remove{Name: "turn"}); err != nil {
		t.Errorf("remove of a templated service: %v", err)
	}
}

func TestEveryDeclaredErrorHasItsOwnCode(t *testing.T) {
	seen := map[int64]string{}
	for _, e := range NewModule(nil, nil).Errors() {
		if other, dup := seen[e.Code]; dup {
			t.Errorf("%s and %s share the code %d", e.Name, other, e.Code)
		}
		seen[e.Code] = e.Name
		if e.Err == nil || e.Message == "" || !strings.HasPrefix(e.Name, "services.") {
			t.Errorf("%+v is not a whole public error", e)
		}
	}
}
