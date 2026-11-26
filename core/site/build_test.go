package site_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yongjohnlee80/golib/dao"

	"github.com/yongjohnlee80/autopanel/core/site"
	"github.com/yongjohnlee80/autopanel/internal/auth"
	"github.com/yongjohnlee80/autopanel/store"
)

// pipe is a Pipeline in a temporary directory. Its builder lays out what
// build.json names, as the kit will, unless theme says otherwise.
type pipe struct {
	t         *testing.T
	dir       string
	mu        sync.Mutex
	runs      int
	theme     func(content, out string) error // the builder's work; nil: the kit's
	onRun     func()                          // called while the build runs
	inputs    map[string]string               // the last job's inputs
	public    map[string]string               // the last public job's inputs
	jobs      []map[string]string             // every job's inputs, in order
	published []site.Manifest
	downs     []string
	held      map[int64]heldFiles // what PublishHeld was last given, by node
	kept      map[int64]int64     // what SweepHeld was last told to keep
}

type heldFiles struct {
	build int64
	files []string
	page  string // the page's text
}

func (p *pipe) Prepare(host string) (site.Job, error) {
	dir := filepath.Join(p.dir, host)
	if err := os.RemoveAll(dir); err != nil {
		return site.Job{}, err
	}
	for _, d := range []string{"content", "out"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			return site.Job{}, err
		}
	}
	p.mu.Lock()
	p.inputs = map[string]string{}
	p.jobs = append(p.jobs, p.inputs)
	p.mu.Unlock()
	return site.Job{Host: host, Ref: dir}, nil
}

func (p *pipe) Input(j site.Job, name string, data []byte) error {
	p.mu.Lock()
	p.inputs[name] = string(data)
	if name == "build.json" && !strings.Contains(string(data), `"held":true`) {
		p.public = p.inputs
	}
	p.mu.Unlock()
	f := filepath.Join(j.Ref.(string), "content", name)
	if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
		return err
	}
	return os.WriteFile(f, data, 0o644)
}

func (p *pipe) Run(_ context.Context, j site.Job) (string, error) {
	p.mu.Lock()
	p.runs++
	p.mu.Unlock()
	if p.onRun != nil {
		p.onRun()
	}
	content, out := filepath.Join(j.Ref.(string), "content"), filepath.Join(j.Ref.(string), "out")
	if p.theme != nil {
		return "the theme ran", p.theme(content, out)
	}
	return "built", kit(content, out)
}

// kit lays out a page for each document at the path the core chose, with the
// kit's scripts on a page that draws a diagram.
func kit(content, out string) error {
	raw, err := os.ReadFile(filepath.Join(content, "build.json"))
	if err != nil {
		return err
	}
	var in site.BuildInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return err
	}
	write := func(name, page string) error {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(out, name)), 0o755); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(out, name), []byte(page), 0o644)
	}
	if err := write("index.html", "<!doctype html><title>home</title><h1>home</h1>"); err != nil {
		return err
	}
	if in.Held {
		// a held document's build: its page at the root, its look beside it,
		// and (as a theme might) a feed naming it, which the core must not keep
		if err := write("look.css", ":root{}"); err != nil {
			return err
		}
		if err := write("feed.xml", `<?xml version="1.0"?><rss version="2.0"><channel><title>`+in.Docs[0].Slug+`</title><link>https://example.org/</link><description>d</description></channel></rss>`); err != nil {
			return err
		}
		// its images beside the page, and an .html document's inert copy
		d := in.Docs[0]
		dir := filepath.Join(content, filepath.FromSlash(d.Dir))
		_ = filepath.WalkDir(dir, func(p string, e os.DirEntry, err error) error {
			if err != nil || e.IsDir() || !strings.HasSuffix(p, ".png") {
				return nil
			}
			data, _ := os.ReadFile(p)
			rel, _ := filepath.Rel(dir, p)
			return write(filepath.ToSlash(rel), string(data))
		})
		if d.Format == site.HTML {
			if err := write(site.InertPage, "<!doctype html><p>inert</p>"); err != nil {
				return err
			}
		}
	}
	for _, d := range in.Docs {
		body := "<!doctype html><title>" + d.Slug + "</title><article>" + d.Slug + "</article>"
		if d.Mermaid {
			body += `<script src="` + in.Base + `/_kit/m.js" integrity="sha256-M" defer></script><script src="` + in.Base + `/_kit/s.js" integrity="sha256-S" defer></script>`
		}
		if err := write(d.Page, body); err != nil {
			return err
		}
	}
	return nil
}

func (p *pipe) TakeAway(j site.Job) (string, error) { return filepath.Join(j.Ref.(string), "out"), nil }
func (p *pipe) Publish(_ site.Job, m site.Manifest) error {
	p.mu.Lock()
	p.published = append(p.published, m)
	p.mu.Unlock()
	return nil
}
func (p *pipe) TakeDown(host string) error {
	p.mu.Lock()
	p.downs = append(p.downs, host)
	p.mu.Unlock()
	return nil
}
func (p *pipe) Remove(string) error { return nil }

func (p *pipe) PublishHeld(j site.Job, node, build int64, files, _ []string) error {
	out := filepath.Join(j.Ref.(string), "out")
	for _, f := range files {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			return err
		}
	}
	page, _ := os.ReadFile(filepath.Join(out, site.HeldPage))
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.held == nil {
		p.held = map[int64]heldFiles{}
	}
	p.held[node] = heldFiles{build: build, files: files, page: string(page)}
	return nil
}

func (p *pipe) SweepHeld(_ string, keep map[int64]int64) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.kept = keep
	for node := range p.held {
		if _, ok := keep[node]; !ok {
			delete(p.held, node)
		}
	}
	return nil
}

type buildFixture struct {
	m    *site.Module
	st   *store.Store
	pipe *pipe
	b    *site.Builds
	ctx  context.Context
	blog site.Site
}

func buildSetup(t *testing.T) *buildFixture {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, store.Config{Engine: dao.DialectSQLite, Path: filepath.Join(t.TempDir(), "store.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ann, err := st.Users().AddUser(ctx, "ann", auth.RoleOperator, nil, "v", false)
	if err != nil {
		t.Fatal(err)
	}
	p := &pipe{t: t, dir: t.TempDir()}
	b := site.NewBuilds(st.Sites(), p, site.Kit{Scripts: []site.KitScript{{Path: "/_kit/m.js", Integrity: "sha256-M"}, {Path: "/_kit/s.js", Integrity: "sha256-S"}}},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	m := site.NewModule(st.Sites(), people{"user:ann": {ID: ann.ID, Name: "ann"}, "user:root": {ID: 999, Name: "root", Admin: true}})
	m.SetBuilds(b)
	if _, err := call[site.SiteView](t, m, "user:root", "site.add", site.SiteAsk{Host: "blog.example.com"}); err != nil {
		t.Fatal(err)
	}
	blog, err := st.Sites().SiteByHost(ctx, "blog.example.com")
	if err != nil {
		t.Fatal(err)
	}
	return &buildFixture{m: m, st: st, pipe: p, b: b, ctx: ctx, blog: blog}
}

func (f *buildFixture) put(t *testing.T, slug, level, body string) site.Published {
	t.Helper()
	p, err := call[site.Published](t, f.m, "user:ann", "site.doc.put", site.Put{Site: "blog.example.com", Slug: slug, Format: "md", Body: body, Visibility: level})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func (f *buildFixture) status(t *testing.T) site.Status {
	t.Helper()
	s, err := call[site.Status](t, f.m, "user:ann", "site.status", site.SiteAsk{Host: "blog.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// A public document is built with what the core chose: its page's path, the
// diagram pages. A held document is in no public job's input; it is built in
// a job of its own, which sees nothing else.
func TestAPublicDocumentAndAHeldOneAreBuiltApart(t *testing.T) {
	f := buildSetup(t)
	held := f.put(t, "diary", "private", "# Diary\nthe held text")
	if held.Build != 1 || held.Served {
		t.Fatalf("a private publish: %+v", held)
	}
	pub := f.put(t, "hello", "public", "# Hello\n\n```mermaid\ngraph TD; A-->B\n```\n")
	if pub.Build != 2 || !pub.Served {
		t.Fatalf("a public publish: %+v", pub)
	}
	if s := f.status(t); s.State != site.BuildWaiting || s.Build != 2 || s.LiveBuild != 0 {
		t.Fatalf("before the build: %+v", s)
	}
	if err := f.b.BuildOnce(f.ctx, f.blog.ID); err != nil {
		t.Fatal(err)
	}
	if s := f.status(t); s.State != site.BuildLive || s.LiveBuild != 2 || s.Error != "" {
		t.Fatalf("after the build: %+v", s)
	}
	if len(f.pipe.jobs) != 2 {
		t.Fatalf("%d jobs; want the public one and the held document's", len(f.pipe.jobs))
	}
	public, alone := f.pipe.jobs[0], f.pipe.jobs[1]
	for name, data := range public {
		if strings.Contains(data, "held text") || strings.Contains(name, "diary") {
			t.Fatalf("a held document is in the public job's input: %s", name)
		}
	}
	if !strings.Contains(public["docs/hello/index.md"], "# Hello") {
		t.Fatalf("the public document's source: %v", public)
	}
	for name, data := range alone {
		if strings.Contains(data, "Hello") || strings.Contains(name, "hello") {
			t.Fatalf("a held job's input holds another document: %s", name)
		}
	}
	var in site.BuildInput
	if err := json.Unmarshal([]byte(alone["build.json"]), &in); err != nil || !in.Held || in.Base != "/s/blog.example.com/diary" || len(in.Docs) != 1 || in.Docs[0].Page != "index.html" {
		t.Fatalf("the held job's index: %+v, %v", in, err)
	}
	m := f.pipe.published[len(f.pipe.published)-1]
	if m.Build != 2 || len(m.Mermaid) != 1 || m.Mermaid[0] != "hello/index.html" || len(m.ScriptHashes) != 2 {
		t.Fatalf("the manifest: %+v", m)
	}
	// What the core kept of the held job: the page and the look, not the feed
	// the job also wrote.
	d, err := f.st.Sites().Child(f.ctx, mustRoot(t, f).ID, "diary")
	if err != nil {
		t.Fatal(err)
	}
	got := f.pipe.held[d.ID]
	if got.build != 2 || strings.Join(got.files, " ") != "index.html look.css" || !strings.Contains(got.page, "diary") {
		t.Fatalf("the held files: %+v", got)
	}
	if h, err := f.st.Sites().HeldOf(f.ctx, d.ID); err != nil || h.Build != 2 || h.Mermaid {
		t.Fatalf("the store's record: %+v, %v", h, err)
	}
	// Nothing owed: no second build.
	if err := f.b.BuildOnce(f.ctx, f.blog.ID); !errors.Is(err, site.ErrNoBuild) {
		t.Fatalf("a build with nothing owed: %v", err)
	}
}

func mustRoot(t *testing.T, f *buildFixture) site.Doc {
	t.Helper()
	r, err := f.st.Sites().Root(f.ctx, f.blog.ID)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// Only what changed is built again: a held document's change runs its own
// job and not the public one, and the reverse; a held document that is
// removed, or made public, has its files swept.
func TestOnlyWhatChangedIsBuiltAgain(t *testing.T) {
	f := buildSetup(t)
	f.put(t, "hello", "public", "# Hello")
	f.put(t, "diary", "private", "# Diary")
	f.put(t, "plans", "internal", "# Plans")
	build := func() {
		t.Helper()
		if err := f.b.BuildOnce(f.ctx, f.blog.ID); err != nil {
			t.Fatal(err)
		}
	}
	build()
	if len(f.pipe.jobs) != 3 || len(f.pipe.held) != 2 {
		t.Fatalf("the first build: %d jobs, %d held", len(f.pipe.jobs), len(f.pipe.held))
	}
	root := mustRoot(t, f)
	diary, _ := f.st.Sites().Child(f.ctx, root.ID, "diary")
	plans, _ := f.st.Sites().Child(f.ctx, root.ID, "plans")

	f.put(t, "diary", "private", "# Diary, more")
	build()
	if len(f.pipe.jobs) != 4 || f.pipe.jobs[3]["docs/diary/index.md"] != "# Diary, more" {
		t.Fatalf("after a held change: %d jobs", len(f.pipe.jobs))
	}
	if f.pipe.held[diary.ID].build != 4 || f.pipe.held[plans.ID].build != 3 || f.pipe.kept[plans.ID] != 3 {
		t.Fatalf("the held builds: %+v, kept %v", f.pipe.held, f.pipe.kept)
	}

	f.put(t, "hello", "public", "# Hello again")
	build()
	if len(f.pipe.jobs) != 5 || f.pipe.jobs[4]["docs/hello/index.md"] != "# Hello again" {
		t.Fatalf("after a public change: %d jobs", len(f.pipe.jobs))
	}

	// internal → private: the same surface, the same page: nothing is built.
	f.put(t, "plans", "private", "# Plans")
	build()
	if len(f.pipe.jobs) != 5 {
		t.Fatalf("a level change between members' levels built something: %d jobs", len(f.pipe.jobs))
	}

	// Made public: its held files go; it is in the public pages now.
	f.put(t, "plans", "public", "# Plans")
	build()
	if _, still := f.pipe.held[plans.ID]; still || len(f.pipe.jobs) != 6 {
		t.Fatalf("after going public: held %v, %d jobs", f.pipe.held, len(f.pipe.jobs))
	}
	if _, err := f.st.Sites().HeldOf(f.ctx, plans.ID); !errors.Is(err, site.ErrNotFound) {
		t.Fatalf("the store still holds a build of a public document: %v", err)
	}

	if _, err := call[struct{}](t, f.m, "user:ann", "site.doc.remove", site.DocAsk{Site: "blog.example.com", Slug: "diary"}); err != nil {
		t.Fatal(err)
	}
	build()
	if len(f.pipe.held) != 0 || len(f.pipe.jobs) != 6 {
		t.Fatalf("after a held document's removal: held %v, %d jobs", f.pipe.held, len(f.pipe.jobs))
	}
}

// A held document whose build fails keeps what it had; the others are still
// built; the site's status names the node and nothing of its text.
func TestAHeldBuildThatFailsKeepsWhatItHad(t *testing.T) {
	f := buildSetup(t)
	f.put(t, "diary", "private", "# Diary")
	f.put(t, "plans", "private", "# Plans")
	if err := f.b.BuildOnce(f.ctx, f.blog.ID); err != nil {
		t.Fatal(err)
	}
	root := mustRoot(t, f)
	diary, _ := f.st.Sites().Child(f.ctx, root.ID, "diary")
	plans, _ := f.st.Sites().Child(f.ctx, root.ID, "plans")
	f.pipe.theme = func(content, out string) error {
		if _, err := os.Stat(filepath.Join(content, "docs", "diary")); err == nil {
			return os.WriteFile(filepath.Join(out, "index.html"), []byte("<script>the secret plan</script>"), 0o644)
		}
		return kit(content, out)
	}
	f.put(t, "diary", "private", "# Diary: the secret plan")
	f.put(t, "plans", "private", "# Plans, more")
	err := f.b.BuildOnce(f.ctx, f.blog.ID)
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("a failing held build: %v", err)
	}
	s := f.status(t)
	if s.State != site.BuildFailed || strings.Contains(s.Error, "secret") || !strings.Contains(s.Error, "held document") {
		t.Fatalf("the status: %+v", s)
	}
	if f.pipe.held[diary.ID].build != 2 || f.pipe.held[plans.ID].build != 4 {
		t.Fatalf("the held builds: %+v", f.pipe.held)
	}
}

// A build whose output fails the check is not published; the pages that were
// live stay, and the reason is recorded.
func TestAFailedBuildLeavesTheLivePages(t *testing.T) {
	f := buildSetup(t)
	f.put(t, "hello", "public", "# Hello")
	if err := f.b.BuildOnce(f.ctx, f.blog.ID); err != nil {
		t.Fatal(err)
	}
	f.pipe.theme = func(_, out string) error {
		return os.WriteFile(filepath.Join(out, "index.html"), []byte("<script>alert(1)</script>"), 0o644)
	}
	f.put(t, "hello", "public", "# Hello again")
	if err := f.b.BuildOnce(f.ctx, f.blog.ID); !errors.Is(err, site.ErrOutput) {
		t.Fatalf("a theme that writes a script: %v", err)
	}
	s := f.status(t)
	if s.State != site.BuildFailed || s.LiveBuild != 1 || s.Build != 2 || !strings.Contains(s.Error, "<script>") {
		t.Fatalf("after a failed build: %+v", s)
	}
	if len(f.pipe.published) != 1 {
		t.Fatalf("a failed build was published: %d", len(f.pipe.published))
	}
	// A diagram script on a page the core did not name fails too.
	f.pipe.theme = func(content, out string) error {
		if err := kit(content, out); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(out, "index.html"), []byte(`<script src="/_kit/m.js" integrity="sha256-M" defer></script>`), 0o644)
	}
	f.put(t, "hello", "public", "# Hello, a third time")
	if err := f.b.BuildOnce(f.ctx, f.blog.ID); !errors.Is(err, site.ErrOutput) {
		t.Fatalf("the kit's script on a page with no diagram: %v", err)
	}
	// Publishing again recovers.
	f.pipe.theme = nil
	f.put(t, "hello", "public", "# Hello, fixed")
	if err := f.b.BuildOnce(f.ctx, f.blog.ID); err != nil {
		t.Fatal(err)
	}
	if s := f.status(t); s.State != site.BuildLive || s.LiveBuild != 4 {
		t.Fatalf("recovered: %+v", s)
	}
}

// Lowering a level takes the pages down before the publish answers; they
// stay down until a build passes, a failed one included.
func TestWithdrawingSomethingPublicTakesThePagesDown(t *testing.T) {
	f := buildSetup(t)
	f.put(t, "hello", "public", "# Hello")
	f.put(t, "notes", "public", "# Notes")
	if err := f.b.BuildOnce(f.ctx, f.blog.ID); err != nil {
		t.Fatal(err)
	}
	f.put(t, "notes", "private", "# Notes")
	if len(f.pipe.downs) != 1 || f.status(t).State != site.BuildWaiting {
		t.Fatalf("lowered: downs %v, %+v", f.pipe.downs, f.status(t))
	}
	f.pipe.theme = func(string, string) error { return errors.New("the build broke") }
	_ = f.b.BuildOnce(f.ctx, f.blog.ID)
	if s := f.status(t); s.State != "down" {
		t.Fatalf("a failed build after a withdrawal: %+v", s)
	}
	f.pipe.theme = nil
	f.put(t, "hello", "public", "# Hello again")
	if err := f.b.BuildOnce(f.ctx, f.blog.ID); err != nil {
		t.Fatal(err)
	}
	if s := f.status(t); s.State != site.BuildLive {
		t.Fatalf("up again: %+v", s)
	}
	if strings.Contains(f.pipe.public["build.json"], "notes") {
		t.Fatal("the withdrawn document is in the next build")
	}
	// Removing a public document takes them down too.
	if _, err := call[struct{}](t, f.m, "user:ann", "site.doc.remove", site.DocAsk{Site: "blog.example.com", Slug: "hello"}); err != nil {
		t.Fatal(err)
	}
	if len(f.pipe.downs) != 2 {
		t.Fatalf("a public document removed: downs %v", f.pipe.downs)
	}
}

// Something public withdrawn while a build runs: its output may hold it, so
// it is discarded, and the build owed after it runs.
func TestABuildThatRanAcrossAWithdrawalIsDiscarded(t *testing.T) {
	f := buildSetup(t)
	f.put(t, "hello", "public", "# Hello")
	f.put(t, "notes", "public", "# Notes")
	f.pipe.onRun = func() {
		f.pipe.onRun = nil
		f.put(t, "notes", "private", "# Notes")
	}
	if err := f.b.BuildOnce(f.ctx, f.blog.ID); !errors.Is(err, site.ErrSuperseded) {
		t.Fatalf("a build across a withdrawal: %v", err)
	}
	if len(f.pipe.published) != 0 {
		t.Fatal("it was published")
	}
	if err := f.b.BuildOnce(f.ctx, f.blog.ID); err != nil {
		t.Fatal(err)
	}
	if len(f.pipe.published) != 1 || strings.Contains(f.pipe.public["build.json"], "notes") {
		t.Fatalf("the next build: %d published, %s", len(f.pipe.published), f.pipe.public["build.json"])
	}
}

// Changes that come together are one build; a build owed when the core
// stopped runs when it starts.
func TestChangesTogetherAreOneBuild(t *testing.T) {
	f := buildSetup(t)
	f.put(t, "a", "public", "# A")
	f.put(t, "b", "public", "# B")
	f.put(t, "c", "public", "# C")
	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()
	done := make(chan struct{})
	go func() { f.b.Run(ctx); close(done) }() // the three were owed before it ran
	deadline := time.Now().Add(10 * time.Second)
	for f.status(t).State != site.BuildLive {
		if time.Now().After(deadline) {
			t.Fatalf("never built: %+v", f.status(t))
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	if f.pipe.runs != 1 {
		t.Fatalf("%d builds for three changes", f.pipe.runs)
	}
	var in site.BuildInput
	if err := json.Unmarshal([]byte(f.pipe.public["build.json"]), &in); err != nil || len(in.Docs) != 3 {
		t.Fatalf("the build's documents: %+v, %v", in, err)
	}
}

// A build is given what is public along its whole path: a public document in
// a private folder is in no build's input, and a public folder's page lists
// what it holds.
func TestABuildTakesWhatIsPublicAlongItsPath(t *testing.T) {
	f := buildSetup(t)
	for _, fo := range []site.FolderAsk{
		{Site: "blog.example.com", Path: "guides", Visibility: "public", Title: str("Guides")},
		{Site: "blog.example.com", Path: "guides/install", Visibility: "public"},
		{Site: "blog.example.com", Path: "drafts", Visibility: "private"},
	} {
		if _, err := call[site.NodeView](t, f.m, "user:ann", "site.folder.add", fo); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []site.Put{
		{Site: "blog.example.com", Folder: "guides/install", Slug: "linux", Format: "md", Body: "# Linux", Visibility: "public"},
		{Site: "blog.example.com", Folder: "drafts", Slug: "secret-plan", Format: "md", Body: "# the held text", Visibility: "public"},
	} {
		if _, err := call[site.Published](t, f.m, "user:ann", "site.doc.put", p); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.b.BuildOnce(f.ctx, f.blog.ID); err != nil {
		t.Fatal(err)
	}
	var in site.BuildInput
	if err := json.Unmarshal([]byte(f.pipe.public["build.json"]), &in); err != nil {
		t.Fatal(err)
	}
	if len(in.Docs) != 1 || in.Docs[0].Path != "guides/install/linux" || in.Docs[0].Folder != "guides/install" || in.Docs[0].Page != "guides/install/linux/index.html" {
		t.Fatalf("the documents: %+v", in.Docs)
	}
	if len(in.Folders) != 2 || in.Folders[0].Path != "guides" || in.Folders[0].Title != "Guides" || in.Folders[1].Page != "guides/install/index.html" {
		t.Fatalf("the folders: %+v", in.Folders)
	}
	for name, data := range f.pipe.public {
		if strings.Contains(name, "drafts") || strings.Contains(name, "secret") || strings.Contains(data, "held text") || strings.Contains(data, "drafts") {
			t.Fatalf("something of a private folder is in the build's input: %s", name)
		}
	}
	if _, ok := f.pipe.public["docs/guides/install/linux/index.md"]; !ok {
		t.Fatal("the source is not at its path in the public job's input")
	}
}
