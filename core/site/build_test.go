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
	inputs    map[string]string               // the last build's inputs
	published []site.Manifest
	downs     []string
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
	p.mu.Unlock()
	return site.Job{Host: host, Ref: dir}, nil
}

func (p *pipe) Input(j site.Job, name string, data []byte) error {
	p.mu.Lock()
	p.inputs[name] = string(data)
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
	for _, d := range in.Docs {
		body := "<!doctype html><title>" + d.Slug + "</title><article>" + d.Slug + "</article>"
		if d.Mermaid {
			body += `<script src="/_kit/m.js" integrity="sha256-M" defer></script><script src="/_kit/s.js" integrity="sha256-S" defer></script>`
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
// diagram pages; a held document is in no build's input at all.
func TestAPublicDocumentIsBuiltAndAHeldOneIsNot(t *testing.T) {
	f := buildSetup(t)
	held := f.put(t, "diary", "private", "# Diary\nthe held text")
	if held.Build != 0 || held.Served {
		t.Fatalf("a private document asked for a build: %+v", held)
	}
	pub := f.put(t, "hello", "public", "# Hello\n\n```mermaid\ngraph TD; A-->B\n```\n")
	if pub.Build != 1 || !pub.Served {
		t.Fatalf("a public publish: %+v", pub)
	}
	if s := f.status(t); s.State != site.BuildWaiting || s.Build != 1 || s.LiveBuild != 0 {
		t.Fatalf("before the build: %+v", s)
	}
	if err := f.b.BuildOnce(f.ctx, f.blog.ID); err != nil {
		t.Fatal(err)
	}
	if s := f.status(t); s.State != site.BuildLive || s.LiveBuild != 1 || s.Error != "" {
		t.Fatalf("after the build: %+v", s)
	}
	for name, data := range f.pipe.inputs {
		if strings.Contains(data, "held text") || strings.Contains(name, "diary") {
			t.Fatalf("a held document is in the build's input: %s", name)
		}
	}
	if !strings.Contains(f.pipe.inputs["docs/hello/index.md"], "# Hello") {
		t.Fatalf("the public document's source: %v", f.pipe.inputs)
	}
	m := f.pipe.published[len(f.pipe.published)-1]
	if m.Build != 1 || len(m.Mermaid) != 1 || m.Mermaid[0] != "hello/index.html" || len(m.ScriptHashes) != 2 {
		t.Fatalf("the manifest: %+v", m)
	}
	// Nothing owed: no second build.
	if err := f.b.BuildOnce(f.ctx, f.blog.ID); !errors.Is(err, site.ErrNoBuild) {
		t.Fatalf("a build with nothing owed: %v", err)
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
	if strings.Contains(f.pipe.inputs["build.json"], "notes") {
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
	if len(f.pipe.published) != 1 || strings.Contains(f.pipe.inputs["build.json"], "notes") {
		t.Fatalf("the next build: %d published, %s", len(f.pipe.published), f.pipe.inputs["build.json"])
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
	if err := json.Unmarshal([]byte(f.pipe.inputs["build.json"]), &in); err != nil || len(in.Docs) != 3 {
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
	if err := json.Unmarshal([]byte(f.pipe.inputs["build.json"]), &in); err != nil {
		t.Fatal(err)
	}
	if len(in.Docs) != 1 || in.Docs[0].Path != "guides/install/linux" || in.Docs[0].Folder != "guides/install" || in.Docs[0].Page != "guides/install/linux/index.html" {
		t.Fatalf("the documents: %+v", in.Docs)
	}
	if len(in.Folders) != 2 || in.Folders[0].Path != "guides" || in.Folders[0].Title != "Guides" || in.Folders[1].Page != "guides/install/index.html" {
		t.Fatalf("the folders: %+v", in.Folders)
	}
	for name, data := range f.pipe.inputs {
		if strings.Contains(name, "drafts") || strings.Contains(name, "secret") || strings.Contains(data, "held text") || strings.Contains(data, "drafts") {
			t.Fatalf("something of a private folder is in the build's input: %s", name)
		}
	}
	if _, err := os.Stat(filepath.Join(f.pipe.dir, "blog.example.com", "content", "docs", "guides", "install", "linux", "index.md")); err != nil {
		t.Fatalf("the source at its path: %v", err)
	}
}
