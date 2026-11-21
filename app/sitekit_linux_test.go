//go:build linux

package app

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yongjohnlee80/golib/dao"

	coresite "github.com/yongjohnlee80/autopanel/core/site"
	hostservices "github.com/yongjohnlee80/autopanel/host/services"
	hostsite "github.com/yongjohnlee80/autopanel/host/site"
	"github.com/yongjohnlee80/autopanel/internal/auth"
	"github.com/yongjohnlee80/autopanel/internal/module"
	"github.com/yongjohnlee80/autopanel/store"
)

// kitPeople are the test's users, by principal.
type kitPeople map[string]coresite.Person

func (p kitPeople) Caller(ctx context.Context) (coresite.Person, error) {
	if who, ok := p[module.Principal(ctx)]; ok {
		return who, nil
	}
	return coresite.Person{}, auth.ErrExpired
}
func (p kitPeople) Named(_ context.Context, name string) (coresite.Person, error) {
	for _, who := range p {
		if who.Name == name {
			return who, nil
		}
	}
	return coresite.Person{}, coresite.ErrNoUser
}
func (p kitPeople) Name(_ context.Context, id int64) string {
	for _, who := range p {
		if who.ID == id {
			return who.Name
		}
	}
	return ""
}

func kitCall(t *testing.T, m *coresite.Module, as, verb string, param any) {
	t.Helper()
	for _, v := range m.Verbs() {
		if v.Verb != verb {
			continue
		}
		raw, err := module.Wire(param)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := v.Call(module.WithPrincipal(context.Background(), as), []any{raw}); err != nil {
			t.Fatalf("%s: %v", verb, err)
		}
		return
	}
	t.Fatalf("no verb %s", verb)
}

// TestTheKitBuildsASite is the whole way, as root on the test VM with the
// kit's image built there (AUTOPANEL_TEST_KIT_IMAGE, by digest): documents
// published through the verbs, built by the builder in its container, the
// output checked, swapped live, and read back from the serving process. A
// held document is nowhere in it. Never run on a workstation.
func TestTheKitBuildsASite(t *testing.T) {
	img := os.Getenv("AUTOPANEL_TEST_KIT_IMAGE")
	if img == "" || os.Getuid() != 0 {
		t.Skip("the kit's own test: AUTOPANEL_TEST_KIT_IMAGE=<name@sha256:…>, as root, on the test VM")
	}
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
	base, err := os.MkdirTemp("/var/tmp", "ap-kit-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	files := hostsite.Files{Dir: filepath.Join(base, "site"), Owner: hostsite.Owner{UID: 0, GID: 0}}
	pipe := &sitePipeline{files: files, builder: hostsite.Builder{Host: hostservices.New("/var/lib/autopanel-services", t.TempDir()), Image: img}}
	builds := coresite.NewBuilds(st.Sites(), pipe, coresite.Kit{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	m := coresite.NewModule(st.Sites(), kitPeople{"user:ann": {ID: ann.ID, Name: "ann"}, "user:root": {ID: ann.ID, Name: "root", Admin: true}})
	m.SetBuilds(builds)

	kitCall(t, m, "user:root", "site.add", coresite.SiteAsk{Host: "blog.example.com"})
	title := "Notes <and> things"
	kitCall(t, m, "user:root", "site.set", coresite.SiteSet{Host: "blog.example.com", Config: &[]string{"title: " + title + "\nlook: {accent: '#aa3300', font: sans}\n"}[0]})
	kitCall(t, m, "user:ann", "site.folder.add", coresite.FolderAsk{Site: "blog.example.com", Path: "guides", Visibility: "public", Title: &[]string{"Guides"}[0]})
	kitCall(t, m, "user:ann", "site.doc.put", coresite.Put{Site: "blog.example.com", Folder: "guides", Slug: "install", Format: "md",
		Body: "# Install\n\nRun it. <script>alert(1)</script> is text.\n", Visibility: "public", Meta: []byte(`{"title":"Install","date":"2026-11-21"}`)})
	kitCall(t, m, "user:ann", "site.doc.put", coresite.Put{Site: "blog.example.com", Slug: "diary", Format: "md", Body: "# the held text\n", Visibility: "private"})

	s, err := st.Sites().SiteByHost(ctx, "blog.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := builds.BuildOnce(ctx, s.ID); err != nil {
		t.Fatalf("the build: %v", err)
	}
	if s, _ = st.Sites().SiteByHost(ctx, "blog.example.com"); s.BuildState != coresite.BuildLive || s.LiveBuild != s.Build {
		t.Fatalf("after the build: %+v", s)
	}
	srv := hostsite.Server{Dir: files.Dir}
	get := func(path string) (int, string, string) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", path, nil)
		req.Host = "blog.example.com"
		srv.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String(), rec.Header().Get("Content-Security-Policy")
	}
	code, body, csp := get("/guides/install/")
	if code != 200 || !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt; is text.") || !strings.HasPrefix(csp, "default-src 'none'") {
		t.Fatalf("the document's page: %d %q %q", code, body, csp)
	}
	if code, body, _ := get("/"); code != 200 || !strings.Contains(body, "Notes &lt;and&gt; things") {
		t.Fatalf("the home page: %d %q", code, body)
	}
	if code, body, _ := get("/guides/"); code != 200 || !strings.Contains(body, `href="/guides/install/"`) {
		t.Fatalf("the folder's page: %d %q", code, body)
	}
	if code, body, _ := get("/look.css"); code != 200 || !strings.Contains(body, "--accent: #aa3300;") {
		t.Fatalf("the look: %d %q", code, body)
	}
	for _, p := range []string{"/feed.xml", "/sitemap.xml", "/robots.txt"} {
		if code, _, _ := get(p); code != 200 {
			t.Errorf("%s: %d", p, code)
		}
	}
	if code, _, _ := get("/diary/"); code != 404 {
		t.Fatalf("a private document: %d", code)
	}
	live := filepath.Join(files.Dir, "blog.example.com")
	_ = filepath.Walk(live, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		data, _ := os.ReadFile(p)
		if strings.Contains(string(data), "held text") || strings.Contains(string(data), "diary") {
			t.Errorf("the held document is in %s", p)
		}
		return nil
	})
}
