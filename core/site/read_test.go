package site_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/yongjohnlee80/autopanel/core/site"
	"github.com/yongjohnlee80/autopanel/internal/auth"
)

const appHost = "app.example.com"

// readers has the fixture answer the serving process as the core does: bob
// and an administrator beside ann, each with a session cookie of their name.
func readers(t *testing.T, f *buildFixture) (bob, root auth.User) {
	t.Helper()
	bob, err := f.st.Users().AddUser(f.ctx, "bob", auth.RoleMember, nil, "v", false)
	if err != nil {
		t.Fatal(err)
	}
	root, err = f.st.Users().AddUser(f.ctx, "boss", auth.RoleOperator, nil, "v", false)
	if err != nil {
		t.Fatal(err)
	}
	ann, err := f.st.Users().User(f.ctx, "ann")
	if err != nil {
		t.Fatal(err)
	}
	sessions := map[string]*site.User{"ann-cookie": {ID: ann.ID}, "bob-cookie": {ID: bob.ID}, "boss-cookie": {ID: root.ID, Admin: true}}
	f.m.SetReaders(func(_ context.Context, host, cookie string) *site.User {
		if host != appHost {
			return nil
		}
		return sessions[cookie]
	}, func(h string) bool { return h == appHost })
	return bob, root
}

func ask(f *buildFixture, path, session string) site.ReadAnswer {
	return f.m.MayReadPath(f.ctx, site.ReadAsk{Surface: site.SurfaceApp, Host: appHost, Path: path, Method: "GET", Session: session})
}

// TestWhoReadsAHeldDocumentOnTheAppHost: the core answers the file to serve
// to a reader the table allows, and the same "missing" to everyone else,
// whatever the reason.
func TestWhoReadsAHeldDocumentOnTheAppHost(t *testing.T) {
	f := buildSetup(t)
	readers(t, f)
	f.put(t, "hello", "public", "# Hello")
	f.put(t, "plans", "internal", "# Plans\n\n```mermaid\ngraph TD; A-->B\n```\n")
	f.put(t, "diary", "private", "# Diary")
	if _, err := call[site.Published](t, f.m, "user:ann", "site.doc.put", site.Put{Site: "blog.example.com", Slug: "report", Format: "html", Body: "<h1>R</h1>", Visibility: "internal"}); err != nil {
		t.Fatal(err)
	}
	if _, err := call[site.AssetView](t, f.m, "user:ann", "site.asset.put", site.AssetAsk{Site: "blog.example.com", Slug: "plans", Name: "img/map.png", Data: "iVBORw0KGgpyZXN0"}); err != nil {
		t.Fatal(err)
	}
	if _, err := call[site.AssetView](t, f.m, "user:ann", "site.asset.put", site.AssetAsk{Site: "blog.example.com", Slug: "plans", Name: "flow.mmd", Data: "Z3JhcGggVEQ7IEEtLT5C"}); err != nil {
		t.Fatal(err)
	}
	const base = "/s/blog.example.com"
	// Before anything is built, nothing is served.
	if a := ask(f, base+"/plans/", "bob-cookie"); a.Status != site.ReadMissing {
		t.Fatalf("before the build: %+v", a)
	}
	if err := f.b.BuildOnce(f.ctx, f.blog.ID); err != nil {
		t.Fatal(err)
	}
	root := mustRoot(t, f)
	plans, _ := f.st.Sites().Child(f.ctx, root.ID, "plans")
	held, err := f.st.Sites().HeldOf(f.ctx, plans.ID)
	if err != nil {
		t.Fatal(err)
	}
	dir := site.HeldFile("blog.example.com", plans.ID, held.Build, "")

	for what, tc := range map[string]struct {
		path, session string
		status, kind  string
		file          string
	}{
		"a member, an internal page":       {base + "/plans/", "bob-cookie", site.ReadFile, site.KindPage, dir + "/index.html"},
		"its owner":                        {base + "/plans/", "ann-cookie", site.ReadFile, site.KindPage, dir + "/index.html"},
		"its image":                        {base + "/plans/img/map.png", "bob-cookie", site.ReadFile, site.KindResource, dir + "/img/map.png"},
		"its look":                         {base + "/plans/look.css", "bob-cookie", site.ReadFile, site.KindAsset, dir + "/look.css"},
		"the kit's script":                 {base + "/plans/_kit/m.js", "bob-cookie", site.ReadFile, site.KindAsset, dir + "/_kit/m.js"},
		"a diagram's source is not served": {base + "/plans/flow.mmd", "bob-cookie", site.ReadMissing, "", ""},
		"a file it does not have":          {base + "/plans/other.png", "bob-cookie", site.ReadMissing, "", ""},
		"no inert copy of Markdown":        {base + "/plans/_doc.html", "bob-cookie", site.ReadMissing, "", ""},
		"a file's name with a slash":       {base + "/plans/img/map.png/", "bob-cookie", site.ReadMissing, "", ""},
		"no session":                       {base + "/plans/", "", site.ReadMissing, "", ""},
		"a session nobody has":             {base + "/plans/", "eve-cookie", site.ReadMissing, "", ""},
		"a private page, another member":   {base + "/diary/", "bob-cookie", site.ReadMissing, "", ""},
		"a public page is not held":        {base + "/hello/", "bob-cookie", site.ReadMissing, "", ""},
		"no such document":                 {base + "/nothing/", "bob-cookie", site.ReadMissing, "", ""},
		"no such site":                     {"/s/other.example.com/plans/", "bob-cookie", site.ReadMissing, "", ""},
		"the site with nothing after":      {"/s/blog.example.com", "bob-cookie", site.ReadMissing, "", ""},
		"the site's root":                  {base + "/", "bob-cookie", site.ReadMissing, "", ""},
		"a path that climbs":               {base + "/plans/../diary/", "bob-cookie", site.ReadMissing, "", ""},
		"a slug that is none":              {base + "/Plans/", "bob-cookie", site.ReadMissing, "", ""},
		"outside /s/":                      {"/plans/", "bob-cookie", site.ReadMissing, "", ""},
	} {
		a := ask(f, tc.path, tc.session)
		if a.Status != tc.status || a.Kind != tc.kind || a.File != tc.file {
			t.Errorf("%s: %+v", what, a)
		}
	}
	// A page that draws a diagram says so, with the kit's hashes.
	if a := ask(f, base+"/plans/", "bob-cookie"); !a.Mermaid || len(a.ScriptHashes) != 2 || len(a.Scripts) != 2 {
		t.Errorf("a diagram page: %+v", a)
	}
	// An .html document's inert copy.
	if a := ask(f, base+"/report/_doc.html", "bob-cookie"); a.Status != site.ReadFile || a.Kind != site.KindInert {
		t.Errorf("an inert copy: %+v", a)
	}
	// The address without its slash: a redirect for a reader who may read
	// it, and the missing page for anyone else.
	if a := ask(f, base+"/plans", "bob-cookie"); a.Status != site.ReadRedirect || a.Location != base+"/plans/" {
		t.Errorf("without the slash: %+v", a)
	}
	for _, session := range []string{"", "eve-cookie"} {
		if a := ask(f, base+"/plans", session); a.Status != site.ReadMissing || a.Location != "" {
			t.Errorf("without the slash, no reader: %+v", a)
		}
	}
	if a := ask(f, base+"/diary", "bob-cookie"); a.Status != site.ReadMissing {
		t.Errorf("without the slash, not allowed: %+v", a)
	}
	// Another host, another method, the other surface: nothing.
	for what, q := range map[string]site.ReadAsk{
		"a host that is not the app's": {Surface: site.SurfaceApp, Host: "evil.example.com", Path: base + "/plans/", Method: "GET", Session: "bob-cookie"},
		"a POST":                       {Surface: site.SurfaceApp, Host: appHost, Path: base + "/plans/", Method: "POST", Session: "bob-cookie"},
		"the site's own host":          {Surface: site.SurfaceSite, Host: "blog.example.com", Path: "/plans/", Method: "GET", Session: "bob-cookie"},
		"no surface":                   {Host: appHost, Path: base + "/plans/", Method: "GET", Session: "bob-cookie"},
	} {
		if a := f.m.MayReadPath(f.ctx, q); a.Status != site.ReadMissing {
			t.Errorf("%s: %+v", what, a)
		}
	}
}

// TestAnAdministratorsReadIsWrittenDownFirst: a private page read because the
// role allows it is audited before it is answered; the owner's own read is
// not.
func TestAnAdministratorsReadIsWrittenDownFirst(t *testing.T) {
	f := buildSetup(t)
	readers(t, f)
	f.put(t, "diary", "private", "# Diary")
	if err := f.b.BuildOnce(f.ctx, f.blog.ID); err != nil {
		t.Fatal(err)
	}
	reads := func() int {
		entries, err := f.st.AuditLog(f.ctx, "site.doc.read", 100)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if strings.Contains(fmt.Sprintf("%+v", e), "Diary") {
				t.Errorf("an audit entry holds the document's text: %+v", e)
			}
		}
		return len(entries)
	}
	const page = "/s/blog.example.com/diary/"
	if a := ask(f, page, "ann-cookie"); a.Status != site.ReadFile || reads() != 0 {
		t.Fatalf("the owner's read: %+v, %d entries", a, reads())
	}
	if a := ask(f, page, "boss-cookie"); a.Status != site.ReadFile || reads() != 1 {
		t.Fatalf("an administrator's read: %+v, %d entries", a, reads())
	}
}

// TestAChainNeedsOneKindOfProof: a protected node is never above or below an
// internal or private one, at a publish, a folder's making, a level's change
// or a move.
func TestAChainNeedsOneKindOfProof(t *testing.T) {
	f := buildSetup(t)
	folder := func(path, level string) error {
		_, err := call[site.NodeView](t, f.m, "user:ann", "site.folder.add", site.FolderAsk{Site: "blog.example.com", Path: path, Visibility: level})
		return err
	}
	put := func(folder, slug, level string) error {
		_, err := call[site.Published](t, f.m, "user:ann", "site.doc.put", site.Put{Site: "blog.example.com", Folder: folder, Slug: slug, Format: "md", Body: "x", Visibility: level})
		return err
	}
	for _, e := range []error{folder("locked", "protected"), folder("team", "internal"), folder("open", "public"), folder("open/deep", "public")} {
		if e != nil {
			t.Fatal(e)
		}
	}
	if err := put("locked", "a", "public"); err != nil {
		t.Fatalf("a public document under a protected folder: %v", err)
	}
	if err := put("locked", "b", "protected"); err != nil {
		t.Fatalf("a protected document under a protected folder: %v", err)
	}
	for what, err := range map[string]error{
		"a private document under a protected folder":   put("locked", "c", "private"),
		"an internal document under a protected one":    put("locked", "d", "internal"),
		"a protected document under an internal folder": put("team", "e", "protected"),
		"a protected folder under an internal one":      folder("team/sub", "protected"),
		"an internal folder under a protected one":      folder("locked/sub", "internal"),
	} {
		if !errors.Is(err, site.ErrMixedLevels) {
			t.Errorf("%s: %v", what, err)
		}
	}
	// A level's change is checked against what is above and what is below.
	if err := put("open/deep", "note", "private"); err != nil {
		t.Fatal(err)
	}
	set := func(path, level string) error {
		_, err := call[site.NodeView](t, f.m, "user:ann", "site.folder.set", site.FolderAsk{Site: "blog.example.com", Path: path, Visibility: level})
		return err
	}
	if err := set("open", "protected"); !errors.Is(err, site.ErrMixedLevels) {
		t.Errorf("protecting a folder with a private document two levels down: %v", err)
	}
	if err := put("locked", "a", "internal"); !errors.Is(err, site.ErrMixedLevels) {
		t.Errorf("a document made internal under a protected folder: %v", err)
	}
	if err := set("locked", "internal"); !errors.Is(err, site.ErrMixedLevels) {
		t.Errorf("a folder made internal over a protected document: %v", err)
	}
	// A move is checked whole.
	move := func(path, to string) error {
		_, err := call[site.NodeView](t, f.m, "user:ann", "site.node.move", site.NodeAsk{Site: "blog.example.com", Path: path, To: to})
		return err
	}
	if err := move("open/deep", "locked"); !errors.Is(err, site.ErrMixedLevels) {
		t.Errorf("moving a folder that holds a private document under a protected one: %v", err)
	}
	if err := move("locked/b", "team"); !errors.Is(err, site.ErrMixedLevels) {
		t.Errorf("moving a protected document under an internal folder: %v", err)
	}
	if err := move("open/deep", "team"); err != nil {
		t.Errorf("moving it under an internal folder: %v", err)
	}
}
