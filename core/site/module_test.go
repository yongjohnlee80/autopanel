package site_test

import (
	"context"
	"encoding/base64"
	"errors"
	"path/filepath"
	"testing"

	"github.com/yongjohnlee80/golib/dao"

	"github.com/yongjohnlee80/autopanel/core/site"
	"github.com/yongjohnlee80/autopanel/internal/auth"
	"github.com/yongjohnlee80/autopanel/internal/module"
	"github.com/yongjohnlee80/autopanel/store"
)

// people are the test's users; the caller is the principal the context carries.
type people map[string]site.Person

func (p people) Caller(ctx context.Context) (site.Person, error) {
	if who, ok := p[module.Principal(ctx)]; ok {
		return who, nil
	}
	return site.Person{}, auth.ErrExpired
}

func (p people) Named(_ context.Context, name string) (site.Person, error) {
	for _, who := range p {
		if who.Name == name {
			return who, nil
		}
	}
	return site.Person{}, site.ErrNoUser
}

func (p people) Name(_ context.Context, id int64) string {
	for _, who := range p {
		if who.ID == id {
			return who.Name
		}
	}
	return ""
}

func call[R any](t *testing.T, m *site.Module, as, verb string, param any) (R, error) {
	t.Helper()
	var out R
	for _, v := range m.Verbs() {
		if v.Verb != verb {
			continue
		}
		ctx := module.WithPrincipal(context.Background(), as)
		raw, err := module.Wire(param)
		if err != nil {
			t.Fatal(err)
		}
		res, err := v.Call(ctx, []any{raw})
		if err == nil {
			w, _ := module.Wire(res)
			if derr := module.Decode(w, &out); derr != nil {
				t.Fatal(derr)
			}
		}
		return out, err
	}
	t.Fatalf("no verb %s", verb)
	return out, nil
}

// TestTheSitesVerbs: documents are kept private unless said, an update keeps
// what it does not name, a document is its owner's to change and read the
// source of, a list shows only what the caller may see listed, a refusal for
// what the caller may not know of is "no such document", and an
// administrator may read (audited) and remove a private document, and not
// change it.
func TestTheSitesVerbs(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, store.Config{Engine: dao.DialectSQLite, Path: filepath.Join(t.TempDir(), "store.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ids := map[string]int64{}
	for _, n := range []string{"root", "ann", "bob", "cyd"} {
		u, err := st.Users().AddUser(ctx, n, auth.RoleOperator, nil, "v", false)
		if err != nil {
			t.Fatal(err)
		}
		ids[n] = u.ID
	}
	ppl := people{
		"user:root": {ID: ids["root"], Name: "root", Admin: true},
		"user:ann":  {ID: ids["ann"], Name: "ann"},
		"user:bob":  {ID: ids["bob"], Name: "bob"},
		"user:cyd":  {ID: ids["cyd"], Name: "cyd"},
	}
	m := site.NewModule(st.Sites(), ppl)

	if _, err := call[site.SiteView](t, m, "user:root", "site.add", site.SiteAsk{Host: "Blog.Example.com"}); !errors.Is(err, site.ErrBadHost) {
		t.Fatalf("a host in capitals: %v", err)
	}
	if _, err := call[site.SiteView](t, m, "user:root", "site.add", site.SiteAsk{Host: "blog.example.com"}); err != nil {
		t.Fatal(err)
	}
	// A first publish with no level is private, and kept, not served.
	pub, err := call[site.Published](t, m, "user:ann", "site.doc.put", site.Put{Site: "blog.example.com", Slug: "notes", Format: "md", Body: "# Notes\nsecret"})
	if err != nil || pub.Visibility != site.Private || pub.Served || pub.Version != 1 {
		t.Fatalf("a first publish: %+v, %v", pub, err)
	}
	// Bob cannot see it, list it, take its slug, read it or remove it; each refusal says nothing.
	if list, err := call[[]site.NodeView](t, m, "user:bob", "site.node.list", site.NodeAsk{Site: "blog.example.com"}); err != nil || len(list) != 0 {
		t.Fatalf("bob's list: %+v, %v", list, err)
	}
	if _, err := call[site.SourceView](t, m, "user:bob", "site.doc.get", site.DocAsk{Site: "blog.example.com", Slug: "notes"}); !errors.Is(err, site.ErrNotFound) {
		t.Fatalf("bob reading ann's private document: %v", err)
	}
	if _, err := call[struct{}](t, m, "user:bob", "site.doc.remove", site.DocAsk{Site: "blog.example.com", Slug: "notes"}); !errors.Is(err, site.ErrNotFound) {
		t.Fatalf("bob removing it: %v", err)
	}
	if _, err := call[site.Published](t, m, "user:bob", "site.doc.put", site.Put{Site: "blog.example.com", Slug: "notes", Format: "md", Body: "mine now"}); !errors.Is(err, site.ErrDuplicate) {
		t.Fatalf("bob publishing over it: %v", err)
	}
	// Shared with bob: he may list it, not change it or read its source.
	if _, err := call[site.Published](t, m, "user:ann", "site.doc.put", site.Put{Site: "blog.example.com", Slug: "notes", Format: "md", Body: "# Notes\nsecret", Share: &[]string{"bob"}}); err != nil {
		t.Fatal(err)
	}
	if list, _ := call[[]site.NodeView](t, m, "user:bob", "site.node.list", site.NodeAsk{Site: "blog.example.com"}); len(list) != 1 || list[0].Owner != "ann" {
		t.Fatalf("bob's list with the document shared: %+v", list)
	}
	if _, err := call[site.Published](t, m, "user:bob", "site.doc.put", site.Put{Site: "blog.example.com", Slug: "notes", Format: "md", Body: "x"}); !errors.Is(err, site.ErrNotYours) {
		t.Fatalf("a shared member changing it: %v", err)
	}
	if _, err := call[site.SourceView](t, m, "user:bob", "site.doc.get", site.DocAsk{Site: "blog.example.com", Slug: "notes"}); !errors.Is(err, site.ErrNotYours) {
		t.Fatalf("a shared member reading the source: %v", err)
	}
	// An update with no level keeps it; new content is a new version.
	pub, err = call[site.Published](t, m, "user:ann", "site.doc.put", site.Put{Site: "blog.example.com", Slug: "notes", Format: "md", Body: "# Notes\nsecond"})
	if err != nil || pub.Visibility != site.Private || pub.Version != 2 {
		t.Fatalf("an update with no level: %+v, %v", pub, err)
	}
	src, err := call[site.SourceView](t, m, "user:ann", "site.doc.get", site.DocAsk{Site: "blog.example.com", Slug: "notes"})
	if err != nil || src.Body != "# Notes\nsecond" || len(src.Share) != 1 || src.Share[0] != "bob" {
		t.Fatalf("the owner's source: %+v, %v", src, err)
	}
	// Refusals of shape.
	for what, p := range map[string]site.Put{
		"an unknown level":               {Site: "blog.example.com", Slug: "a", Format: "md", Visibility: "secret"},
		"a share with no one":            {Site: "blog.example.com", Slug: "b", Format: "md", Share: &[]string{"nobody"}},
		"a share on a public one":        {Site: "blog.example.com", Slug: "c", Format: "md", Visibility: "public", Share: &[]string{"bob"}},
		"an active private document":     {Site: "blog.example.com", Slug: "d", Format: "html", Active: true},
		"front matter that is no object": {Site: "blog.example.com", Slug: "e", Format: "md", Meta: []byte(`[1,2]`)},
		"no such site":                   {Site: "none.example.com", Slug: "f", Format: "md"},
	} {
		if _, err := call[site.Published](t, m, "user:ann", "site.doc.put", p); err == nil {
			t.Errorf("%s was published", what)
		}
	}
	// An administrator answers for the site: they read it, audited, and may
	// remove it; they change nothing of it.
	if v, err := call[site.SourceView](t, m, "user:root", "site.doc.get", site.DocAsk{Site: "blog.example.com", Slug: "notes"}); err != nil || v.Body != "# Notes\nsecond" {
		t.Fatalf("an administrator reading a private document: %+v, %v", v, err)
	}
	if n := auditCount(t, st, "site.doc.read"); n != 1 {
		t.Fatalf("the administrator's read is audited %d times", n)
	}
	if _, err := call[site.Published](t, m, "user:root", "site.doc.put", site.Put{Site: "blog.example.com", Slug: "notes", Format: "md", Body: "edited"}); !errors.Is(err, site.ErrNotYours) {
		t.Fatalf("an administrator changing it: %v", err)
	}
	if _, err := call[struct{}](t, m, "user:root", "site.doc.remove", site.DocAsk{Site: "blog.example.com", Slug: "notes"}); err != nil {
		t.Fatalf("an administrator removing it: %v", err)
	}
	if list, _ := call[[]site.NodeView](t, m, "user:ann", "site.node.list", site.NodeAsk{Site: "blog.example.com"}); len(list) != 0 {
		t.Fatalf("after its removal: %+v", list)
	}
	// Someone the store does not know is no caller.
	if _, err := call[[]site.NodeView](t, m, "user:ghost", "site.node.list", site.NodeAsk{Site: "blog.example.com"}); err == nil {
		t.Fatal("a caller who is no one listed documents")
	}
	if sites, err := call[[]site.SiteView](t, m, "user:root", "site.list", nil); err != nil || len(sites) != 1 || sites[0].Documents != 0 {
		t.Fatalf("site.list = %+v, %v", sites, err)
	}
}

// TestADocumentsFiles: only the owner adds, lists and removes a document's
// files; a file is what its name and content say; data is base64; anyone
// else is told the document is not theirs, or that it is missing.
func TestADocumentsFiles(t *testing.T) {
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
	bob, err := st.Users().AddUser(ctx, "bob", auth.RoleOperator, nil, "v", false)
	if err != nil {
		t.Fatal(err)
	}
	ppl := people{"user:ann": {ID: ann.ID, Name: "ann"}, "user:bob": {ID: bob.ID, Name: "bob"}, "user:root": {ID: 999, Name: "root", Admin: true}}
	m := site.NewModule(st.Sites(), ppl)
	if _, err := call[site.SiteView](t, m, "user:root", "site.add", site.SiteAsk{Host: "docs.example.com"}); err != nil {
		t.Fatal(err)
	}
	if _, err := call[site.Published](t, m, "user:ann", "site.doc.put", site.Put{Site: "docs.example.com", Slug: "guide", Format: "xmd", Body: "x", Visibility: "public"}); err != nil {
		t.Fatal(err)
	}
	png := base64.StdEncoding.EncodeToString([]byte("\x89PNG\r\n\x1a\n...."))
	ask := func(name, data string) site.AssetAsk {
		return site.AssetAsk{Site: "docs.example.com", Slug: "guide", Name: name, Data: data}
	}
	if v, err := call[site.AssetView](t, m, "user:ann", "site.asset.put", ask("images/flow.png", png)); err != nil || v.MIME != "image/png" || v.Size != 12 {
		t.Fatalf("a picture: %+v, %v", v, err)
	}
	for what, tc := range map[string]struct {
		as   string
		ask  site.AssetAsk
		want error
	}{
		"someone else's document":     {"user:bob", ask("b.png", png), site.ErrNotYours},
		"an administrator":            {"user:root", ask("b.png", png), site.ErrNotYours},
		"data that is no base64":      {"user:ann", ask("b.png", "%%%"), site.ErrBadData},
		"a renamed file":              {"user:ann", ask("b.jpg", png), site.ErrResourceType},
		"an svg":                      {"user:ann", ask("b.svg", base64.StdEncoding.EncodeToString([]byte("<svg/>"))), site.ErrResourceType},
		"a name that climbs":          {"user:ann", ask("../b.png", png), site.ErrBadResource},
		"a name of the site's own":    {"user:ann", ask("_doc.html", png), site.ErrReservedName},
		"a name that differs by case": {"user:ann", ask("images/Flow.png", png), site.ErrResourceTaken},
		"no such document":            {"user:ann", site.AssetAsk{Site: "docs.example.com", Slug: "none", Name: "a.png", Data: png}, site.ErrNotFound},
	} {
		if _, err := call[site.AssetView](t, m, tc.as, "site.asset.put", tc.ask); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v; want %v", what, err, tc.want)
		}
	}
	if list, err := call[[]site.AssetView](t, m, "user:ann", "site.asset.list", ask("", "")); err != nil || len(list) != 1 || list[0].Name != "images/flow.png" {
		t.Fatalf("the owner's list: %+v, %v", list, err)
	}
	if _, err := call[[]site.AssetView](t, m, "user:bob", "site.asset.list", ask("", "")); !errors.Is(err, site.ErrNotYours) {
		t.Fatalf("another member's list of a public document's files: %v", err)
	}
	if _, err := call[site.AssetData](t, m, "user:bob", "site.asset.get", ask("images/flow.png", "")); !errors.Is(err, site.ErrNotYours) {
		t.Fatalf("another member reading a file: %v", err)
	}
	// An administrator reads a document's files, audited each time.
	if list, err := call[[]site.AssetView](t, m, "user:root", "site.asset.list", ask("", "")); err != nil || len(list) != 1 {
		t.Fatalf("an administrator's list: %+v, %v", list, err)
	}
	if d, err := call[site.AssetData](t, m, "user:root", "site.asset.get", ask("images/flow.png", "")); err != nil || d.Data != png || d.MIME != "image/png" {
		t.Fatalf("an administrator reading a file: %+v, %v", d, err)
	}
	if n := auditCount(t, st, "site.doc.read"); n != 2 {
		t.Fatalf("an administrator's reads audited %d times", n)
	}
	if _, err := call[struct{}](t, m, "user:ann", "site.asset.remove", ask("images/flow.png", "")); err != nil {
		t.Fatal(err)
	}
	if _, err := call[struct{}](t, m, "user:ann", "site.asset.remove", ask("images/flow.png", "")); !errors.Is(err, site.ErrNoResource) {
		t.Fatalf("removing it twice: %v", err)
	}
}

// TestASitesConfiguration: site.set validates the whole configuration and
// keeps what it is not given; a content host is no site's host and no other
// site's content host; site.get answers the defaults of a site never set.
func TestASitesConfiguration(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, store.Config{Engine: dao.DialectSQLite, Path: filepath.Join(t.TempDir(), "store.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	m := site.NewModule(st.Sites(), people{"user:root": {ID: 1, Name: "root", Admin: true}})
	for _, h := range []string{"blog.example.com", "docs.example.com"} {
		if _, err := call[site.SiteView](t, m, "user:root", "site.add", site.SiteAsk{Host: h}); err != nil {
			t.Fatal(err)
		}
	}
	v, err := call[site.SiteConfigView](t, m, "user:root", "site.get", site.SiteAsk{Host: "blog.example.com"})
	if err != nil || v.Config.Title != "blog.example.com" || v.Config.Theme != "journal" {
		t.Fatalf("a site never set: %+v, %v", v, err)
	}
	str := func(s string) *string { return &s }
	v, err = call[site.SiteConfigView](t, m, "user:root", "site.set", site.SiteSet{Host: "blog.example.com", Config: str("title: Notes\nlook: {accent: '#0b6e4f'}\n"), ContentHost: str("content.example.com")})
	if err != nil || v.Config.Title != "Notes" || v.Config.Look.Accent != "#0b6e4f" || v.ContentHost != "content.example.com" {
		t.Fatalf("set: %+v, %v", v, err)
	}
	// A refused configuration changes nothing, the content host included.
	if _, err := call[site.SiteConfigView](t, m, "user:root", "site.set", site.SiteSet{Host: "blog.example.com", Config: str("title: X\nlook: {accent: red}\n"), ContentHost: str("")}); !errors.Is(err, site.ErrBadConfig) {
		t.Fatalf("a bad colour: %v", err)
	}
	if v, _ := call[site.SiteConfigView](t, m, "user:root", "site.get", site.SiteAsk{Host: "blog.example.com"}); v.Config.Title != "Notes" || v.ContentHost != "content.example.com" {
		t.Fatalf("after a refusal: %+v", v)
	}
	// Leaving the configuration out keeps it; an empty content host clears it.
	if v, err := call[site.SiteConfigView](t, m, "user:root", "site.set", site.SiteSet{Host: "blog.example.com", ContentHost: str("")}); err != nil || v.Config.Title != "Notes" || v.ContentHost != "" {
		t.Fatalf("clearing the content host: %+v, %v", v, err)
	}
	for what, tc := range map[string]struct {
		host, content string
		want          error
	}{
		"its own host":        {"blog.example.com", "blog.example.com", site.ErrBadHost},
		"another site's host": {"blog.example.com", "docs.example.com", site.ErrHostTaken},
		"not a host":          {"blog.example.com", "content", site.ErrBadHost},
		"in capitals":         {"blog.example.com", "Content.example.com", site.ErrBadHost},
	} {
		if _, err := call[site.SiteConfigView](t, m, "user:root", "site.set", site.SiteSet{Host: tc.host, ContentHost: str(tc.content)}); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v", what, err)
		}
	}
	if _, err := call[site.SiteConfigView](t, m, "user:root", "site.set", site.SiteSet{Host: "docs.example.com", ContentHost: str("content.example.com")}); err != nil {
		t.Fatal(err)
	}
	if _, err := call[site.SiteConfigView](t, m, "user:root", "site.set", site.SiteSet{Host: "blog.example.com", ContentHost: str("content.example.com")}); !errors.Is(err, site.ErrHostTaken) {
		t.Fatalf("another site's content host: %v", err)
	}
	if _, err := call[site.SiteView](t, m, "user:root", "site.add", site.SiteAsk{Host: "content.example.com"}); !errors.Is(err, site.ErrHostTaken) {
		t.Fatalf("a site on a content host: %v", err)
	}
	if _, err := call[site.SiteConfigView](t, m, "user:root", "site.set", site.SiteSet{Host: "none.example.com"}); !errors.Is(err, site.ErrNoSite) {
		t.Fatalf("no such site: %v", err)
	}
}

// auditCount is how many audit entries the store holds of action.
func auditCount(t *testing.T, st *store.Store, action string) int {
	t.Helper()
	entries, err := st.AuditLog(context.Background(), action, 100)
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}
