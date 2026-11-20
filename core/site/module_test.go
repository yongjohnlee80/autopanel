package site_test

import (
	"context"
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
// administrator may remove but not read a private document.
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
	if list, err := call[[]site.DocView](t, m, "user:bob", "site.doc.list", site.DocAsk{Site: "blog.example.com"}); err != nil || len(list) != 0 {
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
	if list, _ := call[[]site.DocView](t, m, "user:bob", "site.doc.list", site.DocAsk{Site: "blog.example.com"}); len(list) != 1 || list[0].Owner != "ann" {
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
	// An administrator sees that it exists and may remove it, and cannot read it.
	if _, err := call[site.SourceView](t, m, "user:root", "site.doc.get", site.DocAsk{Site: "blog.example.com", Slug: "notes"}); !errors.Is(err, site.ErrNotYours) {
		t.Fatalf("an administrator reading a private document: %v", err)
	}
	if _, err := call[struct{}](t, m, "user:root", "site.doc.remove", site.DocAsk{Site: "blog.example.com", Slug: "notes"}); err != nil {
		t.Fatalf("an administrator removing it: %v", err)
	}
	if list, _ := call[[]site.DocView](t, m, "user:ann", "site.doc.list", site.DocAsk{Site: "blog.example.com"}); len(list) != 0 {
		t.Fatalf("after its removal: %+v", list)
	}
	// Someone the store does not know is no caller.
	if _, err := call[[]site.DocView](t, m, "user:ghost", "site.doc.list", site.DocAsk{Site: "blog.example.com"}); err == nil {
		t.Fatal("a caller who is no one listed documents")
	}
	if sites, err := call[[]site.SiteView](t, m, "user:root", "site.list", nil); err != nil || len(sites) != 1 || sites[0].Documents != 0 {
		t.Fatalf("site.list = %+v, %v", sites, err)
	}
}
