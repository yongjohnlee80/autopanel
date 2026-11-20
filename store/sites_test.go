package store

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/yongjohnlee80/autopanel/core/site"
)

// testUser makes a user and answers its id.
func testUser(t *testing.T, s *Store, name string) int64 {
	t.Helper()
	rows, err := s.conn.QueryContext(context.Background(), s.q("INSERT INTO app_user(name, created_at) VALUES (?, ?) RETURNING id"), name, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var id int64
	if !rows.Next() {
		t.Fatalf("no id for user %s: %v", name, rows.Err())
	}
	if err := rows.Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// TestSiteDocumentsKeepTheirIdentity: the store's rules for a site's
// documents, on each engine. A document's ID, owner, site and slug are never
// an update's to change; the version rises with the content and the
// generation with who may read; taking a document from public, by a lower
// level or by removal, raises the site's security generation and nothing
// else does; an ID is never used again; and the audit log names a document
// and its level, never its text.
func TestSiteDocumentsKeepTheirIdentity(t *testing.T) {
	for engine, s := range engines(t) {
		t.Run(engine, func(t *testing.T) {
			ctx := context.Background()
			ss := s.Sites()
			ann, bob, cyd := testUser(t, s, "ann"), testUser(t, s, "bob"), testUser(t, s, "cyd")
			blog, err := ss.AddSite(ctx, site.Site{Host: "blog.example.com", CreatedAt: 1})
			if err != nil || blog.ID == 0 || blog.SecurityGen != 1 {
				t.Fatalf("AddSite = %+v, %v", blog, err)
			}
			if _, err := ss.AddSite(ctx, site.Site{Host: "blog.example.com"}); !errors.Is(err, site.ErrSiteExists) {
				t.Fatalf("a host twice: %v", err)
			}
			if got, err := ss.SiteByHost(ctx, "blog.example.com"); err != nil || got != blog {
				t.Fatalf("SiteByHost = %+v, %v", got, err)
			}
			if _, err := ss.SiteByHost(ctx, "none.example.com"); !errors.Is(err, site.ErrNoSite) {
				t.Fatalf("an unknown host: %v", err)
			}
			gen := func() int64 {
				t.Helper()
				v, err := ss.SiteByHost(ctx, "blog.example.com")
				if err != nil {
					t.Fatal(err)
				}
				return v.SecurityGen
			}
			secret := "the body nobody may see in a log"
			src := site.Source{Meta: `{"title":"A secret title"}`, Body: []byte(secret), SHA256: "aa"}
			d, err := ss.Create(ctx, site.Doc{Site: blog.ID, Slug: "notes", Format: site.Markdown, Owner: ann, Visibility: site.Private, Share: []int64{cyd, bob}}, src)
			if err != nil || d.ID == 0 || d.Generation != 1 || d.Version != 1 || !slices.Equal(d.Share, []int64{bob, cyd}) {
				t.Fatalf("Create = %+v, %v", d, err)
			}
			if _, err := ss.Create(ctx, site.Doc{Site: blog.ID, Slug: "notes", Format: site.Markdown, Owner: bob, Visibility: site.Public}, src); !errors.Is(err, site.ErrDuplicate) {
				t.Fatalf("a slug twice: %v", err)
			}
			if _, err := ss.Create(ctx, site.Doc{Site: blog.ID, Slug: "ghost", Format: site.Markdown, Owner: 999999, Visibility: site.Private}, src); !errors.Is(err, site.ErrNoUser) {
				t.Fatalf("an owner who is no user: %v", err)
			}
			if _, err := ss.Create(ctx, site.Doc{Site: blog.ID, Slug: "ghost", Format: site.Markdown, Owner: ann, Visibility: site.Private, Share: []int64{999999}}, src); !errors.Is(err, site.ErrNoUser) {
				t.Fatalf("a share with someone who is no user: %v", err)
			}
			if _, err := ss.Doc(ctx, blog.ID, "ghost"); !errors.Is(err, site.ErrNotFound) {
				t.Fatalf("a refused document was kept: %v", err)
			}
			if got, err := ss.Doc(ctx, blog.ID, "notes"); err != nil || got.ID != d.ID || got.Owner != ann || !slices.Equal(got.Share, []int64{bob, cyd}) {
				t.Fatalf("Doc = %+v, %v", got, err)
			}
			if got, err := ss.Source(ctx, d.ID); err != nil || string(got.Body) != secret || got.Meta != src.Meta || got.SHA256 != "aa" {
				t.Fatalf("Source = %+v, %v", got, err)
			}

			// An update cannot move a document, rename it or give it away.
			got, lowered, err := ss.Update(ctx, d.ID, func(old site.Doc) (site.Doc, *site.Source, error) {
				old.ID, old.Site, old.Slug, old.Owner = 4242, 77, "elsewhere", bob
				old.Generation, old.Version = 900, 900
				return old, nil, nil
			})
			if err != nil || lowered || got.ID != d.ID || got.Site != blog.ID || got.Slug != "notes" || got.Owner != ann || got.Generation != 1 || got.Version != 1 {
				t.Fatalf("an update that tried to change a document's identity: %+v, lowered %v, %v", got, lowered, err)
			}
			// The same content again: no new version. New content: one.
			got, _, err = ss.Update(ctx, d.ID, func(old site.Doc) (site.Doc, *site.Source, error) { return old, &src, nil })
			if err != nil || got.Version != 1 || got.Generation != 1 {
				t.Fatalf("the same content again: %+v, %v", got, err)
			}
			got, _, err = ss.Update(ctx, d.ID, func(old site.Doc) (site.Doc, *site.Source, error) {
				return old, &site.Source{Body: []byte("second"), SHA256: "bb"}, nil
			})
			if err != nil || got.Version != 2 || got.Generation != 1 {
				t.Fatalf("new content: %+v, %v", got, err)
			}
			// A change of the share list is a new generation; the level too.
			got, lowered, err = ss.Update(ctx, d.ID, func(old site.Doc) (site.Doc, *site.Source, error) {
				old.Share = []int64{bob}
				return old, nil, nil
			})
			if err != nil || lowered || got.Generation != 2 || !slices.Equal(got.Share, []int64{bob}) || gen() != 1 {
				t.Fatalf("a share removed: %+v, lowered %v, %v, site generation %d", got, lowered, err, gen())
			}
			got, lowered, err = ss.Update(ctx, d.ID, func(old site.Doc) (site.Doc, *site.Source, error) {
				old.Visibility, old.Share = site.Public, nil
				return old, nil, nil
			})
			if err != nil || lowered || got.Generation != 3 || got.Visibility != site.Public || len(got.Share) != 0 || gen() != 1 {
				t.Fatalf("made public: %+v, lowered %v, %v, site generation %d", got, lowered, err, gen())
			}
			// Taken from public: the site's security generation rises.
			got, lowered, err = ss.Update(ctx, d.ID, func(old site.Doc) (site.Doc, *site.Source, error) {
				old.Visibility = site.Internal
				return old, nil, nil
			})
			if err != nil || !lowered || got.Generation != 4 || gen() != 2 {
				t.Fatalf("taken from public: %+v, lowered %v, %v, site generation %d", got, lowered, err, gen())
			}
			// A change refused by its caller changes nothing.
			refused := errors.New("refused")
			if _, _, err := ss.Update(ctx, d.ID, func(old site.Doc) (site.Doc, *site.Source, error) {
				old.Visibility = site.Public
				return old, nil, refused
			}); !errors.Is(err, refused) {
				t.Fatalf("a refused change: %v", err)
			}
			if got, _ := ss.DocByID(ctx, d.ID); got.Visibility != site.Internal || got.Generation != 4 {
				t.Fatalf("a refused change was kept: %+v", got)
			}
			if _, _, err := ss.Update(ctx, 999999, func(old site.Doc) (site.Doc, *site.Source, error) { return old, nil, nil }); !errors.Is(err, site.ErrNotFound) {
				t.Fatalf("an update of no document: %v", err)
			}

			// Removal: a held document's leaves the generation; a public one's raises it; an ID is never used again.
			if _, err := ss.Remove(ctx, d.ID); err != nil || gen() != 2 {
				t.Fatalf("removing an internal document: %v, site generation %d", err, gen())
			}
			pub, err := ss.Create(ctx, site.Doc{Site: blog.ID, Slug: "notes", Format: site.HTML, Owner: bob, Visibility: site.Public, Active: true}, src)
			if err != nil || pub.ID <= d.ID || !pub.Active || pub.Owner != bob {
				t.Fatalf("the slug used again: %+v (the first was %d), %v", pub, d.ID, err)
			}
			if _, _, err := ss.Update(ctx, pub.ID, func(old site.Doc) (site.Doc, *site.Source, error) {
				old.Visibility = site.Private // still active: the store itself refuses a held active document
				return old, nil, nil
			}); err == nil {
				t.Fatal("the store kept an active document that is not public")
			}
			if _, err := ss.Remove(ctx, pub.ID); err != nil || gen() != 3 {
				t.Fatalf("removing a public document: %v, site generation %d", err, gen())
			}
			if _, err := ss.Remove(ctx, pub.ID); !errors.Is(err, site.ErrNotFound) {
				t.Fatalf("removing it twice: %v", err)
			}
			if docs, err := ss.Docs(ctx, blog.ID); err != nil || len(docs) != 0 {
				t.Fatalf("Docs = %+v, %v", docs, err)
			}

			// The audit log: every change, by name and level; never a title or a body.
			rows, err := s.conn.QueryContext(ctx, "SELECT action, subject, detail FROM audit WHERE action LIKE 'site.%' ORDER BY id")
			if err != nil {
				t.Fatal(err)
			}
			var log []string
			for rows.Next() {
				var a, sub, det string
				if err := rows.Scan(&a, &sub, &det); err != nil {
					t.Fatal(err)
				}
				log = append(log, a+" | "+sub+" | "+det)
			}
			rows.Close()
			all := strings.Join(log, "\n")
			for _, want := range []string{
				"site.add | site blog.example.com | ",
				"site.doc.create | document blog.example.com/notes | private",
				"site.doc.update | document blog.example.com/notes | private to public",
				"site.doc.update | document blog.example.com/notes | public to internal",
				"site.doc.remove | document blog.example.com/notes | internal",
				"site.doc.remove | document blog.example.com/notes | public",
			} {
				if !strings.Contains(all, want) {
					t.Errorf("the audit log lacks %q:\n%s", want, all)
				}
			}
			if strings.Contains(all, "secret") || strings.Contains(all, "title") {
				t.Errorf("the audit log holds a document's text:\n%s", all)
			}

			// A site's removal takes its documents; a user with documents cannot be removed until they are gone.
			keep, err := ss.Create(ctx, site.Doc{Site: blog.ID, Slug: "kept", Format: site.Markdown, Owner: ann, Visibility: site.Private, Share: []int64{bob}}, src)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.conn.ExecContext(ctx, s.q("DELETE FROM app_user WHERE id = ?"), ann); err == nil {
				t.Fatal("a user who owns a document was removed")
			}
			if _, err := s.conn.ExecContext(ctx, s.q("DELETE FROM app_user WHERE id = ?"), bob); err != nil {
				t.Fatalf("removing a user a document is shared with: %v", err)
			}
			if got, err := ss.DocByID(ctx, keep.ID); err != nil || len(got.Share) != 0 {
				t.Fatalf("after its shared user was removed: %+v, %v", got, err)
			}
			if err := ss.RemoveSite(ctx, blog.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := ss.DocByID(ctx, keep.ID); !errors.Is(err, site.ErrNotFound) {
				t.Fatalf("a document outlived its site: %v", err)
			}
			if err := ss.RemoveSite(ctx, blog.ID); !errors.Is(err, site.ErrNoSite) {
				t.Fatalf("removing a site twice: %v", err)
			}
		})
	}
}

// TestSiteResourcesBelongToOneDocument: a document's files on each engine.
// A file is found only by its exact name and only under its own document;
// the same name replaces, a name differing only by case is refused, and one
// more than the limit too; new content is a new version of the document, the
// same content is not; the files go with the document.
func TestSiteResourcesBelongToOneDocument(t *testing.T) {
	for engine, s := range engines(t) {
		t.Run(engine, func(t *testing.T) {
			ctx := context.Background()
			ss := s.Sites()
			ann := testUser(t, s, "ann")
			blog, err := ss.AddSite(ctx, site.Site{Host: "docs.example.com", CreatedAt: 1})
			if err != nil {
				t.Fatal(err)
			}
			src := site.Source{Body: []byte("x"), SHA256: "aa"}
			one, err := ss.Create(ctx, site.Doc{Site: blog.ID, Slug: "one", Format: site.XMD, Owner: ann, Visibility: site.Private}, src)
			if err != nil {
				t.Fatal(err)
			}
			two, err := ss.Create(ctx, site.Doc{Site: blog.ID, Slug: "two", Format: site.XMD, Owner: ann, Visibility: site.Public}, src)
			if err != nil {
				t.Fatal(err)
			}
			version := func(id int64) int64 {
				t.Helper()
				d, err := ss.DocByID(ctx, id)
				if err != nil {
					t.Fatal(err)
				}
				return d.Version
			}
			held := []byte("the private document's picture")
			r, err := ss.PutResource(ctx, one.ID, site.Resource{Name: "images/Flow.png", MIME: "image/png", SHA256: "s1"}, held)
			if err != nil || r.ID == 0 || r.Doc != one.ID || r.Size != int64(len(held)) || version(one.ID) != 2 {
				t.Fatalf("PutResource = %+v, %v; the document's version is %d", r, err, version(one.ID))
			}
			// The same content again: no new version. New content: one, and the file is replaced.
			if _, err := ss.PutResource(ctx, one.ID, site.Resource{Name: "images/Flow.png", MIME: "image/png", SHA256: "s1"}, held); err != nil || version(one.ID) != 2 {
				t.Fatalf("the same file again: %v, version %d", err, version(one.ID))
			}
			if _, err := ss.PutResource(ctx, one.ID, site.Resource{Name: "images/Flow.png", MIME: "image/png", SHA256: "s2"}, []byte("new")); err != nil || version(one.ID) != 3 {
				t.Fatalf("a new file of the same name: %v, version %d", err, version(one.ID))
			}
			if _, err := ss.PutResource(ctx, one.ID, site.Resource{Name: "images/flow.PNG", MIME: "image/png", SHA256: "s3"}, []byte("x")); !errors.Is(err, site.ErrResourceTaken) {
				t.Fatalf("a name that differs only by case: %v", err)
			}
			if _, err := ss.PutResource(ctx, 999999, site.Resource{Name: "a.png", MIME: "image/png", SHA256: "s"}, []byte("x")); !errors.Is(err, site.ErrNotFound) {
				t.Fatalf("a file of no document: %v", err)
			}
			// Found only by its exact name, and only under its own document.
			if got, data, err := ss.ResourceData(ctx, one.ID, "images/Flow.png"); err != nil || string(data) != "new" || got.SHA256 != "s2" {
				t.Fatalf("ResourceData = %+v, %q, %v", got, data, err)
			}
			for what, ask := range map[string]struct {
				doc  int64
				name string
			}{
				"another document":    {two.ID, "images/Flow.png"},
				"another case":        {one.ID, "images/flow.png"},
				"a path that climbs":  {two.ID, "../one/images/Flow.png"},
				"a name it never had": {one.ID, "images/other.png"},
			} {
				if _, _, err := ss.ResourceData(ctx, ask.doc, ask.name); !errors.Is(err, site.ErrNoResource) {
					t.Errorf("asked through %s: %v; want no such resource", what, err)
				}
			}
			// The same name under another document is that document's own file.
			if _, err := ss.PutResource(ctx, two.ID, site.Resource{Name: "images/Flow.png", MIME: "image/png", SHA256: "p1"}, []byte("public")); err != nil {
				t.Fatal(err)
			}
			if _, data, _ := ss.ResourceData(ctx, one.ID, "images/Flow.png"); string(data) != "new" {
				t.Fatalf("another document's file replaced this one's: %q", data)
			}
			// The limit.
			for i := 1; i < site.MaxResources; i++ {
				if _, err := ss.PutResource(ctx, one.ID, site.Resource{Name: "f" + strings.Repeat("x", i) + ".csv", MIME: "text/plain; charset=utf-8", SHA256: "c"}, []byte("a")); err != nil {
					t.Fatalf("file %d: %v", i+1, err)
				}
			}
			if _, err := ss.PutResource(ctx, one.ID, site.Resource{Name: "onemore.csv", MIME: "text/plain; charset=utf-8", SHA256: "c"}, []byte("a")); !errors.Is(err, site.ErrTooMany) {
				t.Fatalf("one file over the limit: %v", err)
			}
			if _, err := ss.PutResource(ctx, one.ID, site.Resource{Name: "images/Flow.png", MIME: "image/png", SHA256: "s4"}, []byte("again")); err != nil {
				t.Fatalf("replacing a file at the limit: %v", err)
			}
			if rs, err := ss.Resources(ctx, one.ID); err != nil || len(rs) != site.MaxResources {
				t.Fatalf("Resources = %d, %v", len(rs), err)
			}
			// Removal: once, and it is a new version.
			before := version(one.ID)
			if err := ss.RemoveResource(ctx, one.ID, "images/Flow.png"); err != nil || version(one.ID) != before+1 {
				t.Fatalf("RemoveResource: %v, version %d after %d", err, version(one.ID), before)
			}
			if err := ss.RemoveResource(ctx, one.ID, "images/Flow.png"); !errors.Is(err, site.ErrNoResource) {
				t.Fatalf("removing it twice: %v", err)
			}
			// The files go with their document, and only with theirs.
			if _, err := ss.Remove(ctx, one.ID); err != nil {
				t.Fatal(err)
			}
			if n := count(t, s, "site_resource"); n != 1 {
				t.Fatalf("%d files after the first document went; want the other document's one", n)
			}
			if err := ss.RemoveSite(ctx, blog.ID); err != nil {
				t.Fatal(err)
			}
			if n := count(t, s, "site_resource"); n != 0 {
				t.Fatalf("%d files outlived their site", n)
			}
		})
	}
}

// TestASitesConfigurationIsReplacedWhole: SetSite replaces the configuration
// and the content host in one change, and its audit entry says what changed,
// never the configuration's text.
func TestASitesConfigurationIsReplacedWhole(t *testing.T) {
	for engine, s := range engines(t) {
		t.Run(engine, func(t *testing.T) {
			ctx := context.Background()
			ss := s.Sites()
			blog, err := ss.AddSite(ctx, site.Site{Host: "blog.example.com", CreatedAt: 1})
			if err != nil {
				t.Fatal(err)
			}
			v, err := ss.SetSite(ctx, blog.ID, `{"title":"a secret title"}`, "content.example.com")
			if err != nil || v.Config != `{"title":"a secret title"}` || v.ContentHost != "content.example.com" || v.Host != blog.Host {
				t.Fatalf("%+v, %v", v, err)
			}
			if v, err = ss.SetSite(ctx, blog.ID, v.Config, ""); err != nil || v.ContentHost != "" {
				t.Fatalf("clearing the content host: %+v, %v", v, err)
			}
			if got, _ := ss.SiteByHost(ctx, "blog.example.com"); got.Config != v.Config || got.ContentHost != "" {
				t.Fatalf("read back: %+v", got)
			}
			if _, err := ss.SetSite(ctx, blog.ID+100, "{}", ""); !errors.Is(err, site.ErrNoSite) {
				t.Fatalf("no such site: %v", err)
			}
			rows, err := s.conn.QueryContext(ctx, "SELECT detail FROM audit WHERE action = 'site.set' ORDER BY id")
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			var details []string
			for rows.Next() {
				var d string
				if err := rows.Scan(&d); err != nil {
					t.Fatal(err)
				}
				details = append(details, d)
			}
			want := []string{"configuration; content host content.example.com", "content host none"}
			if strings.Join(details, "|") != strings.Join(want, "|") {
				t.Fatalf("audit %q, want %q", details, want)
			}
		})
	}
}

// TestASitesBuildsAreCounted: a build asked for is owed until it is live; a
// failure keeps what was live; a site taken down is owed until a build passes.
func TestASitesBuildsAreCounted(t *testing.T) {
	for engine, s := range engines(t) {
		t.Run(engine, func(t *testing.T) {
			ctx := context.Background()
			ss := s.Sites()
			ann := testUser(t, s, "ann")
			blog, err := ss.AddSite(ctx, site.Site{Host: "blog.example.com", CreatedAt: 1})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ss.StartBuild(ctx, blog.ID); !errors.Is(err, site.ErrNoBuild) {
				t.Fatalf("nothing asked: %v", err)
			}
			src := site.Source{Body: []byte("# pub"), SHA256: "p1"}
			pub, err := ss.Create(ctx, site.Doc{Site: blog.ID, Slug: "pub", Format: site.Markdown, Owner: ann, Visibility: site.Public}, src)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ss.Create(ctx, site.Doc{Site: blog.ID, Slug: "held", Format: site.Markdown, Owner: ann, Visibility: site.Private}, site.Source{Body: []byte("x"), SHA256: "h"}); err != nil {
				t.Fatal(err)
			}
			if _, err := ss.PutResource(ctx, pub.ID, site.Resource{Name: "a.png", MIME: "image/png", SHA256: "r1"}, []byte("\x89PNG\r\n\x1a\n")); err != nil {
				t.Fatal(err)
			}
			if n, err := ss.AskBuild(ctx, blog.ID); err != nil || n != 1 {
				t.Fatalf("ask: %d, %v", n, err)
			}
			if owed, _ := ss.Owed(ctx); len(owed) != 1 {
				t.Fatalf("owed: %+v", owed)
			}
			snap, err := ss.StartBuild(ctx, blog.ID)
			if err != nil || snap.Build != 1 || snap.Site.BuildState != site.BuildBuilding || len(snap.Docs) != 1 ||
				snap.Docs[0].Doc.Slug != "pub" || snap.Docs[0].SHA256 != "p1" || len(snap.Docs[0].Resources) != 1 {
				t.Fatalf("the snapshot: %+v, %v", snap, err)
			}
			if n, _ := ss.AskBuild(ctx, blog.ID); n != 2 {
				t.Fatalf("asked while building: %d", n)
			}
			v, err := ss.FinishBuild(ctx, blog.ID, 1, "", 10)
			if err != nil || v.LiveBuild != 1 || v.BuildState != site.BuildWaiting {
				t.Fatalf("build 1 live, 2 owed: %+v, %v", v, err)
			}
			if _, err := ss.StartBuild(ctx, blog.ID); err != nil {
				t.Fatal(err)
			}
			if v, err = ss.FinishBuild(ctx, blog.ID, 2, "it broke", 11); err != nil || v.LiveBuild != 1 || v.BuildState != site.BuildFailed || v.BuildError != "it broke" {
				t.Fatalf("build 2 failed: %+v, %v", v, err)
			}
			if owed, _ := ss.Owed(ctx); len(owed) != 0 {
				t.Fatalf("a failed build is not owed: %+v", owed)
			}
			if err := ss.TakeDown(ctx, blog.ID); err != nil {
				t.Fatal(err)
			}
			if owed, _ := ss.Owed(ctx); len(owed) != 1 || !owed[0].Down {
				t.Fatalf("a site taken down is owed: %+v", owed)
			}
			if _, err := ss.AskBuild(ctx, blog.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := ss.StartBuild(ctx, blog.ID); err != nil {
				t.Fatal(err)
			}
			if v, err = ss.FinishBuild(ctx, blog.ID, 3, "", 12); err != nil || v.Down || v.LiveBuild != 3 || v.BuildState != site.BuildLive {
				t.Fatalf("up again: %+v, %v", v, err)
			}
		})
	}
}
