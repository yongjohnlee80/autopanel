package site_test

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yongjohnlee80/golib/dao"

	"github.com/yongjohnlee80/autopanel/core/site"
	"github.com/yongjohnlee80/autopanel/internal/auth"
	"github.com/yongjohnlee80/autopanel/store"
)

type treeFixture struct {
	m  *site.Module
	st *store.Store
}

func treeSetup(t *testing.T) *treeFixture {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, store.Config{Engine: dao.DialectSQLite, Path: filepath.Join(t.TempDir(), "store.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ppl := people{}
	for _, n := range []string{"root", "ann", "bob"} {
		u, err := st.Users().AddUser(ctx, n, auth.RoleOperator, nil, "v", false)
		if err != nil {
			t.Fatal(err)
		}
		ppl["user:"+n] = site.Person{ID: u.ID, Name: n, Admin: n == "root"}
	}
	m := site.NewModule(st.Sites(), ppl)
	if _, err := call[site.SiteView](t, m, "user:root", "site.add", site.SiteAsk{Host: "docs.example.com"}); err != nil {
		t.Fatal(err)
	}
	return &treeFixture{m: m, st: st}
}

func str(s string) *string { return &s }

func (f *treeFixture) folder(t *testing.T, as, path, level string) site.NodeView {
	t.Helper()
	v, err := call[site.NodeView](t, f.m, as, "site.folder.add", site.FolderAsk{Site: "docs.example.com", Path: path, Visibility: level, Title: str("The " + path)})
	if err != nil {
		t.Fatalf("folder %s: %v", path, err)
	}
	return v
}

func (f *treeFixture) doc(t *testing.T, as, folder, slug, level string) (site.Published, error) {
	t.Helper()
	return call[site.Published](t, f.m, as, "site.doc.put", site.Put{Site: "docs.example.com", Folder: folder, Slug: slug, Format: "md", Body: "# " + slug, Visibility: level})
}

func (f *treeFixture) list(t *testing.T, as, path string) ([]string, error) {
	t.Helper()
	vs, err := call[[]site.NodeView](t, f.m, as, "site.node.list", site.NodeAsk{Site: "docs.example.com", Path: path})
	var out []string
	for _, v := range vs {
		out = append(out, v.Kind+":"+v.Path)
	}
	return out, err
}

func TestFoldersHoldDocumentsAndFolders(t *testing.T) {
	f := treeSetup(t)
	g := f.folder(t, "user:ann", "guides", "public")
	if g.Path != "guides" || g.Kind != "folder" || g.Title != "The guides" || g.Owner != "ann" {
		t.Fatalf("a folder: %+v", g)
	}
	f.folder(t, "user:ann", "guides/install", "public")
	p, err := f.doc(t, "user:ann", "guides/install", "linux", "public")
	if err != nil || p.Path != "guides/install/linux" {
		t.Fatalf("a document in a folder: %+v, %v", p, err)
	}
	if _, err := f.doc(t, "user:ann", "", "about", "public"); err != nil {
		t.Fatal(err)
	}
	if got, _ := f.list(t, "user:bob", ""); strings.Join(got, " ") != "doc:about folder:guides" {
		t.Fatalf("the root: %v", got)
	}
	if got, _ := f.list(t, "user:bob", "guides/install"); strings.Join(got, " ") != "doc:guides/install/linux" {
		t.Fatalf("a folder's children: %v", got)
	}
	// A document is read by its path.
	if v, err := call[site.SourceView](t, f.m, "user:ann", "site.doc.get", site.DocAsk{Site: "docs.example.com", Folder: "guides/install", Slug: "linux"}); err != nil || v.Body != "# linux" {
		t.Fatalf("by its path: %+v, %v", v, err)
	}
	// One slug in two folders; never a folder and a document of one slug in one.
	if _, err := f.doc(t, "user:ann", "guides", "linux", "public"); err != nil {
		t.Fatalf("the same slug in another folder: %v", err)
	}
	if _, err := call[site.NodeView](t, f.m, "user:ann", "site.folder.add", site.FolderAsk{Site: "docs.example.com", Path: "about"}); !errors.Is(err, site.ErrDuplicate) {
		t.Fatalf("a folder where a document is: %v", err)
	}
	if _, err := f.doc(t, "user:ann", "", "guides", "public"); !errors.Is(err, site.ErrDuplicate) {
		t.Fatalf("a document where a folder is: %v", err)
	}
	if _, err := f.doc(t, "user:ann", "about", "x", "public"); !errors.Is(err, site.ErrNotAFolder) {
		t.Fatalf("a document under a document: %v", err)
	}
	if _, err := f.doc(t, "user:ann", "missing", "x", "public"); !errors.Is(err, site.ErrNotFound) {
		t.Fatalf("a folder that does not exist: %v", err)
	}
}

// A folder's level closes what it holds: a member who may not read it
// neither lists nor reads what is in it, and learns nothing of it.
func TestAFoldersLevelClosesWhatItHolds(t *testing.T) {
	f := treeSetup(t)
	f.folder(t, "user:ann", "drafts", "private")
	if _, err := f.doc(t, "user:ann", "drafts", "plan", "public"); err != nil {
		t.Fatal(err)
	}
	if got, _ := f.list(t, "user:bob", ""); len(got) != 0 {
		t.Fatalf("bob sees a private folder: %v", got)
	}
	if _, err := f.list(t, "user:bob", "drafts"); !errors.Is(err, site.ErrNotFound) {
		t.Fatalf("bob lists a private folder: %v", err)
	}
	if _, err := call[site.SourceView](t, f.m, "user:bob", "site.doc.get", site.DocAsk{Site: "docs.example.com", Folder: "drafts", Slug: "plan"}); !errors.Is(err, site.ErrNotFound) {
		t.Fatalf("bob reads a public document in a private folder: %v", err)
	}
	// An administrator reads it, audited.
	if got, err := f.list(t, "user:root", "drafts"); err != nil || len(got) != 1 {
		t.Fatalf("an administrator's list: %v, %v", got, err)
	}
	// Shared with bob, he lists it.
	if _, err := call[site.NodeView](t, f.m, "user:ann", "site.folder.set", site.FolderAsk{Site: "docs.example.com", Path: "drafts", Share: &[]string{"bob"}}); err != nil {
		t.Fatal(err)
	}
	if got, _ := f.list(t, "user:bob", "drafts"); len(got) != 1 {
		t.Fatalf("bob, shared: %v", got)
	}
}

// Into a folder: its owner and an administrator; at the root, anyone who
// publishes. parents: true makes only what is missing, and only where the
// caller may (tifa's review of r3, F3).
func TestWhoPutsWhatWhere(t *testing.T) {
	f := treeSetup(t)
	f.folder(t, "user:ann", "team", "public")
	if _, err := f.doc(t, "user:bob", "team", "note", "public"); !errors.Is(err, site.ErrNotYours) {
		t.Fatalf("bob into ann's folder: %v", err)
	}
	if _, err := call[site.NodeView](t, f.m, "user:bob", "site.folder.add", site.FolderAsk{Site: "docs.example.com", Path: "team/bobs"}); !errors.Is(err, site.ErrNotYours) {
		t.Fatalf("bob's folder in ann's: %v", err)
	}
	if _, err := f.doc(t, "user:root", "team", "notice", "public"); err != nil {
		t.Fatalf("an administrator into ann's folder: %v", err)
	}
	// parents: true
	p, err := call[site.Published](t, f.m, "user:bob", "site.doc.put", site.Put{Site: "docs.example.com", Folder: "bob/notes/2026", Parents: true, Slug: "n1", Format: "md", Body: "x"})
	if err != nil || p.Path != "bob/notes/2026/n1" {
		t.Fatalf("with parents: %+v, %v", p, err)
	}
	if got, _ := f.list(t, "user:bob", "bob/notes"); strings.Join(got, " ") != "folder:bob/notes/2026" {
		t.Fatalf("the folders made: %v", got)
	}
	if got, _ := f.list(t, "user:ann", ""); strings.Contains(strings.Join(got, " "), "bob") {
		t.Fatalf("the folders made are not private: %v", got)
	}
	if _, err := call[site.Published](t, f.m, "user:bob", "site.doc.put", site.Put{Site: "docs.example.com", Folder: "team/bobs/x", Parents: true, Slug: "n2", Format: "md", Body: "x"}); !errors.Is(err, site.ErrNotYours) {
		t.Fatalf("parents through ann's folder: %v", err)
	}
	if got, _ := f.list(t, "user:ann", "team"); strings.Contains(strings.Join(got, " "), "bobs") {
		t.Fatalf("a refused call made a folder: %v", got)
	}
}

func TestFoldersAreRemovedEmpty(t *testing.T) {
	f := treeSetup(t)
	f.folder(t, "user:ann", "old", "private")
	if _, err := f.doc(t, "user:ann", "old", "x", "private"); err != nil {
		t.Fatal(err)
	}
	if _, err := call[struct{}](t, f.m, "user:ann", "site.folder.remove", site.FolderAsk{Site: "docs.example.com", Path: "old"}); !errors.Is(err, site.ErrNotEmpty) {
		t.Fatalf("a folder with something in it: %v", err)
	}
	if _, err := call[struct{}](t, f.m, "user:ann", "site.doc.remove", site.DocAsk{Site: "docs.example.com", Folder: "old", Slug: "x"}); err != nil {
		t.Fatal(err)
	}
	if _, err := call[struct{}](t, f.m, "user:bob", "site.folder.remove", site.FolderAsk{Site: "docs.example.com", Path: "old"}); !errors.Is(err, site.ErrNotFound) {
		t.Fatalf("bob removing ann's private folder: %v", err)
	}
	if _, err := call[struct{}](t, f.m, "user:ann", "site.folder.remove", site.FolderAsk{Site: "docs.example.com", Path: "old"}); err != nil {
		t.Fatal(err)
	}
	if _, err := call[struct{}](t, f.m, "user:ann", "site.folder.remove", site.FolderAsk{Site: "docs.example.com", Path: ""}); !errors.Is(err, site.ErrRoot) {
		t.Fatalf("the root: %v", err)
	}
}

// A move is checked whole (tifa's review of r3, F1): never into itself or
// under itself, within the bounds of depth for all it carries; moving
// something public out of the public is a withdrawal.
func TestAMoveIsCheckedWhole(t *testing.T) {
	f := treeSetup(t)
	f.folder(t, "user:ann", "a", "public")
	f.folder(t, "user:ann", "a/b", "public")
	f.folder(t, "user:ann", "x", "private")
	if _, err := f.doc(t, "user:ann", "a/b", "page", "public"); err != nil {
		t.Fatal(err)
	}
	move := func(as, path, to string) (site.NodeView, error) {
		return call[site.NodeView](t, f.m, as, "site.node.move", site.NodeAsk{Site: "docs.example.com", Path: path, To: to})
	}
	if _, err := move("user:ann", "a", "a/b"); !errors.Is(err, site.ErrCycle) {
		t.Fatalf("a folder into its child: %v", err)
	}
	if _, err := move("user:ann", "a", "a"); !errors.Is(err, site.ErrCycle) {
		t.Fatalf("a folder into itself: %v", err)
	}
	if _, err := move("user:bob", "a/b/page", ""); !errors.Is(err, site.ErrNotYours) {
		t.Fatalf("bob moving ann's document: %v", err)
	}
	gen := func() int64 {
		s, err := f.st.Sites().SiteByHost(context.Background(), "docs.example.com")
		if err != nil {
			t.Fatal(err)
		}
		return s.SecurityGen
	}
	before := gen()
	if v, err := move("user:ann", "a/b/page", "a"); err != nil || v.Path != "a/page" || gen() != before {
		t.Fatalf("within the public: %+v, %v, gen %d→%d", v, err, before, gen())
	}
	if v, err := move("user:ann", "a/page", "x"); err != nil || v.Path != "x/page" || gen() != before+1 {
		t.Fatalf("out of the public, a withdrawal: %+v, %v, gen %d→%d", v, err, before, gen())
	}
	// Depth, for everything the folder carries.
	deep := "d1"
	f.folder(t, "user:ann", deep, "private")
	for i := 2; i <= 7; i++ {
		deep += "/d" + string(rune('0'+i))
		f.folder(t, "user:ann", deep, "private")
	}
	if _, err := move("user:ann", "a", deep); !errors.Is(err, site.ErrTooDeep) {
		t.Fatalf("a folder of two levels under seven: %v", err)
	}
	if _, err := call[site.NodeView](t, f.m, "user:ann", "site.folder.add", site.FolderAsk{Site: "docs.example.com", Path: deep + "/d8"}); err != nil {
		t.Fatalf("the eighth level: %v", err)
	}
	if _, err := call[site.NodeView](t, f.m, "user:ann", "site.folder.add", site.FolderAsk{Site: "docs.example.com", Path: deep + "/d8/d9"}); err == nil {
		t.Fatal("a ninth level")
	}
}

// A call refused for its own fields makes no folder on the way (tifa, N1);
// a node marked public inside a closed folder was never public, so closing
// it withdraws nothing (N2).
func TestARefusedCallLeavesNoFolderAndAClosedFolderWithdrawsNothing(t *testing.T) {
	f := treeSetup(t)
	for name, p := range map[string]site.Put{
		"a level of no kind":  {Site: "docs.example.com", Folder: "new/a", Parents: true, Slug: "x", Format: "md", Body: "x", Visibility: "secret"},
		"a format of no kind": {Site: "docs.example.com", Folder: "new/b", Parents: true, Slug: "x", Format: "pdf", Body: "x"},
		"a bad slug":          {Site: "docs.example.com", Folder: "new/c", Parents: true, Slug: "X Y", Format: "md", Body: "x"},
	} {
		if _, err := call[site.Published](t, f.m, "user:ann", "site.doc.put", p); err == nil {
			t.Fatalf("%s was published", name)
		}
	}
	if _, err := call[site.NodeView](t, f.m, "user:ann", "site.folder.add", site.FolderAsk{Site: "docs.example.com", Path: "new/d", Parents: true, Visibility: "secret"}); err == nil {
		t.Fatal("a folder of no level")
	}
	if got, _ := f.list(t, "user:ann", ""); len(got) != 0 {
		t.Fatalf("refused calls made folders: %v", got)
	}
	// N2
	f.folder(t, "user:ann", "closed", "private")
	if _, err := f.doc(t, "user:ann", "closed", "page", "public"); err != nil {
		t.Fatal(err)
	}
	gen := func() int64 {
		s, err := f.st.Sites().SiteByHost(context.Background(), "docs.example.com")
		if err != nil {
			t.Fatal(err)
		}
		return s.SecurityGen
	}
	before := gen()
	if _, err := f.doc(t, "user:ann", "closed", "page", "internal"); err != nil {
		t.Fatal(err)
	}
	if _, err := call[struct{}](t, f.m, "user:ann", "site.doc.remove", site.DocAsk{Site: "docs.example.com", Folder: "closed", Slug: "page"}); err != nil {
		t.Fatal(err)
	}
	if gen() != before {
		t.Fatalf("a node never public raised the security generation: %d→%d", before, gen())
	}
}
