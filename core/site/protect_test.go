package site_test

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/yongjohnlee80/autopanel/core/site"
)

const (
	blogHost   = "blog.example.com"
	blogOrigin = "https://blog.example.com"
	goodPass   = "a passphrase for readers"
)

var (
	formToken  = regexp.MustCompile(`name="token" value="([^"]+)"`)
	formAction = regexp.MustCompile(`action="/_unlock/(\d+)"`)
	cookieOf   = regexp.MustCompile(`^(__Host-ap_[a-z0-9]+)=([^;]+);`)
)

type protFixture struct {
	*buildFixture
	t   *testing.T
	now time.Time
}

func protSetup(t *testing.T) *protFixture {
	t.Helper()
	site.CheapVerifiers()
	f := &protFixture{buildFixture: buildSetup(t), t: t, now: time.Unix(1_800_000_000, 0)}
	site.SetClock(f.m, func() time.Time { return f.now })
	f.m.SetWeak(func(p string) bool { return p == "unbelievable1" })
	return f
}

func (f *protFixture) folder(path, level string) {
	f.t.Helper()
	if _, err := call[site.NodeView](f.t, f.m, "user:ann", "site.folder.add", site.FolderAsk{Site: blogHost, Path: path, Visibility: level}); err != nil {
		f.t.Fatal(err)
	}
}

func (f *protFixture) doc(folder, slug, level string) {
	f.t.Helper()
	if _, err := call[site.Published](f.t, f.m, "user:ann", "site.doc.put", site.Put{Site: blogHost, Folder: folder, Slug: slug, Format: "md", Body: "# " + slug, Visibility: level}); err != nil {
		f.t.Fatal(err)
	}
}

func (f *protFixture) protect(path, pass string) error {
	_, err := call[struct{}](f.t, f.m, "user:ann", "site.node.protect", site.ProtectAsk{Site: blogHost, Path: path, Passphrase: pass})
	return err
}

func (f *protFixture) build() {
	f.t.Helper()
	if err := f.b.BuildOnce(f.ctx, f.blog.ID); err != nil && !errors.Is(err, site.ErrNoBuild) {
		f.t.Fatal(err)
	}
}

// read asks for path on the site's host with the grant cookies given.
func (f *protFixture) read(path, unlock string, grants ...string) site.ReadAnswer {
	return f.m.MayReadPath(f.ctx, site.ReadAsk{Surface: site.SurfaceSite, Host: blogHost, Path: path, Method: "GET", Grants: grants, Unlock: unlock})
}

// form asks for path with no grant and answers the unlock form's node, its
// token and the form's cookie.
func (f *protFixture) form(path string, grants ...string) (node int64, token, cookie string) {
	f.t.Helper()
	a := f.read(path, "", grants...)
	if a.Status != site.ReadUnlock || !a.Protected {
		f.t.Fatalf("%s: no unlock form: %+v", path, a)
	}
	tok, act, ck := formToken.FindStringSubmatch(a.Form), formAction.FindStringSubmatch(a.Form), cookieOf.FindStringSubmatch(a.SetCookie)
	if tok == nil || act == nil || ck == nil || ck[1] != site.UnlockCookie {
		f.t.Fatalf("%s: the form: %q, cookie %q", path, a.Form, a.SetCookie)
	}
	for _, r := range act[1] {
		node = node*10 + int64(r-'0')
	}
	return node, tok[1], ck[2]
}

func (f *protFixture) unlock(node int64, token, cookie, pass, client string, slots ...string) site.UnlockAnswer {
	return f.m.Unlock(f.ctx, site.UnlockAsk{Host: blogHost, Node: node, Passphrase: pass, Token: token, Next: "/locked/a/", Cookie: cookie,
		Origin: blogOrigin, FetchSite: "same-origin", Client: client, Slots: slots})
}

// grant unlocks the node behind path and answers the grant cookie's value.
func (f *protFixture) grant(path, pass string) string {
	f.t.Helper()
	node, token, cookie := f.form(path)
	a := f.unlock(node, token, cookie, pass, "192.0.2.7")
	ck := cookieOf.FindStringSubmatch(a.SetCookie)
	if a.Status != site.UnlockGranted || ck == nil || !strings.HasPrefix(ck[1], site.GrantCookie) || a.Location != "/locked/a/" {
		f.t.Fatalf("unlocking %s: %+v", path, a)
	}
	for _, want := range []string{"Path=/", "Secure", "HttpOnly", "SameSite=Lax", "Max-Age=43200"} {
		if !strings.Contains(a.SetCookie, want) {
			f.t.Errorf("the grant's cookie lacks %s: %s", want, a.SetCookie)
		}
	}
	return ck[2]
}

// TestAPassphraseOpensAProtectedNode: the whole way. A protected address
// answers its unlock form; the passphrase gives a grant; the grant opens the
// folder's public documents and not a protected document inside it, which
// has a passphrase of its own.
func TestAPassphraseOpensAProtectedNode(t *testing.T) {
	f := protSetup(t)
	f.folder("locked", "protected")
	f.doc("locked", "a", "public")
	f.doc("locked", "inner", "protected")
	f.doc("", "hello", "public")
	// Who may set a passphrase, on what, and which.
	if err := f.protect("hello", goodPass); !errors.Is(err, site.ErrNotProtected) {
		t.Fatalf("a passphrase on a public document: %v", err)
	}
	for _, weak := range []string{"short", "unbelievable1", strings.Repeat("x", 2000)} {
		if err := f.protect("locked", weak); !errors.Is(err, site.ErrWeakPassphrase) {
			t.Fatalf("a weak passphrase (%d bytes): %v", len(weak), err)
		}
	}
	f.build()
	// With no passphrase set, nobody is let in, and no form is shown.
	if a := f.read("/locked/a/", ""); a.Status != site.ReadMissing || !a.Protected {
		t.Fatalf("a protected folder with no passphrase: %+v", a)
	}
	if err := f.protect("locked", goodPass); err != nil {
		t.Fatal(err)
	}
	if err := f.protect("locked/inner", "another passphrase entirely"); err != nil {
		t.Fatal(err)
	}
	// The form: for the folder, on the page's address with or without its
	// slash; one of the page's files without a grant is missing.
	node, token, cookie := f.form("/locked/a/")
	if n2, _, _ := f.form("/locked/a"); n2 != node {
		t.Fatalf("the form without the slash is for node %d, with it %d", n2, node)
	}
	if a := f.read("/locked/a/look.css", ""); a.Status != site.ReadMissing {
		t.Fatalf("a file of a protected page, no grant: %+v", a)
	}
	if a := f.read("/locked/", ""); a.Status != site.ReadMissing {
		t.Fatalf("a protected folder's own address: %+v", a)
	}
	form := f.read("/locked/a/", "").Form
	for _, gone := range []string{"# a", goodPass, "<script"} {
		if strings.Contains(form, gone) {
			t.Fatalf("the form holds %q", gone)
		}
	}
	// A browser that has the form's cookie is given no new one, and its
	// token is for that cookie.
	again := f.read("/locked/a/", cookie)
	if again.SetCookie != "" || formToken.FindStringSubmatch(again.Form)[1] != token {
		t.Fatalf("the form again, with its cookie: %+v", again)
	}

	// What is refused before the passphrase is tried.
	for what, a := range map[string]site.UnlockAnswer{
		"another site's page": f.m.Unlock(f.ctx, site.UnlockAsk{Host: blogHost, Node: node, Passphrase: goodPass, Token: token, Cookie: cookie, Origin: "https://evil.example", FetchSite: "cross-site", Client: "192.0.2.7"}),
		"no origin":           f.m.Unlock(f.ctx, site.UnlockAsk{Host: blogHost, Node: node, Passphrase: goodPass, Token: token, Cookie: cookie, Client: "192.0.2.7"}),
		"a cross-site fetch":  f.m.Unlock(f.ctx, site.UnlockAsk{Host: blogHost, Node: node, Passphrase: goodPass, Token: token, Cookie: cookie, Origin: blogOrigin, FetchSite: "cross-site", Client: "192.0.2.7"}),
		"another browser":     f.unlock(node, token, strings.Repeat("A", 43), goodPass, "192.0.2.7"),
		"no token":            f.unlock(node, "", cookie, goodPass, "192.0.2.7"),
		"another node":        f.unlock(node+1, token, cookie, goodPass, "192.0.2.7"),
		"a node that is none": f.unlock(999, token, cookie, goodPass, "192.0.2.7"),
	} {
		if a.Status != site.UnlockGone || a.SetCookie != "" {
			t.Errorf("%s: %+v", what, a)
		}
	}
	// A wrong passphrase: the form again, saying so, and no grant.
	if a := f.unlock(node, token, cookie, "not the passphrase!", "192.0.2.8"); a.Status != site.UnlockRefused || a.SetCookie != "" || !strings.Contains(a.Form, "did not open") {
		t.Fatalf("a wrong passphrase: %+v", a)
	}
	// The right one.
	g := f.grant("/locked/a/", goodPass)
	if a := f.read("/locked/a/", "", g); a.Status != site.ReadFile || a.Kind != site.KindPage {
		t.Fatalf("with the folder's grant: %+v", a)
	}
	if a := f.read("/locked/a", "", g); a.Status != site.ReadRedirect || a.Location != "/locked/a/" {
		t.Fatalf("with the grant, no slash: %+v", a)
	}
	if a := f.read("/locked/a/look.css", "", g); a.Status != site.ReadFile || a.Kind != site.KindAsset {
		t.Fatalf("the page's look, with the grant: %+v", a)
	}
	// The protected document inside asks for its own passphrase, of someone
	// who is past the folder's.
	inner, itoken, icookie := f.form("/locked/inner/", g)
	if inner == node {
		t.Fatal("the inner document's form is the folder's")
	}
	if a := f.unlock(inner, itoken, icookie, goodPass, "192.0.2.9"); a.Status != site.UnlockRefused {
		t.Fatalf("the folder's passphrase on the inner document: %+v", a)
	}
	ia := f.unlock(inner, itoken, icookie, "another passphrase entirely", "192.0.2.9", g)
	ick := cookieOf.FindStringSubmatch(ia.SetCookie)
	if ia.Status != site.UnlockGranted || ick == nil || ick[1] != site.GrantCookie+"1" {
		t.Fatalf("the inner document's passphrase (the second slot): %+v", ia)
	}
	if a := f.read("/locked/inner/", "", g, ick[2]); a.Status != site.ReadFile {
		t.Fatalf("with both grants: %+v", a)
	}
	if a := f.read("/locked/inner/", "", ick[2]); a.Status != site.ReadUnlock {
		t.Fatalf("the inner grant without the folder's: %+v", a)
	}
	// Nothing of a passphrase is in the audit log; every attempt is.
	entries, err := f.st.AuditLog(f.ctx, "site.unlock", 100)
	if err != nil || len(entries) < 4 {
		t.Fatalf("%d unlock entries, %v", len(entries), err)
	}
	all, _ := f.st.AuditLog(f.ctx, "", 500)
	for _, e := range all {
		if strings.Contains(e.Subject+e.Detail, "passphrase for") || strings.Contains(e.Subject+e.Detail, "entirely") {
			t.Errorf("an audit entry holds a passphrase: %+v", e)
		}
	}
}

// TestWhatEndsAGrant: twelve hours; a new passphrase; its removal; the node
// leaving protected; a document moved out of the folder the grant was for.
func TestWhatEndsAGrant(t *testing.T) {
	f := protSetup(t)
	f.folder("locked", "protected")
	f.folder("open", "public")
	f.doc("locked", "a", "public")
	f.doc("locked", "b", "public")
	if err := f.protect("locked", goodPass); err != nil {
		t.Fatal(err)
	}
	f.build()
	opens := func(path, g string) bool { return f.read(path, "", g).Status == site.ReadFile }

	g := f.grant("/locked/a/", goodPass)
	f.now = f.now.Add(site.GrantFor - time.Minute)
	if !opens("/locked/a/", g) {
		t.Fatal("a grant ended before its twelve hours")
	}
	f.now = f.now.Add(2 * time.Minute)
	if opens("/locked/a/", g) {
		t.Fatal("a grant outlived its twelve hours")
	}

	g = f.grant("/locked/a/", goodPass)
	if err := f.protect("locked", "a new passphrase for them"); err != nil {
		t.Fatal(err)
	}
	if opens("/locked/a/", g) {
		t.Fatal("a grant outlived its passphrase")
	}
	g = f.grant("/locked/a/", "a new passphrase for them")

	// Moved out of the folder into a public one: the document is public now,
	// and the folder's grant was never its own.
	if _, err := call[site.NodeView](t, f.m, "user:ann", "site.node.move", site.NodeAsk{Site: blogHost, Path: "locked/b", To: "open"}); err != nil {
		t.Fatal(err)
	}
	f.build()
	if a := f.read("/open/b/", "", g); a.Status != site.ReadMissing {
		t.Fatalf("a document moved out, asked for as held: %+v", a)
	}
	if !opens("/locked/a/", g) {
		t.Fatal("the grant no longer opens what stayed")
	}

	// The folder leaves protected and comes back: the old grant is gone, the
	// passphrase kept.
	set := func(level string) {
		t.Helper()
		if _, err := call[site.NodeView](t, f.m, "user:ann", "site.folder.set", site.FolderAsk{Site: blogHost, Path: "locked", Visibility: level}); err != nil {
			t.Fatal(err)
		}
	}
	set("public")
	set("protected")
	f.build()
	if opens("/locked/a/", g) {
		t.Fatal("a grant outlived the node's leaving protected")
	}
	g = f.grant("/locked/a/", "a new passphrase for them")
	if _, err := call[struct{}](t, f.m, "user:ann", "site.node.unprotect", site.ProtectAsk{Site: blogHost, Path: "locked"}); err != nil {
		t.Fatal(err)
	}
	if a := f.read("/locked/a/", "", g); a.Status != site.ReadMissing {
		t.Fatalf("after the passphrase's removal: %+v", a)
	}
}

// TestUnlocksAreLimited: five attempts a minute from an address (or a /64);
// thirty failures in an hour slow a node to one attempt a minute, and a
// reader who is in stays in.
func TestUnlocksAreLimited(t *testing.T) {
	f := protSetup(t)
	f.folder("locked", "protected")
	f.doc("locked", "a", "public")
	if err := f.protect("locked", goodPass); err != nil {
		t.Fatal(err)
	}
	f.build()
	g := f.grant("/locked/a/", goodPass)
	node, token, cookie := f.form("/locked/a/")
	wrong := func(client string) site.UnlockAnswer {
		return f.unlock(node, token, cookie, "not the passphrase!", client)
	}

	for i := 0; i < 5; i++ {
		if a := wrong("2001:db8::1"); a.Status != site.UnlockRefused {
			t.Fatalf("attempt %d: %+v", i+1, a)
		}
	}
	if a := wrong("2001:db8::1"); a.Status != site.UnlockBusy || a.Wait == 0 {
		t.Fatalf("a sixth attempt in the minute: %+v", a)
	}
	if a := wrong("2001:db8::ffff"); a.Status != site.UnlockBusy {
		t.Fatalf("another address of the same /64: %+v", a)
	}
	if a := wrong("2001:db8:0:1::1"); a.Status != site.UnlockRefused {
		t.Fatalf("an address of another /64: %+v", a)
	}
	// Many addresses, one node: at thirty failures it slows for everyone new.
	for i := 0; i < 24; i++ {
		_ = wrong(fmt.Sprintf("198.51.100.%d", i+1))
	}
	if a := wrong("203.0.113.1"); a.Status != site.UnlockRefused {
		t.Fatalf("the first attempt once slowed is let through: %+v", a)
	}
	if a := f.unlock(node, token, cookie, goodPass, "203.0.113.2"); a.Status != site.UnlockBusy || a.Wait < 1 {
		t.Fatalf("a second attempt in the slowed minute, even with the right passphrase: %+v", a)
	}
	if f.read("/locked/a/", "", g).Status != site.ReadFile {
		t.Fatal("a reader who was in was shut out by others' failures")
	}
	f.now = f.now.Add(61 * time.Second)
	if a := f.unlock(node, token, cookie, goodPass, "203.0.113.2"); a.Status != site.UnlockGranted {
		t.Fatalf("a minute later, the right passphrase: %+v", a)
	}
	f.now = f.now.Add(time.Hour)
	if a := wrong("203.0.113.3"); a.Status != site.UnlockRefused {
		t.Fatalf("an hour later the node is no longer slowed: %+v", a)
	}
}

// TestANinthGrantTakesTheOldestSlot: a browser keeps eight grants.
func TestANinthGrantTakesTheOldestSlot(t *testing.T) {
	f := protSetup(t)
	f.folder("locked", "protected")
	f.doc("locked", "a", "public")
	if err := f.protect("locked", goodPass); err != nil {
		t.Fatal(err)
	}
	f.build()
	slots := make([]string, site.MaxGrantCookies)
	for i := 0; i < site.MaxGrantCookies; i++ {
		node, token, cookie := f.form("/locked/a/")
		a := f.unlock(node, token, cookie, goodPass, "192.0.2."+string(rune('1'+i)), slots...)
		ck := cookieOf.FindStringSubmatch(a.SetCookie)
		if a.Status != site.UnlockGranted || ck[1] != site.GrantCookie+string(rune('0'+i)) {
			t.Fatalf("grant %d: %+v", i, a)
		}
		slots[i] = ck[2]
		f.now = f.now.Add(time.Minute)
	}
	node, token, cookie := f.form("/locked/a/")
	a := f.unlock(node, token, cookie, goodPass, "192.0.2.99", slots...)
	if ck := cookieOf.FindStringSubmatch(a.SetCookie); a.Status != site.UnlockGranted || ck[1] != site.GrantCookie+"0" {
		t.Fatalf("the ninth grant: %+v", a)
	}
	slots[3] = "a-cookie-whose-grant-is-gone"
	node, token, cookie = f.form("/locked/a/")
	a = f.unlock(node, token, cookie, goodPass, "192.0.2.98", slots...)
	if ck := cookieOf.FindStringSubmatch(a.SetCookie); a.Status != site.UnlockGranted || ck[1] != site.GrantCookie+"3" {
		t.Fatalf("a slot whose grant has ended is taken first: %+v", a)
	}
}
