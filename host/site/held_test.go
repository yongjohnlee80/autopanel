//go:build linux

package site

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	coresite "github.com/yongjohnlee80/autopanel/core/site"
)

// heldOutput makes a held job's output for blog.example.com: what the core
// keeps, and what it must not.
func heldOutput(t *testing.T, f Files) Work {
	t.Helper()
	w, err := f.Fresh("blog.example.com")
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{
		"index.html":       "<h1>the held page</h1>",
		"look.css":         ":root{}",
		"_doc.html":        "<p>inert</p>",
		"img/map.png":      "\x89PNG\r\n\x1a\nrest",
		"_astro/site.css":  "body{}",
		"_kit/m.js":        "/* the kit's */",
		"feed.xml":         "<rss>names the held document</rss>",
		"other/index.html": "<p>a page the job made of its own</p>",
	} {
		p := filepath.Join(w.Out, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.TakeAway(w); err != nil {
		t.Fatal(err)
	}
	return w
}

var heldNames = []string{"index.html", "look.css", "_doc.html", "img/map.png"}

// TestHeldFilesAreTheNamedOnesAlone: of a job's output the core keeps the
// files it names and the kit's directories, closed to every user but root
// and the readers' group; an older build and a node that is gone are swept.
func TestHeldFilesAreTheNamedOnesAlone(t *testing.T) {
	f := files(t)
	if err := f.PublishHeld(heldOutput(t, f), 7, 3, heldNames, []string{"_astro", "_kit", "_none"}); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(f.HeldRoot(), "blog.example.com", "7", "3")
	for _, name := range append(heldNames, "_astro/site.css", "_kit/m.js") {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if m := mode(t, p); m.Perm() != 0o640 {
			t.Errorf("%s: mode %v", name, m)
		}
		if p != filepath.Join(f.HeldRoot(), coresite.HeldFile("blog.example.com", 7, 3, name)) {
			t.Errorf("%s is not where the core names it", name)
		}
	}
	for _, d := range []string{f.HeldRoot(), filepath.Join(f.HeldRoot(), "blog.example.com"), dir, filepath.Join(dir, "img"), filepath.Join(dir, "_kit")} {
		if m := mode(t, d); m.Perm() != 0o750 {
			t.Errorf("%s: mode %v", d, m)
		}
	}
	for _, name := range []string{"feed.xml", "other/index.html", "other"} {
		if _, err := os.Lstat(filepath.Join(dir, filepath.FromSlash(name))); err == nil {
			t.Errorf("%s was kept", name)
		}
	}
	// A file the core expects and the job did not make fails it, and leaves
	// what was there.
	if err := f.PublishHeld(heldOutput(t, f), 7, 4, append(heldNames, "missing.png"), nil); err == nil {
		t.Fatal("a held build without one of its files was kept")
	}
	if _, err := os.Lstat(filepath.Join(f.HeldRoot(), "blog.example.com", "7", "4")); err == nil {
		t.Fatal("half a held build was left under its name")
	}
	for _, bad := range [][]string{{"../x"}, {"/etc/passwd"}, {".hidden"}, {"img/../../x"}} {
		if err := f.PublishHeld(heldOutput(t, f), 7, 5, bad, nil); err == nil {
			t.Errorf("%v was copied", bad)
		}
	}
	// A link where a file should be is not followed.
	w := heldOutput(t, f)
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("s"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(filepath.Join(w.Out, "look.css"))
	if err := os.Symlink(secret, filepath.Join(w.Out, "look.css")); err == nil {
		if err := f.PublishHeld(w, 7, 6, heldNames, nil); err == nil {
			t.Error("a link in the output was followed")
		}
	}

	// A newer build of the node, and another node.
	if err := f.PublishHeld(heldOutput(t, f), 7, 8, heldNames, nil); err != nil {
		t.Fatal(err)
	}
	if err := f.PublishHeld(heldOutput(t, f), 9, 8, heldNames, nil); err != nil {
		t.Fatal(err)
	}
	if err := f.SweepHeld("blog.example.com", map[int64]int64{7: 8}); err != nil {
		t.Fatal(err)
	}
	left, _ := filepath.Glob(filepath.Join(f.HeldRoot(), "blog.example.com", "*", "*"))
	if len(left) != 1 || !strings.HasSuffix(left[0], "/7/8") {
		t.Fatalf("after the sweep: %v", left)
	}
	if err := f.Remove("blog.example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(f.HeldRoot(), "blog.example.com")); err == nil {
		t.Fatal("a removed site's held files stayed")
	}
}

// core stands in for the core on the auth socket: it records each question
// and answers with answer.
type fakeCore struct {
	mu     sync.Mutex
	asks   []coresite.ReadAsk
	answer func(coresite.ReadAsk) coresite.ReadAnswer
}

func (c *fakeCore) decide(_ context.Context, ask coresite.ReadAsk) coresite.ReadAnswer {
	c.mu.Lock()
	c.asks = append(c.asks, ask)
	c.mu.Unlock()
	return c.answer(ask)
}

func (c *fakeCore) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.asks)
}

// heldServer serves blog.example.com's public pages and one held document
// (node 7, build 3), with core answering on the auth socket.
func heldServer(t *testing.T, core *fakeCore) (Server, Files, func()) {
	t.Helper()
	pub, f := served(t)
	if err := f.PublishHeld(heldOutput(t, f), 7, 3, heldNames, []string{"_astro", "_kit"}); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(t.TempDir(), "auth.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = ServeAuth(l, core.decide); close(done) }()
	stop := func() { _ = l.Close(); <-done }
	t.Cleanup(stop)
	return NewServer(pub.Dir, sock), f, stop
}

func heldAnswer(name, kind string) coresite.ReadAnswer {
	return coresite.ReadAnswer{Status: coresite.ReadFile, File: coresite.HeldFile("blog.example.com", 7, 3, name), Kind: kind,
		ScriptHashes: []string{"sha256-AAAA"}, Scripts: []string{"_kit/m.js"}, Protected: true}
}

// TestAHeldFileIsServedOnlyOnTheCoresWord: on the app host the serving
// process asks the core with the session cookie and nothing else of the
// request's cookies, serves exactly the file it is told, never caches it, and
// answers everything else as the public missing page.
func TestAHeldFileIsServedOnlyOnTheCoresWord(t *testing.T) {
	const app = "app.example.com"
	core := &fakeCore{answer: func(coresite.ReadAsk) coresite.ReadAnswer { return coresite.ReadAnswer{Status: coresite.ReadMissing} }}
	s, _, stop := heldServer(t, core)
	missing := get(s, "GET", "blog.example.com", "/nothere/")
	wantMissing := body(t, missing)

	core.answer = func(a coresite.ReadAsk) coresite.ReadAnswer {
		switch {
		case a.Session != "good":
			return coresite.ReadAnswer{Status: coresite.ReadMissing}
		case a.Path == "/s/blog.example.com/plans/":
			ans := heldAnswer("index.html", coresite.KindPage)
			ans.Mermaid = true
			return ans
		case a.Path == "/s/blog.example.com/plans":
			return coresite.ReadAnswer{Status: coresite.ReadRedirect, Location: "/s/blog.example.com/plans/"}
		case a.Path == "/s/blog.example.com/plans/_doc.html":
			return heldAnswer("_doc.html", coresite.KindInert)
		case a.Path == "/s/blog.example.com/plans/img/map.png":
			return heldAnswer("img/map.png", coresite.KindResource)
		case a.Path == "/s/blog.example.com/plans/_kit/m.js":
			return heldAnswer("_kit/m.js", coresite.KindAsset)
		case a.Path == "/s/blog.example.com/plans/x.js":
			return heldAnswer("_kit/m.js", coresite.KindResource) // a script that is no kit asset
		case a.Path == "/s/blog.example.com/plans/gone":
			return heldAnswer("gone.html", coresite.KindPage)
		case a.Path == "/s/blog.example.com/plans/climb":
			return coresite.ReadAnswer{Status: coresite.ReadFile, File: "../blog.example.com/index.html", Kind: coresite.KindPage}
		case a.Path == "/s/blog.example.com/plans/away":
			return coresite.ReadAnswer{Status: coresite.ReadRedirect, Location: "//evil.example/"}
		}
		return coresite.ReadAnswer{Status: coresite.ReadMissing}
	}
	cookies := "theme=dark; __Host-ap_session=good; other=1; __Host-ap_g0=grant"
	res := get(s, "GET", app, "/s/blog.example.com/plans/", "Cookie", cookies)
	csp := res.Header.Get("Content-Security-Policy")
	if res.StatusCode != 200 || body(t, res) != "<h1>the held page</h1>" || res.Header.Get("Cache-Control") != "private, no-store" ||
		!strings.Contains(csp, "script-src 'sha256-AAAA'") || !strings.Contains(csp, "frame-ancestors 'none'") ||
		res.Header.Get("Referrer-Policy") != "no-referrer" || res.Header.Get("ETag") != "" {
		t.Fatalf("a held page: %d %v", res.StatusCode, res.Header)
	}
	last := core.asks[len(core.asks)-1]
	if last.Surface != coresite.SurfaceApp || last.Host != app || last.Session != "good" || len(last.Grants) != 0 || last.Method != "GET" {
		t.Fatalf("the question: %+v", last)
	}
	if res := get(s, "GET", app, "/s/blog.example.com/plans/_doc.html", "Cookie", cookies); res.StatusCode != 200 || !strings.HasPrefix(res.Header.Get("Content-Security-Policy"), "sandbox;") {
		t.Errorf("the inert copy: %d %q", res.StatusCode, res.Header.Get("Content-Security-Policy"))
	}
	if res := get(s, "GET", app, "/s/blog.example.com/plans/img/map.png", "Cookie", cookies); res.StatusCode != 200 || res.Header.Get("Content-Type") != "image/png" || res.Header.Get("Cache-Control") != "private, no-store" {
		t.Errorf("an image: %d %v", res.StatusCode, res.Header)
	}
	if res := get(s, "GET", app, "/s/blog.example.com/plans/_kit/m.js", "Cookie", cookies); res.StatusCode != 200 || !strings.HasPrefix(res.Header.Get("Content-Type"), "text/javascript") {
		t.Errorf("the kit's script: %d", res.StatusCode)
	}
	if res := get(s, "GET", app, "/s/blog.example.com/plans", "Cookie", cookies); res.StatusCode != http.StatusMovedPermanently || res.Header.Get("Location") != "/s/blog.example.com/plans/" || res.Header.Get("Cache-Control") != "private, no-store" {
		t.Errorf("the redirect: %d %v", res.StatusCode, res.Header)
	}
	// Everything else is the public missing page: status, body and policy.
	for what, r := range map[string]*http.Response{
		"no session":                   get(s, "GET", app, "/s/blog.example.com/plans/"),
		"a session of a strange shape": get(s, "GET", app, "/s/blog.example.com/plans/", "Cookie", "__Host-ap_session=good bad"),
		"a session too long":           get(s, "GET", app, "/s/blog.example.com/plans/", "Cookie", "__Host-ap_session="+strings.Repeat("a", 200)),
		"another document":             get(s, "GET", app, "/s/blog.example.com/diary/", "Cookie", cookies),
		"a script that is no asset":    get(s, "GET", app, "/s/blog.example.com/plans/x.js", "Cookie", cookies),
		"a file that is not there":     get(s, "GET", app, "/s/blog.example.com/plans/gone", "Cookie", cookies),
		"a file outside the held root": get(s, "GET", app, "/s/blog.example.com/plans/climb", "Cookie", cookies),
		"a redirect off the host":      get(s, "GET", app, "/s/blog.example.com/plans/away", "Cookie", cookies),
		"the app host outside /s/":     get(s, "GET", app, "/plans/", "Cookie", cookies),
	} {
		if r.StatusCode != missing.StatusCode || body(t, r) != wantMissing || r.Header.Get("Content-Security-Policy") != missing.Header.Get("Content-Security-Policy") ||
			r.Header.Get("Cache-Control") != missing.Header.Get("Cache-Control") || r.Header.Get("Content-Type") != missing.Header.Get("Content-Type") {
			t.Errorf("%s is not the missing page: %d %v", what, r.StatusCode, r.Header)
		}
	}
	if res := get(s, "POST", app, "/s/blog.example.com/plans/", "Cookie", cookies); res.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("a POST: %d", res.StatusCode)
	}
	// The public pages need no core; the held ones answer 503 without it.
	stop()
	if res := get(s, "GET", "blog.example.com", "/a/"); res.StatusCode != 200 {
		t.Errorf("a public page with the core away: %d", res.StatusCode)
	}
	if res := get(s, "GET", app, "/s/blog.example.com/plans/", "Cookie", cookies); res.StatusCode != http.StatusServiceUnavailable || res.Header.Get("Retry-After") == "" {
		t.Errorf("a held page with the core away: %d", res.StatusCode)
	}
}

// TestAMissOnASitesHostAsksOnlyWhileItHasSomethingProtected: the core is
// asked about a path the public pages do not hold, with the grant cookies;
// once it says the site has nothing protected, misses are answered without
// it for a while.
func TestAMissOnASitesHostAsksOnlyWhileItHasSomethingProtected(t *testing.T) {
	core := &fakeCore{}
	s, _, _ := heldServer(t, core)
	protected := true
	core.answer = func(a coresite.ReadAsk) coresite.ReadAnswer {
		if a.Path == "/locked/" && len(a.Grants) == 1 && a.Grants[0] == "grant" {
			return heldAnswer("index.html", coresite.KindPage)
		}
		return coresite.ReadAnswer{Status: coresite.ReadMissing, Protected: protected}
	}
	if res := get(s, "GET", "blog.example.com", "/a/"); res.StatusCode != 200 || core.count() != 0 {
		t.Fatalf("a public page asked the core: %d, %d questions", res.StatusCode, core.count())
	}
	res := get(s, "GET", "blog.example.com", "/locked/", "Cookie", "__Host-ap_session=mine; __Host-ap_g0=grant; __Host-ap_g9=no")
	if res.StatusCode != 200 || body(t, res) != "<h1>the held page</h1>" || res.Header.Get("Cache-Control") != "private, no-store" {
		t.Fatalf("a protected page with its grant: %d", res.StatusCode)
	}
	if q := core.asks[len(core.asks)-1]; q.Surface != coresite.SurfaceSite || q.Session != "" || len(q.Grants) != 1 || q.Host != "blog.example.com" {
		t.Fatalf("the question: %+v", q)
	}
	for i := 0; i < 3; i++ {
		if res := get(s, "GET", "blog.example.com", "/nothere/"); res.StatusCode != http.StatusNotFound {
			t.Fatalf("a miss: %d", res.StatusCode)
		}
	}
	if core.count() != 4 {
		t.Fatalf("%d questions; a site with something protected is asked at every miss", core.count())
	}
	protected = false
	for i := 0; i < 5; i++ {
		if res := get(s, "GET", "blog.example.com", "/nothere/"); res.StatusCode != http.StatusNotFound {
			t.Fatalf("a miss: %d", res.StatusCode)
		}
	}
	if core.count() != 5 {
		t.Fatalf("%d questions; a site with nothing protected is asked once, then left", core.count())
	}
	// The content host never asks.
	if res := get(s, "GET", "content.example.com", "/nothere/"); res.StatusCode != http.StatusNotFound || core.count() != 5 {
		t.Fatalf("the content host asked the core: %d", core.count())
	}
}

// TestTheAuthSocketAnswersOneBoundedQuestion: a question too long, or none,
// gets no answer; more than the limit at once are told the core is busy.
func TestTheAuthSocketAnswersOneBoundedQuestion(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "auth.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	entered := make(chan struct{}, AuthInFlight+1)
	go func() {
		_ = ServeAuth(l, func(_ context.Context, a coresite.ReadAsk) coresite.ReadAnswer {
			if a.Path == "/wait" {
				entered <- struct{}{}
				<-release
			}
			return coresite.ReadAnswer{Status: coresite.ReadMissing}
		})
	}()
	t.Cleanup(func() { _ = l.Close() })
	ctx := context.Background()
	if ans, err := askCore(ctx, sock, coresite.ReadAsk{Path: "/x"}); err != nil || ans.Status != coresite.ReadMissing {
		t.Fatalf("a question: %+v, %v", ans, err)
	}
	if _, err := askCore(ctx, sock, coresite.ReadAsk{Path: "/" + strings.Repeat("a", AuthMessage)}); err != ErrAuthDown {
		t.Fatalf("a question over the limit: %v", err)
	}
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte("not json\n"))
	buf := make([]byte, 16)
	if n, _ := c.Read(buf); n != 0 {
		t.Fatalf("no question was answered: %q", buf[:n])
	}
	c.Close()
	var wg sync.WaitGroup
	for i := 0; i < AuthInFlight; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = askCore(ctx, sock, coresite.ReadAsk{Path: "/wait"}) }()
	}
	for i := 0; i < AuthInFlight; i++ {
		<-entered
	}
	if _, err := askCore(ctx, sock, coresite.ReadAsk{Path: "/x"}); err != ErrAuthDown {
		t.Fatalf("a question over the in-flight limit: %v", err)
	}
	close(release)
	wg.Wait()
}
