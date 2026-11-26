//go:build linux

package site

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// served builds blog.example.com's pages, with the core's manifest, and
// answers a Server over them.
func served(t *testing.T) (Server, Files) {
	t.Helper()
	f := files(t)
	w, err := f.Fresh("blog.example.com")
	if err != nil {
		t.Fatal(err)
	}
	pages := map[string]string{
		"index.html":                     "<h1>home</h1>",
		"a/index.html":                   "<h1>a</h1>",
		"d/index.html":                   `<pre class="mermaid">graph TD; A--&gt;B</pre>`,
		"doc/_doc.html":                  "<p>inert</p>",
		"_active/app/index.html":         "<script>run()</script>",
		"_active/guides/calc/index.html": "<script>calc()</script>",
		"_active/app/extra.html":         "<p>never served</p>",
		"s.css":                          "body{}",
		"p.png":                          "\x89PNG\r\n\x1a\nrest",
		"x.js":                           "alert(1)", // never passes the check; the server must not serve it either
		"_kit/m.js":                      "/* the kit's */",
		"feed.xml":                       "<rss/>",
		"robots.txt":                     "User-agent: *\n",
		".hidden.html":                   "<p>hidden</p>",
		"a/.also-hidden/x":               "x",
	}
	for name, data := range pages {
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
	if err := f.Normalize(w); err != nil {
		t.Fatal(err)
	}
	m := Manifest{Build: 7, SecurityGen: 1, Mermaid: []string{"d/index.html"},
		ScriptHashes: []string{"sha256-AAAA", "sha256-BBBB"}, Scripts: []string{"_kit/m.js"}, Host: "blog.example.com", ContentHost: "content.example.com"}
	if err := f.WriteManifest(w, m); err != nil {
		t.Fatal(err)
	}
	if err := f.WriteManifest(w, m); err == nil {
		t.Fatal("a manifest written twice")
	}
	if _, err := f.Swap(w); err != nil {
		t.Fatal(err)
	}
	if err := f.LinkContent("blog.example.com", "content.example.com"); err != nil {
		t.Fatal(err)
	}
	return Server{Dir: f.Dir}, f
}

func get(s Server, method, host, target string, hdr ...string) *http.Response {
	r := httptest.NewRequest(method, target, nil)
	r.Host = host
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, r)
	return rec.Result()
}

func body(t *testing.T, res *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestTheServerServesPagesWithTheirPolicy(t *testing.T) {
	s, _ := served(t)
	res := get(s, "GET", "blog.example.com", "/")
	if res.StatusCode != 200 || body(t, res) != "<h1>home</h1>" {
		t.Fatalf("home: %d", res.StatusCode)
	}
	h := res.Header
	for k, want := range map[string]string{
		"Content-Type":           "text/html; charset=utf-8",
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "no-referrer",
		"Cache-Control":          "public, max-age=300",
	} {
		if h.Get(k) != want {
			t.Errorf("%s: %q", k, h.Get(k))
		}
	}
	csp := h.Get("Content-Security-Policy")
	if !strings.HasPrefix(csp, "default-src 'none';") || strings.Contains(csp, "script-src") ||
		!strings.Contains(csp, "frame-src 'self' https://content.example.com;") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("a page's policy: %s", csp)
	}
	if h.Get("ETag") == "" {
		t.Error("no ETag")
	}
	// A diagram page names the kit's two scripts; no other page does.
	csp = get(s, "GET", "blog.example.com", "/d/").Header.Get("Content-Security-Policy")
	if !strings.HasSuffix(csp, "; script-src 'sha256-AAAA' 'sha256-BBBB'") {
		t.Errorf("a diagram page's policy: %s", csp)
	}
	if csp := get(s, "GET", "blog.example.com", "/a/").Header.Get("Content-Security-Policy"); strings.Contains(csp, "script-src") {
		t.Errorf("a page with no diagram may run scripts: %s", csp)
	}
	// An inert document is a sandbox.
	if csp := get(s, "GET", "blog.example.com", "/doc/_doc.html").Header.Get("Content-Security-Policy"); !strings.HasPrefix(csp, "sandbox;") {
		t.Errorf("an inert document's policy: %s", csp)
	}
	// The kit's script, named by the manifest, is served as a script; no other is.
	if res := get(s, "GET", "blog.example.com", "/_kit/m.js"); res.StatusCode != 200 || res.Header.Get("Content-Type") != "text/javascript; charset=utf-8" {
		t.Errorf("the kit's script: %d %q", res.StatusCode, res.Header.Get("Content-Type"))
	}
	// Types by the fixed list.
	for target, ctype := range map[string]string{"/s.css": "text/css; charset=utf-8", "/p.png": "image/png", "/feed.xml": "application/xml; charset=utf-8", "/robots.txt": "text/plain; charset=utf-8"} {
		if got := get(s, "GET", "blog.example.com", target).Header.Get("Content-Type"); got != ctype {
			t.Errorf("%s: %q", target, got)
		}
	}
}

func TestTheServerRefusesWhatIsNoPage(t *testing.T) {
	s, _ := served(t)
	cases := map[string]struct {
		method, host, target string
		status               int
	}{
		"a post":                {"POST", "blog.example.com", "/", 405},
		"a put":                 {"PUT", "blog.example.com", "/", 405},
		"the manifest":          {"GET", "blog.example.com", "/" + ManifestName, 404},
		"a hidden page":         {"GET", "blog.example.com", "/.hidden.html", 404},
		"under a hidden folder": {"GET", "blog.example.com", "/a/.also-hidden/x", 404},
		"a script":              {"GET", "blog.example.com", "/x.js", 404},
		"a missing page":        {"GET", "blog.example.com", "/nope/", 404},
		"climbing":              {"GET", "blog.example.com", "/../../../etc/passwd", 404},
		"climbing, encoded":     {"GET", "blog.example.com", "/%2e%2e/%2e%2e/etc/passwd", 404},
		"another site":          {"GET", "other.example.com", "/", 404},
		"a host that climbs":    {"GET", "..", "/", 404},
		"the work directory":    {"GET", ".work", "/", 404},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			res := get(s, tc.method, tc.host, tc.target)
			if res.StatusCode != tc.status {
				t.Fatalf("%d", res.StatusCode)
			}
			if !strings.HasPrefix(res.Header.Get("Content-Security-Policy"), "default-src 'none'") || res.Header.Get("X-Content-Type-Options") != "nosniff" {
				t.Fatalf("a refusal's headers: %v", res.Header)
			}
		})
	}
	if res := get(s, "POST", "blog.example.com", "/"); res.Header.Get("Allow") != "GET, HEAD" {
		t.Errorf("Allow: %q", res.Header.Get("Allow"))
	}
}

func TestTheServerKeepsHTTPsOwnRules(t *testing.T) {
	s, _ := served(t)
	if res := get(s, "GET", "blog.example.com:8443", "/a"); res.StatusCode != 301 || res.Header.Get("Location") != "/a/" {
		t.Errorf("a folder without its slash: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	if res := get(s, "HEAD", "blog.example.com", "/"); res.StatusCode != 200 || body(t, res) != "" || res.Header.Get("Content-Security-Policy") == "" {
		t.Errorf("HEAD: %d", res.StatusCode)
	}
	etag := get(s, "GET", "blog.example.com", "/").Header.Get("ETag")
	if res := get(s, "GET", "blog.example.com", "/", "If-None-Match", etag); res.StatusCode != 304 {
		t.Errorf("a conditional request: %d", res.StatusCode)
	}
	if res := get(s, "GET", "blog.example.com", "/", "Range", "bytes=0-3"); res.StatusCode != 206 || body(t, res) != "<h1>" {
		t.Errorf("a range: %d", res.StatusCode)
	}
}

// Taken down, every path of the site answers 503 at once, the withdrawn pages
// are gone from the disk, and the next build brings it back.
func TestATakenDownSiteAnswers503UntilItsNextBuild(t *testing.T) {
	s, f := served(t)
	if err := f.TakeDown("blog.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := f.TakeDown("blog.example.com"); err != nil {
		t.Fatalf("taken down twice: %v", err)
	}
	for _, target := range []string{"/", "/a/", "/feed.xml", "/p.png", "/nope"} {
		res := get(s, "GET", "blog.example.com", target)
		if res.StatusCode != 503 || res.Header.Get("Retry-After") == "" || res.Header.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: %d %v", target, res.StatusCode, res.Header)
		}
	}
	marker := filepath.Join(f.Dir, downDir, "blog.example.com")
	if entries, err := os.ReadDir(marker); err != nil || len(entries) != 0 {
		t.Fatalf("the withdrawn pages are kept: %v, %v", entries, err)
	}
	if res := get(s, "GET", "other.example.com", "/"); res.StatusCode != 404 {
		t.Errorf("another site: %d", res.StatusCode)
	}
	build(t, f, "blog.example.com", "back")
	if res := get(s, "GET", "blog.example.com", "/"); res.StatusCode != 200 || body(t, res) != "back" {
		t.Fatalf("after the next build: %d", res.StatusCode)
	}
	if _, err := os.Lstat(marker); !os.IsNotExist(err) {
		t.Fatalf("the marker outlived the build: %v", err)
	}
	// A site taken down before its first build is down too; removing it ends that.
	if err := f.TakeDown("new.example.com"); err != nil {
		t.Fatal(err)
	}
	if res := get(s, "GET", "new.example.com", "/"); res.StatusCode != 503 {
		t.Fatalf("a new site taken down: %d", res.StatusCode)
	}
	if err := f.Remove("new.example.com"); err != nil {
		t.Fatal(err)
	}
	if res := get(s, "GET", "new.example.com", "/"); res.StatusCode != 404 {
		t.Fatalf("a removed site: %d", res.StatusCode)
	}
}

// TestTheContentHostServesActiveDocumentsAlone: the content host answers an
// active document at its address under the policy that sandboxes it, and
// nothing else of the site; the site's own host answers none of them; a
// content host the site no longer names stops answering.
func TestTheContentHostServesActiveDocumentsAlone(t *testing.T) {
	s, f := served(t)
	const content, blog = "content.example.com", "blog.example.com"
	for _, target := range []string{"/app/", "/guides/calc/"} {
		res := get(s, "GET", content, target)
		csp := res.Header.Get("Content-Security-Policy")
		if res.StatusCode != 200 || !strings.Contains(body(t, res), "<script>") || !strings.HasPrefix(csp, "sandbox allow-scripts; default-src 'none'") ||
			strings.Contains(csp, "allow-same-origin") || !strings.HasPrefix(res.Header.Get("Content-Type"), "text/html") {
			t.Fatalf("%s: %d %q", target, res.StatusCode, csp)
		}
		if res.Header.Get("Set-Cookie") != "" || res.Header.Get("Access-Control-Allow-Origin") != "" || res.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("%s: headers %v", target, res.Header)
		}
	}
	if res := get(s, "GET", content, "/app"); res.StatusCode != http.StatusMovedPermanently || res.Header.Get("Location") != "/app/" {
		t.Fatalf("without its slash: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	for _, target := range []string{"/", "/a/", "/index.html", "/app/extra.html", "/app/index.html", "/guides/", "/s.css", "/_kit/m.js",
		"/doc/_doc.html", "/_active/app/", "/app/../a/", "/.site.json", "/nothere/"} {
		if res := get(s, "GET", content, target); res.StatusCode != http.StatusNotFound {
			t.Errorf("the content host answers %s: %d", target, res.StatusCode)
		}
	}
	for _, target := range []string{"/_active/app/", "/_active/app/index.html", "/_active/", "/_active"} {
		if res := get(s, "GET", blog, target); res.StatusCode != http.StatusNotFound {
			t.Errorf("the site's host answers %s: %d", target, res.StatusCode)
		}
	}
	if res := get(s, "POST", content, "/app/"); res.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("a POST: %d", res.StatusCode)
	}

	// Taken down with its site.
	if err := f.TakeDown(blog); err != nil {
		t.Fatal(err)
	}
	if res := get(s, "GET", content, "/app/"); res.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("the content host of a site taken down: %d", res.StatusCode)
	}
}

// TestAContentHostIsALinkToItsSite: one link a site; a new name replaces the
// old; a site's own pages are never replaced by a link; removing the site
// removes it.
func TestAContentHostIsALinkToItsSite(t *testing.T) {
	s, f := served(t)
	const blog = "blog.example.com"
	if err := f.LinkContent(blog, "content.example.com"); err != nil { // again: nothing to do
		t.Fatal(err)
	}
	if err := f.LinkContent(blog, "files.example.com"); err != nil {
		t.Fatal(err)
	}
	if res := get(s, "GET", "content.example.com", "/app/"); res.StatusCode != http.StatusNotFound {
		t.Errorf("the old content host: %d", res.StatusCode)
	}
	// The manifest still names the old one until the next build: the new name
	// answers nothing before it.
	if res := get(s, "GET", "files.example.com", "/app/"); res.StatusCode != http.StatusNotFound {
		t.Errorf("a content host the build does not name: %d", res.StatusCode)
	}
	if err := f.LinkContent(blog, blog); err == nil {
		t.Error("a site as its own content host")
	}
	if err := f.LinkContent("other.example.com", blog); err == nil {
		t.Error("a link over a site's pages")
	}
	if err := f.LinkContent(blog, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(f.Dir, "files.example.com")); err == nil {
		t.Error("the link stayed")
	}
	if err := f.LinkContent(blog, "content.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := f.Remove(blog); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(f.Dir, "content.example.com")); err == nil {
		t.Error("a removed site's content host stayed")
	}
}
