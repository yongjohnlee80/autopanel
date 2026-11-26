package site

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"image/color"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	chartvl "github.com/yongjohnlee80/golib/chart/vegalite"
)

const (
	kitMermaid      = "/_kit/mermaid.12.1.0.js"
	kitMermaidSRI   = "sha256-AAAA"
	kitStart        = "/_kit/mermaid-start.js"
	kitStartSRI     = "sha256-BBBB"
	pngBytes        = "\x89PNG\r\n\x1a\nrest"
	pageHead        = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>T</title><meta name="description" content="d"><meta property="og:url" content="https://example.org/a/"><link rel="stylesheet" href="/_astro/site.css"><link rel="canonical" href="https://example.org/a/"><link rel="alternate" type="application/rss+xml" href="/feed.xml"><link rel="icon" href="/favicon.png"></head><body>`
	pageTail        = `</body></html>`
	scriptMermaid   = `<script src="/_kit/mermaid.12.1.0.js" integrity="sha256-AAAA" defer></script>`
	scriptStart     = `<script src="/_kit/mermaid-start.js" integrity="sha256-BBBB" defer></script>`
	contentHostName = "content.example.org"
	activeDoc       = `<html><body><script>document.body.textContent = "hi"</script><form><input></form></body></html>`
)

var activeSum = func() string { s := sha256.Sum256([]byte(activeDoc)); return hex.EncodeToString(s[:]) }()

func page(body string) string { return pageHead + body + pageTail }

// site writes a build's output: the files, by path.
func site(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, data := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func options(mermaidPages ...string) CheckOptions {
	return CheckOptions{
		Mermaid: func(p string) bool {
			for _, m := range mermaidPages {
				if m == p {
					return true
				}
			}
			return false
		},
		KitScripts:  []KitScript{{kitMermaid, kitMermaidSRI}, {kitStart, kitStartSRI}},
		ContentHost: contentHostName,
	}
}

// goodOptions are what the core knows of goodSite: its diagram page and its
// active document.
func goodOptions() CheckOptions {
	opt := options("a/index.html")
	opt.Active = map[string]string{"active": activeSum}
	return opt
}

// A good site: what the kit makes, with a chart, prose about markup, a feed,
// a sitemap and a diagram page.
func goodSite() map[string]string {
	return map[string]string{
		"index.html": page(`<article><h1>Hello</h1><time datetime="2026-11-21">today</time>` +
			`<p>Writing about &lt;script&gt; and onload= in prose is fine, as is <code>&lt;img onerror=x&gt;</code>.</p>` +
			`<pre><code class="language-go"><span class="hl-k">func</span> main() {}</code></pre>` +
			`<a href="/about/">About</a> <a href="https://example.com/x?y#z">out</a> <a href="mailto:a@example.org">mail</a> <a href="#top">top</a>` +
			`<img src="photo.png" alt="p" srcset="photo.png 1x, /a/photo.png 2x" width="10" height="10">` +
			`<picture><source srcset="/a/photo.webp" type="image/webp"><img src="/a/photo.png" alt=""></picture>` +
			`<pre class="mermaid">graph TD; A--&gt;B</pre>` +
			`<ul><li><input disabled="" type="checkbox"> to do</li><li><input checked="" disabled="" type="checkbox"> done</li></ul>` +
			`<img src="./https:/x/photo.png" alt="a folder named like a scheme">` +
			`<table><tr><td align="left">a</td></tr><tr><td colspan="1">… 1200 more rows</td></tr></table>` +
			`</article>`),
		"https:/x/photo.png":        pngBytes,
		"a/index.html":              page(`<pre class="mermaid">graph TD; A--&gt;B</pre>` + scriptMermaid + scriptStart),
		"a/photo.png":               pngBytes,
		"a/photo.webp":              "RIFF\x00\x00\x00\x00WEBPVP8 ",
		"photo.png":                 pngBytes,
		"favicon.png":               pngBytes,
		"_astro/site.css":           `/* the kit */ :root{--accent:#0b6e4f} body{font-family:serif;background:url(/_astro/bg.png) no-repeat} @font-face{font-family:K;src:url("/_astro/k.woff2") format("woff2")} a::after{content:"url(http://x)"}`,
		"_astro/bg.png":             pngBytes,
		"_astro/k.woff2":            "wOF2rest",
		"robots.txt":                "User-agent: *\nAllow: /\n",
		"feed.xml":                  `<?xml version="1.0" encoding="UTF-8"?><rss version="2.0" xmlns:dc="http://purl.org/dc/elements/1.1/"><channel><title>T</title><link>https://example.org/</link><description>&lt;p&gt;d&lt;/p&gt;</description><item><title>A</title><link>https://example.org/a/</link><guid>https://example.org/a/</guid><pubDate>Sat, 21 Nov 2026 00:00:00 GMT</pubDate><dc:creator>me</dc:creator></item></channel></rss>`,
		"sitemap.xml":               `<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://example.org/</loc><lastmod>2026-11-21</lastmod></url></urlset>`,
		"doc/index.html":            page(`<iframe src="_doc.html" sandbox="" title="the document" loading="lazy"></iframe>`),
		"doc/_doc.html":             `<!doctype html><html><head><style>p{color:red} .x{background:url(img.png)}</style></head><body><p style="margin:0">inert</p></body></html>`,
		"active/index.html":         page(`<iframe src="https://content.example.org/active/" sandbox="allow-scripts" title="t"></iframe>`),
		"_active/active/index.html": activeDoc,
	}
}

func TestAGoodSitePasses(t *testing.T) {
	rep, err := CheckOutput(site(t, goodSite()), goodOptions())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Pages != 5 || rep.Files != len(goodSite()) {
		t.Fatalf("report %+v", rep)
	}
}

// Every chart golib's writer draws passes inside a page: the allowlist is
// what that writer emits (testdata/charts).
func TestGolibsChartsPass(t *testing.T) {
	charts, _ := filepath.Glob("testdata/charts/*.svg")
	if len(charts) < 10 {
		t.Fatalf("%d chart fixtures", len(charts))
	}
	for _, c := range charts {
		svg, err := os.ReadFile(c)
		if err != nil {
			t.Fatal(err)
		}
		files := map[string]string{"index.html": page(`<div class="embed chart">` + string(svg) + `</div>`)}
		if _, err := CheckOutput(site(t, files), options()); err != nil {
			t.Errorf("%s: %v", c, err)
		}
	}
}

// Every chart the renderer draws (golib's chart/vegalite, which the site
// kit uses: no GUI, no fonts) passes inside a page, for every fixture spec.
func TestTheRenderersChartsPass(t *testing.T) {
	specs, _ := filepath.Glob("testdata/charts/gen/specs/*.json")
	if len(specs) < 10 {
		t.Fatalf("%d chart specs", len(specs))
	}
	drawn := 0
	for _, f := range specs {
		spec, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		laid, err := chartvl.Lay(context.Background(), string(spec), 640, chartvl.Theme{
			Background: color.NRGBA{246, 242, 231, 255}, Text: color.NRGBA{46, 42, 36, 255},
			Axis: color.NRGBA{122, 113, 99, 255}, Grid: color.NRGBA{179, 170, 150, 255},
		}, nil)
		if err != nil {
			continue // outside the writer's subset: the renderer leaves the spec as its source
		}
		drawn++
		files := map[string]string{"index.html": page(`<div class="embed chart">` + string(laid.SVG()) + `</div>`)}
		if _, err := CheckOutput(site(t, files), options()); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
	if drawn < 8 {
		t.Fatalf("only %d of %d specs drawn", drawn, len(specs))
	}
}

// The SVG the writer could also draw on its canvas (clips, gradients, plain
// shapes) passes; an <image> does not.
func TestTheCanvasRepertoirePasses(t *testing.T) {
	svg := `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10" width="10" height="10"><defs><clipPath id="c1"><rect x="0" y="0" width="5" height="5"/></clipPath><linearGradient id="g1" gradientUnits="userSpaceOnUse" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#000" stop-opacity="0.5"/><stop offset="1" stop-color="#fff"/></linearGradient></defs><g clip-path="url(#c1)"><g transform="translate(1 2) matrix(1 0 0 1 0 0)" opacity="0.5"><rect x="0" y="0" width="1" height="1" rx="1" ry="1" fill="url(#g1)"/><ellipse cx="1" cy="1" rx="1" ry="1" fill="#123456" fill-opacity="0.2"/><circle cx="1" cy="1" r="1"/><line x1="0" y1="0" x2="1" y2="1" stroke="#000"/><polygon points="0,0 1,1 0,1"/><polyline points="0,0 1,1"/><text x="1" y="1" xml:space="preserve" font-family="serif" font-size="10" font-style="italic">a &lt;b&gt;</text></g></g></svg>`
	if _, err := CheckOutput(site(t, map[string]string{"index.html": page(svg)}), options()); err != nil {
		t.Fatal(err)
	}
}

func TestHostilePagesAreRefused(t *testing.T) {
	cases := map[string]string{
		"a script":                             `<script>alert(1)</script>`,
		"a script by src":                      `<script src="/x.js"></script>`,
		"an event attribute":                   `<img src="a.png" onerror="alert(1)">`,
		"an event attribute, upper case":       `<IMG SRC="a.png" ONERROR="alert(1)">`,
		"a style attribute":                    `<p style="color:red">x</p>`,
		"a style element":                      `<style>p{}</style>`,
		"a frame without a sandbox":            `<iframe src="_doc.html"></iframe>`,
		"the inert frame allowing scripts":     `<iframe src="_doc.html" sandbox="allow-scripts"></iframe>`,
		"the inert frame same-origin":          `<iframe src="_doc.html" sandbox="allow-same-origin"></iframe>`,
		"a frame of another host":              `<iframe src="https://evil.example/" sandbox=""></iframe>`,
		"the content host, same-origin":        `<iframe src="https://content.example.org/" sandbox="allow-scripts allow-same-origin"></iframe>`,
		"the content host, no active document": `<iframe src="https://content.example.org/d/1/" sandbox="allow-scripts"></iframe>`,
		"the content host, a query":            `<iframe src="https://content.example.org/active/?x=1" sandbox="allow-scripts"></iframe>`,
		"the content host, another path":       `<iframe src="https://content.example.org/active/x/" sandbox="allow-scripts"></iframe>`,
		"a frame with srcdoc":                  `<iframe srcdoc="&lt;script&gt;x&lt;/script&gt;" sandbox=""></iframe>`,
		"a frame of a missing document":        `<iframe src="nothere/_doc.html" sandbox=""></iframe>`,
		"a form":                               `<form action="/x"><button>go</button></form>`,
		"an input":                             `<input type="image" src="https://evil.example/x.png">`,
		"a checkbox that is enabled":           `<input type="checkbox">`,
		"a disabled text input":                `<input type="text" disabled>`,
		"a checkbox with a form":               `<input type="checkbox" disabled form="f">`,
		"a checkbox with an event":             `<input type="checkbox" disabled onclick="x()">`,
		"a formaction":                         `<button formaction="https://evil.example/">x</button>`,
		"a base":                               `<base href="https://evil.example/">`,
		"a refresh":                            `<meta http-equiv="refresh" content="0;url=https://evil.example/">`,
		"a policy of the page's own":           `<meta http-equiv="Content-Security-Policy" content="default-src *">`,
		"a preconnect":                         `<link rel="preconnect" href="https://evil.example/">`,
		"a remote stylesheet":                  `<link rel="stylesheet" href="https://evil.example/x.css">`,
		"a protocol-relative stylesheet":       `<link rel="stylesheet" href="//evil.example/x.css">`,
		"a remote image":                       `<img src="https://evil.example/x.png">`,
		"a protocol-relative image":            `<img src="//evil.example/x.png">`,
		"a backslash image":                    `<img src="\\evil.example\x.png">`,
		"a data image":                         `<img src="data:image/png;base64,AAAA">`,
		"a remote srcset":                      `<img src="a.png" srcset="a.png 1x, https://evil.example/b.png 2x">`,
		"a javascript link":                    `<a href="javascript:alert(1)">x</a>`,
		"a javascript link, encoded":           `<a href="&#106;avascript:alert(1)">x</a>`,
		"a javascript link, tabbed":            "<a href=\"java\tscript:alert(1)\">x</a>",
		"a javascript link, spaced":            `<a href="  JavaScript:alert(1)">x</a>`,
		"a data link":                          `<a href="data:text/html,x">x</a>`,
		"a ping":                               `<a href="/x" ping="https://evil.example/">x</a>`,
		"an object":                            `<object data="x.swf"></object>`,
		"an embed":                             `<embed src="x.swf">`,
		"a template":                           `<template><script>x</script></template>`,
		"a noscript":                           `<noscript><img src="https://evil.example/t.png"></noscript>`,
		"a video":                              `<video src="/v.mp4"></video>`,
		"MathML":                               `<math><mi>x</mi></math>`,
		"an SVG script":                        `<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`,
		"an SVG foreignObject":                 `<svg><foreignObject><p>x</p></foreignObject></svg>`,
		"an SVG use":                           `<svg><use href="#a"/></svg>`,
		"an SVG image":                         `<svg><image href="x.png" width="1" height="1"/></svg>`,
		"an SVG link":                          `<svg><a href="https://evil.example/"><text>x</text></a></svg>`,
		"an SVG event":                         `<svg onload="alert(1)"></svg>`,
		"an SVG style":                         `<svg><style>*{}</style></svg>`,
		"an SVG animation":                     `<svg><rect><set attributeName="x" to="1"/></rect></svg>`,
		"an SVG remote fill":                   `<svg><rect fill="url(https://evil.example/#g)"/></svg>`,
		"an SVG title":                         `<svg><title>t</title></svg>`,
		"an SVG xlink":                         `<svg><rect xlink:href="#a"/></svg>`,
		"an SVG of another namespace":          `<svg xmlns="http://evil.example/ns"></svg>`,
		"a style attribute in an SVG":          `<svg><rect style="fill:red"/></svg>`,
		"a diagram script off its page":        scriptMermaid,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			files := map[string]string{"index.html": page(body), "a.png": pngBytes, "_doc.html": "<p>x</p>"}
			_, err := CheckOutput(site(t, files), options())
			var oe *OutputError
			if !errors.As(err, &oe) || !errors.Is(err, ErrOutput) || oe.Path != "index.html" {
				t.Fatalf("passed or refused for something else: %v", err)
			}
		})
	}
}

// A diagram page may load the kit's two scripts, exactly as the kit ships
// them, once each, and nothing else.
func TestADiagramPageMayLoadOnlyTheKitsScripts(t *testing.T) {
	cases := map[string]string{
		"another script":         `<script src="/_kit/other.js" integrity="sha256-AAAA" defer></script>`,
		"the wrong integrity":    `<script src="/_kit/mermaid.12.1.0.js" integrity="sha256-ZZZZ" defer></script>`,
		"no integrity":           `<script src="/_kit/mermaid.12.1.0.js" defer></script>`,
		"not deferred":           `<script src="/_kit/mermaid.12.1.0.js" integrity="sha256-AAAA"></script>`,
		"a type":                 `<script type="module" src="/_kit/mermaid.12.1.0.js" integrity="sha256-AAAA" defer></script>`,
		"text of its own":        `<script src="/_kit/mermaid.12.1.0.js" integrity="sha256-AAAA" defer>alert(1)</script>`,
		"inline":                 `<script>mermaid.initialize({securityLevel:"loose"})</script>`,
		"one of the kit's twice": scriptMermaid + scriptMermaid,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := CheckOutput(site(t, map[string]string{"index.html": page(body)}), options("index.html"))
			if !errors.Is(err, ErrOutput) {
				t.Fatalf("passed: %v", err)
			}
		})
	}
}

func TestHostileStylesheetsAreRefused(t *testing.T) {
	cases := map[string]string{
		"an import":               `@import url(/a.css);`,
		"an import, escaped":      `@\69mport "/a.css";`,
		"an import, upper case":   `@IMPORT "/a.css";`,
		"a remote url":            `body{background:url(https://evil.example/x.png)}`,
		"a quoted remote url":     `body{background:url("https://evil.example/x.png")}`,
		"a protocol-relative url": `body{background:url(//evil.example/x.png)}`,
		"an escaped url":          `body{background:u\72l(https://evil.example/x.png)}`,
		"an escaped scheme":       `body{background:url(https\3a //evil.example/x.png)}`,
		"a data url":              `body{background:url(data:image/png;base64,AAAA)}`,
		"an image-set":            `body{background:image-set("https://evil.example/x.png" 1x)}`,
		"an expression":           `body{width:expression(alert(1))}`,
		"a binding":               `body{-moz-binding:url(/x.xml#x)}`,
		"a remote font":           `@font-face{font-family:x;src:url(https://evil.example/f.woff2)}`,
	}
	for name, css := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := CheckOutput(site(t, map[string]string{"s.css": css}), options())
			if !errors.Is(err, ErrOutput) {
				t.Fatalf("passed: %v", err)
			}
		})
	}
	// and inside an inert document's own styles
	files := map[string]string{"_doc.html": `<p style="background:url(https://evil.example/x)">x</p>`}
	if _, err := CheckOutput(site(t, files), options()); !errors.Is(err, ErrOutput) {
		t.Fatalf("an inert document's remote style passed: %v", err)
	}
}

func TestFeedsAndSitemapsHoldOnlyTheirFormats(t *testing.T) {
	cases := map[string]string{
		"a stylesheet":         `<?xml version="1.0"?><?xml-stylesheet href="https://evil.example/x.xsl"?><rss/>`,
		"a document type":      `<?xml version="1.0"?><!DOCTYPE rss [<!ENTITY a "aaaa">]><rss>&a;</rss>`,
		"a bare document type": `<?xml version="1.0"?><!DOCTYPE rss><rss/>`,
		"XHTML in a feed":      `<rss><channel><script xmlns="http://www.w3.org/1999/xhtml">x</script></channel></rss>`,
		"an unknown element":   `<rss><channel><thing/></channel></rss>`,
		"not well formed":      `<rss><channel></rss>`,
	}
	for name, x := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := CheckOutput(site(t, map[string]string{"feed.xml": x}), options())
			if !errors.Is(err, ErrOutput) {
				t.Fatalf("passed: %v", err)
			}
		})
	}
}

func TestHiddenNamesAreRefusedByName(t *testing.T) {
	for _, name := range []string{".hidden.txt", "a/.b.css", ".well-known/x.txt"} {
		_, err := CheckOutput(site(t, map[string]string{name: "x"}), options())
		var oe *OutputError
		if !errors.As(err, &oe) || oe.Reason != "a hidden name" {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestOnlyTheTypesASiteServesPass(t *testing.T) {
	cases := map[string]string{
		"x.js":        "alert(1)",
		"x.svg":       `<svg xmlns="http://www.w3.org/2000/svg"/>`,
		"x.json":      "{}",
		"x.htm":       "<p>x</p>",
		"x.xhtml":     "<p>x</p>",
		"x.png":       "<html>not an image</html>",
		"x.woff2":     "<html>not a font</html>",
		"x.txt":       "\xff\xfe not UTF-8",
		"noext":       "x",
		".htaccess":   "x",
		"a/.hidden":   "x",
		".hidden.txt": "x",
		"a/.b.css":    "p{}",
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := CheckOutput(site(t, map[string]string{name: data}), options())
			if !errors.Is(err, ErrOutput) {
				t.Fatalf("passed: %v", err)
			}
		})
	}
}

// A link, a pipe or a socket fails the build before any file is read: the
// walk looks at entries without following or opening them.
func TestOnlyPlainFilesAndDirectories(t *testing.T) {
	t.Run("a link to a good file", func(t *testing.T) {
		dir := site(t, map[string]string{"index.html": page("x")})
		if err := os.Symlink("index.html", filepath.Join(dir, "other.html")); err != nil {
			t.Fatal(err)
		}
		refusedByTheWalk(t, dir)
	})
	t.Run("a link out of the output", func(t *testing.T) {
		dir := site(t, map[string]string{"index.html": page("x")})
		if err := os.Symlink("/etc", filepath.Join(dir, "etc")); err != nil {
			t.Fatal(err)
		}
		refusedByTheWalk(t, dir)
	})
	t.Run("a pipe, which reading would wait on", func(t *testing.T) {
		dir := site(t, map[string]string{"index.html": page("x")})
		if err := syscall.Mkfifo(filepath.Join(dir, "a.txt"), 0o644); err != nil {
			t.Fatal(err)
		}
		refusedByTheWalk(t, dir)
	})
}

// refusedByTheWalk: the build is refused by the walk, which only looks at
// entries, not later when a file is read.
func refusedByTheWalk(t *testing.T, dir string) {
	t.Helper()
	_, err := CheckOutput(dir, options())
	var oe *OutputError
	if !errors.As(err, &oe) || !strings.HasPrefix(oe.Reason, "not a plain file or directory") {
		t.Fatalf("not refused by the walk: %v", err)
	}
}

func TestTheOutputIsBounded(t *testing.T) {
	t.Run("the site's total", func(t *testing.T) {
		files := map[string]string{"a.txt": strings.Repeat("a", 600), "b.txt": strings.Repeat("b", 600)}
		opt := options()
		opt.MaxBytes = 1000
		if _, err := CheckOutput(site(t, files), opt); !errors.Is(err, ErrOutput) {
			t.Fatalf("passed: %v", err)
		}
	})
	t.Run("depth", func(t *testing.T) {
		deep := strings.Repeat("d/", checkMaxDepth+2) + "a.txt"
		if _, err := CheckOutput(site(t, map[string]string{deep: "x"}), options()); !errors.Is(err, ErrOutput) {
			t.Fatalf("passed: %v", err)
		}
	})
	t.Run("one file", func(t *testing.T) {
		dir := site(t, nil)
		f, err := os.Create(filepath.Join(dir, "big.txt"))
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Truncate(checkMaxFile + 1); err != nil {
			t.Fatal(err)
		}
		f.Close()
		if _, err := CheckOutput(dir, options()); !errors.Is(err, ErrOutput) {
			t.Fatalf("passed: %v", err)
		}
	})
}

// The address rules, apart from any page.
func TestAddresses(t *testing.T) {
	local := []string{"a.png", "/a.png", "./a.png", "../a.png", "a/b:c.png", "#x", "?q=1", "/a?b=c:d"}
	notLocal := []string{"", "https://x/a.png", "//x/a.png", "\\\\x\\a.png", "/\\x", "data:x", "javascript:x", "JAVASCRIPT:x", " java\nscript:x", "x:y"}
	for _, u := range local {
		if !localURL(u) {
			t.Errorf("%q is a path of the site", u)
		}
	}
	for _, u := range notLocal {
		if localURL(u) {
			t.Errorf("%q is not a path of the site", u)
		}
	}
	nav := []string{"https://x/", "http://x/", "mailto:a@b", "/a/", "#top", ""}
	notNav := []string{"javascript:x", "data:x", "vbscript:x", "file:///etc/passwd", "ftp://x/", "tel:1"}
	for _, u := range nav {
		if !navigableURL(u) {
			t.Errorf("%q may be gone to", u)
		}
	}
	for _, u := range notNav {
		if navigableURL(u) {
			t.Errorf("%q may not be gone to", u)
		}
	}
}

// The kit's own scripts pass at their paths, with the bytes their integrity
// names; any other script, or the kit's altered or moved, fails the build.
func TestOnlyTheKitsScriptsPassAsFiles(t *testing.T) {
	script := "/* mermaid */ window.x = 1;\n"
	sum := sha256.Sum256([]byte(script))
	opt := options()
	opt.KitScripts = []KitScript{{Path: "/_kit/mermaid.12.1.0.js", Integrity: "sha256-" + base64.StdEncoding.EncodeToString(sum[:])}}
	if _, err := CheckOutput(site(t, map[string]string{"_kit/mermaid.12.1.0.js": script}), opt); err != nil {
		t.Fatalf("the kit's script: %v", err)
	}
	for name, files := range map[string]map[string]string{
		"altered":        {"_kit/mermaid.12.1.0.js": script + "fetch('//evil.example')"},
		"moved":          {"_kit/other.js": script},
		"another script": {"app.js": "alert(1)"},
		"under a folder": {"a/_kit/mermaid.12.1.0.js": script},
	} {
		if _, err := CheckOutput(site(t, files), opt); !errors.Is(err, ErrOutput) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestActiveDocumentsAreTheCoresOwnBytes: under the active directory a build
// may put only the active documents the core has, as they were published;
// each must be there; and without a content host there is no such directory.
func TestActiveDocumentsAreTheCoresOwnBytes(t *testing.T) {
	change := func(f func(map[string]string)) map[string]string {
		files := goodSite()
		f(files)
		return files
	}
	cases := map[string]map[string]string{
		"an active document changed by the build": change(func(f map[string]string) { f["_active/active/index.html"] = activeDoc + "<script>more()</script>" }),
		"a document the site does not have":       change(func(f map[string]string) { f["_active/other/index.html"] = activeDoc }),
		"another file beside it":                  change(func(f map[string]string) { f["_active/active/extra.html"] = activeDoc }),
		"a script beside it":                      change(func(f map[string]string) { f["_active/active/x.js"] = "x()" }),
		"a file at the top":                       change(func(f map[string]string) { f["_active/index.html"] = activeDoc }),
		"an active document not built":            change(func(f map[string]string) { delete(f, "_active/active/index.html") }),
	}
	for name, files := range cases {
		if _, err := CheckOutput(site(t, files), goodOptions()); !errors.Is(err, ErrOutput) {
			t.Errorf("%s: %v", name, err)
		}
	}
	opt := goodOptions()
	opt.ContentHost = ""
	files := goodSite()
	delete(files, "active/index.html")
	if _, err := CheckOutput(site(t, files), opt); !errors.Is(err, ErrOutput) {
		t.Errorf("an active document with no content host: %v", err)
	}
}
