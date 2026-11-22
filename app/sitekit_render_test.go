package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	coresite "github.com/yongjohnlee80/autopanel/core/site"
)

const renderDoc = "# Install\n\nRun `make`, then see [the guide](../guide/) and [the source](https://example.org/x).\n\n" +
	"[a trap](javascript:alert(1)) and [another](data:text/html,x) and [a third](//evil.example.net/)\n\n" +
	"<script>alert(1)</script> and <img src=x onerror=alert(1)>\n\n" +
	"- [x] done\n- [ ] not yet\n\n" +
	"| a | b |\n|---|---|\n| 1 | 2 |\n\n" +
	"```go\nfunc main() {}\n```\n\n" +
	"![the flow](img/flow.png)\n\n" +
	"```vega-lite\n{\"data\":{\"values\":[{\"a\":\"x\",\"b\":1},{\"a\":\"y\",\"b\":3}]},\"mark\":\"bar\",\"encoding\":{\"x\":{\"field\":\"a\",\"type\":\"nominal\"},\"y\":{\"field\":\"b\",\"type\":\"quantitative\"}}}\n```\n"

// renderKit writes a build's input of one document and renders it.
func renderKit(t *testing.T, source string) (string, error) {
	t.Helper()
	base := t.TempDir()
	p := kitPaths{Content: filepath.Join(base, "input"), Fragments: filepath.Join(base, "fragments")}
	dir := filepath.Join(p.Content, "docs", "1")
	if err := os.MkdirAll(filepath.Join(dir, "img"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.md"), []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "img", "flow.png"), []byte("\x89PNG\r\n\x1a\n"), 0o644)
	in := coresite.BuildInput{Build: 1, Host: "blog.example.com", Docs: []coresite.InputDoc{{Slug: "install", Path: "guides/install", Folder: "guides",
		Format: coresite.Markdown, Source: "docs/1/index.md", Dir: "docs/1", Page: "guides/install/index.html"}}}
	raw, _ := json.Marshal(in)
	if err := os.WriteFile(filepath.Join(p.Content, "build.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := renderFragments(p); err != nil {
		return "", err
	}
	b, err := os.ReadFile(filepath.Join(p.Fragments, "guides", "install.html"))
	return string(b), err
}

// TestTheBodyIsRenderedAndPassesTheCheck: Markdown becomes markup, with a
// chart as inline SVG; no script and no link of a kind the site refuses
// survives; and the page around it passes the core's output check.
func TestTheBodyIsRenderedAndPassesTheCheck(t *testing.T) {
	body, err := renderKit(t, renderDoc)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"<h1", "Install</h1>", "<code>make</code>", `href="../guide/"`, `href="https://example.org/x"`,
		"<table", `type="checkbox"`, `src="img/flow.png"`, "<svg", "&lt;script&gt;"} {
		if !strings.Contains(body, want) {
			t.Errorf("the body lacks %q", want)
		}
	}
	for _, bad := range []string{"<script", "javascript:", "data:text", "//evil.example.net", "<img src=x", `<img src="x"`} {
		if strings.Contains(body, bad) {
			t.Errorf("the body holds %q", bad)
		}
	}
	out := t.TempDir()
	page := "<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>Install</title></head><body>" + body + "</body></html>\n"
	if err := os.MkdirAll(filepath.Join(out, "guides", "install", "img"), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(out, "guides", "install", "index.html"), []byte(page), 0o644)
	_ = os.WriteFile(filepath.Join(out, "guides", "install", "img", "flow.png"), []byte("\x89PNG\r\n\x1a\n"), 0o644)
	if _, err := coresite.CheckOutput(out, coresite.CheckOptions{MaxBytes: 64 << 20}); err != nil {
		t.Fatalf("the rendered page fails the output check: %v", err)
	}
}

// TestTheRendersBounds: too many diagrams, or one too large, refuse the
// build, which says which document.
func TestTheRendersBounds(t *testing.T) {
	if _, err := renderKit(t, strings.Repeat("```mermaid\ngraph TD; A-->B\n```\n\n", maxDiagrams+1)); err == nil || !strings.Contains(err.Error(), "guides/install") {
		t.Fatalf("too many diagrams: %v", err)
	}
	if _, err := renderKit(t, "```mermaid\ngraph TD;\n"+strings.Repeat("A-->B\n", maxDiagramSource/6+1)+"```\n"); err == nil {
		t.Fatal("a diagram over its bound was rendered")
	}
	if _, err := chartSVG(make([]byte, maxChartSpec+1), renderTheme); err == nil {
		t.Fatal("a chart spec over its bound was drawn")
	}
}

func TestTheSitesLinkRule(t *testing.T) {
	for href, want := range map[string]bool{
		"#top": true, "img/a.png": true, "../guide/": true, "/blog/": true, "https://example.org/": true, "http://example.org": true,
		"mailto:a@example.org": true, "javascript:alert(1)": false, "JavaScript:alert(1)": false, "data:image/png;base64,x": false,
		"//evil.example.net/x": false, "vbscript:x": false, "file:///etc/passwd": false, "a\\b": false, "": false, "a\x00b": false,
	} {
		if _, ok := siteLink(href); ok != want {
			t.Errorf("siteLink(%q) = %v", href, ok)
		}
	}
}

// TestAnHTMLDocumentStaysItsSource: no markup of an HTML document reaches the
// page yet.
func TestAnHTMLDocumentStaysItsSource(t *testing.T) {
	b, err := renderBody(coresite.HTML, []byte("<p onclick=x>hi</p>"), "")
	if err != nil || strings.Contains(b, "<p>") || strings.Contains(b, "<p ") || !strings.Contains(b, "&lt;p onclick=x&gt;") {
		t.Fatalf("%q, %v", b, err)
	}
}
