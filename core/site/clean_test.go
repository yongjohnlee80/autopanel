package site

import (
	"strings"
	"testing"
)

// A document that tries everything the copy must not keep.
const hostileDoc = `<!DOCTYPE html><html lang="en-GB"><head><title>  A
 report </title>
<meta http-equiv="refresh" content="0;url=https://evil.example/"><base href="https://evil.example/">
<link rel="stylesheet" href="https://evil.example/x.css">
<style>p{color:red} .hero{background:url(hero.png)}</style>
<style>@import url(https://evil.example/x.css);</style>
<style>body{background:url(https://evil.example/track.png)}</style>
<script>alert(1)</script></head>
<body class="report" onload="alert(2)" style="margin:0">
<h1 id="top" onclick="alert(3)">Title</h1>
<p style="color:blue" data-x="1">Text <b>bold</b> <a href="#top">up</a> <a href="https://example.com/a">out</a>
<a href="javascript:alert(4)">js</a> <a href="/other/" title="mine">site</a></p>
<p style="background:url(https://evil.example/p.png)">styled</p>
<img src="chart.png" alt="chart" onerror="alert(5)" width="10"><img src="https://evil.example/t.gif"><img src="data:image/png;base64,AAAA">
<form action="https://evil.example/post"><input name="q"><button>Send</button><p>inside the form</p></form>
<iframe src="https://evil.example/"></iframe><object data="x.swf"></object><embed src="x.swf">
<svg onload="alert(6)"><script>alert(7)</script><text>svg text</text></svg><math><mtext>math</mtext></math>
<video src="v.mp4"></video><audio src="a.mp3"></audio>
<custom-thing onfoo="x"><em>kept inside an unknown element</em></custom-thing>
<table><tr><td colspan="2" bgcolor="red">cell</td></tr></table>
<details open><summary>More</summary><template><p>templated</p></template></details>
<noscript><img src="https://evil.example/ns.gif"></noscript>
</body></html>`

// TestTheInertCopyKeepsNothingThatActs cleans the hostile document: what
// acts is gone, what reads is kept, and the output check passes the copy as
// the page it is built as.
func TestTheInertCopyKeepsNothingThatActs(t *testing.T) {
	out, title, err := CleanHTML([]byte(hostileDoc))
	if err != nil {
		t.Fatal(err)
	}
	if title != "A report" {
		t.Errorf("title = %q", title)
	}
	got := string(out)
	for _, gone := range []string{"script", "alert(", "evil.example", "onload", "onclick", "onerror", "onfoo", "javascript:",
		"http-equiv", "<base", "<link", "<form", "<input", "<button", "<iframe", "<object", "<embed", "<svg", "<math",
		"svg text", "<video", "<audio", "custom-thing", "bgcolor", "data-x", "data:image", "@import", "templated", "<noscript", "<template"} {
		if strings.Contains(got, gone) {
			t.Errorf("the copy still holds %q:\n%s", gone, got)
		}
	}
	for _, kept := range []string{`<html lang="en-GB">`, `<meta charset="utf-8"/>`, `<title>A report</title>`,
		`<style>p{color:red} .hero{background:url(hero.png)}</style>`, `<body class="report" style="margin:0">`,
		`<h1 id="top">Title</h1>`, `<p style="color:blue">`, `<a href="#top">up</a>`,
		`<a title="https://example.com/a">out</a>`, `<a>js</a>`, `<a title="mine">site</a>`, `<p>styled</p>`,
		`<img src="chart.png" alt="chart" width="10"/>`, `<p>inside the form</p>`,
		`<em>kept inside an unknown element</em>`, `<td colspan="2">cell</td>`, `<details open=""><summary>More</summary></details>`} {
		if !strings.Contains(got, kept) {
			t.Errorf("the copy lacks %q:\n%s", kept, got)
		}
	}
	if n := strings.Count(got, "<img"); n != 1 {
		t.Errorf("%d images kept; want the one of this site", n)
	}

	files := goodSite()
	files["doc/_doc.html"] = got
	files["doc/chart.png"], files["doc/hero.png"] = pngBytes, pngBytes
	if _, err := CheckOutput(site(t, files), options("a/index.html")); err != nil {
		t.Fatalf("the output check refuses the copy: %v", err)
	}
}

// TestTheInertCopyOfAnything: what is no document still makes a page, and a
// document nested deeply is cut, or refused, never followed without end.
func TestTheInertCopyOfAnything(t *testing.T) {
	for name, src := range map[string]string{
		"nothing": "", "text": "just words & <no tags", "a fragment": "<p>one<p>two",
		"not utf-8": "<p>\xff\xfe</p>", "a style that never ends": "<style>p{",
	} {
		out, _, err := CleanHTML([]byte(src))
		if err != nil || !strings.HasPrefix(string(out), "<!DOCTYPE html><html><head>") || !strings.HasSuffix(string(out), "</body></html>") {
			t.Errorf("%s: %q, %v", name, out, err)
		}
	}
	deep := strings.Repeat("<div>", 400) + "bottom" + strings.Repeat("</div>", 400)
	out, _, err := CleanHTML([]byte(deep))
	if err != nil || strings.Contains(string(out), "bottom") || strings.Count(string(out), "<div>") > maxCleanDepth+1 {
		t.Errorf("a deep document: %d bytes, %d divs, %v", len(out), strings.Count(string(out), "<div>"), err)
	}
	if _, _, err := CleanHTML([]byte(strings.Repeat("<div>", 5000))); err == nil {
		t.Error("a document nested past what the parser follows was cleaned")
	}
	long, title, _ := CleanHTML([]byte("<title>" + strings.Repeat("é", 500) + "</title>"))
	if len(title) > maxCleanTitle || !strings.Contains(string(long), "<title>"+title+"</title>") {
		t.Errorf("a long title: %d bytes", len(title))
	}
}
