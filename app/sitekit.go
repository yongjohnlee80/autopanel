package app

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"image/color"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/yongjohnlee80/autodoc/core/export"
	"github.com/yongjohnlee80/autodoc/core/export/mermaid"
	"github.com/yongjohnlee80/golib/chart/vegalite"

	coresite "github.com/yongjohnlee80/autopanel/core/site"
	"github.com/yongjohnlee80/autopanel/internal/hostcmd"
)

// The site kit's container runs autopanel --site-build: it renders each
// document's body into a fragment, then runs Astro, which lays the fragments
// out in the site's theme. It runs in the builder's container, with no
// network; what it writes is checked by the core before anything is served.

// kitPaths are where the container holds what a build reads and writes
// (host/site.Builder's mounts); a test points them elsewhere.
type kitPaths struct {
	Project   string // the kit: package.json, astro.config.mjs, src, node_modules
	Content   string // the core's input, read-only
	Fragments string // the rendered bodies: on the writable scratch
	Out       string // the output, the one place the build writes
	Cache     string // Astro's cache: on the scratch
}

func defaultKitPaths() kitPaths {
	return kitPaths{
		Project:   env("SITE_PROJECT", "/site"),
		Content:   env("SITE_CONTENT", "/input"),
		Fragments: env("SITE_FRAGMENTS", "/tmp/fragments"),
		Out:       env("SITE_OUT", "/site/dist"),
		Cache:     env("SITE_CACHE", "/tmp/astro-cache"),
	}
}

// The render's bounds that are AutoPanel's to keep (Fragment keeps a table's
// and an embed's; docs/decisions/site.md): the rendered body, the diagrams
// and charts one document may ask for, one Mermaid diagram's source, and one
// chart's spec.
const (
	maxFragment      = 4 << 20
	maxDiagrams      = 50
	maxDiagramSource = 64 << 10
	maxChartSpec     = 256 << 10
	chartWidth       = 640
	// renderTheme is the palette a chart is drawn in: the kit's pages are light.
	renderTheme = "light"
)

// siteBuild is autopanel --site-build.
func siteBuild(stdout, stderr io.Writer) int {
	p := defaultKitPaths()
	base, err := buildBase(p)
	if err != nil {
		fmt.Fprintln(stderr, "autopanel --site-build:", err)
		return 1
	}
	if err := renderFragments(p); err != nil {
		fmt.Fprintln(stderr, "autopanel --site-build: rendering:", err)
		return 1
	}
	if err := writeKitIndex(p); err != nil {
		fmt.Fprintln(stderr, "autopanel --site-build: the kit's scripts:", err)
		return 1
	}
	// NAPI_RS_FORCE_WASI: Astro's compiler as WebAssembly; its native build
	// needs AVX2, which older servers lack (see the Containerfile).
	env := []string{"HOME=/tmp", "NODE_ENV=production", "ASTRO_TELEMETRY_DISABLED=1", "NAPI_RS_FORCE_WASI=1",
		"SITE_CONTENT=" + p.Content, "SITE_FRAGMENTS=" + p.Fragments, "SITE_OUT=" + p.Out, "SITE_CACHE=" + p.Cache, "SITE_BASE=" + base}
	if err := hostcmd.Stream(context.Background(), hostcmd.Node, p.Project, env, stdout, stderr,
		filepath.Join(p.Project, "node_modules", "astro", "bin", "astro.mjs"), "build"); err != nil {
		fmt.Fprintln(stderr, "autopanel --site-build: astro:", err)
		return 1
	}
	if err := copyImages(p); err != nil {
		fmt.Fprintln(stderr, "autopanel --site-build: a document's images:", err)
		return 1
	}
	if err := copyInert(p); err != nil {
		fmt.Fprintln(stderr, "autopanel --site-build: an html document's copy:", err)
		return 1
	}
	if err := copyActive(p); err != nil {
		fmt.Fprintln(stderr, "autopanel --site-build: an active html document:", err)
		return 1
	}
	if err := writeKitScripts(p); err != nil {
		fmt.Fprintln(stderr, "autopanel --site-build: the kit's scripts:", err)
		return 1
	}
	// What Astro keeps beside the pages while it builds is not a page: the
	// output check would refuse a hidden name anyway.
	if err := os.RemoveAll(filepath.Join(p.Out, ".prerender")); err != nil {
		fmt.Fprintln(stderr, "autopanel --site-build:", err)
		return 1
	}
	return 0
}

// buildBase is the path a held document's build writes its addresses under
// (build.json's base), "" for the public pages. It is the core's own word,
// and is still held to a path of slugs: nothing else reaches Astro's
// configuration.
func buildBase(p kitPaths) (string, error) {
	raw, err := os.ReadFile(filepath.Join(p.Content, "build.json"))
	if err != nil {
		return "", err
	}
	var in coresite.BuildInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return "", err
	}
	if in.Base == "" {
		return "", nil
	}
	if !strings.HasPrefix(in.Base, "/") || path.Clean(in.Base) != in.Base {
		return "", fmt.Errorf("the build's base %q is no clean path", in.Base)
	}
	for _, part := range strings.Split(in.Base[1:], "/") {
		for _, r := range part {
			if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '-' && r != '.' {
				return "", fmt.Errorf("the build's base %q is no path of slugs", in.Base)
			}
		}
		if part == "" || strings.HasPrefix(part, ".") {
			return "", fmt.Errorf("the build's base %q is no path of slugs", in.Base)
		}
	}
	return in.Base, nil
}

// pageDir is where a document's page is in the output, and so where its
// images and its inert copy go: its address for a public document, the
// output's root for a held one built alone.
func pageDir(d coresite.InputDoc) string { return path.Dir(d.Page) }

// renderFragments writes each document's body, rendered, where the kit reads
// it: <fragments>/<path>.html. A Markdown document (md, xmd) is rendered by
// AutoDoc's Fragment: no page, no inline script, no stylesheet, every URL
// through siteLink, its embeds read from its own files alone. An HTML
// document's body is a frame: of its inert copy, allowing nothing
// (renderInert), or, when it is active, of the document itself on the
// content host, allowing scripts and nothing else (renderActive).
func renderFragments(p kitPaths) error {
	raw, err := os.ReadFile(filepath.Join(p.Content, "build.json"))
	if err != nil {
		return err
	}
	var in coresite.BuildInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return err
	}
	root, err := os.OpenRoot(p.Content)
	if err != nil {
		return err
	}
	defer root.Close()
	for _, d := range in.Docs {
		parts, err := coresite.SplitPath(d.Path)
		if err != nil || len(parts) == 0 {
			return fmt.Errorf("a document's path %q: %v", d.Path, err)
		}
		src, err := root.ReadFile(d.Source)
		if err != nil {
			return fmt.Errorf("%s: %w", d.Path, err)
		}
		var embeds string
		if d.Dir != "" {
			if info, err := root.Stat(d.Dir); err == nil && info.IsDir() {
				embeds = filepath.Join(p.Content, filepath.FromSlash(d.Dir))
			}
		}
		var body string
		switch {
		case d.Format == coresite.HTML && d.Active:
			body, err = renderActive(in.ContentHost, d.Path, src)
		case d.Format == coresite.HTML:
			body, err = renderInert(p, d, src)
		default:
			body, err = renderBody(d.Format, src, embeds)
		}
		if err != nil {
			return fmt.Errorf("%s: %w", d.Path, err)
		}
		if len(body) > maxFragment {
			return fmt.Errorf("%s: its body is larger than %d bytes", d.Path, maxFragment)
		}
		out := filepath.Join(p.Fragments, filepath.FromSlash(d.Path)+".html")
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(out, []byte(body), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// copyImages puts each public document's images beside its page, at the
// names it links them by. A diagram, a chart or a table is the renderer's
// input, not a file the site serves; the output check refuses them.
func copyImages(p kitPaths) error {
	raw, err := os.ReadFile(filepath.Join(p.Content, "build.json"))
	if err != nil {
		return err
	}
	var in coresite.BuildInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return err
	}
	src, err := os.OpenRoot(p.Content)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.OpenRoot(p.Out)
	if err != nil {
		return err
	}
	defer dst.Close()
	for _, d := range in.Docs {
		dir, err := src.OpenRoot(d.Dir)
		if err != nil {
			continue // a document with no files
		}
		err = fs.WalkDir(dir.FS(), ".", func(name string, e fs.DirEntry, err error) error {
			if err != nil || e.IsDir() || !e.Type().IsRegular() {
				return err
			}
			switch strings.ToLower(filepath.Ext(name)) {
			case ".png", ".jpg", ".jpeg", ".webp", ".gif":
			default:
				return nil
			}
			data, err := dir.ReadFile(name)
			if err != nil {
				return err
			}
			to := path.Join(pageDir(d), name)
			if err := dst.MkdirAll(filepath.Dir(to), 0o755); err != nil {
				return err
			}
			return dst.WriteFile(to, data, 0o644)
		})
		dir.Close()
		if err != nil {
			return fmt.Errorf("%s: %w", d.Path, err)
		}
	}
	return nil
}

// The kit's two scripts: Mermaid (vendored in AutoDoc's export, pinned by
// its tarball's integrity) and the start that draws a page's diagrams. They
// are in the binary, so the core that checks a build and the container that
// makes it hold the same bytes: a core and a kit image of different releases
// fail closed, as a script the check does not know.
type kitScript struct {
	coresite.KitScript
	body string
}

func kitScriptFiles() []kitScript {
	return []kitScript{
		{KitScript: coresite.KitScript{Path: "/_kit/mermaid." + mermaid.Version + ".js", Integrity: sri(mermaid.Script())}, body: mermaid.Script()},
		{KitScript: coresite.KitScript{Path: "/_kit/mermaid-start.js", Integrity: sri(export.MermaidStart())}, body: export.MermaidStart()},
	}
}

// KitScripts are the kit's scripts as the output check knows them.
func KitScripts() []coresite.KitScript {
	var out []coresite.KitScript
	for _, k := range kitScriptFiles() {
		out = append(out, k.KitScript)
	}
	return out
}

// sri is a script's integrity: sha256-<base64>.
func sri(body string) string {
	sum := sha256.Sum256([]byte(body))
	return "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
}

// writeKitIndex tells the kit's layout the scripts' paths and integrity, and
// Mermaid's theme: _kit.json beside the fragments.
func writeKitIndex(p kitPaths) error {
	if err := os.MkdirAll(p.Fragments, 0o755); err != nil {
		return err
	}
	type script struct {
		Path      string `json:"path"`
		Integrity string `json:"integrity"`
	}
	idx := struct {
		Scripts      []script `json:"scripts"`
		MermaidTheme string   `json:"mermaidTheme"`
	}{MermaidTheme: "default"}
	for _, k := range kitScriptFiles() {
		idx.Scripts = append(idx.Scripts, script{Path: k.Path, Integrity: k.Integrity})
	}
	b, err := json.Marshal(idx)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(p.Fragments, "_kit.json"), b, 0o644)
}

// writeKitScripts puts the scripts in the output, at their paths.
func writeKitScripts(p kitPaths) error {
	dst, err := os.OpenRoot(p.Out)
	if err != nil {
		return err
	}
	defer dst.Close()
	if err := dst.MkdirAll("_kit", 0o755); err != nil {
		return err
	}
	for _, k := range kitScriptFiles() {
		if err := dst.WriteFile(strings.TrimPrefix(k.Path, "/"), []byte(k.body), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// renderBody is one document's body, rendered.
func renderBody(format string, src []byte, embeds string) (string, error) {
	switch format {
	case coresite.Markdown, coresite.XMD:
	default:
		return renderInterim(src), nil
	}
	b, _, err := export.Fragment(src, export.FragmentOptions{Theme: renderTheme, Chart: chartSVG, Embeds: embeds, Link: siteLink,
		MaxDiagrams: maxDiagrams, MaxDiagramSource: maxDiagramSource})
	switch {
	case errors.Is(err, export.ErrTooManyDiagrams):
		return "", fmt.Errorf("it asks for more than %d diagrams and charts", maxDiagrams)
	case errors.Is(err, export.ErrDiagramTooLarge):
		return "", fmt.Errorf("a diagram's source is over %d bytes", maxDiagramSource)
	case err != nil:
		return "", err
	}
	return string(b), nil
}

// chartSVG draws a Vega-Lite spec as inline SVG with golib's chart/vegalite,
// in the render's palette: no fonts are loaded in the container, so labels
// are measured by an approximation of a sans-serif. A spec it cannot lay out
// stays its source, captioned with why.
func chartSVG(spec []byte, theme string) (string, error) {
	if len(spec) > maxChartSpec {
		return "", fmt.Errorf("the chart's spec is over %d bytes", maxChartSpec)
	}
	bg, fg, muted, border := export.Colors(theme)
	laid, err := vegalite.Lay(context.Background(), string(spec), chartWidth, vegalite.Theme{
		Background: nrgba(bg), Text: nrgba(fg), Axis: nrgba(muted), Grid: nrgba(border),
	}, nil)
	if err != nil {
		return "", err
	}
	return string(laid.SVG()), nil
}

// nrgba is a #rrggbb colour.
func nrgba(hex string) color.NRGBA {
	v, err := strconv.ParseUint(strings.TrimPrefix(hex, "#"), 16, 32)
	if err != nil || len(hex) != 7 {
		return color.NRGBA{A: 0xff}
	}
	return color.NRGBA{R: uint8(v >> 16), G: uint8(v >> 8), B: uint8(v), A: 0xff}
}

// siteLink is the rule for every URL a body holds: a fragment of the page, a
// path on the site (its own files beside it, another page), or an http,
// https or mailto address elsewhere. Anything else (javascript:, data:, a
// protocol-relative //host, a backslash, a space or a control character) is dropped:
// a link keeps its text, an image its alt.
func siteLink(href string) (string, bool) {
	if href == "" || strings.ContainsRune(href, '\\') || strings.HasPrefix(href, "//") {
		return "", false
	}
	for _, r := range href { // a space or a control character anywhere: a browser may strip it, and read another URL
		if r <= 0x20 || r == 0x7f {
			return "", false
		}
	}
	u, err := url.Parse(href)
	if err != nil {
		return "", false
	}
	switch strings.ToLower(u.Scheme) {
	case "":
		return href, u.Host == ""
	case "http", "https", "mailto":
		return href, true
	}
	return "", false
}

// inertDir is where, under the fragments, a build keeps the inert copies it
// made until Astro has written the pages they go beside.
const inertDir = "_inert"

// renderInert cleans an .html document (core/site.CleanHTML), keeps the copy
// for copyInert, and answers the document's body: a frame of that copy with
// sandbox="", so nothing in it runs, sends or goes anywhere, whatever the
// cleaning missed.
func renderInert(p kitPaths, d coresite.InputDoc, src []byte) (string, error) {
	docPath := d.Path
	page, title, err := coresite.CleanHTML(src)
	if err != nil {
		return "", err
	}
	if len(page) > maxFragment {
		return "", fmt.Errorf("its body is larger than %d bytes", maxFragment)
	}
	out := filepath.Join(p.Fragments, inertDir, filepath.FromSlash(pageDir(d)), coresite.InertPage)
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(out, page, 0o644); err != nil {
		return "", err
	}
	if title == "" {
		title = path.Base(docPath)
	}
	return `<iframe class="doc-frame" src="` + coresite.InertPage + `" sandbox="" title="` + html.EscapeString(title) + `" loading="lazy"></iframe>` + "\n", nil
}

// renderActive answers an active .html document's body: a frame of the
// document on the site's content host, where copyActive's file is served
// from. The frame allows scripts and not the site's origin: the document
// reads no page, cookie or storage of the site's, and the content host has
// none of its own.
func renderActive(contentHost, docPath string, src []byte) (string, error) {
	if contentHost == "" {
		return "", errors.New("it runs its scripts, and the site has no content host")
	}
	title := path.Base(docPath)
	if _, t, err := coresite.CleanHTML(src); err == nil && t != "" {
		title = t
	}
	u := url.URL{Scheme: "https", Host: contentHost, Path: "/" + docPath + "/"}
	return `<iframe class="doc-frame" src="` + html.EscapeString(u.String()) + `" sandbox="allow-scripts" title="` + html.EscapeString(title) + `" loading="lazy"></iframe>` + "\n", nil
}

// copyActive puts each active .html document where the content host serves
// it: <ActiveDir>/<address>/index.html, its source byte for byte. The core's
// output check compares each with what was published.
func copyActive(p kitPaths) error {
	raw, err := os.ReadFile(filepath.Join(p.Content, "build.json"))
	if err != nil {
		return err
	}
	var in coresite.BuildInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return err
	}
	src, err := os.OpenRoot(p.Content)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.OpenRoot(p.Out)
	if err != nil {
		return err
	}
	defer dst.Close()
	for _, d := range in.Docs {
		if d.Format != coresite.HTML || !d.Active {
			continue
		}
		data, err := src.ReadFile(d.Source)
		if err != nil {
			return fmt.Errorf("%s: %w", d.Path, err)
		}
		to := coresite.ActiveDir + "/" + d.Path
		if err := dst.MkdirAll(to, 0o755); err != nil {
			return err
		}
		if err := dst.WriteFile(to+"/index.html", data, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// copyInert puts each inert copy beside its document's page, as _doc.html.
func copyInert(p kitPaths) error {
	from := filepath.Join(p.Fragments, inertDir)
	src, err := os.OpenRoot(from)
	if errors.Is(err, fs.ErrNotExist) {
		return nil // no .html document
	}
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.OpenRoot(p.Out)
	if err != nil {
		return err
	}
	defer dst.Close()
	return fs.WalkDir(src.FS(), ".", func(name string, e fs.DirEntry, err error) error {
		if err != nil || e.IsDir() || !e.Type().IsRegular() {
			return err
		}
		data, err := src.ReadFile(name)
		if err != nil {
			return err
		}
		to := filepath.ToSlash(name) // <the page's directory>/_doc.html, as renderInert kept it
		if err := dst.MkdirAll(filepath.Dir(to), 0o755); err != nil {
			return err
		}
		return dst.WriteFile(to, data, 0o644)
	})
}

// renderInterim is a body as its source, escaped.
func renderInterim(src []byte) string {
	return `<pre class="source">` + html.EscapeString(strings.ToValidUTF8(string(src), "�")) + "</pre>\n"
}
