package app

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"os"
	"path/filepath"
	"strings"

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

// maxFragment is the most a rendered body may hold (the site record's bound).
const maxFragment = 4 << 20

// siteBuild is autopanel --site-build.
func siteBuild(stdout, stderr io.Writer) int {
	p := defaultKitPaths()
	if err := renderFragments(p); err != nil {
		fmt.Fprintln(stderr, "autopanel --site-build: rendering:", err)
		return 1
	}
	// NAPI_RS_FORCE_WASI: Astro's compiler as WebAssembly; its native build
	// needs AVX2, which older servers lack (see the Containerfile).
	env := []string{"HOME=/tmp", "NODE_ENV=production", "ASTRO_TELEMETRY_DISABLED=1", "NAPI_RS_FORCE_WASI=1",
		"SITE_CONTENT=" + p.Content, "SITE_FRAGMENTS=" + p.Fragments, "SITE_OUT=" + p.Out, "SITE_CACHE=" + p.Cache}
	if err := hostcmd.Stream(context.Background(), hostcmd.Node, p.Project, env, stdout, stderr,
		filepath.Join(p.Project, "node_modules", "astro", "bin", "astro.mjs"), "build"); err != nil {
		fmt.Fprintln(stderr, "autopanel --site-build: astro:", err)
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

// renderFragments writes each document's body, rendered, where the kit reads
// it: <fragments>/<path>.html.
//
// Interim: until AutoDoc's Fragment is imported (AutoDoc v0.3.18), a body is
// its source, escaped, in a <pre>. Nothing of it is markup.
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
		body := renderInterim(src)
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

// renderInterim is a body as its source, escaped.
func renderInterim(src []byte) string {
	return `<pre class="source">` + html.EscapeString(strings.ToValidUTF8(string(src), "�")) + "</pre>\n"
}
