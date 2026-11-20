//go:build linux

package site

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	coresite "github.com/yongjohnlee80/autopanel/core/site"
)

// ManifestName is the file the core writes into a build's output after the
// output check: what the serving process needs to know of the pages, from the
// core and never from the build. The output check refuses a hidden name in
// what a build wrote, so nothing a build makes can stand in for it, and the
// serving process never serves a hidden name.
const ManifestName = ".autopanel-site.json"

// Manifest is the core's word on one build (core/site).
type Manifest = coresite.Manifest

// WriteManifest writes m into the output, after Normalize, as the core's.
func (f Files) WriteManifest(w Work, m Manifest) error {
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(w.Out)
	if err != nil {
		return err
	}
	defer root.Close()
	file, err := root.OpenFile(ManifestName, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0o644)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return root.Lchown(ManifestName, f.Owner.UID, f.Owner.GID)
}

// The types a site serves, by extension: the output check's list.
var contentTypes = map[string]string{
	".html":  "text/html; charset=utf-8",
	".css":   "text/css; charset=utf-8",
	".xml":   "application/xml; charset=utf-8",
	".txt":   "text/plain; charset=utf-8",
	".png":   "image/png",
	".jpg":   "image/jpeg",
	".jpeg":  "image/jpeg",
	".webp":  "image/webp",
	".gif":   "image/gif",
	".woff2": "font/woff2",
	".woff":  "font/woff",
}

// The response policies (docs/decisions/site.md): each response class has
// one, and none is added to another.
func pagePolicy(m Manifest, mermaid bool) string {
	frames := "'self'"
	if m.ContentHost != "" {
		frames += " https://" + m.ContentHost
	}
	p := "default-src 'none'; style-src 'self'; img-src 'self' data:; font-src 'self'; frame-src " + frames +
		"; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
	if mermaid && len(m.ScriptHashes) > 0 {
		p += "; script-src"
		for _, h := range m.ScriptHashes {
			p += " '" + h + "'"
		}
	}
	return p
}

const inertPolicy = "sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'self'; base-uri 'none'; form-action 'none'"

// Server is the serving process: it reads the live pages of every site and
// decides nothing but which file a request names. It holds no secret.
type Server struct {
	Dir string // Files.Dir
}

// ServeHTTP answers GET and HEAD with a page of the site the request's host
// names. Each request opens the site's directory once, and reads the manifest
// and the page through that one handle: a swap between them cannot give a
// page the policy of another build.
func (s Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		h.Set("Allow", "GET, HEAD")
		s.refuse(w, http.StatusMethodNotAllowed)
		return
	}
	host := strings.ToLower(r.Host)
	if hst, _, err := net.SplitHostPort(host); err == nil {
		host = hst
	}
	if hostName(host) != nil {
		s.refuse(w, http.StatusNotFound)
		return
	}
	root, err := os.OpenRoot(path.Join(s.Dir, host))
	if err != nil {
		if (Files{Dir: s.Dir}).IsDown(host) {
			// Taken down when something public was withdrawn: every path, until
			// a build passes. Not a missing page, so nothing caches it as one.
			h.Set("Retry-After", "30")
			s.refuse(w, http.StatusServiceUnavailable)
			return
		}
		s.refuse(w, http.StatusNotFound)
		return
	}
	defer root.Close()
	m := readManifest(root)
	name, redirect, ok := pageName(root, r.URL.Path)
	if !ok {
		s.refuse(w, http.StatusNotFound)
		return
	}
	if redirect != "" {
		h.Set("Content-Security-Policy", pagePolicy(Manifest{}, false))
		http.Redirect(w, r, redirect, http.StatusMovedPermanently)
		return
	}
	ext := strings.ToLower(path.Ext(name))
	ctype, ok := contentTypes[ext]
	if !ok {
		s.refuse(w, http.StatusNotFound)
		return
	}
	f, err := root.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		s.refuse(w, http.StatusNotFound)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		s.refuse(w, http.StatusNotFound)
		return
	}
	switch {
	case path.Base(name) == "_doc.html":
		h.Set("Content-Security-Policy", inertPolicy)
	default:
		h.Set("Content-Security-Policy", pagePolicy(m, contains(m.Mermaid, name)))
	}
	h.Set("Content-Type", ctype)
	h.Set("Cache-Control", "public, max-age=300")
	h.Set("ETag", fmt.Sprintf(`"%x-%x-%x"`, m.Build, info.Size(), info.ModTime().UnixNano()))
	http.ServeContent(w, r, "", info.ModTime(), f)
}

// pageName is the file a request's path names under the site, or a redirect
// to the path with its slash, or not ok. A hidden name is never a page.
func pageName(root *os.Root, urlPath string) (name, redirect string, ok bool) {
	if !strings.HasPrefix(urlPath, "/") || strings.Contains(urlPath, "\\") || strings.ContainsRune(urlPath, 0) {
		return "", "", false
	}
	clean := path.Clean(urlPath)
	for _, part := range strings.Split(clean, "/") {
		if strings.HasPrefix(part, ".") {
			return "", "", false
		}
	}
	name = strings.TrimPrefix(clean, "/")
	if name == "" {
		return "index.html", "", true
	}
	info, err := root.Lstat(name)
	if err != nil {
		return "", "", false
	}
	if info.IsDir() {
		if !strings.HasSuffix(urlPath, "/") {
			return "", clean + "/", true
		}
		return name + "/index.html", "", true
	}
	return name, "", true
}

func readManifest(root *os.Root) Manifest {
	var m Manifest
	f, err := root.OpenFile(ManifestName, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return m
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err == nil {
		_ = json.Unmarshal(data, &m)
	}
	return m
}

// refuse answers a status with a short text under the page policy: a missing
// page, a wrong method.
func (s Server) refuse(w http.ResponseWriter, status int) {
	h := w.Header()
	h.Set("Content-Security-Policy", pagePolicy(Manifest{}, false))
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, http.StatusText(status)+"\n")
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// Serve serves the sites on l until it fails. It logs nothing per request;
// the gate's counts cover them.
func (s Server) Serve(l net.Listener) error {
	srv := &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       time.Minute,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          nil,
	}
	err := srv.Serve(l)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
