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
	"strconv"
	"strings"
	"sync"
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
	// Its mode is set, not asked for: under the core's umask the serving
	// process, another user, could not read it, and would serve every page
	// without what the manifest allows it.
	if err := writeFile(root, ManifestName, data, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW); err != nil {
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

// activePolicy is the content host's, on a direct load as in a frame: the
// document is sandboxed with scripts and without an origin, loads nothing
// from anywhere, sends no form, and is framed by its site alone.
func activePolicy(m Manifest) string {
	return "sandbox allow-scripts; default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; form-action 'none'; base-uri 'none'; frame-ancestors https://" + m.Host
}

const inertPolicy = "sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'self'; base-uri 'none'; form-action 'none'"

// Server is the serving process: it reads the live pages of every site and
// decides nothing but which file a request names. It holds no secret.
type Server struct {
	Dir string // Files.Dir
	// Auth is the socket the core answers on for held documents (auth.go);
	// "": none is served, and what the public pages do not hold is missing.
	Auth string
	// quiet remembers, for a short while, the sites the core said have
	// nothing protected: a miss on one of them is answered without asking.
	quiet *quietSites
}

// NewServer serves the pages under dir, asking the core at auth for what is
// held.
func NewServer(dir, auth string) Server {
	return Server{Dir: dir, Auth: auth, quiet: &quietSites{until: map[string]time.Time{}}}
}

// quietFor is how long a site with nothing protected is not asked about.
const quietFor = 30 * time.Second

type quietSites struct {
	mu    sync.Mutex
	until map[string]time.Time
}

func (q *quietSites) is(host string, now time.Time) bool {
	if q == nil {
		return false
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	t, ok := q.until[host]
	if ok && !now.Before(t) {
		delete(q.until, host)
		return false
	}
	return ok
}

func (q *quietSites) set(host string, quiet bool, now time.Time) {
	if q == nil {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if !quiet {
		delete(q.until, host)
		return
	}
	if len(q.until) >= 1024 { // more sites than a host has: forget, and ask again
		clear(q.until)
	}
	q.until[host] = now.Add(quietFor)
}

// ServeHTTP answers GET and HEAD with a page of the site the request's host
// names. Each request opens the site's directory once, and reads the manifest
// and the page through that one handle: a swap between them cannot give a
// page the policy of another build.
func (s Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, coresite.UnlockPath) {
		s.unlock(w, r) // the one thing a reader sends: a protected node's passphrase
		return
	}
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
	// A content host is a link to its site's pages: it answers that site's
	// active documents, and nothing else of it.
	site, content := host, false
	if target, err := os.Readlink(path.Join(s.Dir, host)); err == nil {
		if hostName(target) != nil {
			s.refuse(w, http.StatusNotFound)
			return
		}
		site, content = target, true
	}
	root, err := os.OpenRoot(path.Join(s.Dir, site))
	if err != nil {
		if (Files{Dir: s.Dir}).IsDown(site) {
			// Taken down when something public was withdrawn: every path, until
			// a build passes. Not a missing page, so nothing caches it as one.
			h.Set("Retry-After", "30")
			s.refuse(w, http.StatusServiceUnavailable)
			return
		}
		if !content && strings.HasPrefix(r.URL.Path, coresite.AppPrefix) {
			// No site of this name: the app host, where members read. The
			// core says whether it is, and what the reader may have.
			s.held(w, r, coresite.ReadAsk{Surface: coresite.SurfaceApp, Session: cookieValue(r, sessionCookieName)})
			return
		}
		s.refuse(w, http.StatusNotFound)
		return
	}
	defer root.Close()
	m := readManifest(root)
	if content {
		if m.ContentHost != host || m.Host != site {
			s.refuse(w, http.StatusNotFound)
			return
		}
		s.serveActive(w, r, root, m)
		return
	}
	name, redirect, ok := pageName(root, r.URL.Path)
	if first, _, _ := strings.Cut(strings.TrimPrefix(path.Clean(r.URL.Path), "/"), "/"); first == coresite.ActiveDir {
		ok = false // the active documents are the content host's alone
	}
	if !ok {
		s.miss(w, r, host)
		return
	}
	if redirect != "" {
		h.Set("Content-Security-Policy", pagePolicy(Manifest{}, false))
		http.Redirect(w, r, redirect, http.StatusMovedPermanently)
		return
	}
	ext := strings.ToLower(path.Ext(name))
	ctype, ok := contentTypes[ext]
	if ext == ".js" && contains(m.Scripts, name) {
		// the kit's own scripts, which the output check matched to their
		// integrity; no other script is served
		ctype, ok = "text/javascript; charset=utf-8", true
	}
	if !ok {
		s.miss(w, r, host)
		return
	}
	f, err := root.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		s.miss(w, r, host)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		s.miss(w, r, host)
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

// serveActive answers the content host: an active document at its address,
// with a slash, under the policy that sandboxes it. It sets no cookie and no
// CORS header, and serves no other file.
func (s Server) serveActive(w http.ResponseWriter, r *http.Request, root *os.Root, m Manifest) {
	h := w.Header()
	p := r.URL.Path
	clean := path.Clean(p)
	if !strings.HasPrefix(p, "/") || clean == "/" || strings.Contains(p, "\\") || strings.ContainsRune(p, 0) {
		s.refuse(w, http.StatusNotFound)
		return
	}
	for _, part := range strings.Split(strings.TrimPrefix(clean, "/"), "/") {
		if strings.HasPrefix(part, ".") || strings.HasPrefix(part, "_") {
			s.refuse(w, http.StatusNotFound)
			return
		}
	}
	name := coresite.ActiveDir + clean + "/index.html"
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
	if p != clean+"/" {
		h.Set("Content-Security-Policy", activePolicy(m))
		http.Redirect(w, r, clean+"/", http.StatusMovedPermanently)
		return
	}
	h.Set("Content-Security-Policy", activePolicy(m))
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "public, max-age=300")
	h.Set("ETag", fmt.Sprintf(`"%x-%x-%x"`, m.Build, info.Size(), info.ModTime().UnixNano()))
	http.ServeContent(w, r, "", info.ModTime(), f)
}

// The cookies the serving process passes to the core, by name: the app
// host's session, and the site's host's grants. Nothing else of a request's
// cookies leaves it.
const (
	sessionCookieName = "__Host-ap_session"
	grantCookiePrefix = "__Host-ap_g"
	grantCookies      = 8
)

// cookieValue is the cookie of that name when it has a credential's shape:
// short and of plain characters. Anything else is no cookie.
func cookieValue(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil || len(c.Value) == 0 || len(c.Value) > 128 {
		return ""
	}
	for _, ch := range c.Value {
		if !(ch >= 'a' && ch <= 'z') && !(ch >= 'A' && ch <= 'Z') && !(ch >= '0' && ch <= '9') && ch != '-' && ch != '_' {
			return ""
		}
	}
	return c.Value
}

// miss answers a path the site's public pages do not hold. It may be a
// protected document's, so the core is asked, unless it said a moment ago
// that this site has nothing protected.
func (s Server) miss(w http.ResponseWriter, r *http.Request, host string) {
	now := time.Now()
	if s.Auth == "" || s.quiet.is(host, now) {
		s.refuse(w, http.StatusNotFound)
		return
	}
	ask := coresite.ReadAsk{Surface: coresite.SurfaceSite, Unlock: cookieValue(r, coresite.UnlockCookie)}
	for _, v := range grantSlots(r) {
		if v != "" {
			ask.Grants = append(ask.Grants, v)
		}
	}
	if ans, ok := s.held(w, r, ask); ok {
		s.quiet.set(host, !ans.Protected, now)
	}
}

// grantSlots are the grant cookies a request carries, by slot: "" where
// there is none.
func grantSlots(r *http.Request) []string {
	slots := make([]string, grantCookies)
	for i := range slots {
		slots[i] = cookieValue(r, grantCookiePrefix+string(rune('0'+i)))
	}
	return slots
}

// unlockPolicy is the unlock form's: a page's, and it may post to its own
// host.
const unlockPolicy = "default-src 'none'; style-src 'self'; img-src 'self' data:; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

// form answers the core's unlock form, with the form's cookie when the core
// made one. The page is the core's own text: nothing of a build is in it.
func (s Server) form(w http.ResponseWriter, page, cookie string, status int) {
	h := w.Header()
	if page == "" {
		s.refuse(w, http.StatusNotFound)
		return
	}
	if strings.HasPrefix(cookie, "__Host-ap_") && !strings.ContainsAny(cookie, "\r\n") {
		h.Set("Set-Cookie", cookie)
	}
	h.Set("Content-Security-Policy", unlockPolicy)
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "private, no-store")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, page)
}

// unlockBody is the most an unlock's form may hold.
const unlockBody = 4 << 10

// unlock passes a passphrase given at the unlock form to the core, with what
// it needs to judge the post (its origin, the form's cookie and token, the
// reader's address as the gate wrote it, the grant cookies the browser has)
// and answers as the core says: a grant's cookie and the way back, the form
// again, or a wait.
func (s Server) unlock(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	node, err := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, coresite.UnlockPath), 10, 64)
	if s.Auth == "" || err != nil || node <= 0 || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		s.refuse(w, http.StatusNotFound)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, unlockBody)
	if err := r.ParseForm(); err != nil {
		s.refuse(w, http.StatusBadRequest)
		return
	}
	host := strings.ToLower(r.Host)
	if hst, _, err := net.SplitHostPort(host); err == nil {
		host = hst
	}
	ans, err := askUnlock(r.Context(), s.Auth, coresite.UnlockAsk{
		Host: host, Node: node, Passphrase: r.PostForm.Get("passphrase"), Token: r.PostForm.Get("token"), Next: r.PostForm.Get("next"),
		Cookie: cookieValue(r, coresite.UnlockCookie), Origin: r.Header.Get("Origin"), FetchSite: r.Header.Get("Sec-Fetch-Site"),
		Client: r.Header.Get("X-Forwarded-For"), Slots: grantSlots(r),
	})
	if err != nil {
		h.Set("Retry-After", "5")
		s.refuse(w, http.StatusServiceUnavailable)
		return
	}
	switch ans.Status {
	case coresite.UnlockGranted:
		if !strings.HasPrefix(ans.SetCookie, coresite.GrantCookie) || strings.ContainsAny(ans.SetCookie, "\r\n") ||
			!strings.HasPrefix(ans.Location, "/") || strings.HasPrefix(ans.Location, "//") {
			s.refuse(w, http.StatusNotFound)
			return
		}
		h.Set("Set-Cookie", ans.SetCookie)
		h.Set("Content-Security-Policy", pagePolicy(Manifest{}, false))
		h.Set("Cache-Control", "private, no-store")
		http.Redirect(w, r, ans.Location, http.StatusSeeOther)
	case coresite.UnlockRefused:
		s.form(w, ans.Form, "", http.StatusForbidden)
	case coresite.UnlockBusy:
		h.Set("Retry-After", strconv.Itoa(max(ans.Wait, 1)))
		s.refuse(w, http.StatusServiceUnavailable)
	default:
		s.refuse(w, http.StatusNotFound)
	}
}

// held asks the core about a request and answers as it says: the file it
// names, a redirect to the address with its slash, or the missing page. With
// no answer the reader gets 503: no answer is never an allow. ok reports that
// the core answered.
func (s Server) held(w http.ResponseWriter, r *http.Request, ask coresite.ReadAsk) (ans coresite.ReadAnswer, ok bool) {
	h := w.Header()
	if s.Auth == "" {
		s.refuse(w, http.StatusNotFound)
		return ans, false
	}
	host := strings.ToLower(r.Host)
	if hst, _, err := net.SplitHostPort(host); err == nil {
		host = hst
	}
	ask.Host, ask.Path, ask.Method = host, r.URL.Path, r.Method
	ans, err := askCore(r.Context(), s.Auth, ask)
	if err != nil {
		h.Set("Retry-After", "5")
		s.refuse(w, http.StatusServiceUnavailable)
		return ans, false
	}
	switch ans.Status {
	case coresite.ReadRedirect:
		if !strings.HasPrefix(ans.Location, "/") || strings.HasPrefix(ans.Location, "//") {
			s.refuse(w, http.StatusNotFound)
			return ans, true
		}
		h.Set("Content-Security-Policy", pagePolicy(Manifest{}, false))
		h.Set("Cache-Control", "private, no-store")
		http.Redirect(w, r, ans.Location, http.StatusMovedPermanently)
		return ans, true
	case coresite.ReadUnlock:
		s.form(w, ans.Form, ans.SetCookie, http.StatusUnauthorized)
		return ans, true
	case coresite.ReadFile:
	default:
		s.refuse(w, http.StatusNotFound)
		return ans, true
	}
	ext := strings.ToLower(path.Ext(ans.File))
	ctype, known := contentTypes[ext]
	if ext == ".js" && ans.Kind == coresite.KindAsset {
		for _, script := range ans.Scripts {
			if strings.HasSuffix(ans.File, "/"+script) {
				ctype, known = "text/javascript; charset=utf-8", true
			}
		}
	}
	if !known {
		s.refuse(w, http.StatusNotFound)
		return ans, true
	}
	root, err := os.OpenRoot(path.Join(s.Dir, heldDir))
	if err != nil {
		s.refuse(w, http.StatusNotFound)
		return ans, true
	}
	defer root.Close()
	f, err := root.OpenFile(ans.File, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		s.refuse(w, http.StatusNotFound)
		return ans, true
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		s.refuse(w, http.StatusNotFound)
		return ans, true
	}
	switch ans.Kind {
	case coresite.KindInert:
		h.Set("Content-Security-Policy", inertPolicy)
	case coresite.KindPage:
		h.Set("Content-Security-Policy", pagePolicy(Manifest{ScriptHashes: ans.ScriptHashes}, ans.Mermaid))
	default:
		h.Set("Content-Security-Policy", pagePolicy(Manifest{}, false))
	}
	h.Set("Content-Type", ctype)
	// Held: never kept by a cache, whoever's.
	h.Set("Cache-Control", "private, no-store")
	http.ServeContent(w, r, "", time.Time{}, f)
	return ans, true
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
