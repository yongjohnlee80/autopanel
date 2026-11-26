package site

import (
	"context"
	"path"
	"strconv"
	"strings"
)

// READING A HELD DOCUMENT — the serving process asks, for a request the
// public pages do not answer, and the core decides from its own records:
// which node the address names, who is asking (a session it finds valid now),
// and whether they may read it (MayAt). It answers the one file to serve, or
// that there is nothing to serve; the serving process sends no user, no node
// and no level of its own. Decision: docs/decisions/site.md, "Held documents".

// ReadAsk is the serving process's question.
type ReadAsk struct {
	// Surface is where the request arrived: SurfaceSite on a site's own
	// host, SurfaceApp under /s/<site host>/ on the app host.
	Surface string `json:"surface"`
	Host    string `json:"host"`   // the request's host
	Path    string `json:"path"`   // its path, as sent
	Method  string `json:"method"` // GET or HEAD
	// Session is the app host's session cookie; Grants the site's host's
	// grant cookies. One or the other, by the surface.
	Session string   `json:"session,omitempty"`
	Grants  []string `json:"grants,omitempty"`
	// Unlock is the unlock form's cookie, when the browser has one.
	Unlock string `json:"unlock,omitempty"`
}

// The answers.
const (
	ReadFile     = "file"     // serve File, as Kind
	ReadMissing  = "missing"  // the missing page: no such node, no reader, not allowed, not built
	ReadRedirect = "redirect" // to Location: the address with its slash, said only to a reader who may read it
	ReadUnlock   = "unlock"   // a protected address, and no grant for it: show Form, with SetCookie when given
)

// What a held file is served as.
const (
	KindPage     = "page"     // the document's page
	KindInert    = "inert"    // an .html document's inert copy, under the policy that sandboxes it
	KindAsset    = "asset"    // the build's own stylesheet or script
	KindResource = "resource" // one of the document's images
)

// ReadAnswer is the core's answer.
type ReadAnswer struct {
	Status   string `json:"status"`
	File     string `json:"file,omitempty"` // under the held root
	Kind     string `json:"kind,omitempty"`
	Location string `json:"location,omitempty"`
	// Mermaid: the page may load the kit's scripts, whose hashes and paths
	// follow (the core's record, as a public page's manifest has them).
	Mermaid      bool     `json:"mermaid,omitempty"`
	ScriptHashes []string `json:"script_hashes,omitempty"`
	Scripts      []string `json:"scripts,omitempty"`
	// Protected: the site has a protected node, so a miss on its host is
	// worth asking about. Meaningful on SurfaceSite alone.
	Protected bool `json:"protected,omitempty"`
	// Form is the unlock form's page, and SetCookie the form's cookie when a
	// new one was made (ReadUnlock).
	Form      string `json:"form,omitempty"`
	SetCookie string `json:"set_cookie,omitempty"`
}

// HeldFile is a held file's path under the held root: name among node's
// files of build, of the site at host.
func HeldFile(host string, node, build int64, name string) string {
	return path.Join(host, strconv.FormatInt(node, 10), strconv.FormatInt(build, 10), name)
}

// Sessions finds the enabled user of an app-host session cookie, valid now;
// nil for none. The browser login's own lookup.
type Sessions func(ctx context.Context, appHost, cookie string) *User

// SetReaders gives the module what reading on the app host needs: the
// sessions' lookup, and whether a name is the applications' host.
func (m *Module) SetReaders(sessions Sessions, isAppHost func(host string) bool) {
	m.sessions, m.isAppHost = sessions, isAppHost
}

// MayReadPath answers the serving process. Every refusal is the same
// answer, whatever its reason.
func (m *Module) MayReadPath(ctx context.Context, ask ReadAsk) ReadAnswer {
	missing := ReadAnswer{Status: ReadMissing}
	if ask.Method != "GET" && ask.Method != "HEAD" {
		return missing
	}
	host, rest := ask.Host, ask.Path
	var who Reader
	switch ask.Surface {
	case SurfaceApp:
		if m.isAppHost == nil || !m.isAppHost(ask.Host) || !strings.HasPrefix(ask.Path, AppPrefix) {
			return missing
		}
		var ok bool
		if host, rest, ok = strings.Cut(strings.TrimPrefix(ask.Path, AppPrefix), "/"); !ok {
			return missing // /s/<site> with nothing after: no node
		}
		rest = "/" + rest
		if m.sessions != nil && ask.Session != "" {
			who.User = m.sessions(ctx, ask.Host, ask.Session)
		}
		if who.User == nil {
			return missing // before anything is looked up: no session learns what exists
		}
	case SurfaceSite:
		// A grant opens a protected node: looked up once the site is known.
	default:
		return missing
	}
	s, err := m.store.SiteByHost(ctx, host)
	if err != nil {
		return missing
	}
	if ask.Surface == SurfaceSite {
		if has, err := m.store.HasProtected(ctx, s.ID); err == nil {
			missing.Protected = has
		}
		who.Granted = m.granted(ctx, s.ID, ask.Grants)
	}
	if !strings.HasPrefix(rest, "/") || strings.Contains(rest, "\\") || strings.ContainsRune(rest, 0) || len(rest) > MaxPath+MaxResourceName+8 {
		return missing
	}
	slash := strings.HasSuffix(rest, "/")
	clean := path.Clean(rest)
	if clean == "/" {
		return missing // the root is a folder
	}
	parts := strings.Split(strings.TrimPrefix(clean, "/"), "/")
	// The node: slugs from the root down to the first document; what is
	// left names one of its files.
	root, err := m.store.Root(ctx, s.ID)
	if err != nil {
		return missing
	}
	chain := []Doc{root}
	name := ""
	for i, part := range parts {
		if !validName(part, MaxSlug) {
			return missing
		}
		d, err := m.store.Child(ctx, chain[len(chain)-1].ID, part)
		if err != nil {
			return missing
		}
		chain = append(chain, d)
		if !d.IsFolder() {
			name = strings.Join(parts[i+1:], "/")
			break
		}
	}
	d := chain[len(chain)-1]
	if d.IsFolder() {
		return missing // a held folder has no page
	}
	if surface, err := SurfaceOf(chain); err != nil || surface != ask.Surface {
		return missing // public (a static page), the other surface's, or a chain nobody can prove
	}
	if !MayAt(who, ActRead, chain) {
		// A protected address shows its unlock form: protected means gated,
		// not hidden. Only for the page itself, with or without its slash;
		// one of its files without a grant is missing.
		if locked, ok := lock(who, chain); ok && ask.Surface == SurfaceSite && name == "" {
			return m.unlockForm(ctx, s, locked, clean+"/", ask.Unlock, false)
		}
		return missing
	}
	if ByAdminOnlyAt(who, ActRead, chain) {
		// Read because the role allows it, and for no other reason: written
		// down before anything is shown, or nothing is shown.
		if err := m.store.NoteRead(ctx, d); err != nil {
			return missing
		}
	}
	held, err := m.store.HeldOf(ctx, d.ID)
	if err != nil {
		return missing // not built yet
	}
	ans := ReadAnswer{Status: ReadFile, Protected: missing.Protected}
	switch {
	case name == "":
		if !slash {
			to := clean + "/"
			if ask.Surface == SurfaceApp {
				to = AppPrefix + host + to
			}
			return ReadAnswer{Status: ReadRedirect, Location: to, Protected: missing.Protected}
		}
		name, ans.Kind = HeldPage, KindPage
		ans.Mermaid = held.Mermaid
	case slash:
		return missing
	case name == InertPage && d.Format == HTML:
		ans.Kind = KindInert
	case name == "look.css" || strings.HasPrefix(name, "_astro/") || strings.HasPrefix(name, "_kit/"):
		ans.Kind = KindAsset
	default:
		rs, err := m.store.Resources(ctx, d.ID)
		if err != nil {
			return missing
		}
		found := false
		for _, r := range rs {
			if r.Name == name && strings.HasPrefix(r.MIME, "image/") {
				found = true
			}
		}
		if !found {
			return missing
		}
		ans.Kind = KindResource
	}
	if m.builds != nil {
		ans.ScriptHashes, ans.Scripts = m.builds.kitManifest()
	}
	ans.File = HeldFile(s.Host, d.ID, held.Build, name)
	return ans
}
