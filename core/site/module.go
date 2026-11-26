package site

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/yongjohnlee80/autopanel/internal/module"
)

// THE VERBS — sites, and documents published to them. Who may do what is the
// table in access.go, read for every call from the caller the store knows
// now.
//
// Decision: docs/decisions/site.md

// Person is who calls, as the site needs to know them.
type Person struct {
	ID    int64
	Name  string
	Admin bool
}

// People finds users for the site: the caller of a verb, and the members a
// share list names.
type People interface {
	// Caller is the enabled user the call is for; an error for no one.
	Caller(ctx context.Context) (Person, error)
	// Named is the enabled user of that name; ErrNoUser for none or a disabled one.
	Named(ctx context.Context, name string) (Person, error)
	// Name is a user's name, "" when there is none.
	Name(ctx context.Context, id int64) string
}

// The limits of a publish.
const (
	MaxBody = 512 << 10 // a document's body
	MaxMeta = 16 << 10  // its front matter, as JSON
)

var (
	ErrNotYours    = errors.New("site: that document is not yours to change")
	ErrBadHost     = errors.New("site: a site's host is a host name with a dot, in lower case")
	ErrBodyTooLong = errors.New("site: a document's body is at most 512 KiB, and its front matter 16 KiB")
	ErrBadMeta     = errors.New("site: a document's front matter is a JSON object")
	ErrBadData     = errors.New("site: a file's data is base64")
	ErrHostTaken   = errors.New("site: that host is a site's, or a site's content host")
	// ErrNoContentHost: an .html document may run its scripts only from the
	// site's content host, and the site has none; or the content host is being
	// cleared while a document still runs its scripts.
	ErrNoContentHost = errors.New("site: an html document runs its scripts only from the site's content host, and the site has none")
)

// Module is site.*.
type Module struct {
	store  Store
	people People
	now    func() time.Time
	builds *Builds // nil: nothing is built (a host without the builder; tests)
	// routed is called when a site is added or removed, or its content host
	// changes: the gate's table holds a route for each site. taken reports a
	// host something else serves (a route, the mail host, the API). nil: none.
	routed func(ctx context.Context) error
	taken  func(host string) bool
	// sessions and isAppHost are what reading on the app host needs
	// (read.go); nil: no held document is read there.
	sessions  Sessions
	isAppHost func(host string) bool
	// prot is what unlocking protected nodes needs (protect.go); weak the
	// rule a passphrase must pass beside its length, nil for none.
	prot *protection
	weak func(pass string) bool
}

// SetHosts has the module keep the gate's table in step with the sites,
// and refuse a host something else serves.
func (m *Module) SetHosts(routed func(ctx context.Context) error, taken func(host string) bool) {
	m.routed, m.taken = routed, taken
}

func (m *Module) reroute(ctx context.Context) error {
	if m.routed == nil {
		return nil
	}
	return m.routed(ctx)
}

// SetBuilds has the module ask for builds as documents change.
func (m *Module) SetBuilds(b *Builds) { m.builds = b }

// changed asks for a build of s when what it serves may have changed; when
// something public was withdrawn, its pages are taken down first. It answers
// the build that will include the change, 0 for none.
func (m *Module) changed(ctx context.Context, s Site, withdrawn bool) (int64, error) {
	if m.builds == nil {
		return 0, nil
	}
	if withdrawn {
		return m.builds.Lowered(ctx, s)
	}
	return m.builds.Ask(ctx, s.ID)
}

// NewModule is the site's verbs over store.
func NewModule(store Store, people People) *Module {
	return &Module{store: store, people: people, now: time.Now, prot: newProtection()}
}

func (m *Module) Name() string { return "site" }

func (m *Module) Errors() []module.PublicError {
	return []module.PublicError{
		{Err: ErrNotFound, Code: -32300, Name: "site.not_found", Message: "no such document"},
		{Err: ErrDuplicate, Code: -32301, Name: "site.duplicate", Message: "the site has a document with that slug"},
		{Err: ErrNoSite, Code: -32302, Name: "site.no_site", Message: "no such site"},
		{Err: ErrSiteExists, Code: -32303, Name: "site.site_exists", Message: "a site has that host"},
		{Err: ErrNoUser, Code: -32304, Name: "site.no_user", Message: "a member named in a share list is no enabled user"},
		{Err: ErrNotYours, Code: -32305, Name: "site.not_yours", Message: "that document is not yours to change"},
		{Err: ErrBadHost, Code: -32306, Name: "site.bad_host", Message: "a site's host is a host name with a dot, in lower case"},
		{Err: ErrBodyTooLong, Code: -32307, Name: "site.too_long", Message: "a document's body is at most 512 KiB, and its front matter 16 KiB"},
		{Err: ErrBadMeta, Code: -32308, Name: "site.bad_meta", Message: "a document's front matter is a JSON object"},
		{Err: ErrBadLevel, Code: -32309, Name: "site.bad_level", Message: "a document's level is public, protected, internal or private"},
		{Err: ErrBadFormat, Code: -32310, Name: "site.bad_format", Message: "a document's format is md, xmd or html"},
		{Err: ErrBadSlug, Code: -32311, Name: "site.bad_slug", Message: "a slug is 1 to 80 lower-case letters, digits and hyphens"},
		{Err: ErrNotAFolder, Code: -32312, Name: "site.not_a_folder", Message: "that is no folder"},
		{Err: ErrBadShare, Code: -32313, Name: "site.bad_share", Message: "only a private document has a share list, of at most 64 members, never its owner"},
		{Err: ErrActiveHeld, Code: -32314, Name: "site.active_held", Message: "only a public html document may run its scripts"},
		{Err: ErrBadData, Code: -32315, Name: "site.bad_data", Message: "a file's data is base64"},
		{Err: ErrBadResource, Code: -32316, Name: "site.bad_name", Message: "a file's name is a relative path of at most six parts, with no empty, . or .. part"},
		{Err: ErrReservedName, Code: -32317, Name: "site.reserved_name", Message: "a file's name may not start with an underscore or be index.html"},
		{Err: ErrSameName, Code: -32318, Name: "site.same_name", Message: "two of the document's files have names that differ only by case"},
		{Err: ErrResourceTaken, Code: -32318, Name: "site.same_name", Message: "two of the document's files have names that differ only by case"},
		{Err: ErrTooMany, Code: -32319, Name: "site.too_many", Message: "a document has at most 64 files"},
		{Err: ErrResourceType, Code: -32320, Name: "site.bad_type", Message: "a file is a PNG, JPEG, WebP or GIF image, a .mmd, a .chart.json or a .csv, and its content must be what its name says"},
		{Err: ErrResourceSize, Code: -32321, Name: "site.too_large", Message: "an image holds at most 1.4 MiB, a diagram, chart or table 512 KiB"},
		{Err: ErrNoResource, Code: -32322, Name: "site.no_file", Message: "the document has no such file"},
		{Err: ErrBadConfig, Code: -32323, Name: "site.bad_config", Message: "the configuration was refused"},
		{Err: ErrHostTaken, Code: -32324, Name: "site.host_taken", Message: "that host is a site's, or a site's content host"},
		{Err: ErrNotEmpty, Code: -32325, Name: "site.not_empty", Message: "a folder is removed only when it is empty"},
		{Err: ErrCycle, Code: -32326, Name: "site.cycle", Message: "a folder cannot move into itself or anything under it"},
		{Err: ErrTooDeep, Code: -32327, Name: "site.too_deep", Message: "folders nest at most 8 deep"},
		{Err: ErrPathTooLong, Code: -32328, Name: "site.path_too_long", Message: "an address is at most 255 bytes"},
		{Err: ErrTooManyNodes, Code: -32329, Name: "site.folder_full", Message: "a folder holds at most 1000 folders and documents"},
		{Err: ErrBadPath, Code: -32330, Name: "site.bad_path", Message: "a path is slugs joined by /, with no empty part"},
		{Err: ErrNoContentHost, Code: -32332, Name: "site.no_content_host", Message: "an html document runs its scripts only from the site's content host: set one (site.set content_host), or keep it while a document needs it"},
		{Err: ErrMixedLevels, Code: -32333, Name: "site.mixed_levels", Message: "a protected folder or document cannot be above or below an internal or private one: a reader proves a passphrase on the site, and membership on the app host, never both at once"},
		{Err: ErrWeakPassphrase, Code: -32334, Name: "site.weak_passphrase", Message: "a passphrase is at least 12 characters, and none of the common ones"},
		{Err: ErrNotProtected, Code: -32335, Name: "site.not_protected", Message: "only a protected folder or document has a passphrase: set its level to protected first"},
		{Err: ErrBusy, Code: -32336, Name: "site.busy", Message: "too many passphrases are being checked; try again shortly"},
		{Err: ErrRoot, Code: -32331, Name: "site.root", Message: "the site's root folder is not changed, moved or removed"},
	}
}

const since = 11

func (m *Module) Verbs() []module.Verb {
	admin := func(c module.Contract) module.Contract { c.Area, c.Since = "site.admin", since; return c }
	site := func(c module.Contract) module.Contract { c.Area, c.Since = "site", since; return c }
	return []module.Verb{
		module.Handle(admin(module.Contract{Verb: "site.add", Mutates: true, Privileged: true, Param: "{host}", Result: "{host, security_gen}",
			Doc: "Makes a site: a host name its pages will be served on. Nothing is served yet."}), m.add),
		module.Handle(admin(module.Contract{Verb: "site.list", Discloses: module.Plain, Result: "[{host, documents}]",
			Doc: "The sites, and how many documents each holds."}), m.list),
		module.Handle(admin(module.Contract{Verb: "site.remove", Mutates: true, Privileged: true, Param: "{host}",
			Doc: "Deletes a site with every document published to it."}), m.remove),
		module.Handle(admin(module.Contract{Verb: "site.set", Mutates: true, Privileged: true, Param: "{host, config?, content_host?}", Result: "{host, content_host, config}",
			Doc: "Sets a site's configuration (YAML: title, tagline, language, theme, home, nav, footer, look) and its content host. A configuration is validated whole; a refused one changes nothing. Leaving a field out keeps it; an empty content_host clears it."}), m.set),
		module.Handle(admin(module.Contract{Verb: "site.get", Discloses: module.Plain, Param: "{host}", Result: "{host, content_host, config, security_gen, documents}",
			Doc: "A site's configuration, with its defaults filled in."}), m.getSite),
		module.Handle(site(module.Contract{Verb: "site.status", Discloses: module.Plain, Param: "{host}", Result: "{host, build, live_build, state, built_at, error}",
			Doc: "Where a site's builds are: the newest asked for, the one served, and the last failure's reason. A change made in build N is live once live_build is N or more."}), m.status),
		module.Handle(site(module.Contract{Verb: "site.folder.add", Mutates: true, Param: "{site, path, title?, visibility?, share?: [name], order?, parents?}", Result: "{path, kind, title, visibility, owner, order, build}",
			Doc: "Makes a folder at path, private unless said. Its folder must exist (or parents: true makes the missing ones, private and yours) and be one you may put things into: the root, or a folder of yours."}), m.folderAdd),
		module.Handle(site(module.Contract{Verb: "site.folder.set", Mutates: true, Param: "{site, path, title?, visibility?, share?: [name], order?}", Result: "{path, kind, title, visibility, owner, order, build}",
			Doc: "Changes a folder of yours: its title, level, share list or order. What it holds is no more open than it is."}), m.folderSet),
		module.Handle(site(module.Contract{Verb: "site.folder.remove", Mutates: true, Param: "{site, path}",
			Doc: "Deletes an empty folder: its owner or an administrator."}), m.folderRemove),
		module.Handle(site(module.Contract{Verb: "site.node.list", Discloses: module.Plain, Param: "{site, path?}", Result: "[{path, kind, title, format, visibility, owner, order, version}]",
			Doc: "The folders and documents in a folder (the root when path is empty) that the caller may see listed."}), m.nodeList),
		module.Handle(site(module.Contract{Verb: "site.node.move", Mutates: true, Param: "{site, path, to}", Result: "{path, kind, title, visibility, owner, order, build}",
			Doc: "Moves a folder or a document of yours into the folder to, one you may put things into. Its address changes, and its contents'."}), m.nodeMove),
		module.Handle(site(module.Contract{Verb: "site.node.protect", Mutates: true, Param: "{site, path, passphrase}",
			Doc: "Sets the passphrase of a protected folder or document of yours (an administrator may set anyone's). Whoever gives it on the site reads the node, and what a protected folder holds that is public. A new passphrase ends every grant of the one before. At least 12 characters, and none of the common ones."}), m.protect),
		module.Handle(site(module.Contract{Verb: "site.node.unprotect", Mutates: true, Param: "{site, path}",
			Doc: "Removes a protected node's passphrase and ends its grants: nobody is let in until one is set again."}), m.unprotect),
		module.Handle(site(module.Contract{Verb: "site.doc.put", Mutates: true, Param: "{site, folder?, parents?, slug, format, body, meta?, visibility?, share?: [name], order?, active?}",
			Result: "{slug, visibility, version, generation, served}",
			Doc:    "Publishes a document, or a new version of one of yours. A first publish that names no level is private; an update that names none keeps its level. A public document is on the site's host once its build is live; an internal or private one is read by members at /s/<site>/<address>/ on the app host; a protected one is read on the site's host by whoever gives its passphrase (site.node.protect). served says whether it is public."}), m.put),
		module.Handle(site(module.Contract{Verb: "site.doc.get", Param: "{site, slug}", Result: "{slug, format, visibility, share, meta, body, version}",
			Doc: "A document as it was published: its owner's, and an administrator's, who answers for what the site holds; an administrator's read of a document not theirs is audited."}), m.get),
		module.Handle(site(module.Contract{Verb: "site.doc.remove", Mutates: true, Param: "{site, slug}",
			Doc: "Deletes a document: its owner or an administrator."}), m.removeDoc),
		module.Handle(site(module.Contract{Verb: "site.asset.put", Mutates: true, Param: "{site, slug, name, data}", Result: "{name, mime, size}",
			Doc: "Adds one of a document's files, or replaces the one of that name: an image, a Mermaid diagram (.mmd), a Vega-Lite chart (.chart.json) or a table (.csv). data is base64. Its kind is judged by its name and its content together."}), m.assetPut),
		module.Handle(site(module.Contract{Verb: "site.asset.list", Param: "{site, slug}", Result: "[{name, mime, size}]",
			Doc: "A document's files: its owner's, and an administrator's (audited)."}), m.assetList),
		module.Handle(site(module.Contract{Verb: "site.asset.get", Param: "{site, slug, name}", Result: "{name, mime, data}",
			Doc: "One of a document's files, data in base64: its owner's, and an administrator's (audited)."}), m.assetGet),
		module.Handle(site(module.Contract{Verb: "site.asset.remove", Mutates: true, Param: "{site, slug, name}",
			Doc: "Deletes one of a document's files: its owner's alone."}), m.assetRemove),
	}
}

// --- sites ---------------------------------------------------------------------

// SiteAsk names a site by its host.
type SiteAsk struct {
	Host string `json:"host"`
}

// SiteView is a site as the verbs answer it.
type SiteView struct {
	Host        string `json:"host"`
	SecurityGen int64  `json:"security_gen,omitempty"`
	Documents   int    `json:"documents"`
}

func validHost(h string) bool {
	if len(h) < 3 || len(h) > 253 || h != strings.ToLower(h) || !strings.Contains(h, ".") || strings.HasPrefix(h, ".") || strings.HasSuffix(h, ".") {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func (m *Module) add(ctx context.Context, p SiteAsk) (SiteView, error) {
	host := strings.TrimSpace(p.Host)
	if !validHost(host) {
		return SiteView{}, ErrBadHost
	}
	if err := m.hostFree(ctx, host, 0); err != nil {
		return SiteView{}, err
	}
	if m.taken != nil && m.taken(host) {
		return SiteView{}, ErrHostTaken // a route's, the mail host, or the API's
	}
	s, err := m.store.AddSite(ctx, Site{Host: host, CreatedAt: m.now().Unix()})
	if err != nil {
		return SiteView{}, err
	}
	if err := m.reroute(ctx); err != nil {
		return SiteView{}, err
	}
	return SiteView{Host: s.Host, SecurityGen: s.SecurityGen}, nil
}

func (m *Module) list(ctx context.Context, _ struct{}) ([]SiteView, error) {
	ss, err := m.store.Sites(ctx)
	if err != nil {
		return nil, err
	}
	out := []SiteView{}
	for _, s := range ss {
		ds, err := m.store.Docs(ctx, s.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, SiteView{Host: s.Host, SecurityGen: s.SecurityGen, Documents: len(ds)})
	}
	return out, nil
}

func (m *Module) remove(ctx context.Context, p SiteAsk) (struct{}, error) {
	s, err := m.store.SiteByHost(ctx, strings.TrimSpace(p.Host))
	if err != nil {
		return struct{}{}, err
	}
	if err := m.store.RemoveSite(ctx, s.ID); err != nil {
		return struct{}{}, err
	}
	if err := m.reroute(ctx); err != nil {
		return struct{}{}, err
	}
	if m.builds != nil {
		return struct{}{}, m.builds.Removed(s.Host)
	}
	return struct{}{}, nil
}

// Status is where a site's builds are: build is the newest asked for,
// live_build the one served. A change made in build N is live once
// live_build is N or more.
type Status struct {
	Host      string `json:"host"`
	Build     int64  `json:"build"`
	LiveBuild int64  `json:"live_build"`
	State     string `json:"state"` // none, waiting, building, live, failed or down
	BuiltAt   int64  `json:"built_at,omitempty"`
	Error     string `json:"error,omitempty"`
}

func (m *Module) status(ctx context.Context, p SiteAsk) (Status, error) {
	if _, _, err := m.reader(ctx); err != nil {
		return Status{}, err
	}
	s, err := m.siteOf(ctx, p.Host)
	if err != nil {
		return Status{}, err
	}
	st := Status{Host: s.Host, Build: s.Build, LiveBuild: s.LiveBuild, State: s.BuildState, BuiltAt: s.BuiltAt, Error: s.BuildError}
	if s.Down && s.BuildState != BuildBuilding && s.BuildState != BuildWaiting {
		st.State = "down"
	}
	return st, nil
}

// hostFree: no site but except has host as its host or its content host.
// A content host holds no session and no route; were it also a site's host,
// an active document would run on a page's origin.
func (m *Module) hostFree(ctx context.Context, host string, except int64) error {
	ss, err := m.store.Sites(ctx)
	if err != nil {
		return err
	}
	for _, s := range ss {
		if s.ID == except && s.Host == host {
			continue
		}
		if s.Host == host || s.ContentHost == host {
			return ErrHostTaken
		}
	}
	return nil
}

// SiteSet changes a site: the fields left out are kept.
type SiteSet struct {
	Host        string  `json:"host"`
	Config      *string `json:"config,omitempty"`       // YAML
	ContentHost *string `json:"content_host,omitempty"` // "" clears it
}

// SiteConfigView is a site with its configuration.
type SiteConfigView struct {
	Host        string `json:"host"`
	ContentHost string `json:"content_host,omitempty"`
	Config      Config `json:"config"`
	SecurityGen int64  `json:"security_gen,omitempty"`
	Documents   int    `json:"documents"`
}

func (m *Module) set(ctx context.Context, p SiteSet) (SiteConfigView, error) {
	s, err := m.store.SiteByHost(ctx, strings.TrimSpace(p.Host))
	if err != nil {
		return SiteConfigView{}, err
	}
	config := s.Config
	if p.Config != nil {
		c, err := ParseConfig(*p.Config)
		if err != nil {
			return SiteConfigView{}, err
		}
		config = c.JSON()
	}
	content := s.ContentHost
	if p.ContentHost != nil {
		content = strings.TrimSpace(*p.ContentHost)
		if content != "" {
			if !validHost(content) || content == s.Host {
				return SiteConfigView{}, ErrBadHost
			}
			if err := m.hostFree(ctx, content, s.ID); err != nil {
				return SiteConfigView{}, err
			}
			if content != s.ContentHost && m.taken != nil && m.taken(content) {
				return SiteConfigView{}, ErrHostTaken
			}
		}
	}
	if content == "" && s.ContentHost != "" {
		ds, err := m.store.Docs(ctx, s.ID)
		if err != nil {
			return SiteConfigView{}, err
		}
		for _, d := range ds {
			if d.Active {
				return SiteConfigView{}, ErrNoContentHost
			}
		}
	}
	if s, err = m.store.SetSite(ctx, s.ID, config, content); err != nil {
		return SiteConfigView{}, err
	}
	if err := m.reroute(ctx); err != nil {
		return SiteConfigView{}, err
	}
	if _, err := m.changed(ctx, s, false); err != nil {
		return SiteConfigView{}, err
	}
	return m.siteView(ctx, s)
}

func (m *Module) getSite(ctx context.Context, p SiteAsk) (SiteConfigView, error) {
	s, err := m.store.SiteByHost(ctx, strings.TrimSpace(p.Host))
	if err != nil {
		return SiteConfigView{}, err
	}
	return m.siteView(ctx, s)
}

func (m *Module) siteView(ctx context.Context, s Site) (SiteConfigView, error) {
	c, err := StoredConfig(s)
	if err != nil {
		return SiteConfigView{}, err
	}
	ds, err := m.store.Docs(ctx, s.ID)
	if err != nil {
		return SiteConfigView{}, err
	}
	return SiteConfigView{Host: s.Host, ContentHost: s.ContentHost, Config: c, SecurityGen: s.SecurityGen, Documents: len(ds)}, nil
}

// --- documents -----------------------------------------------------------------

// DocAsk names a document: its site's host, its folder's path ("": the
// root) and its slug.
type DocAsk struct {
	Site   string `json:"site"`
	Folder string `json:"folder,omitempty"`
	Slug   string `json:"slug"`
}

func (a DocAsk) path() string { return strings.Trim(strings.Trim(a.Folder, "/")+"/"+a.Slug, "/") }

// Put is site.doc.put's param.
type Put struct {
	Site       string          `json:"site"`
	Slug       string          `json:"slug"`
	Format     string          `json:"format"`
	Body       string          `json:"body"`
	Meta       json.RawMessage `json:"meta,omitempty"`
	Visibility string          `json:"visibility,omitempty"`
	Share      *[]string       `json:"share,omitempty"`   // nil: unchanged on an update, none on a first publish
	Folder     string          `json:"folder,omitempty"`  // its folder's path; "": the root
	Parents    bool            `json:"parents,omitempty"` // make the folders of Folder that are missing, private and the caller's
	Order      int             `json:"order,omitempty"`
	Active     bool            `json:"active,omitempty"`
}

// Published is site.doc.put's answer.
type Published struct {
	Path       string `json:"path"`
	Slug       string `json:"slug"`
	Visibility string `json:"visibility"`
	Version    int64  `json:"version"`
	Generation int64  `json:"generation"`
	// Served: the document is public, and its page is made by Build;
	// site.status says when it is live. A held document's own page is made by
	// Build too, and read after the core's check.
	Served bool  `json:"served"`
	Build  int64 `json:"build,omitempty"`
}

// Source view is site.doc.get's answer.
type SourceView struct {
	Slug       string          `json:"slug"`
	Format     string          `json:"format"`
	Visibility string          `json:"visibility"`
	Share      []string        `json:"share"`
	Meta       json.RawMessage `json:"meta,omitempty"`
	Body       string          `json:"body"`
	Version    int64           `json:"version"`
}

func (m *Module) reader(ctx context.Context) (Reader, Person, error) {
	p, err := m.people.Caller(ctx)
	if err != nil {
		return Reader{}, Person{}, err
	}
	return Reader{User: &User{ID: p.ID, Admin: p.Admin}}, p, nil
}

func (m *Module) siteOf(ctx context.Context, host string) (Site, error) {
	return m.store.SiteByHost(ctx, strings.TrimSpace(host))
}

func (m *Module) share(ctx context.Context, names []string) ([]int64, error) {
	out := make([]int64, 0, len(names))
	for _, n := range names {
		p, err := m.people.Named(ctx, strings.TrimSpace(n))
		if err != nil {
			return nil, ErrNoUser
		}
		out = append(out, p.ID)
	}
	return out, nil
}

func (m *Module) put(ctx context.Context, p Put) (Published, error) {
	who, me, err := m.reader(ctx)
	if err != nil {
		return Published{}, err
	}
	s, err := m.siteOf(ctx, p.Site)
	if err != nil {
		return Published{}, err
	}
	if len(p.Body) > MaxBody || len(p.Meta) > MaxMeta {
		return Published{}, ErrBodyTooLong
	}
	meta := ""
	if len(p.Meta) > 0 {
		var obj map[string]any
		if json.Unmarshal(p.Meta, &obj) != nil || obj == nil {
			return Published{}, ErrBadMeta
		}
		meta = string(p.Meta)
	}
	sum := sha256.Sum256([]byte(p.Body))
	src := Source{Meta: meta, Body: []byte(p.Body), SHA256: hex.EncodeToString(sum[:])}
	var shared []int64
	if p.Share != nil {
		if shared, err = m.share(ctx, *p.Share); err != nil {
			return Published{}, err
		}
	}
	// Its own fields and its address first, so a refused call makes no folder
	// on the way (tifa, N1).
	if _, err := Level(p.Visibility, nil); err != nil {
		return Published{}, err
	}
	probe := Doc{Parent: 1, Kind: KindDoc, Slug: p.Slug, Format: p.Format, Owner: me.ID, Visibility: Private, Order: p.Order}
	if err := probe.Check(); err != nil {
		return Published{}, err
	}
	if p.Active && p.Format != HTML {
		return Published{}, ErrActiveHeld // before any folder is made on the way (tifa, N1)
	}
	if p.Active && s.ContentHost == "" {
		return Published{}, ErrNoContentHost
	}
	if _, err := SplitPath(strings.Trim(p.Folder, "/") + "/" + p.Slug); err != nil {
		return Published{}, err
	}
	folder, err := m.folderFor(ctx, who, me, s, p.Folder, p.Parents)
	if err != nil {
		return Published{}, err
	}
	old, err := m.store.Child(ctx, folder[len(folder)-1].ID, p.Slug)
	switch {
	case errors.Is(err, ErrNotFound): // a first publish
		if !MayPutIn(who, folder) {
			return Published{}, ErrNotYours
		}
		level, err := Level(p.Visibility, nil)
		if err != nil {
			return Published{}, err
		}
		d := Doc{Site: s.ID, Parent: folder[len(folder)-1].ID, Kind: KindDoc, Slug: p.Slug, Format: p.Format, Owner: me.ID,
			Visibility: level, Share: shared, Order: p.Order, Active: p.Active}
		if err := d.Check(); err != nil {
			return Published{}, err
		}
		if _, err := SurfaceOf(append(append([]Doc{}, folder...), d)); err != nil {
			return Published{}, err
		}
		d, err = m.store.Create(ctx, d, src)
		if err != nil {
			return Published{}, err
		}
		return m.published(ctx, s, folder, d, false)
	case err != nil:
		return Published{}, err
	}
	oldChain := append(append([]Doc{}, folder...), old)
	if old.IsFolder() || !MayAt(who, ActChange, oldChain) {
		if !old.IsFolder() && MayAt(who, ActExists, oldChain) {
			return Published{}, ErrNotYours
		}
		return Published{}, ErrDuplicate // someone else's slug, which the caller may not even see
	}
	if level, err := Level(p.Visibility, &old); err == nil {
		as := old
		as.Visibility = level
		if _, err := SurfaceOf(append(append([]Doc{}, folder...), as)); err != nil {
			return Published{}, err
		}
	}
	d, lowered, err := m.store.Update(ctx, old.ID, func(cur Doc) (Doc, *Source, error) {
		if cur.Owner != me.ID { // changed hands since the read: it cannot, but the rule is the store's read
			return Doc{}, nil, ErrNotYours
		}
		level, err := Level(p.Visibility, &cur)
		if err != nil {
			return Doc{}, nil, err
		}
		next := cur
		next.Format, next.Visibility, next.Order, next.Active = p.Format, level, p.Order, p.Active
		if p.Share != nil {
			next.Share = shared
		} else if level != Private {
			next.Share = nil // a share list belongs to a private document alone
		}
		if err := next.Check(); err != nil {
			return Doc{}, nil, err
		}
		return next, &src, nil
	})
	if err != nil {
		return Published{}, err
	}
	if old.Visibility == Protected && d.Visibility != Protected {
		if err := m.store.EndGrants(ctx, d.ID); err != nil { // it left protected: what its passphrase gave ends
			return Published{}, err
		}
	}
	return m.published(ctx, s, folder, d, PublicAt(oldChain) && !PublicAt(append(append([]Doc{}, folder...), d)) && lowered)
}

// published answers a publish into folder, asking for the build that will
// hold it: the public pages' when it is public in effect, its own when it is
// held. When something public was withdrawn, the pages are taken down first.
func (m *Module) published(ctx context.Context, s Site, folder []Doc, d Doc, withdrawn bool) (Published, error) {
	chain := append(append([]Doc{}, folder...), d)
	p := Published{Path: pathOfChain(chain), Slug: d.Slug, Visibility: d.Visibility, Version: d.Version, Generation: d.Generation}
	public := PublicAt(chain)
	n, err := m.changed(ctx, s, withdrawn)
	if err != nil {
		return p, err
	}
	p.Build, p.Served = n, n > 0 && public
	return p, nil
}

// find is a document the caller may at least know exists; any other is
// ErrNotFound, so a refusal says nothing of what is there.
func (m *Module) find(ctx context.Context, who Reader, p DocAsk) ([]Doc, error) {
	s, err := m.siteOf(ctx, p.Site)
	if err != nil {
		return nil, err
	}
	chain, err := m.node(ctx, who, s, p.path())
	if err != nil {
		return nil, err
	}
	if chain[len(chain)-1].IsFolder() {
		return nil, ErrNotFound // a document's verb on a folder: no such document
	}
	return chain, nil
}

func (m *Module) get(ctx context.Context, p DocAsk) (SourceView, error) {
	// An administrator answers for what the site holds and may read anything
	// of it; the read is written down before anything is shown, and nothing
	// is shown if it cannot be.
	d, err := m.readable(ctx, DocAsk{Site: p.Site, Folder: p.Folder, Slug: p.Slug})
	if err != nil {
		return SourceView{}, err
	}
	src, err := m.store.Source(ctx, d.ID)
	if err != nil {
		return SourceView{}, err
	}
	v := SourceView{Slug: d.Slug, Format: d.Format, Visibility: d.Visibility, Share: []string{}, Body: string(src.Body), Version: d.Version}
	if src.Meta != "" {
		v.Meta = json.RawMessage(src.Meta)
	}
	for _, id := range d.Share {
		v.Share = append(v.Share, m.people.Name(ctx, id))
	}
	return v, nil
}

func (m *Module) removeDoc(ctx context.Context, p DocAsk) (struct{}, error) {
	who, _, err := m.reader(ctx)
	if err != nil {
		return struct{}{}, err
	}
	chain, err := m.find(ctx, who, p)
	if err != nil {
		return struct{}{}, err
	}
	d := chain[len(chain)-1]
	if !MayAt(who, ActRemove, chain) {
		return struct{}{}, ErrNotYours
	}
	if _, err = m.store.Remove(ctx, d.ID); err != nil {
		return struct{}{}, err
	}
	s, err := m.store.SiteByID(ctx, d.Site)
	if err != nil {
		return struct{}{}, err
	}
	_, err = m.changed(ctx, s, PublicAt(chain)) // a held one: its files go at the build
	return struct{}{}, err
}

// --- a document's files ----------------------------------------------------------

// AssetAsk names one of a document's files; Data is its content, base64.
type AssetAsk struct {
	Site   string `json:"site"`
	Folder string `json:"folder,omitempty"`
	Slug   string `json:"slug"`
	Name   string `json:"name"`
	Data   string `json:"data,omitempty"`
}

// AssetView is a file as the verbs answer it.
type AssetView struct {
	Name  string `json:"name"`
	MIME  string `json:"mime"`
	Size  int64  `json:"size"`
	Build int64  `json:"build,omitempty"` // the build that will serve it, for a public document's file
}

// owned is a document the caller may change: its owner's. Anything else the
// caller may know exists is not theirs; the rest is missing.
func (m *Module) owned(ctx context.Context, a AssetAsk) ([]Doc, error) {
	who, _, err := m.reader(ctx)
	if err != nil {
		return nil, err
	}
	chain, err := m.find(ctx, who, DocAsk{Site: a.Site, Folder: a.Folder, Slug: a.Slug})
	if err != nil {
		return nil, err
	}
	if !MayAt(who, ActChange, chain) {
		return nil, ErrNotYours
	}
	return chain, nil
}

func (m *Module) assetPut(ctx context.Context, p AssetAsk) (AssetView, error) {
	chain, err := m.owned(ctx, p)
	if err != nil {
		return AssetView{}, err
	}
	d := chain[len(chain)-1]
	if err := ResourceName(p.Name); err != nil {
		return AssetView{}, err
	}
	data, err := base64.StdEncoding.DecodeString(p.Data)
	if err != nil {
		return AssetView{}, ErrBadData
	}
	mime, err := ResourceType(p.Name, data)
	if err != nil {
		return AssetView{}, err
	}
	sum := sha256.Sum256(data)
	r, err := m.store.PutResource(ctx, d.ID, Resource{Name: p.Name, MIME: mime, SHA256: hex.EncodeToString(sum[:])}, data)
	if err != nil {
		return AssetView{}, err
	}
	n, err := m.docChanged(ctx, chain)
	return AssetView{Name: r.Name, MIME: r.MIME, Size: r.Size, Build: n}, err
}

// docChanged asks for a build when a document's files changed.
func (m *Module) docChanged(ctx context.Context, chain []Doc) (int64, error) {
	d := chain[len(chain)-1]
	if m.builds == nil {
		return 0, nil
	}
	s, err := m.store.SiteByID(ctx, d.Site)
	if err != nil {
		return 0, err
	}
	return m.changed(ctx, s, false)
}

// readable is a document whose source the caller may read: its owner's, or
// an administrator's, whose read is audited first.
func (m *Module) readable(ctx context.Context, a DocAsk) (Doc, error) {
	who, _, err := m.reader(ctx)
	if err != nil {
		return Doc{}, err
	}
	chain, err := m.find(ctx, who, a)
	if err != nil {
		return Doc{}, err
	}
	d := chain[len(chain)-1]
	if !MayAt(who, ActSource, chain) {
		return Doc{}, ErrNotYours
	}
	if ByAdminOnlyAt(who, ActSource, chain) {
		if err := m.store.NoteRead(ctx, d); err != nil {
			return Doc{}, err
		}
	}
	return d, nil
}

// AssetData is one of a document's files, its content in base64.
type AssetData struct {
	Name string `json:"name"`
	MIME string `json:"mime"`
	Data string `json:"data"`
}

func (m *Module) assetGet(ctx context.Context, p AssetAsk) (AssetData, error) {
	d, err := m.readable(ctx, DocAsk{Site: p.Site, Folder: p.Folder, Slug: p.Slug})
	if err != nil {
		return AssetData{}, err
	}
	r, data, err := m.store.ResourceData(ctx, d.ID, p.Name)
	if err != nil {
		return AssetData{}, err
	}
	return AssetData{Name: r.Name, MIME: r.MIME, Data: base64.StdEncoding.EncodeToString(data)}, nil
}

func (m *Module) assetList(ctx context.Context, p AssetAsk) ([]AssetView, error) {
	d, err := m.readable(ctx, DocAsk{Site: p.Site, Folder: p.Folder, Slug: p.Slug})
	if err != nil {
		return nil, err
	}
	rs, err := m.store.Resources(ctx, d.ID)
	if err != nil {
		return nil, err
	}
	out := []AssetView{}
	for _, r := range rs {
		out = append(out, AssetView{Name: r.Name, MIME: r.MIME, Size: r.Size})
	}
	return out, nil
}

func (m *Module) assetRemove(ctx context.Context, p AssetAsk) (struct{}, error) {
	chain, err := m.owned(ctx, p)
	if err != nil {
		return struct{}{}, err
	}
	d := chain[len(chain)-1]
	if err := m.store.RemoveResource(ctx, d.ID, p.Name); err != nil {
		return struct{}{}, err
	}
	_, err = m.docChanged(ctx, chain)
	return struct{}{}, err
}
