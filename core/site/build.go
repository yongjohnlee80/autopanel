package site

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// BUILDS — a site's public pages are built from its public documents, one
// build at a time on the host, two seconds after the last change, so an
// article and its ten images are one build. Decision: docs/decisions/site.md.

// Pipeline is the host's side of a build: its directories, the builder, and
// the swap (host/site, through the app).
type Pipeline interface {
	// Prepare makes host's work directories, empty.
	Prepare(host string) (Job, error)
	// Input writes one of the build's inputs, a path under its input.
	Input(job Job, name string, data []byte) error
	// Run runs the builder and waits; it answers the build's last lines.
	Run(ctx context.Context, job Job) (log string, err error)
	// TakeAway closes the output to the builder once it has exited, and
	// answers where it is, for the output check.
	TakeAway(job Job) (out string, err error)
	// Publish makes the checked output the core's, writes the manifest into
	// it, and swaps it live.
	Publish(job Job, m Manifest) error
	// TakeDown withdraws host's live pages at once: every public path
	// answers 503 until a build is published.
	TakeDown(host string) error
	// Remove deletes host's pages and work, and its held files.
	Remove(host string) error
	// PublishHeld makes the named files of the checked output, and the named
	// directories whole, node's held files of build: nothing else a job
	// wrote is kept.
	PublishHeld(job Job, node, build int64, files, dirs []string) error
	// SweepHeld removes every held directory of host that is not a kept
	// node's build (keep: node → build).
	SweepHeld(host string, keep map[int64]int64) error
}

// Job is one build's directories, as the pipeline knows them.
type Job struct {
	Host string
	Ref  any
}

// Manifest is the core's word on one build, written into its output after
// the check: the serving process reads it, never anything the build wrote
// of itself.
type Manifest struct {
	Build       int64 `json:"build"`
	SecurityGen int64 `json:"security_gen"`
	// Mermaid are the pages that may load the kit's scripts; ScriptHashes
	// are those scripts' hashes ("sha256-…"), which their policy names.
	Mermaid      []string `json:"mermaid,omitempty"`
	ScriptHashes []string `json:"script_hashes,omitempty"`
	// Scripts are the kit's scripts' paths: the only .js the serving process
	// serves.
	Scripts []string `json:"scripts,omitempty"`
	// Host is the site's own host, and ContentHost the one its active .html
	// documents are served from: the serving process answers the content
	// host from the directory ActiveDir of this site's pages, and nothing of
	// that directory on the site's host.
	Host        string `json:"host,omitempty"`
	ContentHost string `json:"content_host,omitempty"`
}

// Kit is what the core knows of the site kit's image: the scripts a diagram
// page may load.
type Kit struct {
	// Image is the kit's image, by digest: another image builds every page
	// again.
	Image   string
	Scripts []KitScript
}

// BuildInput is the build's index (build.json): what the kit lays out, at
// the paths the core chose.
type BuildInput struct {
	Build int64  `json:"build"`
	Host  string `json:"host"` // the site's host: its canonical addresses, its feed's and its sitemap's
	// ContentHost is where an active .html document's frame loads it from.
	ContentHost string `json:"content_host,omitempty"`
	// Held: the build is one held document's, alone; its page is at the
	// output's root, and every address it writes is under Base.
	Held    bool          `json:"held,omitempty"`
	Base    string        `json:"base,omitempty"`
	Folders []InputFolder `json:"folders"`
	Docs    []InputDoc    `json:"docs"`
}

// InputFolder is one public folder of a build: its page at Page lists its
// public children, in their order.
type InputFolder struct {
	Path  string `json:"path"`
	Title string `json:"title,omitempty"`
	Order int    `json:"order,omitempty"`
	Page  string `json:"page"`
}

// InputDoc is one document of a build: its source at Source, its files under
// Dir, its page at Page.
type InputDoc struct {
	Slug    string          `json:"slug"`
	Path    string          `json:"path"`   // its address: its folders' slugs and its own
	Folder  string          `json:"folder"` // its folder's path; "": the root
	Format  string          `json:"format"`
	Order   int             `json:"order,omitempty"`
	Active  bool            `json:"active,omitempty"`
	Meta    json.RawMessage `json:"meta,omitempty"`
	Source  string          `json:"source"`
	Dir     string          `json:"dir"`
	Page    string          `json:"page"`
	Mermaid bool            `json:"mermaid,omitempty"`

	sha string // its source's SHA-256: the core's own, never the build's
}

// PagePath is where a node's page is in the output: at its address, as
// <path>/index.html. A folder's page lists what it holds.
func PagePath(path string) string { return path + "/index.html" }

var mermaidFence = regexp.MustCompile("(?m)^[ \t]{0,3}(```|~~~)[ \t]*mermaid\\b")

// hasMermaid is the core's own reading of whether a document draws a Mermaid
// diagram: a mermaid fence in its source, or a .mmd among its files. Only its
// page may load the kit's scripts.
func hasMermaid(source []byte, rs []Resource) bool {
	if mermaidFence.Match(source) {
		return true
	}
	for _, r := range rs {
		if strings.HasSuffix(strings.ToLower(r.Name), ".mmd") {
			return true
		}
	}
	return false
}

// ErrSuperseded is a build that read a document or a level that changed
// while it ran: it is discarded, and the next build, already owed, reads the
// change.
var ErrSuperseded = errors.New("site: superseded by a change made while it ran")

// Builds runs the sites' builds.
type Builds struct {
	store    Store
	pipe     Pipeline
	kit      Kit
	log      *slog.Logger
	now      func() time.Time
	debounce time.Duration

	mu   sync.Mutex
	due  map[int64]time.Time // site → when its build may start
	wake chan struct{}
}

// NewBuilds runs builds through pipe.
func NewBuilds(store Store, pipe Pipeline, kit Kit, log *slog.Logger) *Builds {
	return &Builds{store: store, pipe: pipe, kit: kit, log: log, now: time.Now, debounce: 2 * time.Second,
		due: map[int64]time.Time{}, wake: make(chan struct{}, 1)}
}

// Ask records that site needs a build and answers its number. The build
// starts once no change has come for the debounce.
func (b *Builds) Ask(ctx context.Context, site int64) (int64, error) {
	n, err := b.store.AskBuild(ctx, site)
	if err != nil {
		return 0, err
	}
	b.schedule(site, b.debounce)
	return n, nil
}

// Lowered is called when something public was withdrawn from site: a level
// lowered, a public document removed. The live pages are taken down before
// it answers, and a build is asked for at once.
func (b *Builds) Lowered(ctx context.Context, site Site) (int64, error) {
	if err := b.pipe.TakeDown(site.Host); err != nil {
		return 0, fmt.Errorf("site: taking the pages down: %w", err)
	}
	if err := b.store.TakeDown(ctx, site.ID); err != nil {
		return 0, err
	}
	n, err := b.store.AskBuild(ctx, site.ID)
	if err != nil {
		return 0, err
	}
	b.schedule(site.ID, 0)
	return n, nil
}

// Removed deletes a removed site's pages.
func (b *Builds) Removed(host string) error {
	return b.pipe.Remove(host)
}

func (b *Builds) schedule(site int64, after time.Duration) {
	b.mu.Lock()
	b.due[site] = b.now().Add(after)
	b.mu.Unlock()
	select {
	case b.wake <- struct{}{}:
	default:
	}
}

// Run builds what is owed until ctx ends: first every build owed when the
// core stopped, then each as it falls due, one at a time.
func (b *Builds) Run(ctx context.Context) {
	if owed, err := b.store.Owed(ctx); err == nil {
		for _, s := range owed {
			b.schedule(s.ID, 0)
		}
	} else {
		b.log.Error("site: the builds owed", "err", err)
	}
	for {
		site, wait, ok := b.next()
		if ok {
			if err := b.BuildOnce(ctx, site); err != nil && !errors.Is(err, ErrNoBuild) {
				b.log.Warn("site: a build failed", "site", site, "err", err)
			}
			continue
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-b.wake:
		case <-timer.C:
		}
		timer.Stop()
	}
}

// next is the site whose build is due, or how long until one is.
func (b *Builds) next() (int64, time.Duration, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	wait := time.Hour
	for site, at := range b.due {
		if !at.After(now) {
			delete(b.due, site)
			return site, 0, true
		}
		wait = min(wait, at.Sub(now))
	}
	return 0, wait, false
}

// BuildOnce runs the newest build owed to site, start to finish: the
// snapshot, the inputs, the builder, the output check, the swap. A failure
// leaves the pages that were served (or the site down, if it was down) and
// is recorded with its reason.
func (b *Builds) BuildOnce(ctx context.Context, siteID int64) error {
	snap, err := b.store.StartBuild(ctx, siteID)
	if err != nil {
		return err
	}
	failure := ""
	berr := b.build(ctx, snap)
	if berr != nil {
		failure = berr.Error()
		if errors.Is(berr, ErrSuperseded) {
			b.schedule(siteID, 0)
		}
	}
	_, ferr := b.store.FinishBuild(context.WithoutCancel(ctx), siteID, snap.Build, failure, b.now().Unix())
	return errors.Join(berr, ferr)
}

func (b *Builds) build(ctx context.Context, snap Snapshot) error {
	s := snap.Site
	config, err := StoredConfig(s)
	if err != nil {
		return err
	}
	// The public pages, unless they are already built from this very input.
	if fp := b.publicFingerprint(snap); fp != snap.PublicBuilt || s.Down || s.LiveBuild == 0 {
		if err := b.buildPublic(ctx, snap, config); err != nil {
			return err
		}
		if err := b.store.SetPublicBuilt(ctx, s.ID, fp); err != nil {
			return err
		}
	}
	// Each held document alone, when what is built of it is not from this
	// input. One that fails keeps what it had, and the others are still built.
	keep := map[int64]int64{}
	var failed []string
	for _, sd := range snap.Held {
		id := sd.Doc.ID
		fp := b.heldFingerprint(s, sd)
		was, built := snap.HeldBuilt[id]
		if built && was.Fingerprint == fp {
			keep[id] = was.Build
			continue
		}
		err := b.buildHeld(ctx, snap, sd, config, fp)
		switch {
		case errors.Is(err, ErrSuperseded), errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			return err
		case errors.Is(err, ErrNotFound): // removed while it was built
		case err != nil:
			// The reason may quote the document: it goes to the log the owner
			// and an administrator read, never to the site's status.
			b.log.Warn("site: a held document's build failed", "site", s.Host, "node", id, "err", err)
			failed = append(failed, strconv.FormatInt(id, 10))
			if built {
				keep[id] = was.Build
			}
		default:
			keep[id] = snap.Build
		}
	}
	for id := range snap.HeldBuilt {
		if _, ok := keep[id]; !ok {
			if err := b.store.DropHeld(ctx, id); err != nil {
				return err
			}
		}
	}
	if err := b.pipe.SweepHeld(s.Host, keep); err != nil {
		return err
	}
	if len(failed) > 0 {
		return fmt.Errorf("the build of %d held document(s) failed (node %s): see the core's log", len(failed), strings.Join(failed, ", "))
	}
	return nil
}

// fingerprint is the SHA-256 of what a build reads, as JSON.
func fingerprint(v any) string {
	raw, _ := json.Marshal(v)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

type fpDoc struct {
	Path, Format, Meta, SHA string
	Order                   int
	Active                  bool
	Resources               [][2]string
}

func fpOf(sd SnapDoc) fpDoc {
	d := fpDoc{Path: sd.Path, Format: sd.Doc.Format, Meta: sd.Meta, SHA: sd.SHA256, Order: sd.Doc.Order, Active: sd.Doc.Active}
	for _, r := range sd.Resources {
		d.Resources = append(d.Resources, [2]string{r.Name, r.SHA256})
	}
	return d
}

// publicFingerprint names the public pages' whole input: the configuration,
// the kit, the generation, and every public folder and document.
func (b *Builds) publicFingerprint(snap Snapshot) string {
	type folder struct {
		Path, Meta string
		Order      int
	}
	in := struct {
		Config, ContentHost, Host string
		Kit                       Kit
		Gen                       int64
		Folders                   []folder
		Docs                      []fpDoc
	}{Config: snap.Site.Config, ContentHost: snap.Site.ContentHost, Host: snap.Site.Host, Kit: b.kit, Gen: snap.Site.SecurityGen}
	for _, f := range snap.Folders {
		in.Folders = append(in.Folders, folder{f.Path, f.Meta, f.Doc.Order})
	}
	for _, d := range snap.Docs {
		in.Docs = append(in.Docs, fpOf(d))
	}
	return fingerprint(in)
}

// heldFingerprint names one held document's input: itself, where it is read
// (its base changes with its address and its surface), the configuration
// and the kit. Who may read it is not in it: the page does not hold that.
func (b *Builds) heldFingerprint(s Site, sd SnapDoc) string {
	return fingerprint(struct {
		Config, Host, Base string
		Kit                Kit
		Doc                fpDoc
	}{s.Config, s.Host, HeldBase(s.Host, sd), b.kit, fpOf(sd)})
}

// HeldBase is the path a held document's page, its stylesheets and its files
// are all under, on the host it is read at: its own address on the site's
// host, or /s/<site host>/<address> on the app host.
func HeldBase(host string, sd SnapDoc) string {
	if sd.Surface == SurfaceApp {
		return AppPrefix + host + "/" + sd.Path
	}
	return "/" + sd.Path
}

// AppPrefix is where the app host serves the sites' internal and private
// documents: /s/<site host>/<address>/.
const AppPrefix = "/s/"

// writeDoc writes one document's source and files into the job's input, and
// answers its entry in the build's index.
func (b *Builds) writeDoc(ctx context.Context, job Job, sd SnapDoc, page string) (InputDoc, error) {
	d := sd.Doc
	dir := "docs/" + sd.Path
	src, err := b.store.Source(ctx, d.ID)
	if err != nil {
		return InputDoc{}, err
	}
	if src.SHA256 != sd.SHA256 {
		return InputDoc{}, ErrSuperseded
	}
	source := dir + "/index." + map[string]string{Markdown: "md", XMD: "x.md", HTML: "html"}[d.Format]
	if err := b.pipe.Input(job, source, src.Body); err != nil {
		return InputDoc{}, err
	}
	for _, r := range sd.Resources {
		got, data, err := b.store.ResourceData(ctx, d.ID, r.Name)
		if err != nil || got.SHA256 != r.SHA256 {
			return InputDoc{}, ErrSuperseded
		}
		if err := b.pipe.Input(job, dir+"/"+r.Name, data); err != nil {
			return InputDoc{}, err
		}
	}
	var meta json.RawMessage
	if sd.Meta != "" {
		meta = json.RawMessage(sd.Meta)
	}
	folder := ""
	if i := strings.LastIndex(sd.Path, "/"); i >= 0 {
		folder = sd.Path[:i]
	}
	return InputDoc{Slug: d.Slug, Path: sd.Path, Folder: folder, Format: d.Format, Order: d.Order, Active: d.Active,
		Meta: meta, Source: source, Dir: dir, Page: page, Mermaid: hasMermaid(src.Body, sd.Resources), sha: src.SHA256}, nil
}

func (b *Builds) kitManifest() (hashes, scripts []string) {
	for _, k := range b.kit.Scripts {
		hashes = append(hashes, k.Integrity)
		scripts = append(scripts, strings.TrimPrefix(k.Path, "/"))
	}
	return hashes, scripts
}

// buildPublic builds the site's public pages and swaps them live.
func (b *Builds) buildPublic(ctx context.Context, snap Snapshot, config Config) error {
	s := snap.Site
	job, err := b.pipe.Prepare(s.Host)
	if err != nil {
		return err
	}
	in := BuildInput{Build: snap.Build, Host: s.Host, ContentHost: s.ContentHost, Folders: []InputFolder{}, Docs: []InputDoc{}}
	active := map[string]string{} // an active document's address → its source's SHA-256
	for _, f := range snap.Folders {
		in.Folders = append(in.Folders, InputFolder{Path: f.Path, Title: titleOf(f.Meta), Order: f.Doc.Order, Page: PagePath(f.Path)})
	}
	var mermaid []string
	for _, sd := range snap.Docs {
		doc, err := b.writeDoc(ctx, job, sd, PagePath(sd.Path))
		if err != nil {
			return err
		}
		if doc.Active {
			if s.ContentHost == "" {
				return fmt.Errorf("%s runs its scripts, and the site has no content host", sd.Path)
			}
			active[sd.Path] = doc.sha
		}
		if doc.Mermaid {
			mermaid = append(mermaid, doc.Page)
		}
		in.Docs = append(in.Docs, doc)
	}
	if err := b.writeIndex(job, in, config); err != nil {
		return err
	}
	out, err := b.run(ctx, job)
	if err != nil {
		return err
	}
	pages := map[string]bool{}
	for _, p := range mermaid {
		pages[p] = true
	}
	if _, err := CheckOutput(out, CheckOptions{
		Mermaid:     func(p string) bool { return pages[path.Clean(p)] },
		KitScripts:  b.kit.Scripts,
		ContentHost: s.ContentHost,
		Active:      active,
	}); err != nil {
		return err
	}
	now, err := b.store.SiteByID(ctx, s.ID)
	if err != nil {
		return err
	}
	if now.SecurityGen != s.SecurityGen {
		return ErrSuperseded // something public was withdrawn while it ran: its output may hold it
	}
	hashes, scripts := b.kitManifest()
	return b.pipe.Publish(job, Manifest{Build: snap.Build, SecurityGen: s.SecurityGen, Mermaid: mermaid,
		ScriptHashes: hashes, Scripts: scripts, Host: s.Host, ContentHost: s.ContentHost})
}

func (b *Builds) writeIndex(job Job, in BuildInput, config Config) error {
	index, err := json.Marshal(in)
	if err != nil {
		return err
	}
	if err := b.pipe.Input(job, "build.json", index); err != nil {
		return err
	}
	return b.pipe.Input(job, "site.json", []byte(config.JSON()))
}

// run runs the builder on job and answers where its output is, closed to it.
func (b *Builds) run(ctx context.Context, job Job) (string, error) {
	log, runErr := b.pipe.Run(ctx, job)
	out, err := b.pipe.TakeAway(job)
	if runErr != nil {
		return "", fmt.Errorf("the builder: %v\n%s", runErr, log)
	}
	return out, err
}

// HeldPage is a held document's page, at the root of its own directory.
const HeldPage = "index.html"

// heldDirs are the kit's own files of a held build, copied whole after the
// output check has read each of them.
var heldDirs = []string{"_astro", "_kit"}

// buildHeld builds one held document alone, in a workspace of its own: the
// build sees this document, its files, the site's configuration and the kit,
// and nothing of any other document. Of its checked output the core keeps
// the files it expects (the page, the look, the inert copy, the document's
// images, the kit's own) and nothing else.
func (b *Builds) buildHeld(ctx context.Context, snap Snapshot, sd SnapDoc, config Config, fp string) error {
	s := snap.Site
	if sd.Doc.Active {
		return ErrActiveHeld
	}
	job, err := b.pipe.Prepare(s.Host)
	if err != nil {
		return err
	}
	doc, err := b.writeDoc(ctx, job, sd, HeldPage)
	if err != nil {
		return err
	}
	base := HeldBase(s.Host, sd)
	in := BuildInput{Build: snap.Build, Host: s.Host, Held: true, Base: base, Folders: []InputFolder{}, Docs: []InputDoc{doc}}
	if err := b.writeIndex(job, in, config); err != nil {
		return err
	}
	out, err := b.run(ctx, job)
	if err != nil {
		return err
	}
	if _, err := CheckOutput(out, CheckOptions{
		Mermaid:    func(p string) bool { return doc.Mermaid && path.Clean(p) == HeldPage },
		KitScripts: b.kit.Scripts,
		Base:       base,
	}); err != nil {
		return err
	}
	files := []string{HeldPage, "look.css"}
	if sd.Doc.Format == HTML {
		files = append(files, InertPage)
	}
	for _, r := range sd.Resources {
		if strings.HasPrefix(r.MIME, "image/") {
			files = append(files, r.Name)
		}
	}
	if err := b.pipe.PublishHeld(job, sd.Doc.ID, snap.Build, files, heldDirs); err != nil {
		return err
	}
	return b.store.SetHeldBuilt(ctx, HeldBuild{Node: sd.Doc.ID, Site: s.ID, Fingerprint: fp, Build: snap.Build, Mermaid: doc.Mermaid, BuiltAt: b.now().Unix()})
}
