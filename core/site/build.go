package site

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path"
	"regexp"
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
	// Remove deletes host's pages and work.
	Remove(host string) error
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
	Scripts     []string `json:"scripts,omitempty"`
	ContentHost string   `json:"content_host,omitempty"`
}

// Kit is what the core knows of the site kit's image: the scripts a diagram
// page may load.
type Kit struct {
	Scripts []KitScript
}

// BuildInput is the build's index (build.json): what the kit lays out, at
// the paths the core chose.
type BuildInput struct {
	Build   int64         `json:"build"`
	Host    string        `json:"host"` // the site's host: its canonical addresses, its feed's and its sitemap's
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
	job, err := b.pipe.Prepare(s.Host)
	if err != nil {
		return err
	}
	in := BuildInput{Build: snap.Build, Host: s.Host, Folders: []InputFolder{}, Docs: []InputDoc{}}
	for _, f := range snap.Folders {
		in.Folders = append(in.Folders, InputFolder{Path: f.Path, Title: titleOf(f.Meta), Order: f.Doc.Order, Page: PagePath(f.Path)})
	}
	var mermaid []string
	for _, sd := range snap.Docs {
		d := sd.Doc
		dir := "docs/" + sd.Path
		src, err := b.store.Source(ctx, d.ID)
		if err != nil {
			return err
		}
		if src.SHA256 != sd.SHA256 {
			return ErrSuperseded
		}
		source := dir + "/index." + map[string]string{Markdown: "md", XMD: "x.md", HTML: "html"}[d.Format]
		if err := b.pipe.Input(job, source, src.Body); err != nil {
			return err
		}
		for _, r := range sd.Resources {
			got, data, err := b.store.ResourceData(ctx, d.ID, r.Name)
			if err != nil || got.SHA256 != r.SHA256 {
				return ErrSuperseded
			}
			if err := b.pipe.Input(job, dir+"/"+r.Name, data); err != nil {
				return err
			}
		}
		page := PagePath(sd.Path)
		draws := hasMermaid(src.Body, sd.Resources)
		if draws {
			mermaid = append(mermaid, page)
		}
		var meta json.RawMessage
		if sd.Meta != "" {
			meta = json.RawMessage(sd.Meta)
		}
		folder := ""
		if i := strings.LastIndex(sd.Path, "/"); i >= 0 {
			folder = sd.Path[:i]
		}
		in.Docs = append(in.Docs, InputDoc{Slug: d.Slug, Path: sd.Path, Folder: folder, Format: d.Format, Order: d.Order,
			Active: d.Active, Meta: meta, Source: source, Dir: dir, Page: page, Mermaid: draws})
	}
	index, err := json.Marshal(in)
	if err != nil {
		return err
	}
	if err := b.pipe.Input(job, "build.json", index); err != nil {
		return err
	}
	if err := b.pipe.Input(job, "site.json", []byte(config.JSON())); err != nil {
		return err
	}

	log, runErr := b.pipe.Run(ctx, job)
	out, err := b.pipe.TakeAway(job)
	if runErr != nil {
		return fmt.Errorf("the builder: %v\n%s", runErr, log)
	}
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
	hashes := make([]string, 0, len(b.kit.Scripts))
	scripts := make([]string, 0, len(b.kit.Scripts))
	for _, k := range b.kit.Scripts {
		hashes = append(hashes, k.Integrity)
		scripts = append(scripts, strings.TrimPrefix(k.Path, "/"))
	}
	return b.pipe.Publish(job, Manifest{Build: snap.Build, SecurityGen: s.SecurityGen, Mermaid: mermaid,
		ScriptHashes: hashes, Scripts: scripts, ContentHost: s.ContentHost})
}
