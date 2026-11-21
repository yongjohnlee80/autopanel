package site

import (
	"context"
	"errors"
)

// Site is a host name with pages.
type Site struct {
	ID          int64
	Host        string // lower case; under a registered domain; no route's, nor the API's
	ContentHost string // "": none. Where active html documents are served from: a host with no session
	Config      string // the site's configuration, as validated
	// SecurityGen rises whenever something public is withdrawn (a document's
	// level lowered, a public document removed). A build made before the
	// change carries the older number and is never served.
	SecurityGen int64
	CreatedAt   int64

	// Its builds: the newest asked for, and the one being served. A change
	// made in build N is live once LiveBuild is N or more.
	Build, LiveBuild int64
	BuildState       string // none, waiting, building, live or failed
	BuildError       string // the last failed build's reason
	BuiltAt          int64
	// Down: the live pages were taken down when something public was
	// withdrawn, and stay down until a build passes.
	Down bool
}

// The states of a site's build.
const (
	BuildNone     = "none"
	BuildWaiting  = "waiting"
	BuildBuilding = "building"
	BuildLive     = "live"
	BuildFailed   = "failed"
)

// Snapshot is what one build reads, as it was at one moment: the site, and
// its public documents with the digest of each source and resource. The data
// is read after, by digest: a source or a resource that has changed since
// makes the build superseded, never a mix.
type Snapshot struct {
	Site    Site // its Build is this build's number, SecurityGen the generation it carries
	Build   int64
	Folders []SnapFolder // public folders under public folders only
	Docs    []SnapDoc    // public documents under public folders only
}

// SnapDoc is one public document of a snapshot, at its path.
type SnapDoc struct {
	Doc       Doc
	Meta      string
	SHA256    string
	Path      string // its slugs from the root, joined by /
	Resources []Resource
}

// SnapFolder is one public folder of a snapshot, at its path.
type SnapFolder struct {
	Doc  Doc
	Meta string
	Path string
}

// Source is a document as it was sent.
type Source struct {
	Meta   string // its front matter, as JSON
	Body   []byte
	SHA256 string // of Body, in hex
}

// Store keeps the sites and their documents. Every change is written with
// its audit entry in one transaction; an entry names a document and its
// level, never its title or its text.
type Store interface {
	AddSite(ctx context.Context, s Site) (Site, error) // ErrSiteExists
	Sites(ctx context.Context) ([]Site, error)
	SiteByHost(ctx context.Context, host string) (Site, error) // ErrNoSite
	RemoveSite(ctx context.Context, id int64) error            // with every document; ErrNoSite
	// SetSite replaces the site's configuration and its content host, with
	// its audit entry. ErrNoSite.
	SetSite(ctx context.Context, id int64, config, contentHost string) (Site, error)
	SiteByID(ctx context.Context, id int64) (Site, error) // ErrNoSite

	// AskBuild records that the site needs a build, and answers its number.
	AskBuild(ctx context.Context, id int64) (int64, error)
	// StartBuild marks the newest build asked for as building and answers
	// what it reads, in one transaction. ErrNoBuild when none is owed.
	StartBuild(ctx context.Context, id int64) (Snapshot, error)
	// FinishBuild records build n's end: failure "" when it went live.
	FinishBuild(ctx context.Context, id, n int64, failure string, at int64) (Site, error)
	// TakeDown records that the live pages were taken down.
	TakeDown(ctx context.Context, id int64) error
	// Owed are the sites a build is owed to: asked for and not yet live or
	// failed, or interrupted.
	Owed(ctx context.Context) ([]Site, error)

	Root(ctx context.Context, site int64) (Doc, error)                 // the site's root folder
	Child(ctx context.Context, parent int64, slug string) (Doc, error) // ErrNotFound
	Children(ctx context.Context, parent int64) ([]Doc, error)         // in their order, then by slug
	Chain(ctx context.Context, id int64) ([]Doc, error)                // the node and every folder above it, the root first
	DocByID(ctx context.Context, id int64) (Doc, error)
	Docs(ctx context.Context, site int64) ([]Doc, error) // every node but the root, folders and documents
	Source(ctx context.Context, id int64) (Source, error)
	// NoteRead writes the audit entry for an administrator's read of a
	// document that only the role allowed: which document, never its text.
	NoteRead(ctx context.Context, d Doc) error

	// Create stores a new node in the folder d.Parent. Its ID is the
	// store's, and so are its first generation and version. ErrDuplicate when
	// the folder has the slug; ErrNotAFolder, ErrTooDeep, ErrPathTooLong,
	// ErrTooManyNodes for a place it cannot have.
	Create(ctx context.Context, d Doc, src Source) (Doc, error)
	// Update changes the document as change says, in one transaction with
	// the read change is given: change returns the document as it should be
	// (its ID, site, slug, format's kind of change and owner are not its to
	// alter: Owner is kept whatever it returns) and its new source, or nil
	// to keep the one it has. The version rises when the source differs; the
	// generation when the level or the share list does; and the site's
	// SecurityGen when the change lowers the level (Lowers). lowered says so.
	Update(ctx context.Context, id int64, change func(old Doc) (Doc, *Source, error)) (d Doc, lowered bool, err error)
	// Remove deletes the node, its share list and its resources; a folder
	// only when it is empty (ErrNotEmpty), never the root (ErrRoot). The
	// site's SecurityGen rises when it was public.
	Remove(ctx context.Context, id int64) (Doc, error)
	// Move puts the node into the folder parent, checked whole (ErrCycle,
	// ErrTooDeep, ErrPathTooLong, ErrTooManyNodes, ErrDuplicate). lowered: it
	// was public in effect and is no longer; the site's SecurityGen rose.
	Move(ctx context.Context, id, parent int64) (d Doc, lowered bool, err error)

	// PutResource stores one of a document's files, replacing the one of
	// exactly that name. A name that differs from an existing one only by
	// case is ErrResourceTaken; one more than MaxResources is ErrTooMany.
	// The document's version rises when the content is new.
	PutResource(ctx context.Context, doc int64, r Resource, data []byte) (Resource, error)
	Resources(ctx context.Context, doc int64) ([]Resource, error)                       // by name
	ResourceData(ctx context.Context, doc int64, name string) (Resource, []byte, error) // ErrNoResource
	RemoveResource(ctx context.Context, doc int64, name string) error                   // ErrNoResource
}

var (
	ErrNotFound   = errors.New("site: no such document")
	ErrDuplicate  = errors.New("site: the site has a document with that slug")
	ErrNoSite     = errors.New("site: no such site")
	ErrSiteExists = errors.New("site: a site has that host")
	ErrNoUser     = errors.New("site: a document's owner and the members it is shared with must be users")
	ErrNoBuild    = errors.New("site: no build is owed")
)
