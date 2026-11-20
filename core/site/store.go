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
	Site  Site // its Build is this build's number, SecurityGen the generation it carries
	Build int64
	Docs  []SnapDoc
}

// SnapDoc is one public document of a snapshot.
type SnapDoc struct {
	Doc       Doc
	Meta      string
	SHA256    string
	Resources []Resource
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

	Doc(ctx context.Context, site int64, slug string) (Doc, error) // ErrNotFound
	DocByID(ctx context.Context, id int64) (Doc, error)
	Docs(ctx context.Context, site int64) ([]Doc, error) // by slug
	Source(ctx context.Context, id int64) (Source, error)

	// Create stores a new document. Its ID is the store's, and so are its
	// first generation and version. ErrDuplicate when the site has the slug.
	Create(ctx context.Context, d Doc, src Source) (Doc, error)
	// Update changes the document as change says, in one transaction with
	// the read change is given: change returns the document as it should be
	// (its ID, site, slug, format's kind of change and owner are not its to
	// alter: Owner is kept whatever it returns) and its new source, or nil
	// to keep the one it has. The version rises when the source differs; the
	// generation when the level or the share list does; and the site's
	// SecurityGen when the change lowers the level (Lowers). lowered says so.
	Update(ctx context.Context, id int64, change func(old Doc) (Doc, *Source, error)) (d Doc, lowered bool, err error)
	// Remove deletes the document, its share list and its resources. The
	// site's SecurityGen rises when it was public.
	Remove(ctx context.Context, id int64) (Doc, error)

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
