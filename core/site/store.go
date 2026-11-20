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
}

var (
	ErrNotFound   = errors.New("site: no such document")
	ErrDuplicate  = errors.New("site: the site has a document with that slug")
	ErrNoSite     = errors.New("site: no such site")
	ErrSiteExists = errors.New("site: a site has that host")
	ErrNoUser     = errors.New("site: a document's owner and the members it is shared with must be users")
)
