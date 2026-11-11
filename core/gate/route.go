package gate

import (
	"errors"
	"net/url"
	"strings"
)

// RouteID is a route's identity in the store.
type RouteID int64

// Route sends requests for Host whose path starts with PathPrefix to Upstream.
type Route struct {
	ID         RouteID
	Host       string // canonical (CanonicalHost)
	PathPrefix string // "/" or "/segment[/…]", no trailing slash except "/"
	Upstream   string // an absolute http or https URL
}

var (
	// ErrBadPrefix is a path prefix that is not "/" or a clean absolute path.
	ErrBadPrefix = errors.New("gate: a path prefix must be \"/\" or an absolute path without a trailing slash")
	// ErrBadUpstream is an upstream that is not an absolute http(s) URL with a host.
	ErrBadUpstream = errors.New("gate: an upstream must be an http or https URL with a host and no credentials")
)

// Normalize returns r in canonical form, or why it can't be routed.
func (r Route) Normalize() (Route, error) {
	h, err := CanonicalHost(r.Host)
	if err != nil {
		return Route{}, err
	}
	r.Host = h
	if r.PathPrefix == "" {
		r.PathPrefix = "/"
	}
	if !strings.HasPrefix(r.PathPrefix, "/") || (r.PathPrefix != "/" && strings.HasSuffix(r.PathPrefix, "/")) ||
		strings.Contains(r.PathPrefix, "//") || strings.ContainsAny(r.PathPrefix, "?#") {
		return Route{}, ErrBadPrefix
	}
	u, err := url.Parse(r.Upstream)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return Route{}, ErrBadUpstream // credentials in an upstream URL would be lent to whatever it names (R17)
	}
	return r, nil
}

// UpstreamURL is the parsed upstream of a normalized route.
func (r Route) UpstreamURL() (*url.URL, error) { return url.Parse(r.Upstream) }

// matches reports whether path falls under the prefix on a segment boundary:
// "/api" matches "/api" and "/api/x", never "/apix".
func (r Route) matches(path string) bool {
	if r.PathPrefix == "/" {
		return true
	}
	return path == r.PathPrefix || strings.HasPrefix(path, r.PathPrefix+"/")
}
