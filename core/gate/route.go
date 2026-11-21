package gate

import (
	"errors"
	"github.com/yongjohnlee80/autopanel/internal/tunnel"
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
	Upstream   string // an absolute http or https URL, or tunnel://<agent>/<target>
}

var (
	// ErrBadPrefix is a path prefix that is not "/" or a clean absolute path.
	ErrBadPrefix = errors.New("gate: a path prefix must be \"/\" or an absolute path without a trailing slash")
	// ErrBadUpstream is an upstream that is neither an absolute http(s) URL
	// with a host nor a tunnel agent's target.
	ErrBadUpstream = errors.New("gate: an upstream must be an http or https URL with a host and no credentials, or tunnel://<agent>/<target>")
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
	if r.Upstream == SiteUpstream {
		// AutoPanel's own site, served by its serving process: only on a route
		// the core made (a negative ID; a stored route's is positive), and
		// never with a path of its own, so no route names a socket.
		if r.ID >= 0 || r.PathPrefix != "/" {
			return Route{}, ErrBadUpstream
		}
		return r, nil
	}
	if strings.HasPrefix(r.Upstream, tunnel.Scheme) {
		// A service behind a tunnel agent, by the agent's name and the
		// target's: where it leads is the agent's file's to say.
		if _, _, ok := tunnel.ParseAddress(r.Upstream); !ok {
			return Route{}, ErrBadUpstream
		}
		return r, nil
	}
	u, err := url.Parse(r.Upstream)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return Route{}, ErrBadUpstream // credentials in an upstream URL would be lent to whatever it names (R17)
	}
	return r, nil
}

// SiteUpstream is the upstream of a route the core makes for each of
// AutoPanel's sites: the gate dials the serving process's socket, at the
// path it was told at its start, for it.
const SiteUpstream = "site:"

// SiteRoute is the route the core makes for the site of id at host.
func SiteRoute(id int64, host string) Route {
	return Route{ID: RouteID(-id), Host: host, PathPrefix: "/", Upstream: SiteUpstream}
}

// IsSite reports whether r is a site's route.
func (r Route) IsSite() bool { return r.Upstream == SiteUpstream && r.ID < 0 }

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
