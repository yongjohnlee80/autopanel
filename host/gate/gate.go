// Package gate is the data-plane host: it serves the proxied sites from the
// routing table core/gate keeps.
package gate

import (
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"

	core "github.com/yongjohnlee80/autopanel/core/gate"
)

// Table is the routing table this host serves from.
type Table = core.Table[http.Handler]

// Handler routes each request by its canonical host and path. A host or path no
// route names gets 404, whatever the reason, so the answer discloses nothing (R13).
func Handler(t *Table) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, err := core.CanonicalHost(r.Host)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		_, h, ok := t.Match(host, r.URL.Path)
		if !ok {
			http.NotFound(w, r)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// Trusted are the peers whose CF-Connecting-IP header names the client: the
// Cloudflare ranges the deployment configures. Empty means no proxy is trusted.
type Trusted []netip.Prefix

func (t Trusted) holds(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	for _, p := range t {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// cfConnectingIP is the header Cloudflare's proxy sets to the client's address.
const cfConnectingIP = "Cf-Connecting-Ip"

// NewProxy proxies to the route's upstream. The upstream sees X-Forwarded-For,
// -Host and -Proto that the gate sets; whatever the client sent under those
// names is dropped by Rewrite. Behind Cloudflare the client is CF-Connecting-IP,
// believed only when the peer is a trusted range; from anyone else the header
// is dropped, so a client can't name itself.
func NewProxy(route core.Route, trusted Trusted) (http.Handler, error) {
	up, err := route.UpstreamURL()
	if err != nil {
		return nil, err
	}
	return &httputil.ReverseProxy{Rewrite: func(pr *httputil.ProxyRequest) {
		pr.SetURL(up)
		pr.Out.Host = pr.In.Host // the upstream sees the name the client asked for
		pr.SetXForwarded()
		cf := pr.In.Header.Get(cfConnectingIP)
		pr.Out.Header.Del(cfConnectingIP)
		if cf == "" || !trusted.holds(pr.In.RemoteAddr) {
			return
		}
		if ip, err := netip.ParseAddr(cf); err == nil {
			pr.Out.Header.Set("X-Forwarded-For", ip.String())
			pr.Out.Header.Set(cfConnectingIP, ip.String())
		}
	}}, nil
}

// Build makes a snapshot of routes, each served by NewProxy.
func Build(routes []core.Route, trusted Trusted) (*core.Snapshot[http.Handler], error) {
	return core.Build(routes, func(r core.Route) (http.Handler, error) { return NewProxy(r, trusted) })
}
