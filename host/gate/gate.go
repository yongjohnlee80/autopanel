// Package gate is the data-plane host: it serves the proxied sites from the
// routing table core/gate keeps.
package gate

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"time"

	"github.com/yongjohnlee80/autopanel/internal/tunnel"

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
//
// An upstream behind a tunnel agent is reached through dial, a stream for
// each request: the target sees an ordinary HTTP request with the same
// headers. While the agent is away the answer is 502.
func NewProxy(route core.Route, trusted Trusted, dial TunnelDial) (http.Handler, error) {
	up, err := route.UpstreamURL()
	if err != nil {
		return nil, err
	}
	var transport http.RoundTripper
	var onError func(http.ResponseWriter, *http.Request, error)
	if agent, target, ok := tunnel.ParseAddress(route.Upstream); ok {
		// The URL's host is never resolved: the connection is the stream.
		up = &url.URL{Scheme: "http", Host: target + "." + agent + ".tunnel"}
		transport = &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				if dial == nil {
					return nil, ErrTunnelDown
				}
				return dial(ctx, agent, target)
			},
			// A stream a request: an idle connection kept for the next one
			// would hold one of the agent's streams while it waited.
			DisableKeepAlives:     true,
			ResponseHeaderTimeout: 60 * time.Second,
			ForceAttemptHTTP2:     false,
		}
		onError = tunnelDown
	}
	return &httputil.ReverseProxy{Transport: transport, ErrorHandler: onError, Rewrite: func(pr *httputil.ProxyRequest) {
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

// TunnelDial opens a stream to a tunnel agent's target.
type TunnelDial func(ctx context.Context, agent, target string) (net.Conn, error)

// tunnelDown answers a request whose tunnel could not carry it. It says the
// tunnel is down and nothing of why: the agent's name and its target's are
// the administrator's to know.
func tunnelDown(w http.ResponseWriter, _ *http.Request, _ error) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Retry-After", "30")
	w.WriteHeader(http.StatusBadGateway)
	_, _ = io.WriteString(w, "<!doctype html><title>502</title><h1>This site is not reachable right now</h1><p>The tunnel to it is down. Try again shortly.</p>\n")
}

// Build makes a snapshot of routes, each served by NewProxy. dial reaches the
// upstreams behind tunnel agents; nil where there are no tunnels to dial.
func Build(routes []core.Route, trusted Trusted, dial TunnelDial) (*core.Snapshot[http.Handler], error) {
	return core.Build(routes, func(r core.Route) (http.Handler, error) { return NewProxy(r, trusted, dial) })
}
