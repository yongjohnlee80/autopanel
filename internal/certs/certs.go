// Package certs obtains and renews the gate's TLS certificates through ACME,
// with CertMagic, keeping them in AutoPanel's store. It lives in internal/:
// CertMagic, acmez and libdns are AutoPanel's dependencies alone (ADR §4.1).
//
// The challenge is a deployment setting (ADR Q9): with no DNS provider every
// name is validated over HTTP-01 and TLS-ALPN-01, which needs the name's DNS to
// point straight at this host; with one, every name uses DNS-01, which also
// works behind Cloudflare's proxy.
package certs

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/caddyserver/certmagic"

	"github.com/yongjohnlee80/autopanel/core/gate"
)

// ACMETLS1 is the ALPN protocol of a TLS-ALPN-01 challenge handshake
// (RFC 8737): the validating server offers it alone.
const ACMETLS1 = "acme-tls/1"

// ErrUnknownHost refuses a certificate for a name no route holds.
var ErrUnknownHost = errors.New("certs: no route names this host")

// Options configure a Manager.
type Options struct {
	Blobs   Blobs                  // where certificates and keys are kept
	Allowed func(host string) bool // whether a canonical host may have a certificate: the routing table's Holds
	CA      string                 // the ACME directory: certmagic.LetsEncryptStagingCA first, then LetsEncryptProductionCA
	Email   string                 // the ACME account's contact
	DNS     certmagic.DNSProvider  // nil: HTTP-01 and TLS-ALPN-01; set: DNS-01 for every name
}

// Manager serves certificates to the gate's TLS listener and obtains them on
// demand, for allowed names only.
type Manager struct {
	cache  *certmagic.Cache
	magic  *certmagic.Config
	issuer *certmagic.ACMEIssuer
	opts   Options
}

// New builds a Manager. It starts nothing: certificates are obtained when a
// handshake asks for one, or when Manage names them.
func New(opts Options) (*Manager, error) {
	if opts.Blobs == nil || opts.Allowed == nil || opts.CA == "" || opts.Email == "" {
		return nil, errors.New("certs: Blobs, Allowed, CA and Email are required")
	}
	m := &Manager{opts: opts}
	var magic *certmagic.Config // the cache's callback reads it once New has set it
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) { return magic, nil },
	})
	magic = certmagic.New(cache, certmagic.Config{
		Storage:  &storage{blobs: opts.Blobs, locks: newLocks()},
		OnDemand: &certmagic.OnDemandConfig{DecisionFunc: m.decide},
	})
	tmpl := certmagic.ACMEIssuer{CA: opts.CA, Email: opts.Email, Agreed: true}
	if opts.DNS != nil {
		tmpl.DNS01Solver = &certmagic.DNS01Solver{DNSManager: certmagic.DNSManager{DNSProvider: opts.DNS}}
	}
	m.issuer = certmagic.NewACMEIssuer(magic, tmpl)
	magic.Issuers = []certmagic.Issuer{m.issuer}
	m.magic, m.cache = magic, cache
	return m, nil
}

// decide is CertMagic's on-demand gate: a handshake for a name no route holds
// orders nothing, so a stranger's SNI can't spend our ACME rate limits.
func (m *Manager) decide(_ context.Context, name string) error {
	host, err := gate.CanonicalHost(name)
	if err != nil || !m.opts.Allowed(host) {
		return ErrUnknownHost
	}
	return nil
}

// TLSConfig is the gate's TLS listener configuration. CertMagic's own offers
// only acme-tls/1; HTTP's protocols come first, and acme-tls/1 stays, or the
// TLS-ALPN challenge would fail.
func (m *Manager) TLSConfig() *tls.Config {
	cfg := m.magic.TLSConfig()
	cfg.NextProtos = append([]string{"h2", "http/1.1"}, cfg.NextProtos...)
	cfg.MinVersion = tls.VersionTLS12
	return cfg
}

// GetCertificate serves a handshake: CertMagic's, behind the on-demand gate.
func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return m.magic.GetCertificate(hello)
}

// For is the certificate for name, as a handshake for it would get: from the
// cache, from the store, or obtained first when the name is allowed and has
// none. With alpn it is the TLS-ALPN-01 challenge certificate of an order in
// flight for name. It serves the gate process, which terminates TLS but holds
// no store: it goes through CertMagic's own handshake entry point, so the
// on-demand gate (decide) and the challenge lookup stay CertMagic's.
//
// The certificate's Leaf is always set.
func (m *Manager) For(ctx context.Context, name string, alpn bool) (*tls.Certificate, error) {
	// CertMagic logs the hello's peer, so it needs a connection to ask.
	hello := &tls.ClientHelloInfo{ServerName: name, Conn: linkConn{}}
	if alpn {
		hello.SupportedProtos = []string{ACMETLS1}
	}
	c, err := m.magic.GetCertificateWithContext(ctx, hello)
	if err != nil {
		return nil, err
	}
	if c == nil || len(c.Certificate) == 0 {
		return nil, errors.New("certs: no certificate")
	}
	if c.Leaf == nil {
		leaf, err := x509.ParseCertificate(c.Certificate[0])
		if err != nil {
			return nil, err
		}
		cp := *c // CertMagic's own copy stays as it was
		cp.Leaf = leaf
		c = &cp
	}
	return c, nil
}

// Challenge answers an ACME HTTP-01 request the gate process received for
// host at path. ok is false for a request that is no challenge of ours: the
// gate then serves it as any other.
func (m *Manager) Challenge(ctx context.Context, host, path string) (status int, body []byte, ok bool) {
	r := (&http.Request{Method: http.MethodGet, Host: host, URL: &url.URL{Path: path}, Header: http.Header{}}).WithContext(ctx)
	w := &recorder{header: http.Header{}}
	if !m.issuer.HandleHTTPChallenge(w, r) {
		return 0, nil, false
	}
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.status, w.body, true
}

// recorder keeps what a handler wrote: the status and the body.
type recorder struct {
	header http.Header
	status int
	body   []byte
}

func (r *recorder) Header() http.Header { return r.header }

func (r *recorder) WriteHeader(status int) {
	if r.status == 0 {
		r.status = status
	}
}

func (r *recorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	r.body = append(r.body, b...)
	return len(b), nil
}

// linkConn stands for the connection of a hello that came over the link: it
// has addresses to log and carries nothing.
type linkConn struct{}

type linkAddr struct{}

func (linkAddr) Network() string { return "unix" }
func (linkAddr) String() string  { return "gate" }

func (linkConn) Read([]byte) (int, error)         { return 0, net.ErrClosed }
func (linkConn) Write([]byte) (int, error)        { return 0, net.ErrClosed }
func (linkConn) Close() error                     { return nil }
func (linkConn) LocalAddr() net.Addr              { return linkAddr{} }
func (linkConn) RemoteAddr() net.Addr             { return linkAddr{} }
func (linkConn) SetDeadline(time.Time) error      { return nil }
func (linkConn) SetReadDeadline(time.Time) error  { return nil }
func (linkConn) SetWriteDeadline(time.Time) error { return nil }

// Stop ends the manager's background renewal. A replaced manager is stopped.
func (m *Manager) Stop() { m.cache.Stop() }

// HTTPChallengeHandler answers ACME's HTTP-01 challenge on the gate's :80
// listener and passes every other request to next.
func (m *Manager) HTTPChallengeHandler(next http.Handler) http.Handler {
	return m.issuer.HTTPChallengeHandler(next)
}

// Manage obtains and keeps renewing certificates for names in the background:
// for a wildcard, which on-demand issuance can't serve. A wildcard needs DNS-01.
func (m *Manager) Manage(ctx context.Context, names []string) error {
	return m.magic.ManageAsync(ctx, names)
}
