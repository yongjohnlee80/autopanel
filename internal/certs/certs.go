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
	"errors"
	"net/http"

	"github.com/caddyserver/certmagic"

	"github.com/yongjohnlee80/autopanel/core/gate"
)

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
