package app

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/caddyserver/certmagic"

	"github.com/yongjohnlee80/autopanel/core/gate"
	"github.com/yongjohnlee80/autopanel/internal/certs"
	"github.com/yongjohnlee80/autopanel/internal/keyslot"
	"github.com/yongjohnlee80/autopanel/internal/module"
	"github.com/yongjohnlee80/autopanel/store"
)

// cloudflareSecret names the sealed Cloudflare API token in the store.
const cloudflareSecret = "cloudflare_api_token"

// caSetting names the panel setting that holds the certificate service chosen
// in the panel: "staging" or "production". Once set it replaces
// AUTOPANEL_ACME_CA, which is then only the value a new install starts with.
const caSetting = "acme.ca"

// caURLs are the certificate services the panel offers, by name.
var caURLs = map[string]string{
	"staging":    certmagic.LetsEncryptStagingCA,
	"production": certmagic.LetsEncryptProductionCA,
}

// certSwitch holds the live certificate manager. The challenge is a deployment
// setting (ADR Q9) that changes when the Cloudflare token is set or cleared, or
// when a login unlocks the vault: the manager is rebuilt and swapped, and the
// listeners never restart.
type certSwitch struct {
	cfg   Config
	st    *store.Store
	vault *keyslot.Vault
	table *gate.Table[http.Handler]
	log   *slog.Logger
	// also admits names no route holds that may still have a certificate: the
	// mail host. Set once, before the first certificate is asked for.
	also func(host string) bool

	mu        sync.Mutex // orders rebuilds
	cur       atomic.Pointer[certs.Manager]
	challenge atomic.Value // string, for status
	ca        atomic.Value // string: the ACME directory in use, for status
}

// directory is the ACME directory to use: the panel's setting when one was
// made, the configuration's otherwise.
func (s *certSwitch) directory(ctx context.Context) (string, error) {
	name, ok, err := s.st.Setting(ctx, caSetting)
	if err != nil {
		return "", err
	}
	if url, known := caURLs[name]; ok && known {
		return url, nil
	}
	return s.cfg.CA, nil
}

// rebuild makes a manager from the store's current state and swaps it in.
func (s *certSwitch) rebuild(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ca, err := s.directory(ctx)
	if err != nil {
		return err
	}
	allowed := func(host string) bool { return s.table.Holds(host) || (s.also != nil && s.also(host)) }
	opts := certs.Options{Blobs: s.st.Blobs(s.vault), Allowed: allowed, CA: ca, Email: s.cfg.Email}
	challenge := "http-01, tls-alpn-01"
	if !s.vault.Unlocked() {
		challenge = "locked: log in to unlock"
	} else if tok, err := s.st.Secret(ctx, s.vault, cloudflareSecret); err == nil {
		p, err := certs.Cloudflare(string(tok))
		if err != nil {
			return err
		}
		opts.DNS, challenge = p, "dns-01 (cloudflare)"
	} else if !errors.Is(err, store.ErrNoSecret) {
		return err
	}
	m, err := certs.New(opts)
	if err != nil {
		return err
	}
	if old := s.cur.Swap(m); old != nil {
		old.Stop()
	}
	s.challenge.Store(challenge)
	s.ca.Store(ca)
	s.log.Info("certificates", "challenge", challenge, "ca", ca)
	return nil
}

func (s *certSwitch) Challenge() string {
	c, _ := s.challenge.Load().(string)
	return c
}

// CA is the ACME directory the current manager uses.
func (s *certSwitch) CA() string {
	c, _ := s.ca.Load().(string)
	return c
}

// tlsConfig serves every handshake from the current manager. HTTP's protocols
// come first; acme-tls/1 stays, for the TLS-ALPN challenge.
func (s *certSwitch) tlsConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) { return s.cur.Load().GetCertificate(h) },
		NextProtos:     []string{"h2", "http/1.1", "acme-tls/1"},
		MinVersion:     tls.VersionTLS12,
	}
}

// httpChallenge answers HTTP-01 from the current manager, and passes the rest to next.
func (s *certSwitch) httpChallenge(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.cur.Load().HTTPChallengeHandler(next).ServeHTTP(w, r)
	})
}

// certsModule is certs.*: the certificate service, and the Cloudflare token
// sealed in the store.
type certsModule struct{ sw *certSwitch }

// Token is certs.cloudflare.set's param.
type Token struct {
	Token string `json:"token"`
}

// CA is certs.ca.set's param: "staging" or "production".
type CA struct {
	CA string `json:"ca"`
}

// CertState is what the certs verbs answer.
type CertState struct {
	Challenge string `json:"challenge"`
	CA        string `json:"ca"` // the ACME directory in use
}

var (
	errEmptyToken = errors.New("certs: the token is empty")
	errUnknownCA  = errors.New("certs: the certificate service is staging or production")
)

func (m *certsModule) Name() string { return "certs" }

func (m *certsModule) Errors() []module.PublicError {
	return []module.PublicError{
		{Err: errEmptyToken, Code: -32170, Name: "certs.empty_token", Message: "the token is empty"},
		{Err: errUnknownCA, Code: -32172, Name: "certs.unknown_ca", Message: "the certificate service is staging or production"},
		{Err: keyslot.ErrLocked, Code: -32171, Name: "certs.locked", Message: "the vault is locked; log in as root to unlock it"},
	}
}

func (m *certsModule) Verbs() []module.Verb {
	return []module.Verb{
		module.Handle(module.Contract{Verb: "certs.ca.set", Since: 1, Param: "{ca}", Result: "{challenge, ca}", Mutates: true,
			Doc: "Chooses the Let's Encrypt service that issues certificates: staging (test certificates) or production (trusted ones). Kept in the store, where it replaces AUTOPANEL_ACME_CA. Takes effect at once."}, m.setCA),
		module.Handle(module.Contract{Verb: "certs.cloudflare.set", Since: 1, Param: "{token}", Result: "{challenge, ca}", Mutates: true,
			Doc: "Seals a Cloudflare API token (Zone.DNS:Edit) in the store; every certificate then uses DNS-01. Takes effect at once."}, m.set),
		module.Handle(module.Contract{Verb: "certs.cloudflare.clear", Since: 1, Result: "{challenge, ca}", Mutates: true,
			Doc: "Forgets the Cloudflare token; certificates go back to HTTP-01 and TLS-ALPN-01."}, m.clear),
	}
}

// state is what the verbs answer: the manager now serving.
func (m *certsModule) state() CertState {
	return CertState{Challenge: m.sw.Challenge(), CA: m.sw.CA()}
}

func (m *certsModule) setCA(ctx context.Context, p CA) (CertState, error) {
	if _, ok := caURLs[p.CA]; !ok {
		return CertState{}, errUnknownCA
	}
	if err := m.sw.st.PutSetting(ctx, caSetting, p.CA); err != nil {
		return CertState{}, err
	}
	err := m.sw.rebuild(ctx)
	return m.state(), err
}

func (m *certsModule) set(ctx context.Context, p Token) (CertState, error) {
	if p.Token == "" {
		return CertState{}, errEmptyToken
	}
	if err := m.sw.st.PutSecret(ctx, m.sw.vault, cloudflareSecret, []byte(p.Token)); err != nil {
		return CertState{}, err
	}
	err := m.sw.rebuild(ctx)
	return m.state(), err
}

func (m *certsModule) clear(ctx context.Context, _ struct{}) (CertState, error) {
	if err := m.sw.st.DeleteSecret(ctx, cloudflareSecret); err != nil {
		return CertState{}, err
	}
	err := m.sw.rebuild(ctx)
	return m.state(), err
}
