package app

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/yongjohnlee80/autopanel/core/gate"
	"github.com/yongjohnlee80/autopanel/internal/certs"
	"github.com/yongjohnlee80/autopanel/internal/keyslot"
	"github.com/yongjohnlee80/autopanel/internal/module"
	"github.com/yongjohnlee80/autopanel/store"
)

// cloudflareSecret names the sealed Cloudflare API token in the store.
const cloudflareSecret = "cloudflare_api_token"

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

	mu        sync.Mutex // orders rebuilds
	cur       atomic.Pointer[certs.Manager]
	challenge atomic.Value // string, for status
}

// rebuild makes a manager from the store's current state and swaps it in.
func (s *certSwitch) rebuild(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	opts := certs.Options{Blobs: s.st.Blobs(s.vault), Allowed: s.table.Holds, CA: s.cfg.CA, Email: s.cfg.Email}
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
	s.log.Info("certificates", "challenge", challenge, "ca", s.cfg.CA)
	return nil
}

func (s *certSwitch) Challenge() string {
	c, _ := s.challenge.Load().(string)
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

// certsModule is certs.*: the Cloudflare token, sealed in the store.
type certsModule struct{ sw *certSwitch }

// Token is certs.cloudflare.set's param.
type Token struct {
	Token string `json:"token"`
}

// CertState is what the certs verbs answer.
type CertState struct {
	Challenge string `json:"challenge"`
}

var errEmptyToken = errors.New("certs: the token is empty")

func (m *certsModule) Name() string { return "certs" }

func (m *certsModule) Errors() []module.PublicError {
	return []module.PublicError{
		{Err: errEmptyToken, Code: -32170, Name: "certs.empty_token", Message: "the token is empty"},
		{Err: keyslot.ErrLocked, Code: -32171, Name: "certs.locked", Message: "the vault is locked; log in as root to unlock it"},
	}
}

func (m *certsModule) Verbs() []module.Verb {
	return []module.Verb{
		module.Handle(module.Contract{Verb: "certs.cloudflare.set", Since: 1, Param: "{token}", Result: "{challenge}", Mutates: true,
			Doc: "Seals a Cloudflare API token (Zone.DNS:Edit) in the store; every certificate then uses DNS-01. Takes effect at once."}, m.set),
		module.Handle(module.Contract{Verb: "certs.cloudflare.clear", Since: 1, Result: "{challenge}", Mutates: true,
			Doc: "Forgets the Cloudflare token; certificates go back to HTTP-01 and TLS-ALPN-01."}, m.clear),
	}
}

func (m *certsModule) set(ctx context.Context, p Token) (CertState, error) {
	if p.Token == "" {
		return CertState{}, errEmptyToken
	}
	if err := m.sw.st.PutSecret(ctx, m.sw.vault, cloudflareSecret, []byte(p.Token)); err != nil {
		return CertState{}, err
	}
	err := m.sw.rebuild(ctx)
	return CertState{Challenge: m.sw.Challenge()}, err
}

func (m *certsModule) clear(ctx context.Context, _ struct{}) (CertState, error) {
	if err := m.sw.st.DeleteSecret(ctx, cloudflareSecret); err != nil {
		return CertState{}, err
	}
	err := m.sw.rebuild(ctx)
	return CertState{Challenge: m.sw.Challenge()}, err
}
