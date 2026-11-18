package app

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/caddyserver/certmagic"

	"github.com/yongjohnlee80/autopanel/core/gate"
	"github.com/yongjohnlee80/autopanel/internal/certs"
	"github.com/yongjohnlee80/autopanel/internal/cloudflare"
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
	// extra are those names, for the list of certificates. Set with also.
	extra func() []string
	// events hears each order's end. Set once, before the first rebuild.
	events *certEvents

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
	opts := certs.Options{Blobs: s.st.Blobs(s.vault), Allowed: allowed, CA: ca, Email: s.cfg.Email, Event: s.events.on}
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
	if was, _ := s.ca.Load().(string); was != "" && was != ca {
		s.events.reset() // the other service's failures say nothing of this one's
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
	errEmptyToken   = errors.New("certs: the token is empty")
	errUnknownCA    = errors.New("certs: the certificate service is staging or production")
	errTokenRefused = cloudflare.ErrTokenRefused
	errNoCloudflare = cloudflare.ErrNoAnswer
)

// verifyCloudflare asks Cloudflare whether token is valid and active, before
// it is sealed: a mistyped token would otherwise fail every certificate's
// renewal and every mail record, long after it was set. A variable so that
// tests answer for Cloudflare.
var verifyCloudflare = verifyAt(cloudflare.API)

// verifyAt checks tokens with the API at base: errTokenRefused when it
// answers no, errNoCloudflare when it does not answer.
func verifyAt(base string) func(ctx context.Context, token string) error {
	return func(ctx context.Context, token string) error {
		c := cloudflare.New(func(context.Context) (string, error) { return token, nil })
		c.Base = base
		err := c.Verify(ctx)
		var refused *cloudflare.Error
		switch {
		case err == nil:
			return nil
		case errors.As(err, &refused):
			return errTokenRefused
		default:
			return errNoCloudflare
		}
	}
}

func (m *certsModule) Name() string { return "certs" }

func (m *certsModule) Errors() []module.PublicError {
	return []module.PublicError{
		{Err: errEmptyToken, Code: -32170, Name: "certs.empty_token", Message: "the token is empty"},
		{Err: errUnknownCA, Code: -32172, Name: "certs.unknown_ca", Message: "the certificate service is staging or production"},
		{Err: keyslot.ErrLocked, Code: -32171, Name: "certs.locked", Message: "the vault is locked; log in as root to unlock it"},
		{Err: errTokenRefused, Code: -32173, Name: "certs.token_refused", Message: "Cloudflare refused the token: check that it was copied whole and is active"},
		{Err: errNoCloudflare, Code: -32174, Name: "certs.no_cloudflare", Message: "Cloudflare did not answer, so the token was not checked or kept; try again"},
	}
}

func (m *certsModule) Verbs() []module.Verb {
	return []module.Verb{
		module.Handle(module.Contract{Verb: "certs.ca.set", Since: 1, Param: "{ca}", Result: "{challenge, ca}", Mutates: true,
			Doc: "Chooses the Let's Encrypt service that issues certificates: staging (test certificates) or production (trusted ones). Kept in the store, where it replaces AUTOPANEL_ACME_CA. Takes effect at once."}, m.setCA),
		module.Handle(module.Contract{Verb: "certs.cloudflare.set", Since: 1, Param: "{token}", Result: "{challenge, ca}", Mutates: true,
			Doc: "Checks a Cloudflare API token (Zone.Zone:Read and Zone.DNS:Edit) with Cloudflare, then seals it in the store; every certificate then uses DNS-01, and mail's records are published through it. Takes effect at once."}, m.set),
		module.Handle(module.Contract{Verb: "certs.cloudflare.clear", Since: 1, Result: "{challenge, ca}", Mutates: true,
			Doc: "Forgets the Cloudflare token; certificates go back to HTTP-01 and TLS-ALPN-01."}, m.clear),
		module.Handle(module.Contract{Verb: "certs.list", Public: true, Discloses: module.Plain, Since: 7,
			Result: "[{host, state, issuer, not_before, not_after, renew_from, error, failed_at}]",
			Doc:    "Each name AutoPanel serves and the certificate the store holds for it under the service in use: none, ok, due (the next request renews it), expired or unknown, with the last order's failure. Orders nothing."}, m.list),
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
	p.Token = strings.TrimSpace(p.Token)
	if p.Token == "" {
		return CertState{}, errEmptyToken
	}
	if err := verifyCloudflare(ctx, p.Token); err != nil {
		return CertState{}, err
	}
	return m.swap(ctx, func() error { return m.sw.st.PutSecret(ctx, m.sw.vault, cloudflareSecret, []byte(p.Token)) })
}

func (m *certsModule) clear(ctx context.Context, _ struct{}) (CertState, error) {
	return m.swap(ctx, func() error { return m.sw.st.DeleteSecret(ctx, cloudflareSecret) })
}

// swap changes the sealed token with change, then rebuilds the certificate
// service on it, as one step: when the rebuild fails, the token that was
// there before is put back and served again, so a token that cannot be used
// is never left to fail every later rebuild (the core's start among them).
func (m *certsModule) swap(ctx context.Context, change func() error) (CertState, error) {
	before, err := m.sw.st.Secret(ctx, m.sw.vault, cloudflareSecret)
	had := err == nil
	if err != nil && !errors.Is(err, store.ErrNoSecret) {
		return CertState{}, err
	}
	defer clear(before)
	if err := change(); err != nil {
		return CertState{}, err
	}
	if err := m.sw.rebuild(ctx); err != nil {
		bg := context.WithoutCancel(ctx)
		if had {
			_ = m.sw.st.PutSecret(bg, m.sw.vault, cloudflareSecret, before)
		} else {
			_ = m.sw.st.DeleteSecret(bg, cloudflareSecret)
		}
		if rerr := m.sw.rebuild(bg); rerr != nil {
			m.sw.log.Error("certs: the certificate service as it was could not be served again", "err", rerr)
		}
		return m.state(), err
	}
	return m.state(), nil
}
