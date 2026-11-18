package stalwart

import (
	"crypto/rand"
	"encoding/base64"

	"context"
	"errors"
	"fmt"
	"github.com/yongjohnlee80/golib/auth/password"
	"strings"
	"time"

	"github.com/yongjohnlee80/autopanel/core/mail/provider"
)

// server is provider.Server on Stalwart's JMAP API. What Stalwart does that
// the neutral contract does not say is handled here (tested against the
// pinned v1.1.0; docs/decisions/mail.md):
//
//   - an account's app passwords are entries of its credentials map: a new
//     password is a patch of the Password entry, found by its type, never the
//     map (which would delete them all);
//   - its quotas are a map too: the disk quota and the app passwords' limit
//     are patched one at a time;
//   - the limit is 5 app passwords unless set; AddAppPassword raises it to
//     the room asked for;
//   - a DKIM key's kind is its algorithm; a new certificate is served only
//     after a restart, an updated one after ReloadTlsCertificates.
type server struct{ c *Client }

var _ provider.Server = server{}

// refused turns Stalwart's refusals into the provider's errors, with its words.
func refused(err error) error {
	var se *SetError
	var me *MethodError
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrUnauthorized):
		return fmt.Errorf("%w: %w", provider.ErrUnauthorized, err)
	case errors.As(err, &se) && se.Type == "overQuota":
		return fmt.Errorf("%w: %s", provider.ErrOverLimit, se.Description)
	case errors.As(err, &se):
		return &provider.Refusal{Why: strings.TrimSpace(se.Type + ": " + se.Description)}
	case errors.As(err, &me):
		return &provider.Refusal{Why: strings.TrimSpace(me.Type + ": " + me.Description)}
	}
	return err
}

func (s server) Domains(ctx context.Context) ([]provider.Domain, error) {
	ds, err := s.c.Domains(ctx)
	out := make([]provider.Domain, 0, len(ds))
	for _, d := range ds {
		out = append(out, provider.Domain{ID: d.ID, Name: d.Name})
	}
	return out, refused(err)
}

func (s server) AddDomain(ctx context.Context, name string) (provider.Domain, error) {
	d, err := s.c.AddDomain(ctx, name)
	return provider.Domain{ID: d.ID, Name: d.Name}, refused(err)
}

func (s server) RemoveDomain(ctx context.Context, id string) error {
	return refused(s.c.RemoveDomain(ctx, id))
}

func (s server) Records(ctx context.Context, domainID string) ([]provider.Record, error) {
	text, err := s.c.ZoneFile(ctx, domainID)
	if err != nil {
		return nil, refused(err)
	}
	return parseZone(text), nil
}

func (s server) Accounts(ctx context.Context) ([]provider.Account, error) {
	as, err := s.c.Accounts(ctx)
	if err != nil {
		return nil, refused(err)
	}
	out := make([]provider.Account, 0, len(as))
	for _, a := range as {
		v := provider.Account{ID: a.ID, Local: a.Name, DomainID: a.DomainID, Address: a.Address,
			Quota: a.Quota, Used: a.Used, Admin: a.Admin}
		for _, al := range a.Aliases {
			v.Aliases = append(v.Aliases, provider.Alias{Local: al.Name, DomainID: al.DomainID})
		}
		out = append(out, v)
	}
	return out, nil
}

func (s server) AddAccount(ctx context.Context, a provider.NewAccount) (string, error) {
	secret, err := lockedSecret()
	if err != nil {
		return "", err
	}
	id, err := s.c.AddAccount(ctx, NewAccount{Name: a.Local, DomainID: a.DomainID, Secret: secret,
		Quota: a.Quota, AppPasswords: int64(a.AppPasswords)})
	return id, refused(err)
}

func (s server) LockPassword(ctx context.Context, accountID string) error {
	secret, err := lockedSecret()
	if err != nil {
		return err
	}
	return refused(s.c.SetSecret(ctx, accountID, secret))
}

// lockedHasher hashes a mailbox's own password, which is 32 random bytes no one
// is told: the hash's cost protects nothing (no one can guess 256 bits), and
// Stalwart pays it at every failed sign-in, in a 250 MB container. So the
// least argon2id golib allows.
var lockedHasher = password.Argon2id{Memory: 8 * 1024, Time: 1, Parallelism: 1, SaltLen: 16, KeyLen: 32}

// lockedSecret is a password no one knows, as the hash Stalwart verifies.
// Neither the password nor the hash is kept.
func lockedSecret() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	defer clear(b[:])
	return lockedHasher.Hash(base64.RawStdEncoding.EncodeToString(b[:]))
}

func (s server) SetQuota(ctx context.Context, accountID string, bytes int64) error {
	return refused(s.c.SetQuota(ctx, accountID, bytes))
}

func (s server) RemoveAccount(ctx context.Context, accountID string) error {
	return refused(s.c.RemoveAccount(ctx, accountID))
}

func (s server) AppPasswords(ctx context.Context, accountID string) ([]provider.AppPassword, error) {
	ps, err := s.c.AppPasswords(ctx, accountID)
	if err != nil {
		return nil, refused(err)
	}
	out := make([]provider.AppPassword, 0, len(ps))
	for _, p := range ps {
		out = append(out, provider.AppPassword{ID: p.ID, Device: p.Description, CreatedAt: p.CreatedAt, ExpiresAt: p.ExpiresAt})
	}
	return out, nil
}

func (s server) AddAppPassword(ctx context.Context, accountID, device string, expires time.Time, room int) (provider.AppPassword, string, error) {
	as, err := s.c.Accounts(ctx)
	if err != nil {
		return provider.AppPassword{}, "", refused(err)
	}
	for _, a := range as {
		if a.ID == accountID && a.AppPasswordLimit < int64(room) { // 0: unset, Stalwart's 5 applies
			if err := s.c.SetAppPasswordLimit(ctx, accountID, int64(room)); err != nil {
				return provider.AppPassword{}, "", refused(err)
			}
		}
	}
	p, secret, err := s.c.AddAppPassword(ctx, accountID, device, expires)
	if err != nil {
		return provider.AppPassword{}, "", refused(err)
	}
	return provider.AppPassword{ID: p.ID, Device: p.Description, CreatedAt: p.CreatedAt, ExpiresAt: p.ExpiresAt}, secret, nil
}

func (s server) KeepAppPassword(ctx context.Context, accountID, id string) error {
	return refused(s.c.KeepAppPassword(ctx, accountID, id))
}

func (s server) RevokeAppPassword(ctx context.Context, accountID, id string) error {
	return refused(s.c.RevokeAppPassword(ctx, accountID, id))
}

// kinds are Stalwart's DKIM signature kinds, by algorithm.
var kinds = map[provider.DKIMAlg]string{
	provider.Ed25519: "Dkim1Ed25519Sha256",
	provider.RSA:     "Dkim1RsaSha256",
}

func algOf(kind string) provider.DKIMAlg {
	for a, k := range kinds {
		if k == kind {
			return a
		}
	}
	return provider.DKIMAlg(kind)
}

func (s server) DKIMKeys(ctx context.Context) ([]provider.DKIMKey, error) {
	ks, err := s.c.DKIMKeys(ctx)
	if err != nil {
		return nil, refused(err)
	}
	out := make([]provider.DKIMKey, 0, len(ks))
	for _, k := range ks {
		out = append(out, provider.DKIMKey{ID: k.ID, DomainID: k.DomainID, Selector: k.Selector, Alg: algOf(k.Kind), Stage: provider.DKIMStage(k.Stage)})
	}
	return out, nil
}

func (s server) AddDKIMKey(ctx context.Context, domainID, selector string, alg provider.DKIMAlg, privatePEM string) (string, error) {
	kind, ok := kinds[alg]
	if !ok {
		return "", &provider.Refusal{Why: "no DKIM algorithm " + string(alg)}
	}
	id, err := s.c.AddDKIM(ctx, domainID, selector, kind, privatePEM)
	return id, refused(err)
}

func (s server) SetDKIMStage(ctx context.Context, id string, st provider.DKIMStage) error {
	return refused(s.c.SetDKIMStage(ctx, id, string(st)))
}

func (s server) RemoveDKIMKey(ctx context.Context, id string) error {
	return refused(s.c.RemoveDKIM(ctx, id))
}

func (s server) Certificates(ctx context.Context) ([]provider.Certificate, error) {
	cs, err := s.c.Certificates(ctx)
	if err != nil {
		return nil, refused(err)
	}
	out := make([]provider.Certificate, 0, len(cs))
	for _, c := range cs {
		out = append(out, provider.Certificate{ID: c.ID, SANs: c.SANs, NotAfter: c.NotAfter})
	}
	return out, nil
}

// ServeCertificate: Stalwart serves a new certificate only after a restart,
// and an updated one at once after ReloadTlsCertificates.
func (s server) ServeCertificate(ctx context.Context, id, chainPEM, keyPEM string) (bool, error) {
	if _, err := s.c.PutCertificate(ctx, id, chainPEM, keyPEM); err != nil {
		return false, refused(err)
	}
	if id == "" {
		return true, nil
	}
	return false, refused(s.c.ReloadTLS(ctx))
}
