package mail

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"math"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/yongjohnlee80/golib/auth/password"

	"github.com/yongjohnlee80/autopanel/core/mail/provider"
)

// MAIL APPS SIGN IN WITH APP PASSWORDS — one per device, made by Stalwart at
// AutoPanel's request, shown once, and kept only once the user says the device
// is set up. A mailbox's own password is generated here and told to no one, so
// a mail app cannot sign in with it.
//
// Decision: docs/decisions/mail.md#mail-apps-sign-in-with-app-passwords

// AppPasswordLimit is how many app passwords an account may hold: a device
// each, with room for ones left pending until the hourly pass destroys them.
const AppPasswordLimit = 20

// pendingFor is how long a new app password works before it is kept: long
// enough to type it into a phone, short enough that one shown and forgotten
// is gone before anyone could find it. Stalwart enforces it (expiresAt), so it
// holds with the core down; the hourly pass only tidies the list.
const pendingFor = 10 * time.Minute

// keepMargin: an app password this close to its expiry is treated as expired
// by keep. Stalwart revives an expired one whose expiry is cleared, so keep
// must never clear one that has passed, even between its check and its call.
const keepMargin = 5 * time.Second

// minSecretBits is the least an app password's secret must carry. Stalwart's
// is app_ and 36 of [a-z0-9] (about 186 bits); a weaker one, after an upgrade,
// stops the feature rather than being handed out.
const minSecretBits = 128

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

// strongSecret reports whether an app password's secret is what AutoPanel will
// hand out: app_, then printable ASCII with no space, carrying minSecretBits
// judged by the alphabet it draws from.
func strongSecret(s string) bool {
	rest, ok := strings.CutPrefix(s, "app_")
	if !ok || rest == "" {
		return false
	}
	var lower, upper, digit bool
	other := map[rune]bool{}
	for _, r := range rest {
		switch {
		case r <= ' ' || r > '~':
			return false
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= '0' && r <= '9':
			digit = true
		default:
			other[r] = true
		}
	}
	size := len(other)
	if lower {
		size += 26
	}
	if upper {
		size += 26
	}
	if digit {
		size += 10
	}
	// The alphabet a secret uses is judged by the classes of its characters;
	// one that repeats a few of them (a broken generator) is caught by how
	// many differ: a random 36 of [a-z0-9] has about 23.
	distinct := map[rune]bool{}
	for _, r := range rest {
		distinct[r] = true
	}
	return len(distinct) >= minDistinct && float64(len(rest))*math.Log2(float64(size)) >= minSecretBits
}

// minDistinct is the fewest different characters a secret may hold.
const minDistinct = 12

// AppPasswordAsk names an account, and an app password of it or a new one's
// device.
type AppPasswordAsk struct {
	Address     string `json:"address"`
	ID          string `json:"id"`
	Description string `json:"description"`
}

// AppPasswordView is one app password, without its secret.
type AppPasswordView struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	CreatedAt   int64  `json:"created_at"` // Unix seconds
	Pending     bool   `json:"pending"`    // not kept yet: it stops at expires_at
	ExpiresAt   int64  `json:"expires_at"` // 0: never
}

// NewAppPassword is mail.apppassword.add's answer: the secret, once, and what
// a mail app needs beside it.
type NewAppPassword struct {
	ID         string `json:"id"`
	Secret     string `json:"secret"`
	User       string `json:"user"` // the full address: a bare local part signs in to the default domain's account only
	Host       string `json:"host"`
	IMAP       int    `json:"imap"`       // implicit TLS
	SMTP       int    `json:"smtp"`       // implicit TLS
	Submission int    `json:"submission"` // STARTTLS
	ExpiresAt  int64  `json:"expires_at"`
}

// validDescription is a device's name: 1 to 64 characters, none a control.
func validDescription(d string) (string, error) {
	d = strings.TrimSpace(d)
	if d == "" || utf8.RuneCountInString(d) > 64 {
		return "", ErrBadDescription
	}
	for _, r := range d {
		if unicode.IsControl(r) {
			return "", ErrBadDescription
		}
	}
	return d, nil
}

// account is the account at an address, with Stalwart's client.
func (m *Module) account(ctx context.Context, address string) (provider.Server, provider.Account, error) {
	c, err := m.ready(ctx)
	if err != nil {
		return nil, provider.Account{}, err
	}
	local, domain, err := m.address(ctx, address)
	if err != nil {
		return nil, provider.Account{}, err
	}
	a, _, err := m.find(ctx, c, local, domain)
	return c, a, err
}

func viewOf(p provider.AppPassword) AppPasswordView {
	v := AppPasswordView{ID: p.ID, Description: p.Device, CreatedAt: p.CreatedAt.Unix()}
	if p.ExpiresAt != nil {
		v.Pending, v.ExpiresAt = true, p.ExpiresAt.Unix()
	}
	return v
}

func (m *Module) appPasswordList(ctx context.Context, p AppPasswordAsk) ([]AppPasswordView, error) {
	c, a, err := m.account(ctx, p.Address)
	if err != nil {
		return nil, err
	}
	ps, err := c.AppPasswords(ctx, a.ID)
	if err != nil {
		return nil, serverErr(err)
	}
	out := make([]AppPasswordView, 0, len(ps))
	now := m.now()
	for _, ap := range ps {
		if ap.ExpiresAt != nil && !ap.ExpiresAt.After(now) {
			continue // expired: it signs nothing in, and the hourly pass destroys it
		}
		out = append(out, viewOf(ap))
	}
	return out, nil
}

// appPasswordAdd makes an app password, pending: it works for pendingFor, and
// then stops unless mail.apppassword.keep keeps it.
func (m *Module) appPasswordAdd(ctx context.Context, p AppPasswordAsk) (NewAppPassword, error) {
	desc, err := validDescription(p.Description)
	if err != nil {
		return NewAppPassword{}, err
	}
	st, _, err := m.store.State(ctx)
	if err != nil {
		return NewAppPassword{}, err
	}
	c, a, err := m.account(ctx, p.Address)
	if err != nil {
		return NewAppPassword{}, err
	}
	expires := m.now().Add(pendingFor).Truncate(time.Second)
	made, secret, err := c.AddAppPassword(ctx, a.ID, desc, expires, AppPasswordLimit)
	if err != nil {
		return NewAppPassword{}, serverErr(err)
	}
	if !strongSecret(secret) {
		secret = ""
		if err := c.RevokeAppPassword(ctx, a.ID, made.ID); err != nil {
			m.log.Error("mail: a weak app password was made and could not be revoked; it expires on its own", "account", a.Address, "id", made.ID, "err", err)
		}
		return NewAppPassword{}, ErrWeakSecret
	}
	return NewAppPassword{ID: made.ID, Secret: secret, User: a.Address, Host: st.Host,
		IMAP: 993, SMTP: 465, Submission: 587, ExpiresAt: expires.Unix()}, nil
}

// pick is an account's app password by its id.
func pick(ps []provider.AppPassword, id string) (provider.AppPassword, bool) {
	for _, p := range ps {
		if p.ID == id {
			return p, true
		}
	}
	return provider.AppPassword{}, false
}

// appPasswordKeep clears a pending app password's expiry, once the device is
// set up. One whose expiry has passed is destroyed instead: clearing it would
// bring it back.
func (m *Module) appPasswordKeep(ctx context.Context, p AppPasswordAsk) (struct{}, error) {
	c, a, err := m.account(ctx, p.Address)
	if err != nil {
		return struct{}{}, err
	}
	ps, err := c.AppPasswords(ctx, a.ID)
	if err != nil {
		return struct{}{}, serverErr(err)
	}
	ap, ok := pick(ps, p.ID)
	switch {
	case !ok:
		return struct{}{}, ErrNoAppPassword
	case ap.ExpiresAt == nil:
		return struct{}{}, nil // kept already: asking twice is safe
	case !ap.ExpiresAt.After(m.now().Add(keepMargin)):
		if err := c.RevokeAppPassword(ctx, a.ID, ap.ID); err != nil {
			m.log.Warn("mail: an expired app password could not be destroyed; the hourly pass will", "account", a.Address, "id", ap.ID, "err", err)
		}
		return struct{}{}, ErrExpired
	}
	return struct{}{}, serverErr(c.KeepAppPassword(ctx, a.ID, ap.ID))
}

func (m *Module) appPasswordRevoke(ctx context.Context, p AppPasswordAsk) (struct{}, error) {
	c, a, err := m.account(ctx, p.Address)
	if err != nil {
		return struct{}{}, err
	}
	ps, err := c.AppPasswords(ctx, a.ID)
	if err != nil {
		return struct{}{}, serverErr(err)
	}
	if _, ok := pick(ps, p.ID); !ok {
		return struct{}{}, ErrNoAppPassword
	}
	return struct{}{}, serverErr(c.RevokeAppPassword(ctx, a.ID, p.ID))
}

// accountLock replaces a mailbox's own password, typed under an older
// AutoPanel, with one no one knows: from then on only its app passwords sign
// in. Its app passwords stay.
func (m *Module) accountLock(ctx context.Context, p AccountAsk) (struct{}, error) {
	c, a, err := m.account(ctx, p.Address)
	if err != nil {
		return struct{}{}, err
	}
	secret, err := lockedSecret()
	if err != nil {
		return struct{}{}, err
	}
	return struct{}{}, serverErr(c.SetPasswordHash(ctx, a.ID, secret))
}

// sweepAppPasswords destroys the app passwords whose expiry has passed: shown
// and never kept. They sign nothing in already; destroyed, they stop counting
// toward the account's limit.
func (m *Module) sweepAppPasswords(ctx context.Context, c provider.Server) error {
	accounts, err := c.Accounts(ctx)
	if err != nil {
		return err
	}
	now := m.now()
	var errs []error
	for _, a := range accounts {
		if a.Admin {
			continue
		}
		ps, err := c.AppPasswords(ctx, a.ID)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, p := range ps {
			if p.ExpiresAt != nil && !p.ExpiresAt.After(now) {
				if err := c.RevokeAppPassword(ctx, a.ID, p.ID); err != nil {
					errs = append(errs, err)
				}
			}
		}
	}
	return errors.Join(errs...)
}
