package mail

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// DKIM, ROTATED BY AUTOPANEL — Stalwart does not make DKIM keys on request,
// and rotates them itself only when it publishes DNS itself. So the core makes
// each key, hands it to Stalwart not yet signing, publishes its record, waits
// until public resolvers answer it, and only then has Stalwart sign with it;
// the old key's record stays published a week for mail in flight. A domain
// signs nothing until its first key's record resolves.
//
// Decision: docs/decisions/mail.md#dkim-is-rotated-by-autopanel

// The rotation's timing. Variables so a test need not wait.
var (
	rotateAfter  = 90 * 24 * time.Hour // a key signs this long before the next is made
	retireAfter  = 7 * 24 * time.Hour  // an old key's record stays published this long
	settleBefore = 10 * time.Minute    // a new record is published this long before it is trusted to resolve
)

// The steps of a key's rotation, as mail_dkim keeps them.
const (
	stepCreated   = "created"   // in Stalwart, pending; its record not yet published
	stepPublished = "published" // its record is in the zone; not signing
	stepSigning   = "signing"   // Stalwart signs with it
	stepRetired   = "retired"   // no longer signs; its record stays published for retireAfter
)

// DKIMRow is one key's place in its rotation.
type DKIMRow struct {
	Selector string `json:"selector"`
	Step     string `json:"step"`
	Since    int64  `json:"since"` // when it reached Step, Unix seconds
}

// algorithms are the key pair each rotation makes: one selector each (L2).
var algorithms = []struct{ suffix, kind string }{
	{"e", "Dkim1Ed25519Sha256"},
	{"r", "Dkim1RsaSha256"},
}

// newKey makes a private key of kind, PEM (PKCS #8).
func newKey(kind string) (string, error) {
	var key any
	switch kind {
	case "Dkim1Ed25519Sha256":
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return "", err
		}
		key = k
	case "Dkim1RsaSha256":
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return "", err
		}
		key = k
	default:
		return "", fmt.Errorf("mail: no key of kind %s", kind)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

// selectorFor is a new selector for a month: ap202611e, or ap202611e2 when that
// is taken.
func selectorFor(now time.Time, suffix string, taken map[string]bool) string {
	base := "ap" + now.UTC().Format("200601") + suffix
	if !taken[base] {
		return base
	}
	for i := 2; ; i++ {
		if s := base + strconv.Itoa(i); !taken[s] {
			return s
		}
	}
}

// rotate moves one domain's keys along their rotation, and answers the
// selectors whose records the zone must hold now.
func (m *Module) rotate(ctx context.Context, c *Client, domain, domainID string, zone []Record) ([]string, error) {
	rows, err := m.store.DKIM(ctx, domain)
	if err != nil {
		return nil, err
	}
	keys, err := c.DKIMKeys(ctx)
	if err != nil {
		return nil, err
	}
	keyID := map[string]string{}
	for _, k := range keys {
		if k.DomainID == domainID {
			keyID[k.Selector] = k.ID
		}
	}
	now := m.now()
	by := map[string][]DKIMRow{}
	taken := map[string]bool{}
	for _, r := range rows {
		by[r.Step] = append(by[r.Step], r)
		taken[r.Selector] = true
	}
	oldest := func(rs []DKIMRow) time.Time {
		t := now
		for _, r := range rs {
			if s := time.Unix(r.Since, 0); s.Before(t) {
				t = s
			}
		}
		return t
	}

	// A new pair: for a domain with none, and for one whose signing pair is due.
	inFlight := len(by[stepCreated]) + len(by[stepPublished])
	if inFlight == 0 && (len(by[stepSigning]) == 0 || now.Sub(oldest(by[stepSigning])) >= rotateAfter) {
		for _, a := range algorithms {
			sel := selectorFor(now, a.suffix, taken)
			pemKey, err := newKey(a.kind)
			if err != nil {
				return nil, err
			}
			id, err := c.AddDKIM(ctx, domainID, sel, a.kind, pemKey)
			if err != nil {
				return nil, fmt.Errorf("a DKIM key for %s: %w", domain, err)
			}
			keyID[sel] = id
			taken[sel] = true
			if err := m.store.PutDKIM(ctx, domain, DKIMRow{Selector: sel, Step: stepCreated, Since: now.Unix()}); err != nil {
				return nil, err
			}
		}
		if rows, err = m.store.DKIM(ctx, domain); err != nil {
			return nil, err
		}
		by = map[string][]DKIMRow{}
		for _, r := range rows {
			by[r.Step] = append(by[r.Step], r)
		}
	}

	// Created keys are published by this pass's keep.
	for _, r := range by[stepCreated] {
		r.Step, r.Since = stepPublished, now.Unix()
		if err := m.store.PutDKIM(ctx, domain, r); err != nil {
			return nil, err
		}
	}

	// Published keys switch once their records have settled and resolve.
	if pub := by[stepPublished]; len(pub) > 0 && now.Sub(oldest(pub)) >= settleBefore {
		ready := true
		for _, r := range pub {
			want := dkimFromZone(zone, domain, []string{r.Selector})
			if len(want) != 1 || !m.resolves(ctx, want[0]) {
				ready = false
				break
			}
		}
		if ready {
			for _, r := range pub {
				if err := c.SetDKIMStage(ctx, keyID[r.Selector], "active"); err != nil {
					return nil, err
				}
			}
			for _, r := range by[stepSigning] {
				if err := c.SetDKIMStage(ctx, keyID[r.Selector], "retiring"); err != nil {
					return nil, err
				}
				r.Step, r.Since = stepRetired, now.Unix()
				if err := m.store.PutDKIM(ctx, domain, r); err != nil {
					return nil, err
				}
			}
			for _, r := range pub {
				r.Step, r.Since = stepSigning, now.Unix()
				if err := m.store.PutDKIM(ctx, domain, r); err != nil {
					return nil, err
				}
			}
			m.log.Info("mail: DKIM keys signing", "domain", domain)
		}
	}

	// Retired keys go once mail they signed has had its week.
	for _, r := range by[stepRetired] {
		if now.Sub(time.Unix(r.Since, 0)) < retireAfter {
			continue
		}
		if id := keyID[r.Selector]; id != "" {
			if err := c.RemoveDKIM(ctx, id); err != nil {
				return nil, err
			}
		}
		if err := m.store.DeleteDKIM(ctx, domain, r.Selector); err != nil {
			return nil, err
		}
	}

	rows, err = m.store.DKIM(ctx, domain)
	if err != nil {
		return nil, err
	}
	var publish []string
	for _, r := range rows {
		publish = append(publish, r.Selector)
	}
	return publish, nil
}

// resolves reports whether public resolvers answer a DKIM record with the key
// it should hold.
func (m *Module) resolves(ctx context.Context, r Record) bool {
	want := ""
	for _, part := range strings.Split(r.Value, ";") {
		if p := strings.TrimSpace(part); strings.HasPrefix(p, "p=") {
			want = p
		}
	}
	if want == "" {
		return false
	}
	got, err := m.host.ResolveTXT(ctx, r.Name)
	if err != nil {
		return false
	}
	for _, t := range got {
		if strings.Contains(strings.ReplaceAll(t, " ", ""), want) {
			return true
		}
	}
	return false
}
