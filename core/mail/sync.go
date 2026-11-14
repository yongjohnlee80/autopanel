package mail

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// THE MAIL HOST'S CERTIFICATE AND ITS RECORDS — once mail is set up, a pass
// every hour (and after a change) hands Stalwart the mail host's certificate
// from AutoPanel's own manager, moves each domain's DKIM keys along, and keeps
// every domain's zone and the mail host's in step.
//
// Decision: docs/decisions/mail.md#the-mail-hosts-certificate-is-autopanels

// Certs is AutoPanel's certificate manager, for the mail host's name: it
// answers the certificate it holds, obtaining it first when it has none.
type Certs interface {
	For(ctx context.Context, host string) (*tls.Certificate, error)
}

// syncEvery is how often the pass runs. A variable so a test need not wait.
var syncEvery = time.Hour

// Sync is the last pass's result, for mail.records and mail.status.
type Sync struct {
	At          int64                   `json:"at"` // Unix seconds; 0 before the first
	Certificate string                  `json:"certificate"`
	Records     map[string][]RecordView `json:"records"` // by owner: each domain, and the mail host
	DKIM        map[string][]DKIMRow    `json:"dkim"`
	Errors      []string                `json:"errors"`
}

type syncState struct {
	mu   sync.Mutex
	last Sync
	kick chan struct{}
}

// kickSync asks for a pass now (after a change), without waiting for it.
func (m *Module) kickSync() {
	select {
	case m.sync.kick <- struct{}{}:
	default:
	}
}

func (m *Module) lastSync() Sync {
	m.sync.mu.Lock()
	defer m.sync.mu.Unlock()
	return m.sync.last
}

// syncAll runs one pass. It needs the vault (the API key, the DNS token).
func (m *Module) syncAll(ctx context.Context, st State) Sync {
	out := Sync{At: m.now().Unix(), Records: map[string][]RecordView{}, DKIM: map[string][]DKIMRow{}, Errors: []string{}}
	fail := func(what string, err error) { out.Errors = append(out.Errors, what+": "+err.Error()) }
	c := m.client()

	cfg, _ := m.config(ctx)
	domains, err := m.store.Domains(ctx)
	if err != nil {
		fail("the domains", err)
	}
	theirs, err := c.Domains(ctx)
	if err != nil {
		fail("Stalwart's domains", err)
	}
	ids := map[string]string{}
	for _, d := range theirs {
		ids[d.Name] = d.ID
	}
	for _, d := range domains {
		id := ids[d]
		if id == "" {
			fail(d, errors.New("Stalwart does not hold the domain"))
			continue
		}
		zoneText, err := c.ZoneFile(ctx, id)
		if err != nil {
			fail(d, err)
			continue
		}
		zone := parseZone(zoneText)
		selectors, err := m.rotate(ctx, c, d, id, zone)
		if err != nil {
			fail(d+" DKIM", err)
		}
		if rows, err := m.store.DKIM(ctx, d); err == nil {
			out.DKIM[d] = rows
		}
		if len(selectors) > 0 { // the zone file now lists the new keys too
			if zoneText, err = c.ZoneFile(ctx, id); err == nil {
				zone = parseZone(zoneText)
			}
		}
		want := append(served(zone, d, st.Host, cfg.DMARC), dkimFromZone(zone, d, selectors)...)
		views, err := m.keep(ctx, d, want)
		if err != nil && !errors.Is(err, ErrNoDNS) {
			fail(d+" DNS", err)
		}
		out.Records[d] = views
	}

	ip, err := m.host.PublicIPv4(ctx)
	if err != nil {
		fail("the mail host's address", err)
	}
	views, err := m.keep(ctx, st.Host, hostRecords(st.Host, ip))
	if err != nil && !errors.Is(err, ErrNoDNS) {
		fail(st.Host+" DNS", err)
	}
	out.Records[st.Host] = views

	// The certificate last: obtaining one can take minutes, and the records
	// must not wait for it (its challenge may even need them).
	if m.certs != nil {
		state, err := m.syncCertificate(ctx, c, st.Host)
		out.Certificate = state
		if err != nil {
			fail("the certificate", err)
		}
	}

	m.sync.mu.Lock()
	m.sync.last = out
	m.sync.mu.Unlock()
	return out
}

// config is mail's sealed settings.
func (m *Module) config(ctx context.Context) (Config, error) {
	raw, err := m.vault.Get(ctx, sealedConfig)
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	err = jsonUnmarshal(raw, &cfg)
	return cfg, err
}

// syncCertificate hands Stalwart the mail host's certificate when it does not
// serve the one AutoPanel holds. The first one is made and Stalwart restarted,
// since a new certificate is served only after a restart; a renewal is an
// update, served at once after ReloadTlsCertificates.
func (m *Module) syncCertificate(ctx context.Context, c *Client, host string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	cert, err := m.certs.For(cctx, host)
	if err != nil {
		return "not issued", err
	}
	if cert.Leaf == nil {
		if cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
			return "not issued", err
		}
	}
	have, err := c.Certificates(ctx)
	if err != nil {
		return "unknown", err
	}
	id := ""
	for _, h := range have {
		if h.SANs[host] {
			if h.NotAfter.Equal(cert.Leaf.NotAfter.UTC().Truncate(time.Second)) || h.NotAfter.Unix() == cert.Leaf.NotAfter.Unix() {
				return "ok until " + cert.Leaf.NotAfter.UTC().Format("2006-01-02"), nil
			}
			id = h.ID
		}
	}
	chainPEM, keyPEM, err := pemOf(cert)
	if err != nil {
		return "unknown", err
	}
	newID, err := c.PutCertificate(ctx, id, chainPEM, keyPEM)
	if err != nil {
		return "not handed over", err
	}
	if id == "" {
		m.log.Info("mail: the mail host's first certificate is handed to Stalwart; restarting it", "host", host, "id", newID)
		if _, err := m.restartWait(ctx); err != nil {
			return "handed over, not served", err
		}
	} else if err := c.ReloadTLS(ctx); err != nil {
		return "handed over, not served", err
	}
	return "ok until " + cert.Leaf.NotAfter.UTC().Format("2006-01-02"), nil
}

// pemOf is a certificate's chain and private key as PEM. The key is in the
// core's memory for the call only, and then in Stalwart's store.
func pemOf(c *tls.Certificate) (chain, key string, err error) {
	var b strings.Builder
	for _, der := range c.Certificate {
		b.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	k, err := x509.MarshalPKCS8PrivateKey(c.PrivateKey)
	if err != nil {
		return "", "", fmt.Errorf("the certificate's key: %w", err)
	}
	return b.String(), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k})), nil
}
