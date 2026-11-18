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

	"github.com/yongjohnlee80/autopanel/core/mail/provider"
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
	// Address is the host's public address, and Reverse the names it resolves
	// back to: a mail host whose address does not name it back is refused by
	// many receivers. ReverseKnown is false when the lookup itself failed.
	Address      string   `json:"address"`
	Reverse      []string `json:"reverse"`
	ReverseKnown bool     `json:"reverse_known"`
	// Port25 is whether a connection out to port 25 got through: "ok",
	// "blocked", or "" before the first try.
	Port25 string `json:"port25"`
}

// port25Every is how often the way out to port 25 is tried once it works: a
// provider's block does not come and go by the hour.
const port25Every = 24 * time.Hour

type syncState struct {
	mu   sync.Mutex
	last Sync
	kick chan struct{}

	port25At time.Time // when the way out to port 25 was last tried; the pass's alone
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
		fail("the mail server's domains", err)
	}
	ids := map[string]string{}
	for _, d := range theirs {
		ids[d.Name] = d.ID
	}
	for _, d := range domains {
		id := ids[d]
		if id == "" {
			fail(d, errors.New("the mail server does not hold the domain"))
			continue
		}
		zone, err := c.Records(ctx, id)
		if err != nil {
			fail(d, err)
			continue
		}
		selectors, err := m.rotate(ctx, c, d, id, zone)
		if err != nil {
			fail(d+" DKIM", err)
		}
		if rows, err := m.store.DKIM(ctx, d); err == nil {
			out.DKIM[d] = rows
		}
		if len(selectors) > 0 { // the server's records now list the new keys too
			if again, err := c.Records(ctx, id); err == nil {
				zone = again
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
	m.syncReachability(ctx, &out, ip)

	if err := m.sweepAppPasswords(ctx, c); err != nil {
		fail("expired app passwords", err)
	}

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
func (m *Module) syncCertificate(ctx context.Context, c provider.Server, host string) (string, error) {
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
	restart, err := c.ServeCertificate(ctx, id, chainPEM, keyPEM)
	if err != nil {
		return "not handed over", err
	}
	if restart {
		m.log.Info("mail: the mail host's certificate is handed to the mail server; restarting it", "host", host)
		if _, err := m.restartWait(ctx); err != nil {
			return "handed over, not served", err
		}
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

// syncReachability looks at the two things about the host that decide whether
// its mail is accepted and that AutoPanel cannot set: the reverse name of its
// address, which is the provider's record, and the way out to port 25, which
// the provider may block. Both are read, never changed.
//
// Decision: docs/decisions/mail.md#what-autopanel-cannot-set
func (m *Module) syncReachability(ctx context.Context, out *Sync, ip string) {
	prev := m.lastSync()
	out.Address = ip
	if ip != "" {
		names, err := m.host.ReverseNames(ctx, ip)
		if err == nil {
			out.Reverse, out.ReverseKnown = names, true
		} else {
			m.log.Warn("mail: the reverse name of the host's address", "address", ip, "err", err)
		}
	}
	out.Port25 = prev.Port25
	if prev.Port25 != "ok" || m.now().Sub(m.sync.port25At) >= port25Every {
		if err := m.host.SMTPOut(ctx); err != nil {
			out.Port25 = "blocked"
			m.log.Warn("mail: no connection out to port 25", "err", err)
		} else {
			out.Port25 = "ok"
		}
		m.sync.port25At = m.now()
	}
}

// Finding is something about mail the administrator should know, for Host
// checks: an id the panel has words for, and data for them.
type Finding struct {
	ID     string
	Alert  bool   // false: a notice
	Detail string // data, never prose
}

// Findings are the host checks that are mail's: none until mail is set up.
//
//   - mail-cpu: this processor cannot run the mail server.
//   - mail-loopback-rule: the rule that keeps other local programs off mail's
//     ports was missing or changed, and was loaded again.
//   - mail-ptr: the host's address does not resolve back to the mail host.
//   - mail-port-25: no connection out to port 25 gets through.
//
// Decision: docs/decisions/mail.md#what-autopanel-cannot-set
func (m *Module) Findings(ctx context.Context) []Finding {
	st, ok, err := m.store.State(ctx)
	if err != nil || !ok {
		return nil
	}
	var out []Finding
	if arch, flags, err := m.host.CPU(); err == nil {
		if m.product.CPU(arch, flags) != nil {
			out = append(out, Finding{ID: "mail-cpu", Alert: true, Detail: arch})
		}
	}
	m.mu.Lock()
	lb := m.progress.Loopback
	m.mu.Unlock()
	if lb != "" && lb != "ok" {
		out = append(out, Finding{ID: "mail-loopback-rule", Detail: lb})
	}
	last := m.lastSync()
	if last.Address != "" && last.ReverseKnown && !namesHost(last.Reverse, st.Host) {
		back := "nothing"
		if len(last.Reverse) > 0 {
			back = strings.TrimSuffix(last.Reverse[0], ".")
		}
		out = append(out, Finding{ID: "mail-ptr", Detail: last.Address + " → " + back + ", not " + st.Host})
	}
	if last.Port25 == "blocked" {
		out = append(out, Finding{ID: "mail-port-25", Alert: true})
	}
	return out
}

// namesHost reports whether one of an address's reverse names is host.
func namesHost(names []string, host string) bool {
	for _, n := range names {
		if strings.EqualFold(strings.TrimSuffix(n, "."), host) {
			return true
		}
	}
	return false
}
