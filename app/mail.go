package app

import (
	"context"
	"crypto/tls"
	"errors"
	"strconv"
	"strings"

	"github.com/yongjohnlee80/autopanel/core/mail"
	hostgate "github.com/yongjohnlee80/autopanel/host/gate"
	"github.com/yongjohnlee80/autopanel/internal/cloudflare"
	"github.com/yongjohnlee80/autopanel/internal/keyslot"
	"github.com/yongjohnlee80/autopanel/store"
)

// mailVault is mail's Vault on the store's secret table, sealed under the
// master key, as the Cloudflare token is.
type mailVault struct {
	st    *store.Store
	vault *keyslot.Vault
}

func (v mailVault) Put(ctx context.Context, name string, value []byte) error {
	if !v.vault.Unlocked() {
		return mail.ErrLocked
	}
	return v.st.PutSecret(ctx, v.vault, name, value)
}

func (v mailVault) Get(ctx context.Context, name string) ([]byte, error) {
	if !v.vault.Unlocked() {
		return nil, mail.ErrLocked
	}
	b, err := v.st.Secret(ctx, v.vault, name)
	if errors.Is(err, store.ErrNoSecret) {
		return nil, mail.ErrNoSecret
	}
	return b, err
}

func (v mailVault) Delete(ctx context.Context, name string) error {
	return v.st.DeleteSecret(ctx, name)
}

// mailStreams are the gate's streams for mail's ports: each public port
// forwarded to its loopback port, with mail's limits.
func mailStreams() []hostgate.Stream {
	out := make([]hostgate.Stream, 0, len(mail.Ports))
	for _, p := range mail.Ports {
		out = append(out, hostgate.Stream{Name: p.Name, Listen: ":" + strconv.Itoa(p.Public),
			To: "127.0.0.1:" + strconv.Itoa(p.Loopback), IdleSecs: p.IdleSecs, PerClient: p.PerClient, Share: p.Share})
	}
	return out
}

// switchStreams is mail's Streams on the gate's stream table.
func switchStreams(t *streamTable) mail.Streams {
	return func(on bool) {
		if on {
			t.Set(mail.TotalConnections, mailStreams())
		} else {
			t.Set(0, nil)
		}
	}
}

// mailDNS is mail's DNS on Cloudflare, with the sealed token. With no token
// (or the vault locked) every record is the administrator's to publish.
type mailDNS struct {
	st    *store.Store
	vault *keyslot.Vault
}

func (d mailDNS) client() *cloudflare.Client {
	return cloudflare.New(func(ctx context.Context) (string, error) {
		if !d.vault.Unlocked() {
			return "", mail.ErrNoDNS
		}
		tok, err := d.st.Secret(ctx, d.vault, cloudflareSecret)
		if errors.Is(err, store.ErrNoSecret) {
			return "", mail.ErrNoDNS
		}
		return string(tok), err
	})
}

func (d mailDNS) Zone(ctx context.Context, name string) (string, error) {
	z, err := d.client().ZoneFor(ctx, name)
	return z.ID, err
}

func (d mailDNS) Records(ctx context.Context, zone string) ([]mail.Remote, error) {
	rs, err := d.client().Records(ctx, zone)
	if err != nil {
		return nil, err
	}
	out := make([]mail.Remote, 0, len(rs))
	for _, r := range rs {
		out = append(out, mail.Remote{ID: r.ID, Record: fromCloudflare(r)})
	}
	return out, nil
}

func (d mailDNS) Create(ctx context.Context, zone string, r mail.Record) (string, error) {
	made, err := d.client().Create(ctx, zone, toCloudflare(r))
	return made.ID, err
}

func (d mailDNS) Update(ctx context.Context, zone, id string, r mail.Record) error {
	return d.client().Update(ctx, zone, id, toCloudflare(r))
}

func (d mailDNS) Delete(ctx context.Context, zone, id string) error {
	return d.client().Delete(ctx, zone, id)
}

// fromCloudflare is a Cloudflare record in mail's zone-file terms.
func fromCloudflare(r cloudflare.Record) mail.Record {
	out := mail.Record{Name: strings.ToLower(strings.TrimSuffix(r.Name, ".")), Type: r.Type, Value: r.Content}
	prio := func() uint16 {
		if r.Priority != nil {
			return *r.Priority
		}
		return 0
	}
	switch r.Type {
	case "MX":
		out.Value = strconv.Itoa(int(prio())) + " " + strings.ToLower(strings.TrimSuffix(r.Content, "."))
	case "SRV":
		num := func(k string) string {
			if v, ok := r.Data[k].(float64); ok {
				return strconv.Itoa(int(v))
			}
			return "0"
		}
		target, _ := r.Data["target"].(string)
		if target != "" {
			out.Value = num("priority") + " " + num("weight") + " " + num("port") + " " + strings.ToLower(strings.TrimSuffix(target, "."))
		} else { // content is "weight port target", the priority beside it
			out.Value = strconv.Itoa(int(prio())) + " " + strings.ToLower(strings.TrimSuffix(r.Content, "."))
		}
	case "TXT":
		out.Value = unquoteTXT(r.Content)
	case "CNAME":
		out.Value = strings.ToLower(strings.TrimSuffix(r.Content, "."))
	}
	return out
}

// unquoteTXT joins a TXT record's strings: Cloudflare may answer `"a" "b"`.
func unquoteTXT(s string) string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, `"`) {
		return s
	}
	var b strings.Builder
	in := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && in && i+1 < len(s):
			i++
			b.WriteByte(s[i])
		case c == '"':
			in = !in
		case in:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// toCloudflare is mail's record as Cloudflare takes it: never proxied (mail
// does not pass through Cloudflare), the TTL automatic, a long TXT in strings
// of 255 characters at most.
func toCloudflare(r mail.Record) cloudflare.Record {
	off := false
	out := cloudflare.Record{Type: r.Type, Name: r.Name, Content: r.Value, TTL: 1}
	f := strings.Fields(r.Value)
	switch r.Type {
	case "A", "AAAA", "CNAME":
		out.Proxied = &off
	case "MX":
		if len(f) == 2 {
			p, _ := strconv.Atoi(f[0])
			pr := uint16(p)
			out.Priority, out.Content = &pr, f[1]
		}
	case "SRV":
		if len(f) == 4 {
			n := func(s string) int { v, _ := strconv.Atoi(s); return v }
			out.Content = ""
			out.Data = map[string]any{"priority": n(f[0]), "weight": n(f[1]), "port": n(f[2]), "target": f[3]}
		}
	case "TXT":
		if len(r.Value) > 255 {
			var parts []string
			for v := r.Value; v != ""; {
				k := min(255, len(v))
				parts = append(parts, `"`+v[:k]+`"`)
				v = v[k:]
			}
			out.Content = strings.Join(parts, " ")
		}
	}
	return out
}

// mailCerts is mail's Certs on the live certificate manager.
type mailCerts struct{ sw *certSwitch }

func (c mailCerts) For(ctx context.Context, host string) (*tls.Certificate, error) {
	return c.sw.cur.Load().For(ctx, host, false)
}
