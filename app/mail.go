package app

import (
	"context"
	"errors"
	"strconv"

	"github.com/yongjohnlee80/autopanel/core/mail"
	hostgate "github.com/yongjohnlee80/autopanel/host/gate"
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
