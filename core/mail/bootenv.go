package mail

import (
	"context"
	"errors"
	"time"

	"github.com/yongjohnlee80/autopanel/core/mail/provider"
)

// bootEnv is what the product's Bootstrap may use of AutoPanel: the
// management API, the setup's answers, the stack's first-start credential,
// restarts, the forwarder, and sealed values under sealedServer.
type bootEnv struct {
	m     *Module
	set   provider.Settings
	since time.Time // the stack's current start
}

// firstCredentialWait is how long the first start's credential may take to
// appear in the journal.
var firstCredentialWait = 30 * time.Second

func (e *bootEnv) Base() string                { return e.m.base }
func (e *bootEnv) Settings() provider.Settings { return e.set }

// FirstCredential reads the credential the current start printed: the last
// one, which is this start's. It is never logged or kept.
func (e *bootEnv) FirstCredential(ctx context.Context) (string, error) {
	deadline := time.Now().Add(firstCredentialWait)
	for {
		lines, err := e.m.host.Journal(ctx, e.since)
		if err != nil {
			return "", err
		}
		found := ""
		for _, l := range lines {
			if c, ok := e.m.product.FirstCredential(l); ok {
				found = c
			}
		}
		if found != "" {
			return found, nil
		}
		if time.Now().After(deadline) {
			return "", errors.New("the mail server printed no one-time credential: it is set up already, or has not started")
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

func (e *bootEnv) Restart(ctx context.Context) error {
	since, err := e.m.restartWait(ctx)
	if err == nil {
		e.since = since
	}
	return err
}

func (e *bootEnv) Forwarder(ctx context.Context) (string, error) { return e.m.host.Forwarder(ctx) }

func (e *bootEnv) Sealed(ctx context.Context, name string) ([]byte, error) {
	v, err := e.m.vault.Get(ctx, sealedServer+name)
	if errors.Is(err, ErrNoSecret) {
		return nil, provider.ErrNoSecret
	}
	return v, err
}

func (e *bootEnv) Seal(ctx context.Context, name string, value []byte) error {
	return e.m.vault.Put(ctx, sealedServer+name, value)
}
