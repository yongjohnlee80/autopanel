package stalwart

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/yongjohnlee80/autopanel/core/mail/provider"
)

// REPAIRING ACCESS — a lost API key is replaced by the sealed administrator;
// a lost administrator is given a new secret by Stalwart's recovery
// administrator, which STALWART_RECOVERY_ADMIN (name:secret) gives the server
// for one start. Recovery mode is never used: it stops mail from being served.
//
// Decision: docs/decisions/mail.md#repairing-access

var _ provider.Repairer = Product{}

// recoveryVariable is how Stalwart is given its recovery administrator.
const recoveryVariable = "STALWART_RECOVERY_ADMIN"

// keyDescription names the API keys AutoPanel makes. A key is AutoPanel's
// when its description is exactly this, or this, a space, and more: never
// one that only starts with these letters.
const keyDescription = "autopanel core"

func ourKey(description string) bool {
	return description == keyDescription || strings.HasPrefix(description, keyDescription+" ")
}

// sealedAdminOf is the administrator Bootstrap sealed.
func sealedAdminOf(ctx context.Context, env provider.Env) (Admin, error) {
	raw, err := env.Sealed(ctx, sealedAdmin)
	if err != nil {
		return Admin{}, err
	}
	var a Admin
	if err := json.Unmarshal(raw, &a); err != nil || a.Username == "" || a.Secret == "" {
		return Admin{}, provider.ErrNoSecret
	}
	return a, nil
}

func unauthorized(err error) error {
	if errors.Is(err, ErrUnauthorized) {
		return fmt.Errorf("%w: %w", provider.ErrUnauthorized, err)
	}
	return err
}

func (Product) AdminSignsIn(ctx context.Context, env provider.Env) error {
	a, err := sealedAdminOf(ctx, env)
	if err != nil {
		return err
	}
	_, err = NewClient(env.Base(), Basic(a.Username, a.Secret)).Domains(ctx)
	return unauthorized(err)
}

func (Product) NewAPIKey(ctx context.Context, env provider.Env, at time.Time) (provider.KeyRepair, error) {
	a, err := sealedAdminOf(ctx, env)
	if err != nil {
		return provider.KeyRepair{}, err
	}
	c := NewClient(env.Base(), Basic(a.Username, a.Secret))
	id, secret, err := c.CreateAPIKey(ctx, keyDescription+" "+at.UTC().Format("2006-01-02T15:04Z"))
	if err != nil {
		return provider.KeyRepair{}, unauthorized(err)
	}
	if err := env.Seal(ctx, provider.SealedAPIKey, []byte(secret)); err != nil {
		return provider.KeyRepair{}, fmt.Errorf("sealing the API key: %w", err)
	}
	// The new key must sign in before any old one goes.
	if _, err := NewClient(env.Base(), Bearer(func(context.Context) (string, error) { return secret, nil })).Domains(ctx); err != nil {
		return provider.KeyRepair{}, fmt.Errorf("the new API key does not sign in: %w", unauthorized(err))
	}
	keys, err := c.APIKeys(ctx)
	if err != nil {
		return provider.KeyRepair{}, err
	}
	out := provider.KeyRepair{Kept: []string{}}
	for _, k := range keys {
		switch {
		case k.ID == id:
		case ourKey(k.Description):
			if err := c.DestroyAPIKey(ctx, k.ID); err != nil {
				return out, fmt.Errorf("destroying an older key of AutoPanel's: %w", err)
			}
			out.Destroyed++
		default:
			out.Kept = append(out.Kept, k.Description)
		}
	}
	return out, nil
}

// randomSecret is 256 random bits, as text no Stalwart credential mangles.
func randomSecret() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	defer clear(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// recoveryName is the recovery administrator's name: no account has it.
const recoveryName = "autopanel-recovery"

func (Product) RecoveryCredential() ([]byte, error) {
	s, err := randomSecret()
	if err != nil {
		return nil, err
	}
	return []byte(recoveryName + ":" + s), nil
}

func recoveryClient(base string, recovery []byte) (*Client, error) {
	name, secret, ok := strings.Cut(string(recovery), ":")
	if !ok || name == "" || secret == "" {
		return nil, errors.New("mail: the recovery credential is not name:secret")
	}
	return NewClient(base, Basic(name, secret)), nil
}

func (Product) ResetAdmin(ctx context.Context, env provider.Env, recovery []byte) error {
	rc, err := recoveryClient(env.Base(), recovery)
	if err != nil {
		return err
	}
	accounts, err := rc.Accounts(ctx)
	if err != nil {
		return fmt.Errorf("signing in as the recovery administrator: %w", unauthorized(err))
	}
	var admins []Account
	for _, a := range accounts {
		if a.Admin {
			admins = append(admins, a)
		}
	}
	if len(admins) != 1 {
		return fmt.Errorf("mail: the server has %d administrator accounts, and a repair needs exactly one", len(admins))
	}
	admin := admins[0]
	secret, err := randomSecret()
	if err != nil {
		return err
	}
	hashed, err := lockedHasher.Hash(secret)
	if err != nil {
		return err
	}
	if err := rc.SetSecret(ctx, admin.ID, hashed); err != nil {
		return fmt.Errorf("the administrator's new secret: %w", err)
	}
	raw, _ := json.Marshal(Admin{Username: admin.Address, Secret: secret})
	if err := env.Seal(ctx, sealedAdmin, raw); err != nil {
		return fmt.Errorf("sealing the administrator: %w", err)
	}
	if _, err := NewClient(env.Base(), Basic(admin.Address, secret)).Domains(ctx); err != nil {
		return fmt.Errorf("the administrator does not sign in with its new secret: %w", unauthorized(err))
	}
	return nil
}

func (Product) RecoverySignsIn(ctx context.Context, base string, recovery []byte) error {
	rc, err := recoveryClient(base, recovery)
	if err != nil {
		return err
	}
	_, err = rc.Accounts(ctx)
	return unauthorized(err)
}
