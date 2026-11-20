// Package conformance is the contract a mail server's SDK must meet: what
// core/mail relies on of provider.Server, as tests any implementation runs.
// The server in memory passes it in its own tests; sdk/stalwart passes it
// against a real Stalwart on a throwaway machine. A new SDK ships when it
// passes it against its real server.
//
// Decision: docs/decisions/mail.md#mails-rules-name-no-mail-server
package conformance

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/yongjohnlee80/autopanel/core/mail/provider"
)

// Target is a server to test, and what the suite may ask of it beyond the
// interface.
type Target struct {
	Server provider.Server
	// Domain is a domain name the suite may make and remove: one the server
	// holds nothing of.
	Domain string
	// SignIn answers whether a mail app's sign-in with user and secret
	// succeeds (IMAP, say). It is required: what an app password is for is
	// signing in, and a suite that could not try would prove none of it.
	SignIn func(user, secret string) bool
	// Wait sleeps d of the server's time: time.Sleep for a real one, a clock
	// moved on for one in memory.
	Wait func(d time.Duration)
	// Now is the server's time.
	Now func() time.Time
}

// Run runs the suite. It leaves the server as it found it, failure or not.
func Run(t *testing.T, tg Target) {
	t.Helper()
	if tg.SignIn == nil {
		t.Fatal("conformance: the target gives no SignIn; the suite proves nothing about app passwords without one")
	}
	if tg.Wait == nil {
		tg.Wait = time.Sleep
	}
	if tg.Now == nil {
		tg.Now = time.Now
	}
	ctx := context.Background()
	s := tg.Server

	d, err := s.AddDomain(ctx, tg.Domain)
	if err != nil {
		t.Fatalf("AddDomain: %v", err)
	}
	t.Cleanup(func() { _ = s.RemoveDomain(context.Background(), d.ID) })
	if d.ID == "" || d.Name != tg.Domain {
		t.Fatalf("AddDomain answered %+v", d)
	}

	t.Run("Domains", func(t *testing.T) {
		ds, err := s.Domains(ctx)
		if err != nil || !slices.ContainsFunc(ds, func(x provider.Domain) bool { return x == d }) {
			t.Fatalf("Domains = %+v, %v; want %+v among them", ds, err, d)
		}
		rs, err := s.Records(ctx, d.ID)
		if err != nil || !slices.ContainsFunc(rs, func(r provider.Record) bool { return r.Type == "MX" && r.Name == tg.Domain }) {
			t.Fatalf("Records = %+v, %v; want the domain's MX", rs, err)
		}
	})

	address := "conformance@" + tg.Domain
	id, err := s.AddAccount(ctx, provider.NewAccount{Local: "conformance", DomainID: d.ID, Quota: 1 << 30, AppPasswords: 20})
	if err != nil {
		t.Fatalf("AddAccount: %v", err)
	}
	t.Cleanup(func() { _ = s.RemoveAccount(context.Background(), id) })

	t.Run("Accounts", func(t *testing.T) {
		as, err := s.Accounts(ctx)
		if err != nil {
			t.Fatal(err)
		}
		i := slices.IndexFunc(as, func(a provider.Account) bool { return a.ID == id })
		if i < 0 || as[i].Address != address || as[i].Local != "conformance" || as[i].DomainID != d.ID || as[i].Quota != 1<<30 || as[i].Admin {
			t.Fatalf("the account as listed: %+v", as)
		}
		if _, err := s.AddAccount(ctx, provider.NewAccount{Local: "conformance", DomainID: d.ID, Quota: 1}); err == nil {
			t.Fatal("a second account at the same address was made")
		}
	})

	t.Run("AppPasswords", func(t *testing.T) {
		kept, secret := add(t, s, id, "phone", tg.Now().Add(10*time.Minute))
		if kept.ExpiresAt == nil || kept.Device != "phone" {
			t.Fatalf("a new app password: %+v; want pending, named", kept)
		}
		if !strings.HasPrefix(secret, "app_") && len(secret) < 24 {
			t.Fatalf("its secret is %d characters", len(secret))
		}
		signIn(t, tg, address, secret, true, "a pending app password")
		if err := s.KeepAppPassword(ctx, id, kept.ID); err != nil {
			t.Fatal(err)
		}
		gone, goneSecret := add(t, s, id, "laptop", tg.Now().Add(10*time.Minute))
		if err := s.RevokeAppPassword(ctx, id, gone.ID); err != nil {
			t.Fatal(err)
		}
		ps := list(t, s, id)
		if len(ps) != 1 || ps[0].ID != kept.ID || ps[0].ExpiresAt != nil || ps[0].Device != "phone" {
			t.Fatalf("after keep and revoke: %+v", ps)
		}
		signIn(t, tg, address, secret, true, "a kept app password")
		signIn(t, tg, address, goneSecret, false, "a revoked app password")

		// The account's own password is one nobody knows: nothing a person
		// would try signs in, as it was made or after it is locked again.
		guesses := []string{"", "conformance", address, "password", tg.Domain}
		for _, g := range guesses {
			signIn(t, tg, address, g, false, "the guess "+strconv.Quote(g)+" at a new account's password")
		}
		// Locked again, and its quota changed: its app passwords stay, and the
		// one kept still signs in.
		if err := s.LockPassword(ctx, id); err != nil {
			t.Fatal(err)
		}
		for _, g := range guesses {
			signIn(t, tg, address, g, false, "the guess "+strconv.Quote(g)+" after Lock password")
		}
		if err := s.SetQuota(ctx, id, 2<<30); err != nil {
			t.Fatal(err)
		}
		if ps := list(t, s, id); len(ps) != 1 {
			t.Fatalf("after a new password and quota: %d app passwords", len(ps))
		}
		signIn(t, tg, address, secret, true, "an app password after a new password and quota")
		as, _ := s.Accounts(ctx)
		if i := slices.IndexFunc(as, func(a provider.Account) bool { return a.ID == id }); i < 0 || as[i].Quota != 2<<30 {
			t.Fatal("the quota did not change")
		}

		// Room for the twenty asked, after the quota change too.
		var extra []string
		for i := range 7 {
			p, _ := add(t, s, id, "device "+strconv.Itoa(i), tg.Now().Add(10*time.Minute))
			extra = append(extra, p.ID)
		}
		for _, x := range extra {
			if err := s.RevokeAppPassword(ctx, id, x); err != nil {
				t.Fatal(err)
			}
		}
	})

	t.Run("AnExpiredAppPasswordStops", func(t *testing.T) {
		p, secret := add(t, s, id, "short", tg.Now().Add(3*time.Second))
		signIn(t, tg, address, secret, true, "before its expiry")
		tg.Wait(5 * time.Second)
		signIn(t, tg, address, secret, false, "after its expiry")
		_ = s.RevokeAppPassword(ctx, id, p.ID)
	})

	t.Run("ADisabledAccountSignsNothingIn", func(t *testing.T) {
		p, secret := add(t, s, id, "disabled-test", tg.Now().Add(10*time.Minute))
		defer func() { _ = s.RevokeAppPassword(context.Background(), id, p.ID) }()
		signIn(t, tg, address, secret, true, "an app password of an enabled account")
		disabled := func() bool {
			t.Helper()
			as, err := s.Accounts(ctx)
			if err != nil {
				t.Fatal(err)
			}
			i := slices.IndexFunc(as, func(a provider.Account) bool { return a.ID == id })
			if i < 0 {
				t.Fatal("the account is gone")
			}
			return as[i].Disabled
		}
		if disabled() {
			t.Fatal("a new account is listed as disabled")
		}
		if err := s.SetDisabled(ctx, id, true); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = s.SetDisabled(context.Background(), id, false) }()
		if !disabled() {
			t.Fatal("a disabled account is not listed as disabled")
		}
		signIn(t, tg, address, secret, false, "an app password of a disabled account")
		if ps := list(t, s, id); !slices.ContainsFunc(ps, func(x provider.AppPassword) bool { return x.ID == p.ID }) {
			t.Fatal("disabling an account took its app passwords")
		}
		if err := s.SetDisabled(ctx, id, true); err != nil {
			t.Fatalf("disabling it twice: %v", err)
		}
		if err := s.SetDisabled(ctx, id, false); err != nil {
			t.Fatal(err)
		}
		if disabled() {
			t.Fatal("an enabled account is listed as disabled")
		}
		signIn(t, tg, address, secret, true, "an app password of an account enabled again")
	})

	t.Run("Aliases", func(t *testing.T) {
		aliases := func() []provider.Alias {
			t.Helper()
			as, err := s.Accounts(ctx)
			if err != nil {
				t.Fatal(err)
			}
			i := slices.IndexFunc(as, func(a provider.Account) bool { return a.ID == id })
			if i < 0 {
				t.Fatal("the account is gone")
			}
			out := slices.Clone(as[i].Aliases)
			slices.SortFunc(out, func(a, b provider.Alias) int { return strings.Compare(a.Local, b.Local) })
			return out
		}
		if got := aliases(); len(got) != 0 {
			t.Fatalf("a new account has aliases: %+v", got)
		}
		two := []provider.Alias{{Local: "sales", DomainID: d.ID}, {Local: "info", DomainID: d.ID}}
		if err := s.SetAliases(ctx, id, two); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = s.SetAliases(context.Background(), id, nil) }()
		if got, want := aliases(), []provider.Alias{{Local: "info", DomainID: d.ID}, {Local: "sales", DomainID: d.ID}}; !slices.Equal(got, want) {
			t.Fatalf("after setting two: %+v", got)
		}
		if err := s.SetAliases(ctx, id, two[:1]); err != nil {
			t.Fatal(err)
		}
		if got := aliases(); !slices.Equal(got, two[:1]) {
			t.Fatalf("after setting one: %+v; the other must be gone", got)
		}
		if err := s.SetAliases(ctx, id, nil); err != nil {
			t.Fatal(err)
		}
		if got := aliases(); len(got) != 0 {
			t.Fatalf("after setting none: %+v", got)
		}
	})

	t.Run("DKIM", func(t *testing.T) {
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		der, _ := x509.MarshalPKCS8PrivateKey(key)
		pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
		kid, err := s.AddDKIMKey(ctx, d.ID, "conf1e", provider.Ed25519, pemKey)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s.RemoveDKIMKey(context.Background(), kid) })
		k := key1(t, s, kid)
		if k.Stage != provider.Pending || k.Selector != "conf1e" || k.DomainID != d.ID || k.Alg != provider.Ed25519 {
			t.Fatalf("a new key: %+v; want pending", k)
		}
		rs, _ := s.Records(ctx, d.ID)
		if !slices.ContainsFunc(rs, func(r provider.Record) bool {
			return r.Type == "TXT" && r.Name == "conf1e._domainkey."+tg.Domain && strings.Contains(r.Value, "v=DKIM1")
		}) {
			t.Fatalf("the pending key's record is not among the domain's: %+v", rs)
		}
		if err := s.SetDKIMStage(ctx, kid, provider.Active); err != nil {
			t.Fatal(err)
		}
		if k := key1(t, s, kid); k.Stage != provider.Active {
			t.Fatalf("after SetDKIMStage: %+v", k)
		}
		if err := s.RemoveDKIMKey(ctx, kid); err != nil {
			t.Fatal(err)
		}
		ks, _ := s.DKIMKeys(ctx)
		if slices.ContainsFunc(ks, func(k provider.DKIMKey) bool { return k.ID == kid }) {
			t.Fatal("a removed key is listed")
		}
	})

	t.Run("Certificates", func(t *testing.T) {
		host := "conformance-mail." + tg.Domain
		chain, key, notAfter := selfSigned(t, host, 30)
		if _, err := s.ServeCertificate(ctx, "", chain, key); err != nil {
			t.Fatal(err)
		}
		c := cert(t, s, host)
		if !c.NotAfter.Equal(notAfter) {
			t.Fatalf("the certificate held: %+v; want it valid to %v", c, notAfter)
		}
		chain, key, notAfter = selfSigned(t, host, 60)
		restart, err := s.ServeCertificate(ctx, c.ID, chain, key)
		if err != nil || restart {
			t.Fatalf("a renewal: restart %v, %v; want served with no restart", restart, err)
		}
		if c2 := cert(t, s, host); c2.ID != c.ID || !c2.NotAfter.Equal(notAfter) {
			t.Fatalf("after the renewal: %+v", c2)
		}
	})

	t.Run("AnAccountsRoomIsRaisedWhenAsked", func(t *testing.T) {
		small, err := s.AddAccount(ctx, provider.NewAccount{Local: "conformance3", DomainID: d.ID, Quota: 1 << 20, AppPasswords: 2})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s.RemoveAccount(context.Background(), small) })
		// Made with room for two, it takes eight when eight are asked for: the
		// room an account was made with is not the most it will ever hold. (A
		// server may give more room than asked; the suite does not say where
		// it stops.)
		for i := range 8 {
			if _, _, err := s.AddAppPassword(ctx, small, "device "+strconv.Itoa(i), tg.Now().Add(10*time.Minute), 8); err != nil {
				t.Fatalf("app password %d of an account made with room for 2, asked with room for 8: %v", i+1, err)
			}
		}
		as, _ := s.Accounts(ctx)
		if i := slices.IndexFunc(as, func(a provider.Account) bool { return a.ID == small }); i < 0 || as[i].Quota != 1<<20 {
			t.Fatal("raising the room changed the account's disk quota")
		}
	})

	t.Run("RemovingAnAccountTakesItsAppPasswords", func(t *testing.T) {
		other, err := s.AddAccount(ctx, provider.NewAccount{Local: "conformance2", DomainID: d.ID, Quota: 1 << 20, AppPasswords: 20})
		if err != nil {
			t.Fatal(err)
		}
		_, secret := add(t, s, other, "phone", tg.Now().Add(10*time.Minute))
		if err := s.RemoveAccount(ctx, other); err != nil {
			t.Fatal(err)
		}
		signIn(t, tg, "conformance2@"+tg.Domain, secret, false, "an app password of a removed account")
		as, _ := s.Accounts(ctx)
		if slices.ContainsFunc(as, func(a provider.Account) bool { return a.ID == other }) {
			t.Fatal("a removed account is listed")
		}
	})
}

func add(t *testing.T, s provider.Server, account, device string, expires time.Time) (provider.AppPassword, string) {
	t.Helper()
	p, secret, err := s.AddAppPassword(context.Background(), account, device, expires, 20)
	if err != nil {
		t.Fatalf("AddAppPassword(%s): %v", device, err)
	}
	if p.ID == "" || secret == "" {
		t.Fatalf("AddAppPassword(%s) answered %+v with %d characters of secret", device, p, len(secret))
	}
	return p, secret
}

func list(t *testing.T, s provider.Server, account string) []provider.AppPassword {
	t.Helper()
	ps, err := s.AppPasswords(context.Background(), account)
	if err != nil {
		t.Fatal(err)
	}
	return ps
}

func signIn(t *testing.T, tg Target, user, secret string, want bool, what string) {
	t.Helper()
	if got := tg.SignIn(user, secret); got != want {
		t.Errorf("%s signs in: %v; want %v", what, got, want)
	}
}

func key1(t *testing.T, s provider.Server, id string) provider.DKIMKey {
	t.Helper()
	ks, err := s.DKIMKeys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(ks, func(k provider.DKIMKey) bool { return k.ID == id })
	if i < 0 {
		t.Fatalf("key %s is not listed", id)
	}
	return ks[i]
}

func cert(t *testing.T, s provider.Server, host string) provider.Certificate {
	t.Helper()
	cs, err := s.Certificates(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cs {
		if c.SANs[host] {
			return c
		}
	}
	t.Fatalf("no certificate for %s among %+v", host, cs)
	return provider.Certificate{}
}

func selfSigned(t *testing.T, host string, days int) (chain, key string, notAfter time.Time) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	notAfter = time.Now().Add(time.Duration(days) * 24 * time.Hour).UTC().Truncate(time.Second)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: host},
		DNSNames: []string{host}, NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kd, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(errors.Join(err))
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd})), notAfter
}
