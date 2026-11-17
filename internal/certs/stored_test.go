package certs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
)

// selfSigned is a certificate for name, as PEM.
func selfSigned(t *testing.T, name string, from, to time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{name}, NotBefore: from, NotAfter: to,
		Subject: pkix.Name{Organization: []string{"Test CA"}, CommonName: "T1"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestStoredReadsTheStoreAndOrdersNothing(t *testing.T) {
	m := newManager(t, "a.example.com")
	defer m.Stop()
	ctx := context.Background()
	if c, ok, err := m.Stored(ctx, "a.example.com"); ok || err != nil {
		t.Fatalf("with nothing stored = %+v, %v, %v; want none", c, ok, err)
	}
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(90 * 24 * time.Hour)
	key := certmagic.StorageKeys.SiteCert(m.issuer.IssuerKey(), "a.example.com")
	if err := m.magic.Storage.Store(ctx, key, selfSigned(t, "a.example.com", from, to)); err != nil {
		t.Fatal(err)
	}
	c, ok, err := m.Stored(ctx, "a.example.com")
	if err != nil || !ok {
		t.Fatalf("Stored = %v, %v", ok, err)
	}
	if c.Issuer != "Test CA T1" || !c.NotBefore.Equal(from) || !c.NotAfter.Equal(to) {
		t.Errorf("Stored = %+v", c)
	}
	// The last third of its life: day 60 of 90.
	if want := from.Add(60 * 24 * time.Hour); !c.RenewFrom.Equal(want) {
		t.Errorf("RenewFrom = %v; want %v", c.RenewFrom, want)
	}
	// Another name's certificate is not this name's, and another CA's is not this CA's.
	if _, ok, _ := m.Stored(ctx, "b.example.com"); ok {
		t.Error("a name with no certificate was given another's")
	}
	other, err := New(Options{Blobs: m.opts.Blobs, Allowed: m.opts.Allowed, CA: certmagic.LetsEncryptProductionCA, Email: "admin@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Stop()
	if _, ok, _ := other.Stored(ctx, "a.example.com"); ok {
		t.Error("the staging certificate was shown under the production service")
	}
	if err := m.magic.Storage.Store(ctx, key, []byte("not a certificate")); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := m.Stored(ctx, "a.example.com"); ok || err == nil {
		t.Errorf("a stored value that is no certificate = %v, %v; want an error", ok, err)
	}
}

func TestAnOrdersEndIsTold(t *testing.T) {
	var got []Event
	m, err := New(Options{Blobs: newMemBlobs(), Allowed: func(string) bool { return true }, CA: certmagic.LetsEncryptStagingCA,
		Email: "admin@example.com", Event: func(e Event) { got = append(got, e) }})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()
	ctx := context.Background()
	refused := errors.New("rate limited")
	for _, e := range []struct {
		event string
		data  map[string]any
	}{
		{"cert_obtaining", map[string]any{"identifier": "a.example.com"}}, // not an ending
		{"cert_obtained", map[string]any{"identifier": "a.example.com", "renewal": false}},
		{"cert_obtained", map[string]any{"identifier": "a.example.com", "renewal": true}},
		{"cert_failed", map[string]any{"identifier": "b.example.com", "renewal": true, "error": refused}},
		{"cert_failed", map[string]any{"identifier": "c.example.com"}},
	} {
		if err := m.magic.OnEvent(ctx, e.event, e.data); err != nil {
			t.Fatalf("%s was refused: %v", e.event, err)
		}
	}
	if len(got) != 4 {
		t.Fatalf("told %d endings; want 4: %+v", len(got), got)
	}
	if got[0] != (Event{Name: "a.example.com"}) || got[1] != (Event{Name: "a.example.com", Renewal: true}) {
		t.Errorf("the certificates obtained = %+v, %+v", got[0], got[1])
	}
	if got[2].Name != "b.example.com" || !got[2].Renewal || !errors.Is(got[2].Err, refused) {
		t.Errorf("the failed renewal = %+v", got[2])
	}
	if got[3].Name != "c.example.com" || got[3].Err == nil {
		t.Errorf("a failure with no error given = %+v; want one all the same", got[3])
	}
}
