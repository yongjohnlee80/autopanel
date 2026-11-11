package certs

import (
	"context"
	"errors"
	"io/fs"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
)

// memBlobs is Blobs in memory: the reference the store adapter's own tests
// must agree with.
type memBlobs struct {
	mu sync.Mutex
	m  map[string][]byte
	at map[string]time.Time
}

func newMemBlobs() *memBlobs { return &memBlobs{m: map[string][]byte{}, at: map[string]time.Time{}} }

func (b *memBlobs) Put(_ context.Context, key string, v []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.m[key] = slices.Clone(v)
	b.at[key] = time.Now()
	return nil
}

func (b *memBlobs) Get(_ context.Context, key string) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	v, ok := b.m[key]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return slices.Clone(v), nil
}

func under(key, prefix string) bool {
	return prefix == "" || key == prefix || strings.HasPrefix(key, prefix+"/")
}

func (b *memBlobs) Delete(_ context.Context, key string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	for k := range b.m {
		if under(k, key) {
			delete(b.m, k)
			delete(b.at, k)
		}
	}
	return nil
}

func (b *memBlobs) List(_ context.Context, prefix string, recursive bool) ([]string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	seen := map[string]bool{}
	for k := range b.m {
		if k == prefix || !under(k, prefix) {
			continue
		}
		if !recursive {
			child := strings.SplitN(strings.TrimPrefix(strings.TrimPrefix(k, prefix), "/"), "/", 2)[0]
			k = strings.TrimPrefix(prefix+"/"+child, "/") // the direct child; a root prefix has no leading slash
		}
		seen[k] = true
	}
	if len(seen) == 0 {
		return nil, fs.ErrNotExist
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}

func (b *memBlobs) Stat(_ context.Context, key string) (certmagic.KeyInfo, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if v, ok := b.m[key]; ok {
		return certmagic.KeyInfo{Key: key, Modified: b.at[key], Size: int64(len(v)), IsTerminal: true}, nil
	}
	for k := range b.m {
		if under(k, key) {
			return certmagic.KeyInfo{Key: key, IsTerminal: false}, nil
		}
	}
	return certmagic.KeyInfo{}, fs.ErrNotExist
}

func TestStorageKeepsCertMagicsFileSemantics(t *testing.T) {
	ctx := context.Background()
	s := &storage{blobs: newMemBlobs(), locks: newLocks()}
	for _, k := range []string{"certs/ca/a.example/a.crt", "certs/ca/a.example/a.key", "certs/ca/ab.example/ab.crt"} {
		if err := s.Store(ctx, k, []byte(k)); err != nil {
			t.Fatal(err)
		}
	}
	if v, err := s.Load(ctx, "certs/ca/a.example/a.key"); err != nil || string(v) != "certs/ca/a.example/a.key" {
		t.Fatalf("Load = %q, %v", v, err)
	}
	if _, err := s.Load(ctx, "certs/ca/none"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Load of a missing key = %v; want fs.ErrNotExist", err)
	}
	if !s.Exists(ctx, "certs/ca/a.example") || s.Exists(ctx, "certs/ca/a.ex") {
		t.Error("Exists must see a directory and never a partial component")
	}
	if got, _ := s.List(ctx, "certs/ca", false); !slices.Equal(got, []string{"certs/ca/a.example", "certs/ca/ab.example"}) {
		t.Errorf("List(non-recursive) = %v", got)
	}
	if err := s.Delete(ctx, "certs/ca/a.example"); err != nil {
		t.Fatal(err)
	}
	if s.Exists(ctx, "certs/ca/a.example/a.crt") || !s.Exists(ctx, "certs/ca/ab.example/ab.crt") {
		t.Error("Delete of a directory must remove its keys, and only its keys")
	}
	if err := s.Delete(ctx, "certs/ca/a.example"); err != nil {
		t.Errorf("a second Delete = %v; a missing key is not an error", err)
	}
}

func TestLocksExcludeAndHonorTheContext(t *testing.T) {
	l := newLocks()
	ctx := context.Background()
	if err := l.lock(ctx, "issue_cert_a.example"); err != nil {
		t.Fatal(err)
	}
	short, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	if err := l.lock(short, "issue_cert_a.example"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a held lock was taken again: %v", err)
	}
	if err := l.lock(ctx, "issue_cert_b.example"); err != nil {
		t.Fatalf("another name must not wait: %v", err)
	}
	got := make(chan error, 1)
	go func() { got <- l.lock(ctx, "issue_cert_a.example") }()
	if err := l.unlock("issue_cert_a.example"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-got:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a waiter was not woken by Unlock")
	}
	if err := l.unlock("never-held"); err == nil {
		t.Error("an unlock of a lock no one holds must fail")
	}
}

func newManager(t *testing.T, allowed ...string) *Manager {
	t.Helper()
	m, err := New(Options{
		Blobs:   newMemBlobs(),
		Allowed: func(h string) bool { return slices.Contains(allowed, h) },
		CA:      certmagic.LetsEncryptStagingCA,
		Email:   "admin@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestOnlyARoutedHostMayHaveACertificate(t *testing.T) {
	m := newManager(t, "a.example.com")
	for name, want := range map[string]error{
		"a.example.com":  nil,
		"A.Example.COM.": nil, // canonicalised before the decision
		"b.example.com":  ErrUnknownHost,
		"*.example.com":  ErrUnknownHost,
		"":               ErrUnknownHost,
	} {
		if got := m.decide(context.Background(), name); !errors.Is(got, want) && got != want {
			t.Errorf("decide(%q) = %v; want %v", name, got, want)
		}
	}
}

func TestTLSConfigOffersHTTPAndKeepsTheALPNChallenge(t *testing.T) {
	cfg := newManager(t).TLSConfig()
	if !slices.Equal(cfg.NextProtos, []string{"h2", "http/1.1", "acme-tls/1"}) {
		t.Errorf("NextProtos = %v", cfg.NextProtos)
	}
	if cfg.GetCertificate == nil || cfg.MinVersion < 0x0303 {
		t.Error("the TLS config must serve CertMagic's certificates at TLS 1.2 or later")
	}
}

func TestNewRefusesAnIncompleteConfiguration(t *testing.T) {
	if _, err := New(Options{Blobs: newMemBlobs(), CA: certmagic.LetsEncryptStagingCA, Email: "a@example.com"}); err == nil {
		t.Error("New accepted no Allowed: every SNI would order a certificate")
	}
	if _, err := Cloudflare(""); err == nil {
		t.Error("an empty Cloudflare token was accepted")
	}
}
