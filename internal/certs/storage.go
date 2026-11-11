package certs

import (
	"context"
	"errors"
	"sync"

	"github.com/caddyserver/certmagic"
)

// Blobs is CertMagic's key space as AutoPanel's store keeps it: certificates,
// their private keys and ACME account keys, by slash-separated key. The store
// adapter implements it on the cert_blob table; tests use an in-memory one.
//
// Keys follow CertMagic's file semantics: "a" is a prefix of "a/b", never of
// "ab/c". A missing key answers fs.ErrNotExist from Get, List and Stat.
type Blobs interface {
	Put(ctx context.Context, key string, value []byte) error
	Get(ctx context.Context, key string) ([]byte, error)
	// Delete removes key and every key under it; a missing key is not an error.
	Delete(ctx context.Context, key string) error
	// List names the keys under prefix: its direct children, or with recursive
	// every key below it.
	List(ctx context.Context, prefix string, recursive bool) ([]string, error)
	Stat(ctx context.Context, key string) (certmagic.KeyInfo, error)
}

// storage is certmagic.Storage over Blobs. Its lock is in-process: one
// AutoPanel per store (ADR Q8, rationale §R8), so no other process obtains
// certificates from the same store.
type storage struct {
	blobs Blobs
	locks *locks
}

var _ certmagic.Storage = (*storage)(nil)

// bg is ctx, or the background context when CertMagic passes none: it reads a
// handshake's context from the ClientHelloInfo, and one made outside a
// handshake (Manager.For) has none.
func bg(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func (s *storage) Store(ctx context.Context, key string, value []byte) error {
	return s.blobs.Put(bg(ctx), key, value)
}

func (s *storage) Load(ctx context.Context, key string) ([]byte, error) {
	return s.blobs.Get(bg(ctx), key)
}

func (s *storage) Delete(ctx context.Context, key string) error { return s.blobs.Delete(bg(ctx), key) }

func (s *storage) Exists(ctx context.Context, key string) bool {
	_, err := s.blobs.Stat(bg(ctx), key)
	return err == nil
}

func (s *storage) List(ctx context.Context, prefix string, recursive bool) ([]string, error) {
	return s.blobs.List(bg(ctx), prefix, recursive)
}

func (s *storage) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	return s.blobs.Stat(bg(ctx), key)
}

func (s *storage) Lock(ctx context.Context, name string) error { return s.locks.lock(bg(ctx), name) }

func (s *storage) Unlock(_ context.Context, name string) error { return s.locks.unlock(name) }

// locks are named, context-aware, in-process locks.
type locks struct {
	mu   sync.Mutex
	held map[string]chan struct{} // closed when the holder unlocks
}

func newLocks() *locks { return &locks{held: map[string]chan struct{}{}} }

func (l *locks) lock(ctx context.Context, name string) error {
	for {
		l.mu.Lock()
		wait, busy := l.held[name]
		if !busy {
			l.held[name] = make(chan struct{})
			l.mu.Unlock()
			return nil
		}
		l.mu.Unlock()
		select {
		case <-wait:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// errNotLocked is an Unlock of a name no one holds: a bug in the caller.
var errNotLocked = errors.New("certs: unlock of a lock that is not held")

func (l *locks) unlock(name string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	wait, busy := l.held[name]
	if !busy {
		return errNotLocked
	}
	delete(l.held, name)
	close(wait)
	return nil
}
