// Package store is AutoPanel's store: SQLite by default, PostgreSQL when
// configured, one SQL text for both. It implements the core's ports (the gate's
// Routes, certs' Blobs) and holds the lease that keeps one AutoPanel per store.
package store

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/yongjohnlee80/golib/dao"
	"github.com/yongjohnlee80/golib/dao/postgres"
	"github.com/yongjohnlee80/golib/dao/sqlite"

	"github.com/yongjohnlee80/autopanel/sql/deployments"
)

// Config names the store.
type Config struct {
	Engine string // dao.DialectSQLite (the default) or dao.DialectPostgres
	// Path is the SQLite file (under the 0700 state directory). DSN is the
	// PostgreSQL connection string; its search_path names the "autopanel" schema.
	Path string
	DSN  string
}

// Store is an open, migrated store.
type Store struct {
	conn dao.DataConn
	now  func() time.Time
}

// Open opens the store and applies every pending migration in one
// transaction; a store newer than this binary is refused (dao/deploy).
func Open(ctx context.Context, cfg Config) (*Store, error) {
	var conn dao.DataConn
	var err error
	switch cfg.Engine {
	case "", dao.DialectSQLite:
		if cfg.Path == "" {
			return nil, errors.New("store: no SQLite path")
		}
		dsn := "file:" + cfg.Path + "?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_txlock=immediate"
		conn, err = sqlite.OpenNamed(ctx, "autopanel-store", dsn, sqlite.MaxOpenConns(1))
	case dao.DialectPostgres:
		conn, err = postgres.OpenNamed(ctx, "autopanel-store", cfg.DSN)
	default:
		return nil, fmt.Errorf("store: unknown engine %q", cfg.Engine)
	}
	if err != nil {
		return nil, fmt.Errorf("store: opening: %w", err)
	}
	if _, err := deployments.Runner().Apply(ctx, conn); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("store: migrating: %w", err)
	}
	return &Store{conn: conn, now: time.Now}, nil
}

// Engine is the store's dialect name.
func (s *Store) Engine() string { return s.conn.Dialect().Name() }

// Close closes the store.
func (s *Store) Close() error { return s.conn.Close() }

// q renders a statement written with "?" placeholders in the store's dialect.
// No statement here holds a literal "?".
func (s *Store) q(stmt string) string {
	d := s.conn.Dialect()
	var b strings.Builder
	n := 0
	for _, c := range stmt {
		if c == '?' {
			n++
			b.WriteString(d.Placeholder(n))
			continue
		}
		b.WriteRune(c)
	}
	return b.String()
}

func (s *Store) translate(err error) error { return s.conn.Dialect().TranslateError(err) }

// tx runs fn in one transaction, committed when fn returns nil.
func (s *Store) tx(ctx context.Context, fn func(tx dao.TxConn) error) (err error) {
	tx, err := s.conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if err = fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// ErrLeased is a store another AutoPanel holds.
var ErrLeased = errors.New("store: another AutoPanel holds this store")

// LeaseTTL is how long a holder's lease lasts without renewal. A crashed
// holder's lease lapses after it, so a restart is never locked out for good.
const LeaseTTL = 2 * time.Minute

// Lease takes the store for holder, or refuses with ErrLeased while another
// holder's lease is live. It is one statement, serialised by the database: two
// AutoPanels starting at once can't both win (R3).
func (s *Store) Lease(ctx context.Context, holder string) error {
	now := s.now().Unix()
	stale := now - int64(LeaseTTL/time.Second)
	res, err := s.conn.ExecContext(ctx, s.q(`INSERT INTO store_lease(id, holder, started_at, renewed_at) VALUES (1, ?, ?, ?)
ON CONFLICT (id) DO UPDATE SET holder = excluded.holder, started_at = excluded.started_at, renewed_at = excluded.renewed_at
WHERE store_lease.holder = excluded.holder OR store_lease.renewed_at < ?`), holder, now, now, stale)
	if err != nil {
		return fmt.Errorf("store: lease: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return ErrLeased
	}
	return nil
}

// Renew keeps holder's lease live; it fails if the lease was lost.
func (s *Store) Renew(ctx context.Context, holder string) error {
	res, err := s.conn.ExecContext(ctx, s.q(`UPDATE store_lease SET renewed_at = ? WHERE id = 1 AND holder = ?`), s.now().Unix(), holder)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return ErrLeased
	}
	return nil
}

// Release gives the store up, for a clean stop.
func (s *Store) Release(ctx context.Context, holder string) error {
	_, err := s.conn.ExecContext(ctx, s.q(`DELETE FROM store_lease WHERE id = 1 AND holder = ?`), holder)
	return err
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
