package store

import (
	"context"
	"io/fs"
	"sort"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"

	"github.com/yongjohnlee80/autopanel/internal/certs"
)

// Blobs is certs' Blobs port on the cert_blob table.
func (s *Store) Blobs() certs.Blobs { return blobs{s} }

type blobs struct{ s *Store }

// below bounds the keys under a prefix as a range: "p/" ≤ key < "p0", since
// '0' follows '/' in byte order (SQLite compares bytes; PostgreSQL's columns
// are COLLATE "C"). It needs no LIKE, so a key's '%' or '_' means nothing.
func below(prefix string) (lo, hi string) { return prefix + "/", prefix + "0" }

func (b blobs) Put(ctx context.Context, key string, value []byte) error {
	_, err := b.s.conn.ExecContext(ctx, b.s.q(`INSERT INTO cert_blob(key, value, modified_at) VALUES (?, ?, ?)
ON CONFLICT (key) DO UPDATE SET value = excluded.value, modified_at = excluded.modified_at`), key, value, b.s.now().UnixNano())
	return err
}

func (b blobs) Get(ctx context.Context, key string) ([]byte, error) {
	rows, err := b.s.conn.QueryContext(ctx, b.s.q("SELECT value FROM cert_blob WHERE key = ?"), key)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, err
		}
		return nil, fs.ErrNotExist
	}
	var v []byte
	if err := rows.Scan(&v); err != nil {
		return nil, err
	}
	return v, nil
}

func (b blobs) Delete(ctx context.Context, key string) error {
	lo, hi := below(key)
	_, err := b.s.conn.ExecContext(ctx, b.s.q("DELETE FROM cert_blob WHERE key = ? OR (key >= ? AND key < ?)"), key, lo, hi)
	return err
}

// List names the keys under prefix. The set is a host's few certificate files
// and the ACME account's; it is read whole for the prefix and grouped here.
func (b blobs) List(ctx context.Context, prefix string, recursive bool) ([]string, error) {
	var stmt string
	var args []any
	if prefix == "" {
		stmt = "SELECT key FROM cert_blob ORDER BY key"
	} else {
		lo, hi := below(prefix)
		stmt, args = "SELECT key FROM cert_blob WHERE key >= ? AND key < ? ORDER BY key", []any{lo, hi}
	}
	rows, err := b.s.conn.QueryContext(ctx, b.s.q(stmt), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		if !recursive {
			rest := strings.TrimPrefix(strings.TrimPrefix(k, prefix), "/")
			k = strings.TrimPrefix(prefix+"/"+strings.SplitN(rest, "/", 2)[0], "/")
		}
		seen[k] = true
	}
	if err := rows.Err(); err != nil {
		return nil, err
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

func (b blobs) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	rows, err := b.s.conn.QueryContext(ctx, b.s.q("SELECT length(value), modified_at FROM cert_blob WHERE key = ?"), key)
	if err != nil {
		return certmagic.KeyInfo{}, err
	}
	if rows.Next() {
		var size, at int64
		err := rows.Scan(&size, &at)
		_ = rows.Close()
		if err != nil {
			return certmagic.KeyInfo{}, err
		}
		return certmagic.KeyInfo{Key: key, Modified: time.Unix(0, at), Size: size, IsTerminal: true}, nil
	}
	if err := rows.Close(); err != nil {
		return certmagic.KeyInfo{}, err
	}
	lo, hi := below(key)
	rows, err = b.s.conn.QueryContext(ctx, b.s.q("SELECT 1 FROM cert_blob WHERE key >= ? AND key < ? LIMIT 1"), lo, hi)
	if err != nil {
		return certmagic.KeyInfo{}, err
	}
	defer rows.Close()
	if rows.Next() {
		return certmagic.KeyInfo{Key: key, IsTerminal: false}, nil
	}
	if err := rows.Err(); err != nil {
		return certmagic.KeyInfo{}, err
	}
	return certmagic.KeyInfo{}, fs.ErrNotExist
}
