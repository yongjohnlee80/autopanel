package store

import (
	"context"

	"github.com/yongjohnlee80/golib/dao"

	"github.com/yongjohnlee80/autopanel/core/audit"
)

// Setting reads the panel setting key. ok is false when it was never set: its
// owner then uses its default.
func (s *Store) Setting(ctx context.Context, key string) (value string, ok bool, err error) {
	rows, err := s.conn.QueryContext(ctx, s.q("SELECT value FROM setting WHERE key = ?"), key)
	if err != nil {
		return "", false, err
	}
	defer rows.Close()
	if !rows.Next() {
		return "", false, rows.Err()
	}
	if err := rows.Scan(&value); err != nil {
		return "", false, err
	}
	return value, true, nil
}

// PutSetting keeps value as the panel setting key, with its audit entry in the
// same transaction (R2). Settings are not secrets: the value is in the entry.
func (s *Store) PutSetting(ctx context.Context, key, value string) error {
	now := s.now().Unix()
	return s.tx(ctx, func(tx dao.TxConn) error {
		if _, err := tx.ExecContext(ctx, s.q(`INSERT INTO setting(key, value, updated_at) VALUES (?, ?, ?)
ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`), key, value, now); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, s.q("INSERT INTO audit(at, actor, action, subject, detail) VALUES (?, ?, 'setting.set', ?, ?)"),
			now, audit.Actor(ctx), "setting "+key, value)
		return err
	})
}
