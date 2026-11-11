package store

import (
	"context"
	"errors"

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

// AuditEntry is one row of the audit log, as it is read back.
type AuditEntry struct {
	ID      int64  `json:"id"`
	At      int64  `json:"at"` // Unix seconds
	Actor   string `json:"actor"`
	Action  string `json:"action"`
	Subject string `json:"subject"`
	Detail  string `json:"detail"`
	// Outcome is set on a privileged action's entry: "attempt" until the
	// action ends, then "ok" or the error's name. Empty on every other entry.
	Outcome string `json:"outcome"`
}

// AuditLog reads the newest audit entries, newest first, at most limit. With
// an action, only that action's entries.
func (s *Store) AuditLog(ctx context.Context, action string, limit int) ([]AuditEntry, error) {
	stmt, args := "SELECT id, at, actor, action, subject, detail, outcome FROM audit ORDER BY id DESC LIMIT ?", []any{limit}
	if action != "" {
		stmt, args = "SELECT id, at, actor, action, subject, detail, outcome FROM audit WHERE action = ? ORDER BY id DESC LIMIT ?", []any{action, limit}
	}
	rows, err := s.conn.QueryContext(ctx, s.q(stmt), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.At, &e.Actor, &e.Action, &e.Subject, &e.Detail, &e.Outcome); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// AuditAttempt writes the entry of a privileged action before the action
// runs, with the outcome "attempt", and answers the entry's id.
func (s *Store) AuditAttempt(ctx context.Context, actor, action, subject string) (int64, error) {
	rows, err := s.conn.QueryContext(ctx, s.q("INSERT INTO audit(at, actor, action, subject, outcome) VALUES (?, ?, ?, ?, 'attempt') RETURNING id"),
		s.now().Unix(), actor, action, subject)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return 0, err
		}
		return 0, errors.New("store: the audit entry was not written")
	}
	var id int64
	if err := rows.Scan(&id); err != nil {
		return 0, err
	}
	return id, rows.Close()
}

// AuditResult sets the outcome of the privileged action whose entry is id.
func (s *Store) AuditResult(ctx context.Context, id int64, outcome string) error {
	_, err := s.conn.ExecContext(ctx, s.q("UPDATE audit SET outcome = ? WHERE id = ?"), outcome, id)
	return err
}
