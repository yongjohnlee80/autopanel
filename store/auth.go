package store

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/yongjohnlee80/golib/dao"

	"github.com/yongjohnlee80/autopanel/core/audit"
	"github.com/yongjohnlee80/autopanel/internal/keyslot"
)

var (
	// ErrInitialized is an --init on a store that already has its root user.
	ErrInitialized = errors.New("store: already initialized")
	// ErrNotInitialized is a store with no keyslots: run --init first.
	ErrNotInitialized = errors.New("store: not initialized; run autopanel --init")
	// ErrNoUser is a login for a name with no passphrase slot. Callers report it
	// exactly as a wrong passphrase.
	ErrNoUser = errors.New("store: no such user")
)

// InitRoot makes the first user and both keyslots, in one transaction. It
// refuses a store that has any user: re-initialising would strand every
// secret sealed under the old master key.
func (s *Store) InitRoot(ctx context.Context, name string, pass keyslot.PassphraseSlot, svc keyslot.ServiceSlot) error {
	ps, err := json.Marshal(pass)
	if err != nil {
		return err
	}
	ss, err := json.Marshal(svc)
	if err != nil {
		return err
	}
	now := s.now().Unix()
	return s.tx(ctx, func(tx dao.TxConn) error {
		rows, err := tx.QueryContext(ctx, "SELECT COUNT(*) FROM app_user")
		if err != nil {
			return err
		}
		var n int
		rows.Next()
		err = rows.Scan(&n)
		_ = rows.Close()
		if err != nil {
			return err
		}
		if n > 0 {
			return ErrInitialized
		}
		rows, err = tx.QueryContext(ctx, s.q("INSERT INTO app_user(name, created_at) VALUES (?, ?) RETURNING id"), name, now)
		if err != nil {
			return err
		}
		var id int64
		rows.Next()
		err = rows.Scan(&id)
		_ = rows.Close()
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, s.q("INSERT INTO keyslot(kind, user_id, slot, created_at) VALUES ('passphrase', ?, ?, ?)"), id, string(ps), now); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, s.q("INSERT INTO keyslot(kind, user_id, slot, created_at) VALUES ('service', NULL, ?, ?)"), string(ss), now); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, s.q("INSERT INTO audit(at, actor, action, subject, detail) VALUES (?, 'init', 'user.init', ?, 'root user and keyslots created')"), now, "user "+name)
		return err
	})
}

func (s *Store) slot(ctx context.Context, stmt string, args ...any) (string, error) {
	rows, err := s.conn.QueryContext(ctx, s.q(stmt), args...)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	if !rows.Next() {
		return "", rows.Err()
	}
	var v string
	return v, rows.Scan(&v)
}

// PassphraseSlot is name's passphrase slot, or ErrNoUser.
func (s *Store) PassphraseSlot(ctx context.Context, name string) (keyslot.PassphraseSlot, error) {
	v, err := s.slot(ctx, "SELECT k.slot FROM keyslot k JOIN app_user u ON u.id = k.user_id WHERE k.kind = 'passphrase' AND u.name = ?", name)
	if err != nil {
		return keyslot.PassphraseSlot{}, err
	}
	if v == "" {
		return keyslot.PassphraseSlot{}, ErrNoUser
	}
	var p keyslot.PassphraseSlot
	return p, json.Unmarshal([]byte(v), &p)
}

// ServiceSlot is the service keyslot, or ErrNotInitialized.
func (s *Store) ServiceSlot(ctx context.Context) (keyslot.ServiceSlot, error) {
	v, err := s.slot(ctx, "SELECT slot FROM keyslot WHERE kind = 'service'")
	if err != nil {
		return keyslot.ServiceSlot{}, err
	}
	if v == "" {
		return keyslot.ServiceSlot{}, ErrNotInitialized
	}
	var p keyslot.ServiceSlot
	return p, json.Unmarshal([]byte(v), &p)
}

// Audit writes one audit entry on its own: for events that change nothing
// else, such as a login attempt (recorded before its effect, R12).
func (s *Store) Audit(ctx context.Context, actor, action, subject, detail string) error {
	_, err := s.conn.ExecContext(ctx, s.q("INSERT INTO audit(at, actor, action, subject, detail) VALUES (?, ?, ?, ?, ?)"),
		s.now().Unix(), actor, action, subject, detail)
	return err
}

// ErrNoSecret is a secret the store doesn't hold.
var ErrNoSecret = errors.New("store: no such secret")

func secretAAD(name string) string { return "autopanel:secret:" + name + ":v1" }

// PutSecret seals value under the master key and keeps it as name, with its
// audit entry in the same transaction (R2). The value never reaches the log.
func (s *Store) PutSecret(ctx context.Context, v *keyslot.Vault, name string, value []byte) error {
	sealed, err := v.Seal(secretAAD(name), value)
	if err != nil {
		return err
	}
	now := s.now().Unix()
	return s.tx(ctx, func(tx dao.TxConn) error {
		if _, err := tx.ExecContext(ctx, s.q(`INSERT INTO secret(name, value, updated_at) VALUES (?, ?, ?)
ON CONFLICT (name) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`), name, sealed, now); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, s.q("INSERT INTO audit(at, actor, action, subject, detail) VALUES (?, ?, 'secret.set', ?, '')"), now, audit.Actor(ctx), "secret "+name)
		return err
	})
}

// Secret opens the secret name, or ErrNoSecret.
func (s *Store) Secret(ctx context.Context, v *keyslot.Vault, name string) ([]byte, error) {
	rows, err := s.conn.QueryContext(ctx, s.q("SELECT value FROM secret WHERE name = ?"), name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, err
		}
		return nil, ErrNoSecret
	}
	var sealed []byte
	if err := rows.Scan(&sealed); err != nil {
		return nil, err
	}
	return v.Open(secretAAD(name), sealed)
}

// DeleteSecret forgets the secret name, with its audit entry.
func (s *Store) DeleteSecret(ctx context.Context, name string) error {
	return s.tx(ctx, func(tx dao.TxConn) error {
		if _, err := tx.ExecContext(ctx, s.q("DELETE FROM secret WHERE name = ?"), name); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, s.q("INSERT INTO audit(at, actor, action, subject, detail) VALUES (?, ?, 'secret.delete', ?, '')"), s.now().Unix(), audit.Actor(ctx), "secret "+name)
		return err
	})
}
