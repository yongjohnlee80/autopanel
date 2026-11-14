package store

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/yongjohnlee80/golib/dao"

	"github.com/yongjohnlee80/autopanel/core/audit"
	"github.com/yongjohnlee80/autopanel/internal/auth"
	"github.com/yongjohnlee80/autopanel/internal/keyslot"
)

// Users is the auth module's Store on the store. Each change writes its audit
// entry in the same transaction (R2), and a change that could leave no admin
// checks the admins inside it, under a lock on their rows (R3).
func (s *Store) Users() auth.Store { return userStore{s} }

type userStore struct{ s *Store }

const userColumns = "id, name, role, verifier, must_change, disabled_at, locked_until, fail_count, last_login_at, totp, totp_last_step, created_at"

// rowQuerier is a connection or a transaction.
type rowQuerier interface {
	QueryContext(ctx context.Context, query string, args ...any) (dao.Rows, error)
}

func (us userStore) PassphraseSlot(ctx context.Context, name string) (keyslot.PassphraseSlot, error) {
	return us.s.PassphraseSlot(ctx, name)
}

func scanUser(rows dao.Rows) (auth.User, error) {
	var u auth.User
	var role string
	var mustChange, totp int64
	err := rows.Scan(&u.ID, &u.Name, &role, &u.Verifier, &mustChange, &u.DisabledAt, &u.LockedUntil, &u.FailCount,
		&u.LastLoginAt, &totp, &u.TOTPLastStep, &u.CreatedAt)
	u.Role, u.MustChange, u.TOTP = auth.Role(role), mustChange != 0, totp != 0
	return u, err
}

// rootID is the first user's id: --init's.
func (us userStore) rootID(ctx context.Context, q rowQuerier) (int64, error) {
	rows, err := q.QueryContext(ctx, "SELECT COALESCE(MIN(id), 0) FROM app_user")
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var id int64
	rows.Next()
	return id, rows.Scan(&id)
}

func (us userStore) users(ctx context.Context, q rowQuerier, where string, args ...any) ([]auth.User, error) {
	root, err := us.rootID(ctx, q)
	if err != nil {
		return nil, err
	}
	rows, err := q.QueryContext(ctx, us.s.q("SELECT "+userColumns+" FROM app_user "+where), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []auth.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		u.Root = u.ID == root
		out = append(out, u)
	}
	return out, rows.Err()
}

func (us userStore) one(ctx context.Context, q rowQuerier, where string, args ...any) (auth.User, error) {
	list, err := us.users(ctx, q, where, args...)
	if err != nil {
		return auth.User{}, err
	}
	if len(list) == 0 {
		return auth.User{}, auth.ErrNoUser
	}
	return list[0], nil
}

func (us userStore) User(ctx context.Context, name string) (auth.User, error) {
	return us.one(ctx, us.s.conn, "WHERE name = ?", name)
}

func (us userStore) UserByID(ctx context.Context, id int64) (auth.User, error) {
	return us.one(ctx, us.s.conn, "WHERE id = ?", id)
}

func (us userStore) Users(ctx context.Context) ([]auth.User, error) {
	list, err := us.users(ctx, us.s.conn, "ORDER BY name")
	if list == nil {
		list = []auth.User{}
	}
	return list, err
}

func (us userStore) audit(ctx context.Context, tx dao.TxConn, action, subject string) error {
	_, err := tx.ExecContext(ctx, us.s.q("INSERT INTO audit(at, actor, action, subject, detail) VALUES (?, ?, ?, ?, '')"),
		us.s.now().Unix(), audit.Actor(ctx), action, subject)
	return err
}

// lockAdmins takes the admins' rows for the rest of the transaction, so two
// changes cannot both see another admin left (R3). SQLite's write lock
// serialises the transactions instead.
func (us userStore) lockAdmins(ctx context.Context, tx dao.TxConn) error {
	if us.s.Engine() != dao.DialectPostgres {
		return nil
	}
	rows, err := tx.QueryContext(ctx, "SELECT id FROM app_user WHERE role = 'admin' FOR UPDATE")
	if err != nil {
		return err
	}
	return rows.Close()
}

// othersLeft counts the enabled admins other than id.
func (us userStore) othersLeft(ctx context.Context, tx dao.TxConn, id int64) (int, error) {
	rows, err := tx.QueryContext(ctx, us.s.q("SELECT COUNT(*) FROM app_user WHERE role = 'admin' AND disabled_at = 0 AND id <> ?"), id)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var n int
	rows.Next()
	return n, rows.Scan(&n)
}

func (us userStore) setSlot(ctx context.Context, tx dao.TxConn, id int64, slot *keyslot.PassphraseSlot) error {
	if _, err := tx.ExecContext(ctx, us.s.q("DELETE FROM keyslot WHERE kind = 'passphrase' AND user_id = ?"), id); err != nil {
		return err
	}
	if slot == nil {
		return nil
	}
	b, err := json.Marshal(slot)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, us.s.q("INSERT INTO keyslot(kind, user_id, slot, created_at) VALUES ('passphrase', ?, ?, ?)"), id, string(b), us.s.now().Unix())
	return err
}

func flag(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (us userStore) AddUser(ctx context.Context, name string, role auth.Role, slot *keyslot.PassphraseSlot, verifier string, mustChange bool) (auth.User, error) {
	if (role == auth.RoleAdmin) != (slot != nil) || (role == auth.RoleAdmin) == (verifier != "") {
		return auth.User{}, errors.New("store: an admin has a slot and no verifier, any other user a verifier and no slot")
	}
	var id int64
	err := us.s.tx(ctx, func(tx dao.TxConn) error {
		rows, err := tx.QueryContext(ctx, us.s.q("INSERT INTO app_user(name, created_at, role, verifier, must_change) VALUES (?, ?, ?, ?, ?) RETURNING id"),
			name, us.s.now().Unix(), string(role), verifier, flag(mustChange))
		if err != nil {
			if errors.Is(us.s.translate(err), dao.ErrDuplicate) {
				return auth.ErrUserExists
			}
			return err
		}
		rows.Next()
		err = rows.Scan(&id)
		_ = rows.Close()
		if err != nil {
			if errors.Is(us.s.translate(err), dao.ErrDuplicate) {
				return auth.ErrUserExists
			}
			return err
		}
		if err := us.setSlot(ctx, tx, id, slot); err != nil {
			return err
		}
		return us.audit(ctx, tx, "auth.user.add", "user "+name+" role "+string(role))
	})
	if err != nil {
		return auth.User{}, err
	}
	return us.UserByID(ctx, id)
}

func (us userStore) SetLogin(ctx context.Context, id int64, role auth.Role, slot *keyslot.PassphraseSlot, verifier string, mustChange bool) error {
	if (role == auth.RoleAdmin) != (slot != nil) || (role == auth.RoleAdmin) == (verifier != "") {
		return errors.New("store: an admin has a slot and no verifier, any other user a verifier and no slot")
	}
	return us.s.tx(ctx, func(tx dao.TxConn) error {
		if err := us.lockAdmins(ctx, tx); err != nil {
			return err
		}
		u, err := us.one(ctx, tx, "WHERE id = ?", id)
		if err != nil {
			return err
		}
		if u.Role == auth.RoleAdmin && role != auth.RoleAdmin {
			if u.Root {
				return auth.ErrRootUser
			}
			if n, err := us.othersLeft(ctx, tx, id); err != nil {
				return err
			} else if n == 0 {
				return auth.ErrLastAdmin
			}
		}
		if _, err := tx.ExecContext(ctx, us.s.q("UPDATE app_user SET role = ?, verifier = ?, must_change = ? WHERE id = ?"),
			string(role), verifier, flag(mustChange), id); err != nil {
			return err
		}
		if err := us.setSlot(ctx, tx, id, slot); err != nil {
			return err
		}
		action := "auth.passphrase"
		if role != u.Role {
			action = "auth.user.role"
		}
		return us.audit(ctx, tx, action, "user "+u.Name+" role "+string(role))
	})
}

func (us userStore) SetDisabled(ctx context.Context, id int64, disabled bool) error {
	return us.s.tx(ctx, func(tx dao.TxConn) error {
		if err := us.lockAdmins(ctx, tx); err != nil {
			return err
		}
		u, err := us.one(ctx, tx, "WHERE id = ?", id)
		if err != nil {
			return err
		}
		at := int64(0)
		if disabled {
			if u.Root {
				return auth.ErrRootUser
			}
			if u.Role == auth.RoleAdmin {
				if n, err := us.othersLeft(ctx, tx, id); err != nil {
					return err
				} else if n == 0 {
					return auth.ErrLastAdmin
				}
			}
			at = us.s.now().Unix()
		}
		if _, err := tx.ExecContext(ctx, us.s.q("UPDATE app_user SET disabled_at = ? WHERE id = ?"), at, id); err != nil {
			return err
		}
		return us.audit(ctx, tx, "auth.user.disable", "user "+u.Name+" disabled "+strconv.FormatBool(disabled))
	})
}

func (us userStore) RemoveUser(ctx context.Context, id int64) error {
	return us.s.tx(ctx, func(tx dao.TxConn) error {
		if err := us.lockAdmins(ctx, tx); err != nil {
			return err
		}
		u, err := us.one(ctx, tx, "WHERE id = ?", id)
		if err != nil {
			return err
		}
		if u.Root {
			return auth.ErrRootUser
		}
		if u.Role == auth.RoleAdmin {
			if n, err := us.othersLeft(ctx, tx, id); err != nil {
				return err
			} else if n == 0 {
				return auth.ErrLastAdmin
			}
		}
		for _, stmt := range []string{"DELETE FROM api_token WHERE user_id = ?", "DELETE FROM recovery_code WHERE user_id = ?",
			"DELETE FROM keyslot WHERE user_id = ?", "DELETE FROM app_user WHERE id = ?"} {
			if _, err := tx.ExecContext(ctx, us.s.q(stmt), id); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, us.s.q("DELETE FROM secret WHERE name = ?"), "auth/totp/"+strconv.FormatInt(id, 10)); err != nil {
			return err
		}
		return us.audit(ctx, tx, "auth.user.remove", "user "+u.Name)
	})
}

func (us userStore) RecordFailure(ctx context.Context, id int64, lockAfter int, lockUntil int64) (int, error) {
	var n int
	err := us.s.tx(ctx, func(tx dao.TxConn) error {
		if _, err := tx.ExecContext(ctx, us.s.q("UPDATE app_user SET fail_count = fail_count + 1 WHERE id = ?"), id); err != nil {
			return err
		}
		u, err := us.one(ctx, tx, "WHERE id = ?", id)
		if err != nil {
			return err
		}
		n = u.FailCount
		if n >= lockAfter && !u.Root {
			if _, err := tx.ExecContext(ctx, us.s.q("UPDATE app_user SET locked_until = ?, fail_count = 0 WHERE id = ?"), lockUntil, id); err != nil {
				return err
			}
			return us.audit(ctx, tx, "auth.locked", "user "+u.Name)
		}
		return nil
	})
	return n, err
}

func (us userStore) RecordLogin(ctx context.Context, id int64) error {
	_, err := us.s.conn.ExecContext(ctx, us.s.q("UPDATE app_user SET fail_count = 0, locked_until = 0, last_login_at = ? WHERE id = ?"), us.s.now().Unix(), id)
	return err
}

func (us userStore) ClearLock(ctx context.Context, id int64) error {
	return us.s.tx(ctx, func(tx dao.TxConn) error {
		if _, err := tx.ExecContext(ctx, us.s.q("UPDATE app_user SET fail_count = 0, locked_until = 0 WHERE id = ?"), id); err != nil {
			return err
		}
		return us.audit(ctx, tx, "auth.user.unlock", "user #"+strconv.FormatInt(id, 10))
	})
}

func (us userStore) SetTOTP(ctx context.Context, id int64, enrolled bool, recovery [][]byte) error {
	return us.s.tx(ctx, func(tx dao.TxConn) error {
		if _, err := tx.ExecContext(ctx, us.s.q("UPDATE app_user SET totp = ?, totp_last_step = 0 WHERE id = ?"), flag(enrolled), id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, us.s.q("DELETE FROM recovery_code WHERE user_id = ?"), id); err != nil {
			return err
		}
		for _, h := range recovery {
			if _, err := tx.ExecContext(ctx, us.s.q("INSERT INTO recovery_code(user_id, hash) VALUES (?, ?)"), id, h); err != nil {
				return err
			}
		}
		return us.audit(ctx, tx, "auth.totp", "user #"+strconv.FormatInt(id, 10)+" enrolled "+strconv.FormatBool(enrolled))
	})
}

func (us userStore) SpendStep(ctx context.Context, id, step int64) (bool, error) {
	res, err := us.s.conn.ExecContext(ctx, us.s.q("UPDATE app_user SET totp_last_step = ? WHERE id = ? AND totp_last_step < ?"), step, id, step)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

func (us userStore) SpendRecovery(ctx context.Context, id int64, hash []byte) (bool, error) {
	res, err := us.s.conn.ExecContext(ctx, us.s.q("DELETE FROM recovery_code WHERE user_id = ? AND hash = ?"), id, hash)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

const tokenColumns = "t.id, t.user_id, u.name, t.name, t.hash, t.role, t.created_at, t.expires_at, t.last_used_at, t.revoked_at"

func (us userStore) tokens(ctx context.Context, where string, args ...any) ([]auth.Token, error) {
	rows, err := us.s.conn.QueryContext(ctx, us.s.q("SELECT "+tokenColumns+" FROM api_token t JOIN app_user u ON u.id = t.user_id "+where+" ORDER BY t.id"), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []auth.Token{}
	for rows.Next() {
		var t auth.Token
		var role string
		if err := rows.Scan(&t.ID, &t.UserID, &t.Owner, &t.Name, &t.Hash, &role, &t.CreatedAt, &t.ExpiresAt, &t.LastUsedAt, &t.RevokedAt); err != nil {
			return nil, err
		}
		t.Role = auth.Role(role)
		out = append(out, t)
	}
	return out, rows.Err()
}

func (us userStore) AddToken(ctx context.Context, t auth.Token) (int64, error) {
	var id int64
	err := us.s.tx(ctx, func(tx dao.TxConn) error {
		rows, err := tx.QueryContext(ctx, us.s.q("INSERT INTO api_token(user_id, name, hash, role, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?) RETURNING id"),
			t.UserID, t.Name, t.Hash, string(t.Role), t.CreatedAt, t.ExpiresAt)
		if err != nil {
			return err
		}
		rows.Next()
		err = rows.Scan(&id)
		_ = rows.Close()
		if err != nil {
			return err
		}
		return us.audit(ctx, tx, "auth.token.create", "token "+t.Name+" #"+strconv.FormatInt(id, 10)+" role "+string(t.Role))
	})
	return id, err
}

func (us userStore) Token(ctx context.Context, id int64) (auth.Token, error) {
	list, err := us.tokens(ctx, "WHERE t.id = ?", id)
	if err != nil {
		return auth.Token{}, err
	}
	if len(list) == 0 {
		return auth.Token{}, auth.ErrNoToken
	}
	return list[0], nil
}

func (us userStore) Tokens(ctx context.Context, userID int64) ([]auth.Token, error) {
	if userID == 0 {
		return us.tokens(ctx, "")
	}
	return us.tokens(ctx, "WHERE t.user_id = ?", userID)
}

func (us userStore) RevokeToken(ctx context.Context, id int64) error {
	return us.s.tx(ctx, func(tx dao.TxConn) error {
		res, err := tx.ExecContext(ctx, us.s.q("UPDATE api_token SET revoked_at = ? WHERE id = ? AND revoked_at = 0"), us.s.now().Unix(), id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return auth.ErrNoToken
		}
		return us.audit(ctx, tx, "auth.token.revoke", "token #"+strconv.FormatInt(id, 10))
	})
}

func (us userStore) TouchToken(ctx context.Context, id, at int64) error {
	_, err := us.s.conn.ExecContext(ctx, us.s.q("UPDATE api_token SET last_used_at = ? WHERE id = ?"), at, id)
	return err
}
