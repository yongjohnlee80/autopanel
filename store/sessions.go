package store

import (
	"context"

	"github.com/yongjohnlee80/golib/dao"

	"github.com/yongjohnlee80/autopanel/internal/auth"
)

// Sessions is the browser sessions' store.
func (s *Store) Sessions() auth.SessionStore { return sessions{s} }

type sessions struct{ s *Store }

const sessionCols = "id_hash, csrf_key, user_id, host, created_at, seen_at, client, agent"

func scanSession(rows dao.Rows) (auth.Session, error) {
	var v auth.Session
	var id, key []byte
	if err := rows.Scan(&id, &key, &v.UserID, &v.Host, &v.CreatedAt, &v.SeenAt, &v.Client, &v.Agent); err != nil {
		return auth.Session{}, err
	}
	if len(id) != 32 || len(key) != 32 {
		return auth.Session{}, auth.ErrNoSession
	}
	copy(v.IDHash[:], id)
	copy(v.CSRFKey[:], key)
	return v, nil
}

func (ss sessions) list(ctx context.Context, q querier, stmt string, args ...any) ([]auth.Session, error) {
	rows, err := q.QueryContext(ctx, ss.s.q(stmt), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []auth.Session
	for rows.Next() {
		v, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// PutSession removes every session expired says is over, then the user's
// oldest while the user holds max, then inserts s: one transaction.
func (ss sessions) PutSession(ctx context.Context, s auth.Session, max int, expired func(auth.Session) bool) error {
	return ss.s.tx(ctx, func(tx dao.TxConn) error {
		all, err := ss.list(ctx, tx, "SELECT "+sessionCols+" FROM web_session ORDER BY created_at, id_hash")
		if err != nil {
			return err
		}
		var mine []auth.Session
		for _, o := range all {
			switch {
			case expired(o):
				if _, err := tx.ExecContext(ctx, ss.s.q("DELETE FROM web_session WHERE id_hash = ?"), o.IDHash[:]); err != nil {
					return err
				}
			case o.UserID == s.UserID:
				mine = append(mine, o)
			}
		}
		for len(mine) >= max && len(mine) > 0 {
			if _, err := tx.ExecContext(ctx, ss.s.q("DELETE FROM web_session WHERE id_hash = ?"), mine[0].IDHash[:]); err != nil {
				return err
			}
			mine = mine[1:]
		}
		_, err = tx.ExecContext(ctx, ss.s.q("INSERT INTO web_session("+sessionCols+") VALUES (?, ?, ?, ?, ?, ?, ?, ?)"),
			s.IDHash[:], s.CSRFKey[:], s.UserID, s.Host, s.CreatedAt, s.SeenAt, s.Client, s.Agent)
		return err
	})
}

func (ss sessions) Session(ctx context.Context, idHash [32]byte) (auth.Session, error) {
	got, err := ss.list(ctx, ss.s.conn, "SELECT "+sessionCols+" FROM web_session WHERE id_hash = ?", idHash[:])
	if err != nil {
		return auth.Session{}, err
	}
	if len(got) != 1 {
		return auth.Session{}, auth.ErrNoSession
	}
	return got[0], nil
}

func (ss sessions) TouchSession(ctx context.Context, idHash [32]byte, seenAt int64) error {
	_, err := ss.s.conn.ExecContext(ctx, ss.s.q("UPDATE web_session SET seen_at = ? WHERE id_hash = ? AND seen_at < ?"), seenAt, idHash[:], seenAt)
	return err
}

func (ss sessions) EndSession(ctx context.Context, idHash [32]byte) error {
	_, err := ss.s.conn.ExecContext(ctx, ss.s.q("DELETE FROM web_session WHERE id_hash = ?"), idHash[:])
	return err
}

func (ss sessions) EndUserSessions(ctx context.Context, userID int64, except *[32]byte) (int, error) {
	var res dao.Result
	var err error
	if except == nil {
		res, err = ss.s.conn.ExecContext(ctx, ss.s.q("DELETE FROM web_session WHERE user_id = ?"), userID)
	} else {
		res, err = ss.s.conn.ExecContext(ctx, ss.s.q("DELETE FROM web_session WHERE user_id = ? AND id_hash <> ?"), userID, except[:])
	}
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

func (ss sessions) UserSessions(ctx context.Context, userID int64) ([]auth.Session, error) {
	return ss.list(ctx, ss.s.conn, "SELECT "+sessionCols+" FROM web_session WHERE user_id = ? ORDER BY created_at DESC, id_hash", userID)
}
