package store

import (
	"context"
	"errors"

	"github.com/yongjohnlee80/golib/dao"

	"github.com/yongjohnlee80/autopanel/core/audit"
	"github.com/yongjohnlee80/autopanel/core/tunnel"
)

// Tunnels is the tunnel agents' Store on the store.
func (s *Store) Tunnels() tunnel.Store { return tunnels{s} }

type tunnels struct{ s *Store }

const agentCols = "id, name, pubkey, enrolled_from, enrolled_at, token_id, token_hash, token_expires, created_at"

func scanAgent(rows dao.Rows) (tunnel.Agent, error) {
	var a tunnel.Agent
	err := rows.Scan(&a.ID, &a.Name, &a.Key, &a.EnrolledFrom, &a.EnrolledAt, &a.TokenID, &a.TokenHash, &a.TokenExpires, &a.CreatedAt)
	return a, err
}

// All reads every agent, by name. They number sixteen at most.
func (ts tunnels) All(ctx context.Context) ([]tunnel.Agent, error) {
	rows, err := ts.s.conn.QueryContext(ctx, "SELECT "+agentCols+" FROM tunnel_agent ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []tunnel.Agent
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// audit records a change to an agent. A token, or its hash, is never in it.
func (ts tunnels) audit(ctx context.Context, tx dao.TxConn, actor, action string, a tunnel.Agent) error {
	detail := ""
	if a.Key != "" {
		detail = tunnel.Fingerprint(a.Key) + " from " + a.EnrolledFrom
	}
	_, err := tx.ExecContext(ctx, ts.s.q("INSERT INTO audit(at, actor, action, subject, detail) VALUES (?, ?, ?, ?, ?)"),
		ts.s.now().Unix(), actor, action, "tunnel agent "+a.Name, detail)
	return err
}

// one runs a statement that answers at most one agent; none is missing.
func (ts tunnels) one(ctx context.Context, tx dao.TxConn, missing error, stmt string, args ...any) (tunnel.Agent, error) {
	rows, err := tx.QueryContext(ctx, ts.s.q(stmt), args...)
	if err != nil {
		return tunnel.Agent{}, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return tunnel.Agent{}, err
		}
		return tunnel.Agent{}, missing
	}
	a, err := scanAgent(rows)
	if err != nil {
		return tunnel.Agent{}, err
	}
	return a, rows.Close()
}

// Add inserts a and its audit entry in one transaction.
func (ts tunnels) Add(ctx context.Context, a tunnel.Agent) (out tunnel.Agent, err error) {
	err = ts.s.tx(ctx, func(tx dao.TxConn) error {
		out, err = ts.one(ctx, tx, tunnel.ErrNotFound, `INSERT INTO tunnel_agent(name, token_id, token_hash, token_expires, created_at)
			VALUES (?, ?, ?, ?, ?) RETURNING `+agentCols, a.Name, a.TokenID, a.TokenHash, a.TokenExpires, a.CreatedAt)
		if err != nil {
			if errors.Is(ts.s.translate(err), dao.ErrDuplicate) {
				return tunnel.ErrDuplicate
			}
			return err
		}
		return ts.audit(ctx, tx, audit.Actor(ctx), "tunnel.agent.add", out)
	})
	return out, err
}

// Enrol spends the token and gives its agent the key, in one statement: two
// callers with one token cannot both win.
func (ts tunnels) Enrol(ctx context.Context, tokenID, tokenHash, key, from string, now int64) (out tunnel.Agent, err error) {
	err = ts.s.tx(ctx, func(tx dao.TxConn) error {
		out, err = ts.one(ctx, tx, tunnel.ErrBadToken, `UPDATE tunnel_agent
			SET pubkey = ?, enrolled_from = ?, enrolled_at = ?, token_id = '', token_hash = '', token_expires = 0
			WHERE token_id = ? AND token_hash = ? AND token_expires > ? AND pubkey = '' RETURNING `+agentCols,
			key, from, now, tokenID, tokenHash, now)
		if err != nil {
			if errors.Is(ts.s.translate(err), dao.ErrDuplicate) {
				return tunnel.ErrBadToken // the key is another agent's
			}
			return err
		}
		// The agent enrolled itself: no administrator is the actor.
		return ts.audit(ctx, tx, "agent "+out.Name, "tunnel.agent.enrol", out)
	})
	return out, err
}

// Remove deletes the agent and records it.
func (ts tunnels) Remove(ctx context.Context, id int64) (out tunnel.Agent, err error) {
	err = ts.s.tx(ctx, func(tx dao.TxConn) error {
		out, err = ts.one(ctx, tx, tunnel.ErrNotFound, "DELETE FROM tunnel_agent WHERE id = ? RETURNING "+agentCols, id)
		if err != nil {
			return err
		}
		return ts.audit(ctx, tx, audit.Actor(ctx), "tunnel.agent.remove", out)
	})
	return out, err
}
