package store

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/yongjohnlee80/golib/dao"

	"github.com/yongjohnlee80/autopanel/core/audit"
	"github.com/yongjohnlee80/autopanel/core/forward"
)

// Forwards is the port forwards' Store on the store.
func (s *Store) Forwards() forward.Store { return forwards{s} }

type forwards struct{ s *Store }

const forwardCols = "id, name, proto, port_from, port_to, target, proxy, allow, per_client, idle_secs"

func scanForward(rows dao.Rows) (forward.Forward, error) {
	var f forward.Forward
	var proxy int
	var allow string
	err := rows.Scan(&f.ID, &f.Name, &f.Proto, &f.From, &f.To, &f.Target, &proxy, &allow, &f.PerClient, &f.IdleSecs)
	f.Proxy, f.Allow = proxy != 0, strings.Fields(allow)
	return f, err
}

// All reads every forward, by name. They number sixteen at most.
func (fs forwards) All(ctx context.Context) ([]forward.Forward, error) {
	rows, err := fs.s.conn.QueryContext(ctx, "SELECT "+forwardCols+" FROM forward ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []forward.Forward
	for rows.Next() {
		f, err := scanForward(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (fs forwards) audit(ctx context.Context, tx dao.TxConn, action string, f forward.Forward) error {
	ports := strconv.Itoa(f.From)
	if f.To > f.From {
		ports += "-" + strconv.Itoa(f.To)
	}
	detail := "to " + f.Target
	if len(f.Allow) > 0 {
		detail += " from " + strings.Join(f.Allow, " ")
	}
	_, err := tx.ExecContext(ctx, fs.s.q("INSERT INTO audit(at, actor, action, subject, detail) VALUES (?, ?, ?, ?, ?)"),
		fs.s.now().Unix(), audit.Actor(ctx), action, "forward "+f.Name+" "+f.Proto+"/"+ports, detail)
	return err
}

func (fs forwards) one(ctx context.Context, tx dao.TxConn, stmt string, args ...any) (forward.Forward, error) {
	rows, err := tx.QueryContext(ctx, fs.s.q(stmt), args...)
	if err != nil {
		return forward.Forward{}, fs.mapErr(err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return forward.Forward{}, fs.mapErr(err)
		}
		return forward.Forward{}, forward.ErrNotFound
	}
	f, err := scanForward(rows)
	if err != nil {
		return forward.Forward{}, err
	}
	return f, rows.Close()
}

func (fs forwards) mapErr(err error) error {
	if errors.Is(fs.s.translate(err), dao.ErrDuplicate) {
		return forward.ErrDuplicate
	}
	return err
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Add inserts f and its audit entry in one transaction.
func (fs forwards) Add(ctx context.Context, f forward.Forward) (out forward.Forward, err error) {
	now := fs.s.now().Unix()
	err = fs.s.tx(ctx, func(tx dao.TxConn) error {
		out, err = fs.one(ctx, tx, `INSERT INTO forward(name, proto, port_from, port_to, target, proxy, allow, per_client, idle_secs, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING `+forwardCols,
			f.Name, f.Proto, f.From, f.To, f.Target, b2i(f.Proxy), strings.Join(f.Allow, " "), f.PerClient, f.IdleSecs, now, now)
		if err != nil {
			return err
		}
		return fs.audit(ctx, tx, "forward.add", out)
	})
	return out, err
}

// Update replaces everything of f but its name, with its audit entry.
func (fs forwards) Update(ctx context.Context, f forward.Forward) (out forward.Forward, err error) {
	err = fs.s.tx(ctx, func(tx dao.TxConn) error {
		out, err = fs.one(ctx, tx, `UPDATE forward SET proto = ?, port_from = ?, port_to = ?, target = ?, proxy = ?, allow = ?, per_client = ?, idle_secs = ?, updated_at = ?
			WHERE id = ? RETURNING `+forwardCols,
			f.Proto, f.From, f.To, f.Target, b2i(f.Proxy), strings.Join(f.Allow, " "), f.PerClient, f.IdleSecs, fs.s.now().Unix(), f.ID)
		if err != nil {
			return err
		}
		return fs.audit(ctx, tx, "forward.update", out)
	})
	return out, err
}

// Remove deletes the forward and records it.
func (fs forwards) Remove(ctx context.Context, id int64) (out forward.Forward, err error) {
	err = fs.s.tx(ctx, func(tx dao.TxConn) error {
		out, err = fs.one(ctx, tx, "DELETE FROM forward WHERE id = ? RETURNING "+forwardCols, id)
		if err != nil {
			return err
		}
		return fs.audit(ctx, tx, "forward.remove", out)
	})
	return out, err
}
