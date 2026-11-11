package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/yongjohnlee80/golib/dao"

	"github.com/yongjohnlee80/autopanel/core/audit"
	"github.com/yongjohnlee80/autopanel/core/gate"
)

// Routes is the gate's Routes port on the store.
func (s *Store) Routes() gate.Routes { return routes{s} }

type routes struct{ s *Store }

const routeCols = "id, host, path_prefix, upstream"

func scanRoute(rows dao.Rows) (gate.Route, error) {
	var r gate.Route
	var id int64
	err := rows.Scan(&id, &r.Host, &r.PathPrefix, &r.Upstream)
	r.ID = gate.RouteID(id)
	return r, err
}

// All reads every route. Routes number in the tens: the gate rebuilds its
// table whole (rationale §R9), and this read is bounded by that.
func (rs routes) All(ctx context.Context) ([]gate.Route, error) {
	rows, err := rs.s.conn.QueryContext(ctx, "SELECT "+routeCols+" FROM route ORDER BY host, path_prefix")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []gate.Route
	for rows.Next() {
		r, err := scanRoute(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (rs routes) audit(ctx context.Context, tx dao.TxConn, action string, r gate.Route) error {
	_, err := tx.ExecContext(ctx, rs.s.q("INSERT INTO audit(at, actor, action, subject, detail) VALUES (?, ?, ?, ?, ?)"),
		rs.s.now().Unix(), audit.Actor(ctx), action,
		"route "+itoa(int64(r.ID))+" "+r.Host+r.PathPrefix, "upstream "+r.Upstream)
	return err
}

func (rs routes) one(ctx context.Context, tx dao.TxConn, stmt string, args ...any) (gate.Route, error) {
	rows, err := tx.QueryContext(ctx, rs.s.q(stmt), args...)
	if err != nil {
		return gate.Route{}, rs.mapErr(err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return gate.Route{}, rs.mapErr(err)
		}
		return gate.Route{}, gate.ErrNotFound
	}
	r, err := scanRoute(rows)
	if err != nil {
		return gate.Route{}, err
	}
	return r, rows.Close()
}

func (rs routes) mapErr(err error) error {
	if errors.Is(rs.s.translate(err), dao.ErrDuplicate) {
		return gate.ErrDuplicate
	}
	return err
}

// Add inserts r and its audit entry in one transaction.
func (rs routes) Add(ctx context.Context, r gate.Route) (out gate.Route, err error) {
	now := rs.s.now().Unix()
	err = rs.s.tx(ctx, func(tx dao.TxConn) error {
		out, err = rs.one(ctx, tx, "INSERT INTO route(host, path_prefix, upstream, created_at, updated_at) VALUES (?, ?, ?, ?, ?) RETURNING "+routeCols,
			r.Host, r.PathPrefix, r.Upstream, now, now)
		if err != nil {
			return err
		}
		return rs.audit(ctx, tx, "route.add", out)
	})
	return out, err
}

// Update replaces r's host, prefix and upstream, with its audit entry.
func (rs routes) Update(ctx context.Context, r gate.Route) (out gate.Route, err error) {
	err = rs.s.tx(ctx, func(tx dao.TxConn) error {
		out, err = rs.one(ctx, tx, "UPDATE route SET host = ?, path_prefix = ?, upstream = ?, updated_at = ? WHERE id = ? RETURNING "+routeCols,
			r.Host, r.PathPrefix, r.Upstream, rs.s.now().Unix(), int64(r.ID))
		if err != nil {
			return err
		}
		return rs.audit(ctx, tx, "route.update", out)
	})
	return out, err
}

// Remove deletes the route and records it.
func (rs routes) Remove(ctx context.Context, id gate.RouteID) (out gate.Route, err error) {
	err = rs.s.tx(ctx, func(tx dao.TxConn) error {
		out, err = rs.one(ctx, tx, "DELETE FROM route WHERE id = ? RETURNING "+routeCols, int64(id))
		if err != nil {
			return err
		}
		return rs.audit(ctx, tx, "route.remove", out)
	})
	if err != nil && !errors.Is(err, gate.ErrNotFound) {
		err = fmt.Errorf("store: removing route %d: %w", id, err)
	}
	return out, err
}
