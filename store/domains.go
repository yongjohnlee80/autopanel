package store

import (
	"context"
	"errors"

	"github.com/yongjohnlee80/golib/dao"

	"github.com/yongjohnlee80/autopanel/core/audit"
	"github.com/yongjohnlee80/autopanel/core/gate"
)

// Domains is the gate's Domains port on the store. Each write also writes its
// audit entry, in one transaction, as a route's does.
func (s *Store) Domains() gate.Domains { return domains{s} }

type domains struct{ s *Store }

// All reads every domain, by name. Domains number in the tens.
func (ds domains) All(ctx context.Context) ([]gate.Domain, error) {
	rows, err := ds.s.conn.QueryContext(ctx, "SELECT name FROM domain ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []gate.Domain{}
	for rows.Next() {
		var d gate.Domain
		if err := rows.Scan(&d.Name); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (ds domains) audit(ctx context.Context, tx dao.TxConn, action, name string) error {
	_, err := tx.ExecContext(ctx, ds.s.q("INSERT INTO audit(at, actor, action, subject, detail) VALUES (?, ?, ?, ?, '')"),
		ds.s.now().Unix(), audit.Actor(ctx), action, "domain "+name)
	return err
}

func (ds domains) Add(ctx context.Context, d gate.Domain) error {
	return ds.s.tx(ctx, func(tx dao.TxConn) error {
		if _, err := tx.ExecContext(ctx, ds.s.q("INSERT INTO domain(name, created_at) VALUES (?, ?)"), d.Name, ds.s.now().Unix()); err != nil {
			if errors.Is(ds.s.translate(err), dao.ErrDuplicate) {
				return gate.ErrDomainExists
			}
			return err
		}
		return ds.audit(ctx, tx, "domain.add", d.Name)
	})
}

func (ds domains) Remove(ctx context.Context, name string) error {
	return ds.s.tx(ctx, func(tx dao.TxConn) error {
		res, err := tx.ExecContext(ctx, ds.s.q("DELETE FROM domain WHERE name = ?"), name)
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			return gate.ErrNoSuchDomain
		}
		return ds.audit(ctx, tx, "domain.remove", name)
	})
}
