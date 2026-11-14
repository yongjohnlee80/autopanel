package store

import (
	"context"
	"errors"

	"github.com/yongjohnlee80/golib/dao"

	"github.com/yongjohnlee80/autopanel/core/audit"
	"github.com/yongjohnlee80/autopanel/core/mail"
)

// Mail is the mail module's Store port on the store: that mail exists, how far
// it got, and its domains. Every key and setting of mail is a secret, not
// here. Each write also writes its audit entry, in one transaction.
func (s *Store) Mail() mail.Store { return mailStore{s} }

type mailStore struct{ s *Store }

func (ms mailStore) audit(ctx context.Context, tx dao.TxConn, action, subject string) error {
	_, err := tx.ExecContext(ctx, ms.s.q("INSERT INTO audit(at, actor, action, subject, detail) VALUES (?, ?, ?, ?, '')"),
		ms.s.now().Unix(), audit.Actor(ctx), action, subject)
	return err
}

func (ms mailStore) State(ctx context.Context) (mail.State, bool, error) {
	rows, err := ms.s.conn.QueryContext(ctx, "SELECT host, bootstrapped, created_at FROM mail WHERE id = 1")
	if err != nil {
		return mail.State{}, false, err
	}
	defer rows.Close()
	if !rows.Next() {
		return mail.State{}, false, rows.Err()
	}
	var st mail.State
	if err := rows.Scan(&st.Host, &st.Bootstrapped, &st.CreatedAt); err != nil {
		return mail.State{}, false, err
	}
	return st, true, nil
}

func (ms mailStore) Create(ctx context.Context, host, firstDomain string) error {
	return ms.s.tx(ctx, func(tx dao.TxConn) error {
		now := ms.s.now().Unix()
		if _, err := tx.ExecContext(ctx, ms.s.q("INSERT INTO mail(id, host, bootstrapped, created_at) VALUES (1, ?, 0, ?)"), host, now); err != nil {
			if errors.Is(ms.s.translate(err), dao.ErrDuplicate) {
				return mail.ErrSetUp
			}
			return err
		}
		if _, err := tx.ExecContext(ctx, ms.s.q("INSERT INTO mail_domain(name, created_at) VALUES (?, ?)"), firstDomain, now); err != nil {
			return err
		}
		return ms.audit(ctx, tx, "mail.setup", "host "+host+" domain "+firstDomain)
	})
}

func (ms mailStore) SetBootstrapped(ctx context.Context, at int64) error {
	return ms.s.tx(ctx, func(tx dao.TxConn) error {
		res, err := tx.ExecContext(ctx, ms.s.q("UPDATE mail SET bootstrapped = ? WHERE id = 1"), at)
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			return mail.ErrNotSetUp
		}
		return ms.audit(ctx, tx, "mail.bootstrapped", "stack mail")
	})
}

func (ms mailStore) Domains(ctx context.Context) ([]string, error) {
	rows, err := ms.s.conn.QueryContext(ctx, "SELECT name FROM mail_domain ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (ms mailStore) AddDomain(ctx context.Context, name string) error {
	return ms.s.tx(ctx, func(tx dao.TxConn) error {
		if _, err := tx.ExecContext(ctx, ms.s.q("INSERT INTO mail_domain(name, created_at) VALUES (?, ?)"), name, ms.s.now().Unix()); err != nil {
			if errors.Is(ms.s.translate(err), dao.ErrDuplicate) {
				return mail.ErrDomainExists
			}
			return err
		}
		return ms.audit(ctx, tx, "mail.domain.add", "domain "+name)
	})
}

func (ms mailStore) RemoveDomain(ctx context.Context, name string) error {
	return ms.s.tx(ctx, func(tx dao.TxConn) error {
		res, err := tx.ExecContext(ctx, ms.s.q("DELETE FROM mail_domain WHERE name = ?"), name)
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			return mail.ErrNoDomain
		}
		return ms.audit(ctx, tx, "mail.domain.remove", "domain "+name)
	})
}

// Owned are the DNS records AutoPanel published for owner (a domain, or the
// mail host).
func (ms mailStore) Owned(ctx context.Context, owner string) ([]mail.Owned, error) {
	rows, err := ms.s.conn.QueryContext(ctx, ms.s.q("SELECT name, type, value, remote_id, merged FROM mail_record WHERE domain = ? ORDER BY name, type"), owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []mail.Owned{}
	for rows.Next() {
		var o mail.Owned
		var merged int64
		if err := rows.Scan(&o.Name, &o.Type, &o.Value, &o.RemoteID, &merged); err != nil {
			return nil, err
		}
		o.Merged = merged != 0
		out = append(out, o)
	}
	return out, rows.Err()
}

func (ms mailStore) PutOwned(ctx context.Context, owner string, o mail.Owned) error {
	merged := 0
	if o.Merged {
		merged = 1
	}
	return ms.s.tx(ctx, func(tx dao.TxConn) error {
		if _, err := tx.ExecContext(ctx, ms.s.q(`INSERT INTO mail_record(domain, name, type, value, remote_id, merged, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (domain, name, type) DO UPDATE SET value = excluded.value, remote_id = excluded.remote_id, merged = excluded.merged, updated_at = excluded.updated_at`),
			owner, o.Name, o.Type, o.Value, o.RemoteID, merged, ms.s.now().Unix()); err != nil {
			return err
		}
		return ms.audit(ctx, tx, "mail.record.set", o.Type+" "+o.Name)
	})
}

func (ms mailStore) DeleteOwned(ctx context.Context, owner, name, typ string) error {
	return ms.s.tx(ctx, func(tx dao.TxConn) error {
		if _, err := tx.ExecContext(ctx, ms.s.q("DELETE FROM mail_record WHERE domain = ? AND name = ? AND type = ?"), owner, name, typ); err != nil {
			return err
		}
		return ms.audit(ctx, tx, "mail.record.delete", typ+" "+name)
	})
}

// DKIM is each of a domain's DKIM keys and its place in its rotation.
func (ms mailStore) DKIM(ctx context.Context, domain string) ([]mail.DKIMRow, error) {
	rows, err := ms.s.conn.QueryContext(ctx, ms.s.q("SELECT selector, step, since FROM mail_dkim WHERE domain = ? ORDER BY selector"), domain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []mail.DKIMRow{}
	for rows.Next() {
		var r mail.DKIMRow
		if err := rows.Scan(&r.Selector, &r.Step, &r.Since); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (ms mailStore) PutDKIM(ctx context.Context, domain string, r mail.DKIMRow) error {
	return ms.s.tx(ctx, func(tx dao.TxConn) error {
		if _, err := tx.ExecContext(ctx, ms.s.q(`INSERT INTO mail_dkim(domain, selector, step, since) VALUES (?, ?, ?, ?)
ON CONFLICT (domain, selector) DO UPDATE SET step = excluded.step, since = excluded.since`), domain, r.Selector, r.Step, r.Since); err != nil {
			return err
		}
		return ms.audit(ctx, tx, "mail.dkim."+r.Step, "domain "+domain+" selector "+r.Selector)
	})
}

func (ms mailStore) DeleteDKIM(ctx context.Context, domain, selector string) error {
	return ms.s.tx(ctx, func(tx dao.TxConn) error {
		if _, err := tx.ExecContext(ctx, ms.s.q("DELETE FROM mail_dkim WHERE domain = ? AND selector = ?"), domain, selector); err != nil {
			return err
		}
		return ms.audit(ctx, tx, "mail.dkim.deleted", "domain "+domain+" selector "+selector)
	})
}
