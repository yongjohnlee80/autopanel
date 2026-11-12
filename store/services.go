package store

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/yongjohnlee80/golib/dao"

	"github.com/yongjohnlee80/autopanel/core/services"
)

// Services is the services' Store port. It keeps what was asked for: a
// service's template, options and where its deployment got to. Its writes
// carry no audit entry of their own: every one happens inside a privileged
// verb, which the control socket records before it runs.
func (s *Store) Services() services.Store { return serviceRows{s} }

type serviceRows struct{ s *Store }

const serviceCols = "name, template, options, state"

func scanService(rows dao.Rows) (services.Service, error) {
	var v services.Service
	var opts, state string
	if err := rows.Scan(&v.Name, &v.Template, &opts, &state); err != nil {
		return v, err
	}
	v.State = services.State(state)
	return v, json.Unmarshal([]byte(opts), &v.Options)
}

// All reads every service, by name. Services number in the tens.
func (r serviceRows) All(ctx context.Context) ([]services.Service, error) {
	rows, err := r.s.conn.QueryContext(ctx, "SELECT "+serviceCols+" FROM service ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []services.Service{}
	for rows.Next() {
		v, err := scanService(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (r serviceRows) Get(ctx context.Context, name string) (services.Service, error) {
	rows, err := r.s.conn.QueryContext(ctx, r.s.q("SELECT "+serviceCols+" FROM service WHERE name = ?"), name)
	if err != nil {
		return services.Service{}, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return services.Service{}, err
		}
		return services.Service{}, services.ErrNotFound
	}
	return scanService(rows)
}

func (r serviceRows) Add(ctx context.Context, v services.Service) error {
	opts, err := json.Marshal(v.Options)
	if err != nil {
		return err
	}
	now := r.s.now().Unix()
	_, err = r.s.conn.ExecContext(ctx, r.s.q("INSERT INTO service(name, template, options, state, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)"),
		v.Name, v.Template, string(opts), string(v.State), now, now)
	if err != nil && errors.Is(r.s.translate(err), dao.ErrDuplicate) {
		return services.ErrDuplicate
	}
	return err
}

// changed runs an UPDATE or DELETE of one service, and answers
// services.ErrNotFound when the store holds none of that name.
func (r serviceRows) changed(ctx context.Context, stmt string, args ...any) error {
	res, err := r.s.conn.ExecContext(ctx, r.s.q(stmt), args...)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return services.ErrNotFound
	}
	return nil
}

func (r serviceRows) SetOptions(ctx context.Context, name string, options map[string]string) error {
	opts, err := json.Marshal(options)
	if err != nil {
		return err
	}
	return r.changed(ctx, "UPDATE service SET options = ?, updated_at = ? WHERE name = ?", string(opts), r.s.now().Unix(), name)
}

func (r serviceRows) SetState(ctx context.Context, name string, state services.State) error {
	return r.changed(ctx, "UPDATE service SET state = ?, updated_at = ? WHERE name = ?", string(state), r.s.now().Unix(), name)
}

func (r serviceRows) Remove(ctx context.Context, name string) error {
	return r.changed(ctx, "DELETE FROM service WHERE name = ?", name)
}
