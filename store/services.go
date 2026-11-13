package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/yongjohnlee80/golib/dao"

	"github.com/yongjohnlee80/autopanel/core/services"
)

// Services is the stacks' Store port. It keeps what was applied: a stack's
// definition by its hashes, its units, and where an apply got to. Its writes
// carry no audit entry of their own: every one happens inside a privileged
// verb, which the control socket records before it runs.
func (s *Store) Services() services.Store { return serviceRows{s} }

type serviceRows struct{ s *Store }

const serviceCols = "name, template, state, applied, applied_at, stopped, pending"

func scanService(rows dao.Rows) (services.Service, error) {
	var v services.Service
	var template, state, applied, stopped, pending string
	var at int64
	if err := rows.Scan(&v.Name, &template, &state, &applied, &at, &stopped, &pending); err != nil {
		return v, err
	}
	v.State = services.State(state)
	// A row with a template is one an older AutoPanel deployed from it.
	v.Legacy = template != ""
	if at > 0 {
		v.AppliedAt = time.Unix(at, 0)
	}
	if applied != "" {
		if err := json.Unmarshal([]byte(applied), &v.Applied); err != nil {
			return v, err
		}
	}
	if stopped != "" {
		if err := json.Unmarshal([]byte(stopped), &v.Stopped); err != nil {
			return v, err
		}
	}
	if pending != "" {
		v.Pending = &services.Pending{}
		if err := json.Unmarshal([]byte(pending), v.Pending); err != nil {
			return v, err
		}
	}
	return v, nil
}

// All reads every stack, by name. Stacks number in the tens.
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

// Add writes a stack's row, in the state deploying. template and options are
// an older AutoPanel's columns: a stack leaves them empty.
func (r serviceRows) Add(ctx context.Context, name string) error {
	now := r.s.now().Unix()
	_, err := r.s.conn.ExecContext(ctx, r.s.q("INSERT INTO service(name, template, options, state, created_at, updated_at) VALUES (?, '', '{}', ?, ?, ?)"),
		name, string(services.Deploying), now, now)
	if err != nil && errors.Is(r.s.translate(err), dao.ErrDuplicate) {
		return services.ErrDuplicate
	}
	return err
}

// changed runs an UPDATE or DELETE of one stack, and answers
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

func (r serviceRows) SetState(ctx context.Context, name string, state services.State) error {
	return r.changed(ctx, "UPDATE service SET state = ?, updated_at = ? WHERE name = ?", string(state), r.s.now().Unix(), name)
}

func (r serviceRows) SetPending(ctx context.Context, name string, p services.Pending) error {
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return r.changed(ctx, "UPDATE service SET pending = ?, updated_at = ? WHERE name = ?", string(b), r.s.now().Unix(), name)
}

// SetApplied records what an apply left. The pending plan goes with the same
// statement: a stack is never both applied and pending the same apply.
func (r serviceRows) SetApplied(ctx context.Context, name string, a services.Applied) error {
	b, err := json.Marshal(a)
	if err != nil {
		return err
	}
	now := r.s.now().Unix()
	return r.changed(ctx, "UPDATE service SET applied = ?, applied_at = ?, pending = '', state = ?, updated_at = ? WHERE name = ?",
		string(b), now, string(services.Deployed), now, name)
}

func (r serviceRows) SetStopped(ctx context.Context, name string, stopped []string) error {
	if stopped == nil {
		stopped = []string{}
	}
	b, err := json.Marshal(stopped)
	if err != nil {
		return err
	}
	return r.changed(ctx, "UPDATE service SET stopped = ?, updated_at = ? WHERE name = ?", string(b), r.s.now().Unix(), name)
}

func (r serviceRows) Remove(ctx context.Context, name string) error {
	return r.changed(ctx, "DELETE FROM service WHERE name = ?", name)
}
