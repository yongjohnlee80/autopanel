package store

import (
	"context"
	"encoding/json"

	"github.com/yongjohnlee80/autopanel/core/firewall"
)

// FirewallRows reads the rules AutoPanel created, by owner then id. They
// number in the tens.
func (s *Store) FirewallRows(ctx context.Context) ([]firewall.Row, error) {
	rows, err := s.conn.QueryContext(ctx, "SELECT id, owner, rule, state, created_at FROM firewall_rule ORDER BY owner, id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []firewall.Row{}
	for rows.Next() {
		var r firewall.Row
		var rule string
		if err := rows.Scan(&r.ID, &r.Owner, &rule, &r.State, &r.CreatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(rule), &r.Rule); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// PutFirewallRow writes r, replacing the row with its id.
func (s *Store) PutFirewallRow(ctx context.Context, r firewall.Row) error {
	rule, err := json.Marshal(r.Rule)
	if err != nil {
		return err
	}
	if r.CreatedAt == 0 {
		r.CreatedAt = s.now().Unix()
	}
	_, err = s.conn.ExecContext(ctx, s.q(`INSERT INTO firewall_rule(id, owner, rule, state, created_at) VALUES (?, ?, ?, ?, ?)
ON CONFLICT (id) DO UPDATE SET owner = excluded.owner, rule = excluded.rule, state = excluded.state, created_at = excluded.created_at`),
		r.ID, r.Owner, string(rule), r.State, r.CreatedAt)
	return err
}

// SetFirewallState sets a row's state; a row that is gone is not an error.
func (s *Store) SetFirewallState(ctx context.Context, id, state string) error {
	_, err := s.conn.ExecContext(ctx, s.q("UPDATE firewall_rule SET state = ? WHERE id = ?"), state, id)
	return err
}

// DeleteFirewallRow deletes a row; a row that is gone is not an error.
func (s *Store) DeleteFirewallRow(ctx context.Context, id string) error {
	_, err := s.conn.ExecContext(ctx, s.q("DELETE FROM firewall_rule WHERE id = ?"), id)
	return err
}
