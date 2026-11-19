package store

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/yongjohnlee80/autopanel/core/tunnel"
)

// TestTunnelAgentsEnrolOnce: the store's rules for agents, on each engine: a
// token is spent in the statement that uses it, an expired or wrong one does
// nothing, a key is one agent's, and each change is in the audit log without
// the token.
func TestTunnelAgentsEnrolOnce(t *testing.T) {
	for engine, s := range engines(t) {
		t.Run(engine, func(t *testing.T) {
			ctx := context.Background()
			ts := s.Tunnels()
			keyA, keyB := strings.Repeat("a1", 32), strings.Repeat("b2", 32)
			nas, err := ts.Add(ctx, tunnel.Agent{Name: "nas", TokenID: "t-nas", TokenHash: "h-nas", TokenExpires: 100, CreatedAt: 1})
			if err != nil || nas.ID == 0 || nas.TokenHash != "h-nas" {
				t.Fatalf("Add = %+v, %v", nas, err)
			}
			if _, err := ts.Add(ctx, tunnel.Agent{Name: "nas", TokenID: "t-2", TokenHash: "h", TokenExpires: 100}); !errors.Is(err, tunnel.ErrDuplicate) {
				t.Fatalf("a name twice: %v", err)
			}
			home, err := ts.Add(ctx, tunnel.Agent{Name: "home", TokenID: "t-home", TokenHash: "h-home", TokenExpires: 100, CreatedAt: 1})
			if err != nil {
				t.Fatal(err)
			}
			for what, c := range map[string]struct {
				id, hash string
				now      int64
			}{
				"an unknown id":      {"t-none", "h-nas", 50},
				"a wrong hash":       {"t-nas", "h-home", 50},
				"a token at its end": {"t-nas", "h-nas", 100},
				"a token past it":    {"t-nas", "h-nas", 101},
			} {
				if _, err := ts.Enrol(ctx, c.id, c.hash, keyA, "203.0.113.9", c.now); !errors.Is(err, tunnel.ErrBadToken) {
					t.Errorf("%s: %v, want ErrBadToken", what, err)
				}
			}
			got, err := ts.Enrol(ctx, "t-nas", "h-nas", keyA, "203.0.113.9", 50)
			if err != nil || got.Name != "nas" || got.Key != keyA || got.EnrolledFrom != "203.0.113.9" || got.EnrolledAt != 50 || got.TokenID != "" || got.TokenHash != "" || got.TokenExpires != 0 {
				t.Fatalf("Enrol = %+v, %v", got, err)
			}
			if _, err := ts.Enrol(ctx, "t-nas", "h-nas", keyB, "x", 50); !errors.Is(err, tunnel.ErrBadToken) {
				t.Fatalf("a spent token: %v", err)
			}
			if _, err := ts.Enrol(ctx, "t-home", "h-home", keyA, "x", 50); !errors.Is(err, tunnel.ErrBadToken) {
				t.Fatalf("another agent's key: %v", err)
			}
			if _, err := ts.Enrol(ctx, "t-home", "h-home", keyB, "x", 50); err != nil {
				t.Fatalf("the token was spent by the refusal: %v", err)
			}
			all, err := ts.All(ctx)
			if err != nil || len(all) != 2 || all[0].Name != "home" || all[1].Name != "nas" {
				t.Fatalf("All = %+v, %v", all, err)
			}
			if gone, err := ts.Remove(ctx, home.ID); err != nil || gone.Name != "home" {
				t.Fatalf("Remove = %+v, %v", gone, err)
			}
			if _, err := ts.Remove(ctx, home.ID); !errors.Is(err, tunnel.ErrNotFound) {
				t.Fatalf("Remove twice: %v", err)
			}

			rows, err := s.conn.QueryContext(ctx, "SELECT actor, action, subject, detail FROM audit WHERE action LIKE 'tunnel.%' ORDER BY id")
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			var actions []string
			for rows.Next() {
				var actor, action, subject, detail string
				if err := rows.Scan(&actor, &action, &subject, &detail); err != nil {
					t.Fatal(err)
				}
				if strings.Contains(subject+detail, "h-nas") || strings.Contains(subject+detail, "t-nas") {
					t.Errorf("the audit log holds a token: %q %q", subject, detail)
				}
				if action == "tunnel.agent.enrol" && (actor != "agent nas" && actor != "agent home" || !strings.Contains(detail, "SHA256:")) {
					t.Errorf("an enrolment's entry: actor %q, detail %q", actor, detail)
				}
				actions = append(actions, action)
			}
			if want := "tunnel.agent.add tunnel.agent.add tunnel.agent.enrol tunnel.agent.enrol tunnel.agent.remove"; strings.Join(actions, " ") != want {
				t.Fatalf("audit = %v", actions)
			}
		})
	}
}
