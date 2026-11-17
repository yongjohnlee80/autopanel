package store

import (
	"context"
	"reflect"
	"testing"

	"github.com/yongjohnlee80/autopanel/core/firewall"
	"github.com/yongjohnlee80/autopanel/internal/sysinfo"
)

// TestFirewallRowsUpsertAndKeepTheirRule: a row keeps the rule's fields, a
// second put with its id replaces it (re-opening a rule whose row outlived
// it), its state moves, and a row that is gone is no error.
func TestFirewallRowsUpsertAndKeepTheirRule(t *testing.T) {
	for engine, s := range engines(t) {
		t.Run(engine, func(t *testing.T) {
			ctx := context.Background()
			rule := sysinfo.Rule{ID: "abc", Action: "allow", Direction: "in", Family: "both", Proto: "tcp", From: 993, To: 993, Modelled: true, Permanent: true}
			if err := s.PutFirewallRow(ctx, firewall.Row{ID: "abc", Owner: firewall.OwnerMail, Rule: rule, State: firewall.StateOpening}); err != nil {
				t.Fatal(err)
			}
			if err := s.PutFirewallRow(ctx, firewall.Row{ID: "abc", Owner: firewall.OwnerMail, Rule: rule, State: firewall.StateOpen, CreatedAt: 7}); err != nil {
				t.Fatal(err)
			}
			if err := s.PutFirewallRow(ctx, firewall.Row{ID: "def", Owner: firewall.StackOwner("chat"), Rule: rule, State: firewall.StateOpen}); err != nil {
				t.Fatal(err)
			}
			rows, err := s.FirewallRows(ctx)
			if err != nil || len(rows) != 2 || rows[0].ID != "abc" || rows[0].State != firewall.StateOpen || rows[0].CreatedAt != 7 || !reflect.DeepEqual(rows[0].Rule, rule) {
				t.Fatalf("rows = %+v, %v", rows, err)
			}
			if rows[1].Owner != "stack:chat" || rows[1].CreatedAt == 0 {
				t.Fatalf("the stack's row = %+v", rows[1])
			}
			if err := s.SetFirewallState(ctx, "abc", firewall.StateClosing); err != nil {
				t.Fatal(err)
			}
			if err := s.DeleteFirewallRow(ctx, "def"); err != nil {
				t.Fatal(err)
			}
			if err := s.DeleteFirewallRow(ctx, "gone"); err != nil {
				t.Fatal(err)
			}
			if err := s.SetFirewallState(ctx, "gone", firewall.StateOpen); err != nil {
				t.Fatal(err)
			}
			rows, _ = s.FirewallRows(ctx)
			if len(rows) != 1 || rows[0].State != firewall.StateClosing {
				t.Fatalf("after = %+v", rows)
			}
			if err := s.PutFirewallRow(ctx, firewall.Row{ID: "x", Owner: "nobody", Rule: rule, State: firewall.StateOpen}); err == nil {
				t.Error("an owner of no kind was stored")
			}
		})
	}
}
