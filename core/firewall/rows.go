// Package firewall is the core's side of the host's firewall: the rules
// AutoPanel created for an owner (a stack, or mail), the one lock every
// change takes, the lockout guard, and the enable that undoes itself unless
// confirmed. The host's manager is behind Host; the store behind Store.
//
// Decision: docs/decisions/firewall.md
package firewall

import (
	"context"
	"strings"

	"github.com/yongjohnlee80/autopanel/internal/sysinfo"
)

// A row's states: the manager is being asked for the rule; it was read back;
// its owner asked for it to go.
const (
	StateOpening = "opening"
	StateOpen    = "open"
	StateClosing = "closing"
)

// OwnerMail owns the gate's mail ports' rules; a stack's are "stack:<name>",
// a port forward's "forward:<name>".
const OwnerMail = "mail"

// StackOwner is a stack's owner name.
func StackOwner(stack string) string { return "stack:" + stack }

// ForwardOwner is a port forward's owner name.
func ForwardOwner(name string) string { return "forward:" + name }

// ValidOwner reports whether owner is mail, a named stack or a named forward.
func ValidOwner(owner string) bool {
	for _, kind := range []string{"stack:", "forward:"} {
		if strings.HasPrefix(owner, kind) && len(owner) > len(kind) {
			return true
		}
	}
	return owner == OwnerMail
}

// Row is a rule AutoPanel created for its owner. A rule that was already
// there when the owner asked has none: it is the administrator's.
//
// Decision: docs/decisions/firewall.md#owners
type Row struct {
	ID        string       `json:"id"` // the rule's identity
	Owner     string       `json:"owner"`
	Rule      sysinfo.Rule `json:"rule"` // as read back after the allow
	State     string       `json:"state"`
	CreatedAt int64        `json:"created_at"`
}

// Store keeps the rows.
type Store interface {
	FirewallRows(ctx context.Context) ([]Row, error)
	// PutFirewallRow writes r, replacing a row with its id: an owner opening
	// again a rule whose row outlived it replaces the stale row.
	PutFirewallRow(ctx context.Context, r Row) error
	SetFirewallState(ctx context.Context, id, state string) error
	DeleteFirewallRow(ctx context.Context, id string) error
}
