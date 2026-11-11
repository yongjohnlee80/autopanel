// Package audit is the audit log's domain: who did what to which subject. An
// entry is written in the same transaction as the change it records (R2), by
// the store that makes the change.
package audit

import "context"

// Entry is one audit row.
type Entry struct {
	Actor   string // "local:<uid>" on the control socket; a user name on the panel
	Action  string // "route.add", "route.update", "route.remove"
	Subject string // what it acted on: "route 7 example.com/"
	Detail  string // what changed, for people
}

type actorKey struct{}

// WithActor names who is calling, for every entry written under ctx. A host
// sets it once it has authenticated the caller.
func WithActor(ctx context.Context, actor string) context.Context {
	return context.WithValue(ctx, actorKey{}, actor)
}

// Actor is the caller WithActor named, or "unknown": a write is never refused
// for want of a name, and an unknown actor is itself worth seeing in the log.
func Actor(ctx context.Context) string {
	if a, ok := ctx.Value(actorKey{}).(string); ok && a != "" {
		return a
	}
	return "unknown"
}
