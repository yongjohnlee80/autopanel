package app

import (
	"context"
	"slices"
	"sync"

	hostgate "github.com/yongjohnlee80/autopanel/host/gate"
)

// streamTable is the streams the core asks the gate to forward: none until
// mail is set up, which names its four ports. The gate long-polls it over the
// link (link.streams), as it does the routes.
//
// Decision: docs/decisions/mail.md#the-gate-forwards-the-mail-ports
type streamTable struct {
	rev *revision

	mu      sync.Mutex
	total   int
	streams []hostgate.Stream
}

func newStreamTable(start int64) *streamTable {
	return &streamTable{rev: newRevision(start)}
}

// Set replaces the streams and the limit they share. An unchanged set wakes no
// one.
func (t *streamTable) Set(total int, streams []hostgate.Stream) {
	t.mu.Lock()
	same := t.total == total && slices.Equal(t.streams, streams)
	if !same {
		t.total = total
		t.streams = slices.Clone(streams)
	}
	t.mu.Unlock()
	if !same {
		t.rev.bump()
	}
}

// wait answers once the revision is not after, with the streams then.
func (t *streamTable) wait(ctx context.Context, after int64) (hostgate.Streams, error) {
	rev, err := t.rev.waitNot(ctx, after)
	if err != nil {
		return hostgate.Streams{}, err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return hostgate.Streams{Rev: rev, Total: t.total, Streams: slices.Clone(t.streams)}, nil
}
