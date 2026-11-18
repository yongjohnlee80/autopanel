package app

import (
	"context"
	"github.com/yongjohnlee80/autopanel/core/mail"
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

	mu       sync.Mutex
	total    int               // mail's limit; 0 while mail is off
	streams  []hostgate.Stream // mail's
	forwards []hostgate.Stream // the port forwards'
}

func newStreamTable(start int64) *streamTable {
	return &streamTable{rev: newRevision(start)}
}

// Set replaces mail's streams and the limit every stream shares. An unchanged
// set wakes no one.
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
	total := t.total
	if total == 0 && len(t.forwards) > 0 {
		total = mail.TotalConnections // the same limit with mail off: the gate's memory is sized for it
	}
	return hostgate.Streams{Rev: rev, Total: total, Streams: slices.Concat(t.streams, t.forwards)}, nil
}

// SetForwards replaces the port forwards' streams. They share the limit with
// mail's: each forward's own share keeps them to a small part of it.
func (t *streamTable) SetForwards(streams []hostgate.Stream) {
	t.mu.Lock()
	same := slices.Equal(t.forwards, streams)
	if !same {
		t.forwards = slices.Clone(streams)
	}
	t.mu.Unlock()
	if !same {
		t.rev.bump()
	}
}
