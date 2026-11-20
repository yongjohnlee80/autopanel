package app

import (
	"context"
	"testing"
	"time"
)

// TestTheGateBusyCheck: the check speaks of what the gate refused within the
// last ten minutes, counts a new gate's totals from nothing, and is silent
// when nothing was refused or the refusals are old.
func TestTheGateBusyCheck(t *testing.T) {
	var c counters
	t0 := time.Now().Add(-time.Hour)
	if conns, reqs := c.busy(t0); conns != 0 || reqs != 0 {
		t.Fatalf("a quiet gate refused %d and %d", conns, reqs)
	}
	c.noteRefused(0, 0, t0)
	c.noteRefused(2, 5, t0.Add(time.Minute))   // 2 connections, 5 requests
	c.noteRefused(2, 9, t0.Add(2*time.Minute)) // 4 more requests
	c.noteRefused(1, 3, t0.Add(3*time.Minute)) // a new gate: all of its totals are new
	c.noteRefused(1, 3, t0.Add(4*time.Minute)) // nothing since
	if conns, reqs := c.busy(t0.Add(5 * time.Minute)); conns != 3 || reqs != 12 {
		t.Fatalf("within the window: %d connections and %d requests; want 3 and 12", conns, reqs)
	}
	// The first two reports fall out of the window; the new gate's stay.
	if conns, reqs := c.busy(t0.Add(2*time.Minute + busyWindow + time.Second)); conns != 1 || reqs != 3 {
		t.Fatalf("as the window moves: %d and %d; want 1 and 3", conns, reqs)
	}
	if conns, reqs := c.busy(t0.Add(time.Hour)); conns != 0 || reqs != 0 {
		t.Fatalf("an hour on: %d and %d", conns, reqs)
	}
	check := busyChecks(&c)
	if got := check(context.Background()); got != nil {
		t.Fatalf("a check with nothing refused lately: %v", got)
	}
	c.noteRefused(1, 10, time.Now())
	got := check(context.Background())
	if len(got) != 1 || got[0].ID != "gate-busy" || got[0].Severity != notice || got[0].Detail != "7 requests, 0 connections" {
		t.Fatalf("the check: %+v", got)
	}
}
