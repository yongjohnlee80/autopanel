package mail

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yongjohnlee80/autopanel/core/mail/provider"
)

func queueAsks(calls []string) int {
	n := 0
	for _, c := range calls {
		if c == "Queue" {
			n++
		}
	}
	return n
}

// TestTheQueueIsReadAtMostEveryThirtySeconds: mail.queue answers what waits
// to leave; within thirty seconds it answers again without asking the server;
// a failure is never kept, so the server's recovery shows at the next call.
func TestTheQueueIsReadAtMostEveryThirtySeconds(t *testing.T) {
	m, srv, clk := readyMail(t)
	ctx := context.Background()
	q, err := m.queue(ctx, struct{}{})
	if err != nil || q.Waiting != 0 || q.Failing != 0 || q.OldestAt != 0 || q.Sample == nil || q.ReadAt != clk.now().Unix() {
		t.Fatalf("an empty queue: %+v, %v", q, err)
	}
	since := clk.now().Add(-4 * time.Hour)
	srv.Scheduled = 1
	srv.Outgoing = []provider.QueuedMessage{{From: "ana@example.net", To: "bob@slow.example", Others: 1, Since: since, Attempts: 5,
		Next: clk.now().Add(time.Hour), Why: "connectionError: mx.slow.example: No route to host"}}
	// Still the first answer: the server is not asked again yet.
	clk.add(29 * time.Second)
	if q, _ = m.queue(ctx, struct{}{}); q.Waiting != 0 || queueAsks(srv.Calls()) != 1 {
		t.Fatalf("within thirty seconds: %+v, %d questions", q, queueAsks(srv.Calls()))
	}
	clk.add(2 * time.Second)
	q, err = m.queue(ctx, struct{}{})
	if err != nil || q.Waiting != 2 || q.Failing != 1 || q.OldestAt != since.Unix() || len(q.Sample) != 1 || queueAsks(srv.Calls()) != 2 {
		t.Fatalf("after thirty seconds: %+v, %v", q, err)
	}
	if s := q.Sample[0]; s.From != "ana@example.net" || s.To != "bob@slow.example" || s.Others != 1 || s.Attempts != 5 || s.Since != since.Unix() || s.NextAt == 0 || s.Why == "" {
		t.Fatalf("the failing message: %+v", s)
	}
	// The server stops answering: an error, at once, and not kept.
	clk.add(31 * time.Second)
	down := errors.New("connection refused")
	srv.Fail = func(method string) error {
		if method == "Queue" {
			return down
		}
		return nil
	}
	if _, err := m.queue(ctx, struct{}{}); err == nil {
		t.Fatal("a server that does not answer gave a queue")
	}
	srv.Fail = nil
	srv.Outgoing, srv.Scheduled = nil, 0
	if q, err = m.queue(ctx, struct{}{}); err != nil || q.Waiting != 0 {
		t.Fatalf("the server answers again, a second later: %+v, %v", q, err)
	}
}

// TestTheQueueNeedsMailSetUp: with no mail there is no queue to read.
func TestTheQueueNeedsMailSetUp(t *testing.T) {
	m, _, _, _, _, _ := newTestModule(t)
	if _, err := m.queue(context.Background(), struct{}{}); !errors.Is(err, ErrNotSetUp) {
		t.Fatalf("mail.queue with no mail: %v", err)
	}
}

// TestStatusCountsTheRecordsNotOK: mail.status says, for each domain, how
// many of its records the last pass did not find as they should be; a record
// left to the administrator (manual) is not one.
func TestStatusCountsTheRecordsNotOK(t *testing.T) {
	m, _, _ := readyMail(t)
	m.sync.mu.Lock()
	m.sync.last = Sync{At: 5, Records: map[string][]RecordView{
		"example.net":      {{State: "ok"}, {State: "different"}, {State: "failed"}, {State: "manual"}, {State: "publishing"}},
		"mail.example.net": {{State: "ok"}, {State: "manual"}},
		"another.example":  {{State: "different"}},
	}}
	m.sync.mu.Unlock()
	st, err := m.status(context.Background(), struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	want := []RecordsCount{{"another.example", 1}, {"example.net", 3}}
	if len(st.RecordsNotOK) != len(want) || st.RecordsNotOK[0] != want[0] || st.RecordsNotOK[1] != want[1] {
		t.Fatalf("records not ok: %+v; want %+v", st.RecordsNotOK, want)
	}
}
