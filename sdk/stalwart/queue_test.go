package stalwart

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/yongjohnlee80/autopanel/core/mail/provider"
)

// queued is one message of Stalwart's queue, as its API answers it.
func queued(id, created, from string, recipients map[string]any) map[string]any {
	return map[string]any{"id": id, "createdAt": created, "nextRetry": "2026-11-27T10:00:00Z", "returnPath": from, "recipients": recipients}
}

func recipient(status, errType, host, msg string, tries int) map[string]any {
	return map[string]any{"retryCount": tries, "retryDue": "2026-11-27T10:05:00Z", "queueName": "remote",
		"status": map[string]any{"@type": status, "errorType": errType, "errorMessage": msg, "responseHostname": host}}
}

// TestTheQueueIsSummed: what waits is counted, what is failing is told apart
// from what has not been tried, the oldest is found, the failing ones are
// answered oldest first with a printable reason, and more than the limit is
// said, not counted.
func TestTheQueueIsSummed(t *testing.T) {
	ctx := context.Background()
	var list []any
	total := 0
	var asked map[string]any
	_, c := newFake(t, func(m string, args map[string]any) (string, any) {
		switch m {
		case "x:QueuedMessage/query":
			asked = args
			ids := []string{}
			for i := range list {
				if i < int(args["limit"].(float64)) {
					ids = append(ids, fmt.Sprintf("m%d", i))
				}
			}
			out := map[string]any{"ids": ids}
			if total > 0 {
				out["total"] = total
			}
			return m, out
		case "x:QueuedMessage/get":
			n := len(args["ids"].([]any))
			return m, map[string]any{"list": list[:n]}
		}
		return "error", map[string]any{"type": "unknownMethod"}
	})
	s := server{c: c}

	q, err := s.Queue(ctx, 0)
	if err != nil || q.Waiting != 0 || q.Failing != 0 || q.More || !q.Oldest.IsZero() || q.Sample == nil || len(q.Sample) != 0 {
		t.Fatalf("an empty queue: %+v, %v", q, err)
	}
	if asked["limit"].(float64) != provider.MaxQueue+1 {
		t.Fatalf("the query asked for %v; want one more than is counted", asked["limit"])
	}

	list = []any{
		queued("m0", "2026-11-27T09:00:00Z", "ana@example.net", map[string]any{"bob@slow.example": recipient("Scheduled", "", "", "", 0)}),
		queued("m1", "2026-11-27T08:00:00Z", "ana@example.net", map[string]any{
			"zed@slow.example": recipient("TemporaryFailure", "connectionError", "mx.slow.example", "I/O error: No route to host", 3),
			"amy@slow.example": recipient("TemporaryFailure", "connectionError", "mx.slow.example", "refused\x1b[31m\r\nRCPT TO:<x>", 4),
			"ok@fine.example":  recipient("Completed", "", "", "", 1)}),
		queued("m2", "2026-11-27T07:00:00Z", "ben@example.net", map[string]any{
			"cat@gone.example": recipient("PermanentFailure", "dnsError", "", strings.Repeat("é", 300), 1)}),
	}
	q, err = s.Queue(ctx, 0)
	if err != nil || q.Waiting != 3 || q.Failing != 2 || q.More || !q.Oldest.Equal(time.Date(2026, 11, 27, 7, 0, 0, 0, time.UTC)) || len(q.Sample) != 2 {
		t.Fatalf("three waiting, two failing: %+v, %v", q, err)
	}
	first, second := q.Sample[0], q.Sample[1]
	if first.From != "ben@example.net" || first.To != "cat@gone.example" || first.Others != 0 || first.Attempts != 1 {
		t.Fatalf("the oldest failing one: %+v", first)
	}
	if len(first.Why) > provider.MaxQueueWhy || !strings.HasPrefix(first.Why, "dnsError: é") || strings.ToValidUTF8(first.Why, "") != first.Why {
		t.Fatalf("a long reason: %d bytes, %q", len(first.Why), first.Why)
	}
	if second.To != "amy@slow.example" || second.Others != 1 || second.Attempts != 4 || second.Next.IsZero() ||
		second.Why != "connectionError: mx.slow.example: refused [31m RCPT TO:<x>" {
		t.Fatalf("a message failing for two recipients, its reason made printable: %+v", second)
	}

	// More than the limit: the limit is counted, and more is said.
	list = nil
	for i := 0; i < 8; i++ {
		list = append(list, queued(fmt.Sprintf("m%d", i), "2026-11-27T09:00:00Z", "ana@example.net",
			map[string]any{"bob@slow.example": recipient("TemporaryFailure", "connectionError", "mx", "no", 1)}))
	}
	q, err = s.Queue(ctx, 5)
	if err != nil || q.Waiting != 5 || q.Failing != 5 || !q.More {
		t.Fatalf("eight waiting, five counted: %+v, %v", q, err)
	}
	// Exactly the limit is not "more"; a total the server gives is believed.
	if q, _ = s.Queue(ctx, 8); q.Waiting != 8 || q.More {
		t.Fatalf("exactly the limit: %+v", q)
	}
	total = 5000
	if q, _ = s.Queue(ctx, 8); !q.More {
		t.Fatalf("a total over the limit: %+v", q)
	}
}
