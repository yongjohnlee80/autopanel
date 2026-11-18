package app

import (
	"context"
	"testing"
	"time"

	hostgate "github.com/yongjohnlee80/autopanel/host/gate"
)

func TestStreamTable(t *testing.T) {
	st := newStreamTable(100)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	first, err := st.wait(ctx, 0)
	if err != nil || first.Rev != 100 || len(first.Streams) != 0 {
		t.Fatalf("no streams at first: %+v, %v", first, err)
	}
	got := make(chan hostgate.Streams, 1)
	go func() {
		s, _ := st.wait(ctx, first.Rev)
		got <- s
	}()
	smtp := hostgate.Stream{Name: "smtp", Listen: ":25", To: "127.0.0.1:10025", IdleSecs: 600, PerClient: 20}
	st.Set(200, []hostgate.Stream{smtp})
	select {
	case s := <-got:
		if s.Rev == first.Rev || s.Total != 200 || len(s.Streams) != 1 || s.Streams[0] != smtp {
			t.Fatalf("after Set: %+v", s)
		}
	case <-ctx.Done():
		t.Fatal("a waiting gate was not woken by Set")
	}
	before := st.rev.n
	st.Set(200, []hostgate.Stream{smtp})
	if st.rev.n != before {
		t.Fatal("setting the same streams again should wake no one")
	}
}

// TestTheGatesProbeReachesMail: what the gate's probe found rides its report
// and is what mail's host check reads; before any report there is nothing; and
// of a list the gate sends, the core keeps a short one.
func TestTheGatesProbeReachesMail(t *testing.T) {
	counts := &counters{}
	if ports, at := counts.unproxied(); ports != nil || at != 0 {
		t.Fatalf("before any report: %v, %d", ports, at)
	}
	m := &linkModule{counts: counts}
	ctx := context.Background()
	if _, err := m.report(ctx, hostgate.Report{PID: 7, ProbedAt: 100, Unproxied: []string{"smtp"}}); err != nil {
		t.Fatal(err)
	}
	if ports, at := counts.unproxied(); at != 100 || len(ports) != 1 || ports[0] != "smtp" {
		t.Fatalf("after a report: %v, %d", ports, at)
	}
	long := make([]string, 1000)
	for i := range long {
		long[i] = "stream"
	}
	if _, err := m.report(ctx, hostgate.Report{ProbedAt: 200, Unproxied: long}); err != nil {
		t.Fatal(err)
	}
	if ports, at := counts.unproxied(); at != 200 || len(ports) != maxUnproxied {
		t.Fatalf("a thousand names from the gate: the core kept %d", len(ports))
	}
}
