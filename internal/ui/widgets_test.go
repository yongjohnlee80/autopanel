package ui

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	tuidecl "github.com/yongjohnlee80/golib/tui/decl"
	"github.com/yongjohnlee80/golib/tui/decl/decltest"

	"github.com/yongjohnlee80/autopanel/core/gate"
)

func TestBar(t *testing.T) {
	for in, want := range map[float64]string{0: "░░░░░░░░░░░░░░░░", 50: "████████░░░░░░░░", 100: "████████████████", 140: "████████████████", -3: "░░░░░░░░░░░░░░░░"} {
		if got := bar(in); got != want {
			t.Errorf("bar(%v) = %q, want %q", in, got, want)
		}
	}
}

func TestRateText(t *testing.T) {
	for in, want := range map[uint64]string{0: "0 B/s", 999: "999 B/s", 1500: "1.5 KB/s", 2_300_000: "2.3 MB/s", 4_000_000_000: "4.0 GB/s"} {
		if got := rateText(in); got != want {
			t.Errorf("rateText(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestUptimeText(t *testing.T) {
	for in, want := range map[int64]string{0: "-", 59: "0 h 0 min", 3*3600 + 20*60: "3 h 20 min", 3*86400 + 4*3600 + 120: "3 d 4 h"} {
		if got := uptimeText(inEnglish{}, in); got != want {
			t.Errorf("uptimeText(%d) = %q, want %q", in, got, want)
		}
	}
}

// TestHostGauges: the host widget's gauges from sys.metrics: CPU from the
// activity sample, memory used of the total, swap, the disk, the load and the
// uptime; a share at or past 85% is hot, and a first read measures the CPU.
func TestHostGauges(t *testing.T) {
	m := someMetrics()
	cpu, memory, swap, disk, load, uptime := hostGauges(inEnglish{}, m)
	for _, c := range []struct {
		got  hostGauge
		want hostGauge
	}{
		{cpu, hostGauge{bar: bar(42), value: "42% of 4 CPUs"}},
		{memory, hostGauge{bar: bar(50), value: "1.0 GiB of 2.0 GiB"}},
		{swap, hostGauge{bar: bar(25), value: "256.0 MiB of 1.0 GiB"}},
		{disk, hostGauge{bar: bar(25), value: "10.0 GiB of 40.0 GiB"}},
	} {
		if c.got != c.want {
			t.Errorf("gauge = %+v, want %+v", c.got, c.want)
		}
	}
	if load != "0.50 · 0.25 · 0.10" || uptime != "3 d 4 h" {
		t.Errorf("load %q, uptime %q", load, uptime)
	}
	m.Activity.CPUPercent, m.Activity.SwapTotal, m.Host.MemAvailable = -1, 0, 100<<20
	cpu, memory, swap, _, _, _ = hostGauges(inEnglish{}, m)
	if cpu.value != "measuring…" || swap.value != "no swap" || !memory.hot {
		t.Errorf("first read: cpu %+v, swap %+v, memory %+v", cpu, swap, memory)
	}
}

// TestNetworkRows: an interface a row, by name, with its rates a second and
// its totals.
func TestNetworkRows(t *testing.T) {
	rows := networkRows(someMetrics().Activity.Network)
	var got []string
	for _, r := range rows {
		got = append(got, fmt.Sprint(r["name"], " ", r["rx"], " ", r["tx"], " ", r["rxTotal"], " ", r["txTotal"], " ", r["errors"]))
	}
	want := "eth0 1.5 KB/s 2.3 MB/s 5.0 GiB 2.0 GiB 3|podman0 512 B/s 0 B/s 3.0 MiB 1.0 MiB 0"
	if strings.Join(got, "|") != want {
		t.Errorf("networkRows = %q, want %q", strings.Join(got, "|"), want)
	}
}

// TestHostRows: the certificates widget's hosts, each once, with its domain.
func TestHostRows(t *testing.T) {
	routes := []gate.RouteView{{Host: "app.example.com"}, {Host: "app.example.com", PathPrefix: "/v2"}, {Host: "lone.example.org"}}
	rows := hostRows(routes, []gate.DomainView{{Name: "example.com"}})
	if len(rows) != 2 || rows[0]["host"] != "app.example.com" || rows[0]["domain"] != "example.com" || rows[1]["domain"] != "-" {
		t.Errorf("hostRows = %v", rows)
	}
}

// TestEveryWidgetRendersFromTheDaemon: the main screen, signed in, shows each
// widget from the fake daemon's answers: the host's gauges, each interface,
// each container, the gate's requests and the domains, the certificate
// service and its hosts, the sockets, the newest audit entries.
func TestEveryWidgetRendersFromTheDaemon(t *testing.T) {
	f := withStacks()
	s := start(t, f)
	for _, part := range []string{
		"CPU", "42% of 4 CPUs", "1.0 GiB of 2.0 GiB", "256.0 MiB of 1.0 GiB", "10.0 GiB of 40.0 GiB", "0.50 · 0.25 · 0.10", "3 d 4 h",
		"███████░░░░░░░░░", // CPU at 42%
		"eth0", "1.5 KB/s", "2.3 MB/s", "podman0", "512 B/s",
		"web/app", "active (running)", "21.0 MiB", "web/db", "stopped", "prepared, not",
		"41", "7 HTTP", "example.com", "example.net",
		"Issuer: Let's Encrypt staging", "Challenge: http-01", "app.example.com", "api.example.com",
		"sshd", "autopanel", "3478",
		"route.add", "root (local:999)", "auth.login",
	} {
		s.WaitForText(t, part)
	}
	if strings.Contains(s.String(), "read failed") {
		t.Fatalf("a widget says a read failed:\n%s", s)
	}
}

// TestAFailedReadShowsInTheWidget: a read that fails is a line in the
// widgets it feeds, not a dialog; the next good read clears it.
func TestAFailedReadShowsInTheWidget(t *testing.T) {
	f := newFakeClient()
	f.metricsErr = errors.New("sys: the core is busy")
	h, s := startHost(t, f)
	s.WaitForText(t, "read failed: sys: the core is busy")
	if n := strings.Count(s.String(), "read failed: sys: the core"); n < 3 { // host, network, traffic
		t.Fatalf("the failure is in %d widgets, want the three that read sys.metrics:\n%s", n, s)
	}
	f.mu.Lock()
	f.metricsErr = nil
	f.mu.Unlock()
	run(t, h, func() error { h.poll(); return nil })
	gone(t, s, "read failed")
	s.WaitForText(t, "42% of 4 CPUs")
}

// TestTheScreenIsReadAgain: the widgets shown are read again on the poller's
// tick; a widget hidden is not read, and View lists it unchecked.
func TestTheScreenIsReadAgain(t *testing.T) {
	f := newFakeClient()
	ctx := t.Context()
	h := newHost(ctx, f, "v0.1.0")
	h.pollEvery = 100 * time.Millisecond
	s := decltest.RunWith(t, 120, 36, func(p *tuidecl.Program) error { h.attach(p); return nil }, h.options(nil)...)
	signIn(t, s)
	reads := func() int { f.mu.Lock(); defer f.mu.Unlock(); return f.metricsReads }
	first := reads()
	s.WaitFor(t, "the metrics read again", func(string) bool { return reads() >= first+2 })

	for _, id := range []string{"hostWidget", "networkWidget", "trafficWidget"} {
		run(t, h, func() error { return h.toggleWidgetNamed(id) })
	}
	gone(t, s, "42% of 4 CPUs")
	time.Sleep(300 * time.Millisecond) // the polls under way end
	n := reads()
	time.Sleep(500 * time.Millisecond)
	if got := reads(); got != n {
		t.Fatalf("the hidden widgets were read: %d reads, then %d", n, got)
	}
	if shown := onLoop(h, func() bool { return h.shown("hostWidget") }); shown {
		t.Fatal("a hidden widget reads as shown")
	}
	s.Keys(t, decltest.Alt('v'))
	s.WaitForText(t, "Reset the layout")
	s.Keys(t, decltest.Rune('l')) // Reset the layout: every widget shown
	s.WaitForText(t, "42% of 4 CPUs")
}

// TestTheDockHidesAndShowsAWidget: a widget's icon hides it, its tile going
// to the ones beside it, and shows it again.
func TestTheDockHidesAndShowsAWidget(t *testing.T) {
	s := start(t, newFakeClient())
	s.WaitForText(t, "42% of 4 CPUs")
	x, y := dockAt(t, s, "◫")
	click(t, s, x, y)
	gone(t, s, "42% of 4 CPUs")
	click(t, s, x, y)
	s.WaitForText(t, "42% of 4 CPUs")
}

// TestViewHidesTheStatusBar: View › Status bar hides it, and shows it again.
func TestViewHidesTheStatusBar(t *testing.T) {
	s := start(t, newFakeClient())
	s.WaitForText(t, "CA LE staging")
	s.Keys(t, decltest.Alt('v'))
	s.WaitForText(t, "Status bar")
	s.Keys(t, decltest.Rune('s'))
	gone(t, s, "CA LE staging")
	s.Keys(t, decltest.Alt('v'))
	s.WaitForText(t, "Status bar")
	s.Keys(t, decltest.Rune('s'))
	s.WaitForText(t, "CA LE staging")
}
