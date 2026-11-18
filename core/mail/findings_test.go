package mail

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// pass runs the part of the pass that reads the reverse name and the way out
// to port 25, and keeps its result as the last pass's.
func pass(m *Module, ip string) Sync {
	var out Sync
	m.syncReachability(context.Background(), &out, ip)
	m.sync.mu.Lock()
	m.sync.last = out
	m.sync.mu.Unlock()
	return out
}

func findings(m *Module) map[string]Finding {
	out := map[string]Finding{}
	for _, f := range m.Findings(context.Background()) {
		out[f.ID] = f
	}
	return out
}

// TestMailsHostChecks: nothing until mail is set up; then the reverse name of
// the host's address, the way out to port 25, the loopback rule and the
// processor, each only when it is known to be wrong.
func TestMailsHostChecks(t *testing.T) {
	m, st, _, _, h, _ := newTestModule(t)
	clk := &clock{t: time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC)}
	m.now = clk.now

	h.reverse = nil // the address names nothing back
	pass(m, "192.0.2.10")
	if got := findings(m); len(got) != 0 {
		t.Fatalf("before mail is set up: %+v", got)
	}
	st.state = &State{Host: "mail.example.net", CreatedAt: 1, Bootstrapped: 1}

	// The reverse name.
	if f, ok := findings(m)["mail-ptr"]; !ok || f.Alert || f.Detail != "192.0.2.10 → nothing, not mail.example.net" {
		t.Fatalf("an address that names nothing back: %+v", findings(m))
	}
	h.reverse = []string{"host-10.provider.example."}
	pass(m, "192.0.2.10")
	if f := findings(m)["mail-ptr"]; f.Detail != "192.0.2.10 → host-10.provider.example, not mail.example.net" {
		t.Fatalf("the provider's own name: %+v", f)
	}
	h.reverse = []string{"other.example.", "MAIL.example.net."}
	pass(m, "192.0.2.10")
	if _, ok := findings(m)["mail-ptr"]; ok {
		t.Fatal("an address that names the mail host back is still found wrong")
	}
	h.reverse, h.reverseErr = nil, errors.New("no resolver answered")
	pass(m, "192.0.2.10")
	if _, ok := findings(m)["mail-ptr"]; ok {
		t.Fatal("a lookup that failed is reported as a wrong name")
	}
	h.reverseErr = nil
	pass(m, "") // no one public address: nothing to look up
	if _, ok := findings(m)["mail-ptr"]; ok {
		t.Fatal("a host with no public address has a reverse-name finding")
	}

	// The way out to port 25: tried every pass while it fails, once a day once it works.
	clk.add(25 * time.Hour) // the passes above found it open: a day on, it is tried again
	h.smtpErr = errors.New("connection timed out")
	h.smtpTries = 0
	pass(m, "192.0.2.10")
	pass(m, "192.0.2.10")
	if f, ok := findings(m)["mail-port-25"]; !ok || !f.Alert || h.smtpTries != 2 {
		t.Fatalf("a blocked port 25: %+v after %d tries", findings(m), h.smtpTries)
	}
	h.smtpErr = nil
	pass(m, "192.0.2.10")
	if _, ok := findings(m)["mail-port-25"]; ok || h.smtpTries != 3 {
		t.Fatalf("port 25 open again: %+v after %d tries", findings(m), h.smtpTries)
	}
	clk.add(time.Hour)
	pass(m, "192.0.2.10")
	if h.smtpTries != 3 {
		t.Fatalf("an open port 25 was tried again an hour later (%d tries)", h.smtpTries)
	}
	clk.add(24 * time.Hour)
	pass(m, "192.0.2.10")
	if h.smtpTries != 4 {
		t.Fatalf("an open port 25 was not tried again a day later (%d tries)", h.smtpTries)
	}

	// The loopback rule.
	m.setLoopback("ok")
	if _, ok := findings(m)["mail-loopback-rule"]; ok {
		t.Fatal("a loopback rule in place is found wrong")
	}
	m.setLoopback("reloaded at 2026-11-18T09:00:00Z")
	if f, ok := findings(m)["mail-loopback-rule"]; !ok || f.Alert || f.Detail != "reloaded at 2026-11-18T09:00:00Z" {
		t.Fatalf("a loopback rule loaded again: %+v", findings(m))
	}

	for _, state := range []string{"failed: nft: permission denied", "unknown: no such user"} {
		m.setLoopback(state)
		if f, ok := findings(m)["mail-loopback-rule"]; !ok || !f.Alert || f.Detail != state {
			t.Fatalf("a loopback rule in state %q: %+v; want an alert", state, findings(m))
		}
	}
	m.setLoopback("ok")
	// A reverse name is a stranger's text: it reaches the check on one line, and short.
	h.reverse = []string{"evil\nline\x00." + strings.Repeat("x", 400)}
	pass(m, "192.0.2.10")
	if d := findings(m)["mail-ptr"].Detail; strings.ContainsAny(d, "\n\x00") || len([]rune(d)) > 220 {
		t.Fatalf("a reverse name reached the check raw: %q", d)
	}
	h.reverse = []string{"mail.example.net."}
	pass(m, "192.0.2.10")

	// What the gate's probe found.
	var unproxied []string
	var probedAt int64
	m.SetProxyProbe(func() ([]string, int64) { return unproxied, probedAt })
	if _, ok := findings(m)["mail-proxy-trust"]; ok {
		t.Fatal("a finding before the gate has probed")
	}
	probedAt = clk.now().Unix()
	if _, ok := findings(m)["mail-proxy-trust"]; ok {
		t.Fatal("a finding when every port waits for the header")
	}
	unproxied = []string{"smtp", "submission"}
	if f, ok := findings(m)["mail-proxy-trust"]; !ok || !f.Alert || f.Detail != "smtp, submission" {
		t.Fatalf("ports that no longer wait for the header: %+v", findings(m))
	}
	unproxied = nil

	// The processor.
	if _, ok := findings(m)["mail-cpu"]; ok {
		t.Fatal("a processor the server runs on is found wrong")
	}
	prod(m).CPUError = errors.New("needs x86-64-v2")
	if f, ok := findings(m)["mail-cpu"]; !ok || !f.Alert || f.Detail != "amd64" {
		t.Fatalf("a processor the server cannot run on: %+v", findings(m))
	}
}
