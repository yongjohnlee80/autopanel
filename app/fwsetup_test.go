package app

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	corefw "github.com/yongjohnlee80/autopanel/core/firewall"
	"github.com/yongjohnlee80/autopanel/internal/sysinfo"
)

// setupHost is a ufw in memory for the installer's step.
type setupHost struct {
	fw        sysinfo.Firewall
	failAllow int
	failOn    bool
	ssh       corefw.SSHFacts
}

func (h *setupHost) Read(context.Context) (sysinfo.Firewall, error) {
	out := h.fw
	out.Rules = nil
	for i, r := range h.fw.Rules {
		r.Seq4, r.Seq6, r.Runtime, r.Permanent, r.ID = i+1, i+1, h.fw.Active, true, ""
		r.ID = sysinfo.Identity(r)
		out.Rules = append(out.Rules, r)
	}
	return out, nil
}
func (h *setupHost) Allow(_ context.Context, _ sysinfo.Firewall, r sysinfo.Rule) error {
	if r.From == h.failAllow {
		return errors.New("exit status 1")
	}
	h.fw.Rules = append(h.fw.Rules, r)
	return nil
}
func (h *setupHost) Revoke(_ context.Context, _ sysinfo.Firewall, r sysinfo.Rule) error {
	var keep []sysinfo.Rule
	for _, x := range h.fw.Rules {
		x.ID, x.Seq4, x.Seq6, x.Runtime, x.Permanent = "", 0, 0, false, false
		y := r
		y.ID, y.Seq4, y.Seq6, y.Runtime, y.Permanent = "", 0, 0, false, false
		if x != y { // ufw deletes by the rule's fields
			keep = append(keep, x)
		}
	}
	h.fw.Rules = keep
	return nil
}
func (h *setupHost) Default(_ context.Context, _ sysinfo.Firewall, p string) (string, error) {
	prev := h.fw.Default
	h.fw.Default = p
	return prev, nil
}
func (h *setupHost) Enable(_ context.Context, _ sysinfo.Firewall, on bool) error {
	if h.failOn && on {
		return errors.New("exit status 1")
	}
	h.fw.Active = on
	return nil
}
func (h *setupHost) SSHFacts(context.Context, []sysinfo.Listener) corefw.SSHFacts { return h.ssh }
func (h *setupHost) ArmUndo(context.Context, sysinfo.Firewall, string, time.Duration) error {
	return nil
}
func (h *setupHost) DisarmUndo(context.Context) error                  { return nil }
func (h *setupHost) UndoArmed(context.Context) bool                    { return false }
func (h *setupHost) Commands(sysinfo.Firewall, corefw.Change) []string { return nil }

func withSetupHost(t *testing.T, h *setupHost) {
	t.Helper()
	old, oldL := firewallHost, readListeners
	firewallHost = func() corefw.Host { return h }
	readListeners = func(context.Context) ([]sysinfo.Listener, error) { return nil, nil }
	t.Cleanup(func() { firewallHost, readListeners = old, oldL })
}

func run(t *testing.T, args ...string) (int, string) {
	var out, errs bytes.Buffer
	code := Main(append([]string{"--firewall-setup"}, args...), &out, &errs)
	return code, out.String() + errs.String()
}

// TestTheInstallersFirewallStep (claim 21's logic): SSH and the gate's ports
// allowed, then on; a firewall that is on is left; a failure leaves nothing.
func TestTheInstallersFirewallStep(t *testing.T) {
	ssh := corefw.SSHFacts{Socket: []string{"0.0.0.0:2222 (Stream)"}, Families: map[string]bool{"v4": true},
		Listeners: []sysinfo.Listener{{Proto: "tcp", Address: "0.0.0.0", Port: 2222, PID: 1, Process: "systemd"}}}
	h := &setupHost{fw: sysinfo.Firewall{Manager: "ufw", Default: "deny", Limits: []string{}}, ssh: ssh}
	withSetupHost(t, h)
	if code, out := run(t, "--ports", "80,443"); code != 0 || !h.fw.Active || len(h.fw.Rules) != 3 || !strings.Contains(out, "tcp/2222") {
		t.Fatalf("code %d, %q, rules %+v", code, out, h.fw.Rules)
	}
	if code, out := run(t, "--ports", "80,443"); code != 0 || !strings.Contains(out, "left as it is") || len(h.fw.Rules) != 3 {
		t.Fatalf("on already: %d %q", code, out)
	}

	for _, fail := range []string{"allow", "on"} {
		h := &setupHost{fw: sysinfo.Firewall{Manager: "ufw", Default: "deny", Limits: []string{}}, ssh: ssh}
		if fail == "allow" {
			h.failAllow = 443
		} else {
			h.failOn = true
		}
		withSetupHost(t, h)
		if code, _ := run(t, "--ports", "80,443"); code != 1 || h.fw.Active || len(h.fw.Rules) != 0 {
			t.Fatalf("%s failing: code %d, active %v, rules %+v", fail, code, h.fw.Active, h.fw.Rules)
		}
	}

	h = &setupHost{fw: sysinfo.Firewall{Manager: "ufw", Default: "deny", Limits: []string{}}}
	withSetupHost(t, h)
	if code, out := run(t, "--ports", "80,443"); code != 1 || h.fw.Active || !strings.Contains(out, "no SSH port") {
		t.Fatalf("no SSH port: %d %q", code, out)
	}
	h = &setupHost{fw: sysinfo.Firewall{Manager: "unknown", Active: true}}
	withSetupHost(t, h)
	if code, out := run(t, "--ports", "80"); code != 0 || !strings.Contains(out, "left as they are") {
		t.Fatalf("unknown: %d %q", code, out)
	}
	h = &setupHost{fw: sysinfo.Firewall{Manager: "none"}}
	withSetupHost(t, h)
	if code, _ := run(t, "--ports", "80"); code != 3 {
		t.Fatalf("none: %d", code)
	}
	if code, _ := run(t, "--ports", "eighty"); code != 2 {
		t.Fatalf("bad ports: %d", code)
	}
}

// TestTheInstallersStepIsCareful (C3): endpoints not all found, a default of
// allow, and a deny saved before the allows.
func TestTheInstallersStepIsCareful(t *testing.T) {
	ssh := corefw.SSHFacts{Socket: []string{"0.0.0.0:22 (Stream)"}, Families: map[string]bool{"v4": true},
		Listeners: []sysinfo.Listener{{Proto: "tcp", Address: "0.0.0.0", Port: 22, PID: 1, Process: "systemd"}}}
	unexplained := ssh
	unexplained.Listeners = append(unexplained.Listeners, sysinfo.Listener{Proto: "tcp", Address: "0.0.0.0", Port: 2022, Process: "sshd"})
	h := &setupHost{fw: sysinfo.Firewall{Manager: "ufw", Default: "deny", Limits: []string{}}, ssh: unexplained}
	withSetupHost(t, h)
	if code, out := run(t, "--ports", "80"); code != 1 || h.fw.Active || len(h.fw.Rules) != 0 || !strings.Contains(out, "could not all be found") {
		t.Fatalf("an unexplained sshd: %d %q", code, out)
	}

	h = &setupHost{fw: sysinfo.Firewall{Manager: "ufw", Default: "allow", Limits: []string{}}, ssh: ssh}
	withSetupHost(t, h)
	if code, _ := run(t, "--ports", "80"); code != 0 || !h.fw.Active || h.fw.Default != "deny" {
		t.Fatalf("a default of allow: %d, %+v", code, h.fw)
	}

	h = &setupHost{fw: sysinfo.Firewall{Manager: "ufw", Default: "allow", Limits: []string{}, Rules: []sysinfo.Rule{
		{Action: "deny", Direction: "in", Family: "both", Proto: "tcp", From: 80, To: 80, Modelled: true},
	}}, ssh: ssh}
	withSetupHost(t, h)
	if code, out := run(t, "--ports", "80"); code != 1 || h.fw.Active || len(h.fw.Rules) != 1 || h.fw.Default != "allow" || !strings.Contains(out, "would still block tcp/80") {
		t.Fatalf("a deny before: %d %q %+v", code, out, h.fw)
	}
}
