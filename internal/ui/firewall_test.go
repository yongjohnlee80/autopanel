package ui

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	corefw "github.com/yongjohnlee80/autopanel/core/firewall"
	"github.com/yongjohnlee80/autopanel/internal/sysinfo"
	"github.com/yongjohnlee80/golib/tui/decl/decltest"
)

// fakeFW is the firewall the fake daemon answers for.
type fakeFW struct {
	fw      sysinfo.Firewall
	checks  []Check
	plan    corefw.EnablePlan
	asks    []string
	failing error
}

func (f *fakeClient) Checks(context.Context) ([]Check, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fw.checks, nil
}
func (f *fakeClient) Firewall(context.Context) (sysinfo.Firewall, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fw.fw, nil
}
func (f *fakeClient) FirewallPlan(context.Context) (corefw.EnablePlan, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fw.plan, nil
}
func (f *fakeClient) fwAsk(ask string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fw.asks = append(f.fw.asks, ask)
	return f.fw.failing
}
func (f *fakeClient) FirewallAllow(_ context.Context, a corefw.AllowAsk) error {
	return f.fwAsk("allow " + a.Proto + " " + strconv.Itoa(a.From) + " " + a.Source)
}
func (f *fakeClient) FirewallRevoke(_ context.Context, id string) error {
	return f.fwAsk("revoke " + id)
}
func (f *fakeClient) FirewallEnable(_ context.Context, plan string, allow []string) (corefw.Armed, error) {
	err := f.fwAsk("enable " + plan + " " + strings.Join(allow, ","))
	return corefw.Armed{ConfirmBy: 1700000000}, err
}
func (f *fakeClient) FirewallConfirm(context.Context) error { return f.fwAsk("confirm") }
func (f *fakeClient) FirewallDisable(context.Context) error { return f.fwAsk("disable") }

// TestAllowsOneLine: the one-line form of Allow.
func TestAllowsOneLine(t *testing.T) {
	for in, want := range map[string]corefw.AllowAsk{
		"tcp/8443":                 {Proto: "tcp", From: 8443},
		"udp/49152-49160":          {Proto: "udp", From: 49152, To: 49160},
		"tcp/22 from 192.0.2.0/24": {Proto: "tcp", From: 22, Source: "192.0.2.0/24"},
	} {
		if got, err := parseAllow(in); err != nil || got != want {
			t.Errorf("%q = %+v, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "8443", "icmp/1", "tcp/0", "tcp/9-1", "tcp/22 to x", "tcp/22 from nonsense", "tcp/22 from 192.0.2.0/24 extra"} {
		if _, err := parseAllow(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

// TestARefusalCarriesItsCommands: the commands after "run: " in a refusal.
func TestARefusalCarriesItsCommands(t *testing.T) {
	err := errors.New("firewall: the change would stop new SSH logins (the change would stop new SSH logins from your address: run: sudo ufw delete allow proto tcp from any to any port 22; sudo ufw reload)")
	got := commandsIn(err)
	if len(got) != 2 || got[0] != "sudo ufw delete allow proto tcp from any to any port 22" || got[1] != "sudo ufw reload" {
		t.Fatalf("commands = %q", got)
	}
	if commandsIn(errors.New("plain")) != nil || commandsIn(nil) != nil {
		t.Fatal("commands from nothing")
	}
}

// TestThePortChoiceSaysWhatWillBeDone: ticked, it opens; one AutoPanel cannot
// open is by hand; one already allowed is left.
func TestThePortChoiceSaysWhatWillBeDone(t *testing.T) {
	w := inEnglish{}
	open := corefw.PortState{Key: "tcp/993", Verdict: "allowed", Needs: true, Managed: true, Want: corefw.Want{Proto: "tcp", From: 993, To: 993}}
	if got := firewallChoice(w, open, true); !strings.HasPrefix(got, w.tr("autopanel.value.review.portOpen")) {
		t.Errorf("ticked = %q", got)
	}
	hand := open
	hand.Managed, hand.Commands = false, []string{"sudo ufw allow proto tcp from any to any port 993"}
	if got := firewallChoice(w, hand, false); !strings.HasPrefix(got, w.tr("autopanel.value.review.portByHand")) {
		t.Errorf("by hand = %q", got)
	}
	if d := portDetailOf(w, hand, false); !strings.Contains(d, hand.Commands[0]) || !strings.Contains(d, "nc -vz <server> 993") {
		t.Errorf("the detail = %q", d)
	}
	done := open
	done.Needs, done.By = false, "mail"
	if got := firewallChoice(w, done, false); !strings.HasPrefix(got, w.tr("autopanel.value.review.portAllowed")) {
		t.Errorf("allowed = %q", got)
	}
	_ = netip.Addr{}
}

// asked reports whether the fake daemon was asked for exactly this.
func (f *fakeClient) fwAsked(ask string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, a := range f.fw.asks {
		if a == ask {
			return true
		}
	}
	return false
}

func waitFwAsked(t *testing.T, s *decltest.Screen, f *fakeClient, ask string) {
	t.Helper()
	s.WaitFor(t, "the daemon asked for "+ask, func(string) bool { return f.fwAsked(ask) })
}

// TestFirewallPanel walks System › Firewall: the rules and what the read
// cannot see, an allow, a revoke, a refusal with the commands that would do
// it by hand, turning it off, and turning it on through the plan and a
// confirmation.
func TestFirewallPanel(t *testing.T) {
	f := newFakeClient()
	f.fw.fw = sysinfo.Firewall{Manager: "ufw", Active: true, Default: "deny", Limits: []string{sysinfo.LimitDocker},
		Rules: []sysinfo.Rule{
			{ID: "r1", Action: "allow", Direction: "in", Family: "both", Proto: "tcp", From: 22, To: 22, Raw: "allow 22/tcp", Modelled: true},
			{ID: "r2", Action: "allow", Direction: "in", Family: "v4", Proto: "tcp", From: 993, To: 993, Source: "192.0.2.0/24", Raw: "allow 993/tcp", By: "mail", Modelled: true},
			{ID: "r3", Raw: "allow in on eth1 to any"},
		}}
	f.fw.plan = corefw.EnablePlan{SHA256: "abc", Manager: "ufw", Complete: true, Default: "deny",
		SSH: []corefw.Endpoint{{Family: "v4", Port: 22}},
		Blocked: []corefw.PlannedPort{
			{Key: "tcp/80", Use: "the gate", Suggest: true},
			{Key: "tcp/5432", Use: "postgres", Owner: "stack:db"},
		}}
	s := start(t, f)
	s.WaitForText(t, "CA LE staging")

	openSystem(t, s, 'f')
	for _, part := range []string{"Manager: ufw · on, incoming deny by default · 3 rules", "Docker filters what it publishes", "993", "mail", "allow in on"} {
		s.WaitForText(t, part)
	}

	// Allow: a line that is no port is refused in the prompt; a good one is asked for.
	s.Keys(t, decltest.Rune('a'))
	s.WaitForText(t, "Allow a port")
	s.Keys(t, decltest.Type("x")...)
	s.Keys(t, enter)
	s.WaitForText(t, "Write a protocol and a port")
	s.Keys(t, backspace)
	s.Keys(t, decltest.Type("8443 from 192.0.2.7")...)
	s.Keys(t, enter)
	s.WaitForText(t, "The rule is in place.")
	waitFwAsked(t, s, f, "allow tcp 8443 192.0.2.7")

	// Revoke the second rule, after the question names it.
	s.Keys(t, decltest.Rune('j'))
	waitFact(t, s, "Rule made for", "mail")
	s.Keys(t, decltest.Rune('v'))
	s.WaitForText(t, "Delete the rule “allow 993/tcp”?")
	s.Keys(t, decltest.Rune('y'))
	s.WaitForText(t, "The rule is gone.")
	waitFwAsked(t, s, f, "revoke r2")

	// A refusal stays in the details, with the commands, and Copy appears.
	f.mu.Lock()
	f.fw.failing = errors.New("the change would stop new SSH logins from your address (run: ufw delete allow 22/tcp; ufw reload)")
	f.mu.Unlock()
	s.Keys(t, decltest.Rune('v'))
	s.WaitForText(t, "Delete the rule")
	s.Keys(t, decltest.Rune('y'))
	for _, part := range []string{"AutoPanel did not make this change", "ufw delete allow 22/tcp", "ufw reload", "Copy commands"} {
		s.WaitForText(t, part)
	}
	s.Keys(t, decltest.Rune('y'))
	s.WaitForText(t, "clipboard")
	f.mu.Lock()
	f.fw.failing = nil
	f.mu.Unlock()

	// Turn off asks first.
	s.Keys(t, decltest.Rune('f'))
	s.WaitForText(t, "Every port that listens is then open")
	s.Keys(t, decltest.Rune('y'))
	s.WaitForText(t, "The firewall is off.")
	waitFwAsked(t, s, f, "disable")

	// Turn on: the plan, with the suggested port ticked; each port's choice
	// can change; the enable carries the plan's hash and the ports ticked.
	s.Keys(t, decltest.Rune('o'))
	for _, part := range []string{"With ufw. SSH stays allowed from anywhere: 0.0.0.0:22", "tcp/5432", "postgres", "Leave it blocked"} {
		s.WaitForText(t, part)
	}
	waitFact(t, s, "Used by", "the gate")
	s.Keys(t, decltest.Rune('l'))
	s.WaitForText(t, "Allow it")
	s.Keys(t, decltest.Rune('a'))
	s.WaitForText(t, "Leave it blocked")
	s.Keys(t, decltest.Rune('j'))
	waitFact(t, s, "Rule made for", "stack:db")
	s.WaitForText(t, "Allow it")
	s.Keys(t, decltest.Rune('a'))
	s.WaitForText(t, "Leave it blocked")
	s.Keys(t, decltest.Rune('o'))
	waitFwAsked(t, s, f, "enable abc tcp/80,tcp/5432")
	s.WaitForText(t, "Log in again in a second terminal")

	s.Keys(t, decltest.Rune('c'))
	s.WaitForText(t, "The firewall stays on.")
	waitFwAsked(t, s, f, "confirm")
}

// TestHostChecksPanel: System › Host checks lists the findings, alerts as the
// daemon ordered them, each with what to do about it; with none it says so.
func TestHostChecksPanel(t *testing.T) {
	f := newFakeClient()
	f.fw.checks = []Check{
		{ID: "firewall-off", Severity: "alert", Detail: "ufw"},
		{ID: "cert-expiring", Severity: "alert", Detail: "late.example.com (2026-03-07)"},
		{ID: "reboot-required", Severity: "notice"},
	}
	// Every check the daemon can raise has its line and its advice, in English at least.
	for _, id := range []string{"mail-cpu", "mail-loopback-rule", "mail-ptr", "mail-port-25", "mail-proxy-trust"} {
		for _, kind := range []string{"value", "notice"} {
			if key := "autopanel." + kind + ".check." + camel(id); englishText(key) == key || englishText(key) == "" {
				t.Errorf("no English text for %s", key)
			}
		}
	}
	s := start(t, f)
	s.WaitForText(t, "CA LE staging")

	openSystem(t, s, 'h')
	for _, part := range []string{"Host checks", "· 3 · read at ", englishText("autopanel.value.check.rebootRequired")} {
		s.WaitForText(t, part)
	}
	s.Keys(t, decltest.Rune('j'))
	s.WaitForText(t, "late.example.com (2026-03-07)")
	s.WaitForText(t, "A certificate is renewed in the last")

	f.mu.Lock()
	f.fw.checks = nil
	f.mu.Unlock()
	s.Keys(t, decltest.Rune('r'))
	s.WaitForText(t, "Nothing to report")
}
