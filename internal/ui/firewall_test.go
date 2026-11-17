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
	return corefw.Armed{ConfirmBy: 1794887066}, err
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
