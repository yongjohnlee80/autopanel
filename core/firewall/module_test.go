package firewall

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"sort"
	"testing"
	"time"

	"github.com/yongjohnlee80/autopanel/internal/module"
	"github.com/yongjohnlee80/autopanel/internal/sysinfo"
)

// fakeHost is a ufw in memory: rules kept in order, both families' halves
// numbered as ufw numbers them.
type fakeHost struct {
	fw       sysinfo.Firewall
	ssh      SSHFacts
	armed    bool
	previous string
	skip     map[int]bool // ports whose allow the manager silently skips
	failOn   string       // "allow", "default", "arm", "enable"
	calls    []string
}

func newFake(active bool) *fakeHost {
	return &fakeHost{
		fw: sysinfo.Firewall{Manager: "ufw", Active: active, Default: "deny", Rules: []sysinfo.Rule{}, Limits: []string{}},
		ssh: SSHFacts{Socket: []string{"0.0.0.0:22 (Stream)"}, Families: map[string]bool{"v4": true},
			Listeners: []sysinfo.Listener{{Proto: "tcp", Address: "0.0.0.0", Port: 22, PID: 1, Process: "systemd"}}},
		skip: map[int]bool{},
	}
}

func (h *fakeHost) renumber() {
	n4, n6 := 0, 0
	for i := range h.fw.Rules {
		r := &h.fw.Rules[i]
		r.Seq4, r.Seq6 = 0, 0
		if r.Family != "v6" {
			n4++
			r.Seq4 = n4
		}
		if r.Family != "v4" {
			n6++
			r.Seq6 = n6
		}
		r.Runtime, r.Permanent = h.fw.Active, true
		r.ID = identityOf(*r)
	}
}

func (h *fakeHost) Read(context.Context) (sysinfo.Firewall, error) {
	h.renumber()
	out := h.fw
	out.Rules = append([]sysinfo.Rule(nil), h.fw.Rules...)
	return out, nil
}

func (h *fakeHost) Allow(_ context.Context, _ sysinfo.Firewall, r sysinfo.Rule) error {
	h.calls = append(h.calls, "allow")
	if h.failOn == "allow" {
		return errors.New("exit status 1")
	}
	if h.skip[r.From] {
		return nil // ufw's exit 0 with nothing done
	}
	if r.Family == "both" && h.fw.Has(sysinfo.LimitIPv6Unmanaged) {
		r.Family = "v4" // ufw with IPV6=no writes the IPv4 half alone
	}
	for _, x := range h.fw.Rules {
		if identityOf(x) == identityOf(r) {
			return nil
		}
	}
	h.fw.Rules = append(h.fw.Rules, r)
	return nil
}

func (h *fakeHost) Revoke(_ context.Context, _ sysinfo.Firewall, r sysinfo.Rule) error {
	h.calls = append(h.calls, "revoke")
	var out []sysinfo.Rule
	for _, x := range h.fw.Rules {
		if x.ID != r.ID {
			out = append(out, x)
		}
	}
	h.fw.Rules = out
	return nil
}

func (h *fakeHost) Default(_ context.Context, _ sysinfo.Firewall, p string) (string, error) {
	if h.failOn == "default" {
		return "", errors.New("exit status 1")
	}
	prev := h.fw.Default
	h.fw.Default = p
	return prev, nil
}

func (h *fakeHost) Enable(_ context.Context, _ sysinfo.Firewall, on bool) error {
	if h.failOn == "enable" && on {
		return errors.New("exit status 1")
	}
	h.fw.Active = on
	return nil
}

func (h *fakeHost) SSHFacts(context.Context, []sysinfo.Listener) SSHFacts { return h.ssh }

func (h *fakeHost) ArmUndo(_ context.Context, _ sysinfo.Firewall, prev string, _ time.Duration) error {
	if h.failOn == "arm" {
		return errors.New("exit status 1")
	}
	h.armed, h.previous = true, prev
	return nil
}

func (h *fakeHost) DisarmUndo(context.Context) error { h.armed = false; return nil }
func (h *fakeHost) UndoArmed(context.Context) bool   { return h.armed }
func (h *fakeHost) Commands(_ sysinfo.Firewall, c Change) []string {
	var out []string
	for range c.Allow {
		out = append(out, "sudo ufw allow …")
	}
	for range c.Revoke {
		out = append(out, "sudo ufw delete …")
	}
	return out
}

// fire is the undo timer firing.
func (h *fakeHost) fire() {
	h.armed, h.fw.Active, h.fw.Default = false, false, h.previous
}

type fakeStore struct{ rows map[string]Row }

func (s *fakeStore) FirewallRows(context.Context) ([]Row, error) {
	var out []Row
	for _, r := range s.rows {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
func (s *fakeStore) PutFirewallRow(_ context.Context, r Row) error { s.rows[r.ID] = r; return nil }
func (s *fakeStore) SetFirewallState(_ context.Context, id, st string) error {
	if r, ok := s.rows[id]; ok {
		r.State = st
		s.rows[id] = r
	}
	return nil
}
func (s *fakeStore) DeleteFirewallRow(_ context.Context, id string) error {
	delete(s.rows, id)
	return nil
}

func newModule(h *fakeHost, ls []sysinfo.Listener, uses map[string]Use) (*Module, *fakeStore) {
	st := &fakeStore{rows: map[string]Row{}}
	m := New(h, st, func(context.Context) ([]sysinfo.Listener, error) { return append(ls, h.ssh.Listeners...), nil },
		func(context.Context) map[string]Use { return uses }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return m, st
}

var (
	sshLogin   = module.Login{Session: "43", From: netip.MustParseAddrPort("192.0.2.20:54042"), To: netip.MustParseAddrPort("192.0.2.10:22")}
	otherLogin = module.Login{Session: "44", From: netip.MustParseAddrPort("192.0.2.20:54099"), To: netip.MustParseAddrPort("192.0.2.10:22")}
	asAdmin    = module.WithLogin(context.Background(), sshLogin)
)

func mailWants() []Want {
	var out []Want
	for _, p := range []int{25, 465, 587, 993} {
		out = append(out, Want{Proto: "tcp", From: p, To: p})
	}
	return out
}

// TestOwnersOpenOnAnInactiveFirewall (T1): with ufw off every port is allowed
// now, yet each still needs a rule; the opening makes them, recorded, and a
// second opening (a retry) changes nothing.
func TestOwnersOpenOnAnInactiveFirewall(t *testing.T) {
	h := newFake(false)
	m, st := newModule(h, nil, nil)
	states, err := m.Review(asAdmin, OwnerMail, mailWants())
	if err != nil || len(states) != 4 {
		t.Fatal(states, err)
	}
	for _, s := range states {
		if s.Verdict != sysinfo.VerdictAllowed || s.Why != sysinfo.WhyFirewallOff || !s.Needs || !s.Managed {
			t.Fatalf("on an inactive firewall %s = %+v", s.Key, s)
		}
	}
	if err := m.Open(asAdmin, OwnerMail, mailWants()); err != nil {
		t.Fatal(err)
	}
	if len(h.fw.Rules) != 4 || len(st.rows) != 4 {
		t.Fatalf("rules %d, rows %d", len(h.fw.Rules), len(st.rows))
	}
	for _, r := range st.rows {
		if r.State != StateOpen || r.Owner != OwnerMail || !r.Rule.Modelled {
			t.Fatalf("row = %+v", r)
		}
	}
	h.calls = nil
	if err := m.Open(asAdmin, OwnerMail, mailWants()); err != nil || len(h.calls) != 0 || len(st.rows) != 4 {
		t.Fatalf("a retry: %v, calls %q, rows %d", err, h.calls, len(st.rows))
	}
	states, _ = m.Review(asAdmin, OwnerMail, mailWants())
	if states[0].Needs || states[0].By != OwnerMail {
		t.Fatalf("after: %+v", states[0])
	}
}

// TestAnAdministratorsRuleIsNeverAnOwners: a rule there before the owner asks
// gets no row, and the owner's close leaves it.
func TestAnAdministratorsRuleIsNeverAnOwners(t *testing.T) {
	h := newFake(true)
	h.fw.Rules = []sysinfo.Rule{allowFrom(1, "", 22)}
	m, st := newModule(h, nil, nil)
	if _, err := m.Allow(asAdmin, AllowAsk{Proto: "tcp", From: 993}); err != nil {
		t.Fatal(err)
	}
	if err := m.Open(asAdmin, OwnerMail, mailWants()); err != nil {
		t.Fatal(err)
	}
	if len(st.rows) != 3 {
		t.Fatalf("rows = %d; 993 was the administrator's", len(st.rows))
	}
	if err := m.Close(asAdmin, OwnerMail, nil); err != nil {
		t.Fatal(err)
	}
	if len(st.rows) != 0 || len(h.fw.Rules) != 2 {
		t.Fatalf("after the close: rows %d, rules %+v", len(st.rows), h.fw.Rules)
	}
	fw, _ := m.Read(asAdmin)
	for _, r := range fw.Rules {
		if r.By != "" {
			t.Fatalf("a rule with an owner left: %+v", r)
		}
	}
}

// TestAnOpeningTheManagerSkippedIsNotRecorded: ufw's exit 0 with nothing done
// is found by the read-back; no row stays.
func TestAnOpeningTheManagerSkippedIsNotRecorded(t *testing.T) {
	h := newFake(true)
	h.fw.Rules = []sysinfo.Rule{allowFrom(1, "", 22)}
	h.skip[465] = true
	m, st := newModule(h, nil, nil)
	if err := m.Open(asAdmin, OwnerMail, mailWants()); !errors.Is(err, ErrNotApplied) {
		t.Fatalf("err = %v", err)
	}
	if len(st.rows) != 1 { // 25 was made before 465 failed; the retry finishes it
		t.Fatalf("rows = %d", len(st.rows))
	}
	delete(h.skip, 465)
	if err := m.Open(asAdmin, OwnerMail, mailWants()); err != nil || len(st.rows) != 4 {
		t.Fatalf("the retry: %v, rows %d", err, len(st.rows))
	}
}

// TestClosingFindsWhatIsLeft: an owner's rule edited by hand since is left
// alone (its row goes); a both-families rule with one half removed by hand
// has the other half closed.
func TestClosingFindsWhatIsLeft(t *testing.T) {
	h := newFake(true)
	h.fw.Rules = []sysinfo.Rule{allowFrom(1, "", 22)}
	m, st := newModule(h, nil, nil)
	if err := m.Open(asAdmin, OwnerMail, mailWants()[:2]); err != nil {
		t.Fatal(err)
	}
	// 25 edited by hand into a source-limited rule; 465's IPv6 half removed.
	for i, r := range h.fw.Rules {
		switch r.From {
		case 25:
			h.fw.Rules[i].Source, h.fw.Rules[i].Family = "198.51.100.0/24", "v4"
		case 465:
			h.fw.Rules[i].Family = "v4"
		}
	}
	if err := m.Close(asAdmin, OwnerMail, nil); err != nil {
		t.Fatal(err)
	}
	if len(st.rows) != 0 {
		t.Fatalf("rows = %d", len(st.rows))
	}
	var ports []int
	for _, r := range h.fw.Rules {
		ports = append(ports, r.From)
	}
	if len(ports) != 2 || ports[1] != 25 {
		t.Fatalf("rules left = %v; want 22 and the edited 25", ports)
	}
}

// TestSettleFinishesWhatAChangeLeft: an opening row is dropped whatever the
// manager has; a closing row is closed.
func TestSettleFinishesWhatAChangeLeft(t *testing.T) {
	h := newFake(true)
	h.fw.Rules = []sysinfo.Rule{allowFrom(1, "", 22)}
	m, st := newModule(h, nil, nil)
	if err := m.Open(asAdmin, OwnerMail, mailWants()[:2]); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for id := range st.rows {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	_ = st.SetFirewallState(asAdmin, ids[0], StateOpening)
	_ = st.SetFirewallState(asAdmin, ids[1], StateClosing)
	if err := m.Settle(asAdmin); err != nil {
		t.Fatal(err)
	}
	if len(st.rows) != 0 || len(h.fw.Rules) != 2 {
		t.Fatalf("rows %d, rules %d: want the opening row dropped (its rule stays) and the closing one closed", len(st.rows), len(h.fw.Rules))
	}
}

// TestRevokeIsGuarded: taking away the only rule that lets the
// administrator's address in is refused, with the commands; another is not.
func TestRevokeIsGuarded(t *testing.T) {
	h := newFake(true)
	h.fw.Rules = []sysinfo.Rule{allowFrom(1, "", 22), allowFrom(2, "", 443)}
	m, _ := newModule(h, nil, nil)
	fw, _ := m.Read(asAdmin)
	_, err := m.Revoke(asAdmin, fw.Rules[0].ID)
	var in *Instructed
	if !errors.Is(err, ErrLockout) || !errors.As(err, &in) || len(in.Commands) != 1 {
		t.Fatalf("revoking SSH's rule: %v", err)
	}
	if _, err := m.Revoke(asAdmin, fw.Rules[1].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Revoke(asAdmin, "nothing"); !errors.Is(err, ErrNoSuchRule) {
		t.Fatal(err)
	}
	if _, err := m.Allow(asAdmin, AllowAsk{Proto: "icmp", From: 1}); !errors.Is(err, ErrBadAllow) {
		t.Fatal(err)
	}
	h.fw.Manager = "unknown"
	if _, err := m.Allow(asAdmin, AllowAsk{Proto: "tcp", From: 25}); !errors.Is(err, ErrUnmanaged) {
		t.Fatal(err)
	}
}

// TestEnableIsPlannedConfirmedOrUndone: the plan lists what would be
// blocked; the enable does what it showed and nothing else; a confirm from
// the same login is refused, from another it keeps the firewall on; unconfirmed,
// the timer turns it off.
func TestEnableIsPlannedConfirmedOrUndone(t *testing.T) {
	h := newFake(false)
	h.fw.Default = "allow"
	ls := []sysinfo.Listener{
		{Proto: "tcp", Address: "0.0.0.0", Port: 443, Process: "autopanel"},
		{Proto: "tcp", Address: "::", Port: 993, Process: "autopanel"},
		{Proto: "tcp", Address: "0.0.0.0", Port: 5432, Process: "postgres"},
		{Proto: "tcp", Address: "127.0.0.1", Port: 8080, Process: "app"},
	}
	m, st := newModule(h, ls, map[string]Use{"tcp/443": {Name: "the gate", Suggest: true}, "tcp/993": {Name: "mail", Owner: OwnerMail}})
	plan, err := m.Plan(asAdmin)
	if err != nil || !plan.Complete || len(plan.SSH) != 1 || len(plan.Blocked) != 3 {
		t.Fatalf("plan = %+v, %v", plan, err)
	}
	if b := plan.Blocked[0]; b.Key != "tcp/443" || !b.Suggest || b.Use != "the gate" {
		t.Fatalf("the gate = %+v", b)
	}
	if b := plan.Blocked[2]; b.Key != "tcp/993" || b.Owner != OwnerMail || !b.Suggest {
		t.Fatalf("mail = %+v", b)
	}
	if _, err := m.Enable(asAdmin, EnableAsk{Plan: "stale"}); !errors.Is(err, ErrChanged) {
		t.Fatal(err)
	}
	if _, err := m.Enable(asAdmin, EnableAsk{Plan: plan.SHA256, Allow: []string{"tcp/22"}}); !errors.Is(err, ErrNotPlanned) {
		t.Fatal(err)
	}
	armed, err := m.Enable(asAdmin, EnableAsk{Plan: plan.SHA256, Allow: []string{"tcp/443", "tcp/993"}})
	if err != nil || !armed.Firewall.Active || armed.Firewall.Default != "deny" || !h.armed || h.previous != "allow" {
		t.Fatalf("enable = %+v, %v", armed, err)
	}
	if len(h.fw.Rules) != 3 || len(st.rows) != 1 { // 22 and 443 the administrator's, 993 mail's
		t.Fatalf("rules %d, rows %d", len(h.fw.Rules), len(st.rows))
	}
	if _, err := m.Confirm(asAdmin); !errors.Is(err, ErrSameLogin) {
		t.Fatalf("a confirm from the enabling login: %v", err)
	}
	if _, err := m.Confirm(module.WithLogin(context.Background(), module.Login{Session: "2"})); !errors.Is(err, ErrConfirmBySSH) {
		t.Fatalf("a confirm from the console after an SSH enable: %v", err)
	}
	if fw, err := m.Confirm(module.WithLogin(context.Background(), otherLogin)); err != nil || !fw.Active || h.armed {
		t.Fatalf("a confirm from a new SSH login: %+v, %v", fw, err)
	}
	if _, err := m.Confirm(module.WithLogin(context.Background(), otherLogin)); !errors.Is(err, ErrNotArmed) {
		t.Fatal(err)
	}

	// Unconfirmed, the timer turns it off and puts the default back.
	if _, err := m.Disable(asAdmin); err != nil {
		t.Fatal(err)
	}
	h.fw.Default = "allow"
	plan, _ = m.Plan(asAdmin)
	if _, err := m.Enable(asAdmin, EnableAsk{Plan: plan.SHA256}); err != nil {
		t.Fatal(err)
	}
	h.fire()
	if h.fw.Active || h.fw.Default != "allow" {
		t.Fatalf("after the timer: %+v", h.fw)
	}
	if _, err := m.Confirm(module.WithLogin(context.Background(), otherLogin)); !errors.Is(err, ErrNotArmed) {
		t.Fatalf("a confirm after the timer: %v", err)
	}
}

// TestAnEnableThatFailsLeavesNothing: every step before the failing one is
// undone, the owner's rows and the default included.
func TestAnEnableThatFailsLeavesNothing(t *testing.T) {
	for _, step := range []string{"allow", "default", "arm", "enable"} {
		h := newFake(false)
		h.fw.Default = "allow"
		ls := []sysinfo.Listener{{Proto: "tcp", Address: "0.0.0.0", Port: 993}}
		m, st := newModule(h, ls, map[string]Use{"tcp/993": {Name: "mail", Owner: OwnerMail}})
		plan, _ := m.Plan(asAdmin)
		h.failOn = step
		if _, err := m.Enable(asAdmin, EnableAsk{Plan: plan.SHA256, Allow: []string{"tcp/993"}}); err == nil {
			t.Fatalf("%s: no error", step)
		}
		if h.fw.Active || h.fw.Default != "allow" || h.armed || len(h.fw.Rules) != 0 || len(st.rows) != 0 {
			t.Fatalf("%s: left %+v, armed %v, rows %d", step, h.fw, h.armed, len(st.rows))
		}
	}
}

// TestAnEnableTheGuardCannotJudgeIsRefused: endpoints not found completely.
func TestAnEnableTheGuardCannotJudgeIsRefused(t *testing.T) {
	h := newFake(false)
	h.ssh.Listeners = nil
	m, _ := newModule(h, nil, nil)
	plan, _ := m.Plan(asAdmin)
	var in *Instructed
	if _, err := m.Enable(asAdmin, EnableAsk{Plan: plan.SHA256}); !errors.Is(err, ErrLockoutUnknown) || !errors.As(err, &in) {
		t.Fatalf("err = %v", err)
	}
	if h.fw.Active {
		t.Fatal("enabled anyway")
	}
}

// TestOwnersOnAHostWithIPv6Off (C1): ufw keeps the IPv4 half alone; the
// opening finds it, records it, and a retry and a close find it again.
func TestOwnersOnAHostWithIPv6Off(t *testing.T) {
	h := newFake(true)
	h.fw.Limits = []string{sysinfo.LimitIPv6Unmanaged}
	h.fw.Rules = []sysinfo.Rule{allowFrom(1, "", 22)}
	m, st := newModule(h, nil, nil)
	if err := m.Open(asAdmin, OwnerMail, mailWants()); err != nil {
		t.Fatal(err)
	}
	for _, r := range st.rows {
		if r.Rule.Family != "v4" || r.ID != r.Rule.ID || r.State != StateOpen {
			t.Fatalf("row = %+v", r)
		}
	}
	h.calls = nil
	if err := m.Open(asAdmin, OwnerMail, mailWants()); err != nil || len(h.calls) != 0 {
		t.Fatalf("a retry: %v %q", err, h.calls)
	}
	states, _ := m.Review(asAdmin, OwnerMail, mailWants())
	if states[0].Needs || states[0].By != OwnerMail {
		t.Fatalf("review after = %+v", states[0])
	}
	if _, err := m.Allow(asAdmin, AllowAsk{Proto: "tcp", From: 8443}); err != nil {
		t.Fatalf("an administrator's allow: %v", err)
	}
	if err := m.Close(asAdmin, OwnerMail, nil); err != nil || len(st.rows) != 0 || len(h.fw.Rules) != 2 {
		t.Fatalf("close: %v, rows %d, rules %d", err, len(st.rows), len(h.fw.Rules))
	}
}

// TestAnEnablesRowHoldsTheRuleAsKept (C2): an owner's row made by an enable
// holds the rule read back, its identity and all.
func TestAnEnablesRowHoldsTheRuleAsKept(t *testing.T) {
	h := newFake(false)
	ls := []sysinfo.Listener{{Proto: "tcp", Address: "0.0.0.0", Port: 993}}
	m, st := newModule(h, ls, map[string]Use{"tcp/993": {Name: "mail", Owner: OwnerMail}})
	plan, _ := m.Plan(asAdmin)
	if _, err := m.Enable(asAdmin, EnableAsk{Plan: plan.SHA256, Allow: []string{"tcp/993"}}); err != nil {
		t.Fatal(err)
	}
	for _, r := range st.rows {
		if r.Rule.ID != r.ID || !r.Rule.Permanent || r.State != StateOpen {
			t.Fatalf("row = %+v", r)
		}
	}
}
