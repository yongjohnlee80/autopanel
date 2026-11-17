package mail

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sort"
	"sync"
	"testing"
	"time"

	corefw "github.com/yongjohnlee80/autopanel/core/firewall"
	"github.com/yongjohnlee80/autopanel/core/services"
	"github.com/yongjohnlee80/autopanel/internal/sysinfo"
)

// fwMachine is a ufw in memory under the real firewall module: what mail
// and the services module are tested against together.
type fwMachine struct {
	mu        sync.Mutex
	fw        sysinfo.Firewall
	failAllow int // the allow for this port fails
}

func (h *fwMachine) Read(context.Context) (sysinfo.Firewall, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := h.fw
	out.Rules = nil
	for i, r := range h.fw.Rules {
		r.Seq4, r.Seq6, r.Runtime, r.Permanent = i+1, i+1, h.fw.Active, true
		r.ID = ""
		r.ID = sysinfo.Identity(r)
		out.Rules = append(out.Rules, r)
	}
	return out, nil
}
func (h *fwMachine) Allow(_ context.Context, _ sysinfo.Firewall, r sysinfo.Rule) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if r.From == h.failAllow {
		return errors.New("exit status 1")
	}
	h.fw.Rules = append(h.fw.Rules, r)
	return nil
}
func (h *fwMachine) Revoke(_ context.Context, _ sysinfo.Firewall, r sysinfo.Rule) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	var keep []sysinfo.Rule
	for _, x := range h.fw.Rules {
		if x.From != r.From || x.Proto != r.Proto {
			keep = append(keep, x)
		}
	}
	h.fw.Rules = keep
	return nil
}
func (h *fwMachine) Default(_ context.Context, fw sysinfo.Firewall, _ string) (string, error) {
	return fw.Default, nil
}
func (h *fwMachine) Enable(context.Context, sysinfo.Firewall, bool) error { return nil }
func (h *fwMachine) SSHFacts(context.Context, []sysinfo.Listener) corefw.SSHFacts {
	return corefw.SSHFacts{Socket: []string{"0.0.0.0:22 (Stream)"}, Families: map[string]bool{"v4": true},
		Listeners: []sysinfo.Listener{{Proto: "tcp", Address: "0.0.0.0", Port: 22, PID: 1, Process: "systemd"}}}
}
func (h *fwMachine) ArmUndo(context.Context, sysinfo.Firewall, string, time.Duration) error {
	return nil
}
func (h *fwMachine) DisarmUndo(context.Context) error                  { return nil }
func (h *fwMachine) UndoArmed(context.Context) bool                    { return false }
func (h *fwMachine) Commands(sysinfo.Firewall, corefw.Change) []string { return nil }

func (h *fwMachine) ports() []int {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []int
	for _, r := range h.fw.Rules {
		out = append(out, r.From)
	}
	sort.Ints(out)
	return out
}

type rowMap struct {
	mu   sync.Mutex
	rows map[string]corefw.Row
}

func (s *rowMap) FirewallRows(context.Context) ([]corefw.Row, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []corefw.Row
	for _, r := range s.rows {
		out = append(out, r)
	}
	return out, nil
}
func (s *rowMap) PutFirewallRow(_ context.Context, r corefw.Row) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rows[r.ID] = r
	return nil
}
func (s *rowMap) SetFirewallState(_ context.Context, id, st string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.rows[id]; ok {
		r.State = st
		s.rows[id] = r
	}
	return nil
}
func (s *rowMap) DeleteFirewallRow(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.rows, id)
	return nil
}

// withFirewall is wired's mail and services modules with the real firewall
// module over an inactive ufw (Ubuntu's default) with SSH allowed.
func withFirewall(t *testing.T) (*Module, *services.Module, *fakeStore, *fwMachine, *rowMap, *machine) {
	m, svcs, st, _, _, mach := wired(t)
	fwh := &fwMachine{fw: sysinfo.Firewall{Manager: "ufw", Default: "deny", Limits: []string{}, Rules: []sysinfo.Rule{
		{Action: "allow", Direction: "in", Family: "both", Proto: "tcp", From: 22, To: 22, Modelled: true},
	}}}
	rows := &rowMap{rows: map[string]corefw.Row{}}
	fwm := corefw.New(fwh, rows, func(context.Context) ([]sysinfo.Listener, error) { return nil, nil }, nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	m.SetFirewall(fwm)
	svcs.SetFirewall(fwm)
	return m, svcs, st, fwh, rows, mach
}

// TestMailOpensItsPortsAtSetUp (T1, claim 20): on an inactive ufw the four
// ports are allowed now and still need a rule; the set-up opens the ones
// ticked, as mail's, after its stack and before the record.
func TestMailOpensItsPortsAtSetUp(t *testing.T) {
	m, _, st, fwh, rows, _ := withFirewall(t)
	ctx := context.Background()
	out, err := m.setup(ctx, SetupAsk{Host: "mail.example.net", Domain: "example.net"})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Ports) != 4 {
		t.Fatalf("the review's ports = %+v", out.Ports)
	}
	for _, p := range out.Ports {
		if p.Verdict != sysinfo.VerdictAllowed || !p.Needs || !p.Managed {
			t.Fatalf("%s = %+v; want allowed now (ufw is off) and needing a rule", p.Key, p)
		}
	}
	if _, err := m.apply(ctx, Accept{Accept: out.SHA256, Open: []int{25, 2525}}); !errors.Is(err, ErrNotMailPort) {
		t.Fatalf("a port that is not mail's = %v", err)
	}
	if st.state != nil || len(fwh.ports()) != 1 {
		t.Fatal("a refused apply did something")
	}
	if _, err := m.apply(ctx, Accept{Accept: out.SHA256, Open: []int{25, 465, 587, 993}}); err != nil {
		t.Fatal(err)
	}
	if got := fwh.ports(); len(got) != 5 || st.state == nil || len(rows.rows) != 4 {
		t.Fatalf("ports %v, recorded %v, rows %d", got, st.state != nil, len(rows.rows))
	}
	for _, r := range rows.rows {
		if r.Owner != corefw.OwnerMail || r.State != corefw.StateOpen {
			t.Fatalf("row = %+v", r)
		}
	}
	status, err := m.status(ctx, struct{}{})
	if err != nil || len(status.Ports) != 4 || status.Ports[0].By != corefw.OwnerMail || status.Ports[0].Needs {
		t.Fatalf("Mail → Server's ports = %+v, %v", status.Ports, err)
	}
}

// TestASetUpThatFailedAtItsPortsIsFinishedByAskingAgain (T2): the stack is
// registered and mail not recorded; after a core restart (the pending set-up
// gone) the set-up is asked again, reviewed from the registered stack, and
// finished, with no rule made twice.
func TestASetUpThatFailedAtItsPortsIsFinishedByAskingAgain(t *testing.T) {
	m, svcs, st, fwh, rows, _ := withFirewall(t)
	ctx := context.Background()
	ask := SetupAsk{Host: "mail.example.net", Domain: "example.net"}
	out, err := m.setup(ctx, ask)
	if err != nil {
		t.Fatal(err)
	}
	fwh.failAllow = 587
	if _, err := m.apply(ctx, Accept{Accept: out.SHA256, Open: []int{25, 465, 587, 993}}); err == nil {
		t.Fatal("no error")
	}
	if st.state != nil || len(rows.rows) != 2 {
		t.Fatalf("after the failure: recorded %v, rows %d", st.state != nil, len(rows.rows))
	}
	if _, _, err := svcs.Up(ctx, Stack); err != nil {
		t.Fatalf("the stack is not registered: %v", err)
	}
	m.pending = nil // the core restarted
	fwh.failAllow = 0
	again, err := m.setup(ctx, ask)
	if err != nil {
		t.Fatalf("asking again: %v", err)
	}
	if again.SHA256 != out.SHA256 {
		t.Fatalf("the registered stack reviews as %s, the draft as %s", again.SHA256, out.SHA256)
	}
	if _, err := m.apply(ctx, Accept{Accept: again.SHA256, Open: []int{25, 465, 587, 993}}); err != nil {
		t.Fatalf("finishing: %v", err)
	}
	if got := fwh.ports(); len(got) != 5 || st.state == nil || len(rows.rows) != 4 {
		t.Fatalf("ports %v, recorded %v, rows %d", got, st.state != nil, len(rows.rows))
	}
}

// TestMailIsRemovedWholeAndOnlyByMail: services.remove refuses the stack;
// mail.remove closes mail's ports (a rule the administrator made for one stays),
// removes the stack, the loopback rule and the definition, then the record.
func TestMailIsRemovedWholeAndOnlyByMail(t *testing.T) {
	m, svcs, st, fwh, rows, _ := withFirewall(t)
	ctx := context.Background()
	fwh.fw.Rules = append(fwh.fw.Rules, sysinfo.Rule{Action: "allow", Direction: "in", Family: "both", Proto: "tcp", From: 993, To: 993, Modelled: true})
	out, err := m.setup(ctx, SetupAsk{Host: "mail.example.net", Domain: "example.net"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.apply(ctx, Accept{Accept: out.SHA256, Open: []int{25, 465, 587, 993}}); err != nil {
		t.Fatal(err)
	}
	if len(rows.rows) != 3 {
		t.Fatalf("rows = %d; 993 was the administrator's", len(rows.rows))
	}
	if err := callVerb(ctx, svcs, "services.remove", map[string]any{"name": Stack}); !errors.Is(err, services.ErrReserved) {
		t.Fatalf("services.remove of mail = %v", err)
	}
	if _, err := m.remove(ctx, RemoveAsk{}); err != nil {
		t.Fatal(err)
	}
	if st.state != nil || len(rows.rows) != 0 {
		t.Fatalf("after: recorded %v, rows %d", st.state != nil, len(rows.rows))
	}
	if got := fwh.ports(); len(got) != 2 || got[0] != 22 || got[1] != 993 {
		t.Fatalf("rules left = %v; want SSH's and the administrator's 993", got)
	}
	if _, _, err := svcs.Up(ctx, Stack); !errors.Is(err, services.ErrNotFound) {
		t.Fatalf("the stack is still registered: %v", err)
	}
	if _, err := m.remove(ctx, RemoveAsk{}); !errors.Is(err, ErrNotSetUp) {
		t.Fatalf("a second removal = %v", err)
	}
	if _, err := m.portsOpen(ctx, PortsAsk{Ports: []int{25}}); !errors.Is(err, ErrNotSetUp) {
		t.Fatalf("opening ports with mail gone = %v", err)
	}
}

// callVerb calls one of the services module's verbs as the control socket
// does.
func callVerb(ctx context.Context, svcs *services.Module, verb string, param any) error {
	for _, v := range svcs.Verbs() {
		if v.Verb == verb {
			_, err := v.Call(ctx, []any{param})
			return err
		}
	}
	return errors.New("no such verb")
}
