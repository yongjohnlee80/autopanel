package firewall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yongjohnlee80/autopanel/internal/module"
	"github.com/yongjohnlee80/autopanel/internal/sysinfo"
)

// The module's declared errors.
var (
	ErrUnmanaged    = errors.New("firewall: this host's firewall is not one AutoPanel can change; the commands to run are given")
	ErrNotApplied   = errors.New("firewall: the manager did not make the change (read back, it is not there)")
	ErrNoSuchRule   = errors.New("firewall: no rule has that id")
	ErrChanged      = errors.New("firewall: the host changed since the plan was made; review the new plan")
	ErrNotPlanned   = errors.New("firewall: a port to allow is not one the plan lists")
	ErrNotArmed     = errors.New("firewall: no enable is waiting to be confirmed")
	ErrSameLogin    = errors.New("firewall: confirm from a new login, not the one that turned the firewall on: log in again in a second terminal and confirm there")
	ErrConfirmBySSH = errors.New("firewall: the firewall was turned on over SSH; confirm from a new SSH login, to prove one still gets in")
	ErrBadAllow     = errors.New("firewall: a rule needs tcp or udp, a port from 1 to 65535 (a range in order), and addresses of one family")
	ErrUndoArmed    = errors.New("firewall: an enable is already waiting to be confirmed")
	ErrActive       = errors.New("firewall: the firewall is already on")
)

// UndoAfter is how long an enable stays unless confirmed.
const UndoAfter = 120 * time.Second

// Host is the machine's firewall: host/firewall on it, a fake in a test.
type Host interface {
	Read(ctx context.Context) (sysinfo.Firewall, error)
	Allow(ctx context.Context, fw sysinfo.Firewall, r sysinfo.Rule) error
	Revoke(ctx context.Context, fw sysinfo.Firewall, r sysinfo.Rule) error
	Default(ctx context.Context, fw sysinfo.Firewall, policy string) (previous string, err error)
	Enable(ctx context.Context, fw sysinfo.Firewall, on bool) error
	SSHFacts(ctx context.Context, listeners []sysinfo.Listener) SSHFacts
	// ArmUndo arms the timer that turns the firewall off after d, putting
	// the incoming default back to previous; DisarmUndo stops it.
	ArmUndo(ctx context.Context, fw sysinfo.Firewall, previous string, d time.Duration) error
	DisarmUndo(ctx context.Context) error
	UndoArmed(ctx context.Context) bool
	// Commands are the manager's own command lines for a change the core
	// will not make: the same argument lists it would run.
	Commands(fw sysinfo.Firewall, c Change) []string
}

// Change is a change, as commands for the administrator: rules to allow and
// to revoke, and whether the firewall is then turned on.
type Change struct {
	Allow  []sysinfo.Rule
	Revoke []sysinfo.Rule
	Enable bool
}

// Use is what a port is for, as the rest of the core knows it.
type Use struct {
	Name    string // "the gate", "mail", "stack chat"
	Owner   string // the owner that wants it open, or ""
	Suggest bool   // ticked by default in an enable's plan
}

// Module is the firewall's verbs and the owners' openings and closings, all
// under one lock.
type Module struct {
	host      Host
	store     Store
	listeners func(ctx context.Context) ([]sysinfo.Listener, error)
	uses      func(ctx context.Context) map[string]Use // "tcp/443" → its use
	log       *slog.Logger
	now       func() time.Time

	mu        sync.Mutex   // the firewall lock: every change, the core's and the owners'
	enabledBy module.Login // the login that armed the undo; the zero Login when none is waiting
	armedAt   time.Time
}

// New is the module. uses may be nil.
func New(host Host, store Store, listeners func(ctx context.Context) ([]sysinfo.Listener, error), uses func(ctx context.Context) map[string]Use, log *slog.Logger) *Module {
	if uses == nil {
		uses = func(context.Context) map[string]Use { return nil }
	}
	return &Module{host: host, store: store, listeners: listeners, uses: uses, log: log, now: time.Now}
}

// Read is the firewall, each rule named by its owner.
func (m *Module) Read(ctx context.Context) (sysinfo.Firewall, error) {
	fw, err := m.host.Read(ctx)
	if err != nil {
		return fw, err
	}
	rows, err := m.store.FirewallRows(ctx)
	if err != nil {
		return fw, err
	}
	by := map[string]string{}
	for _, r := range rows {
		by[r.ID] = r.Owner
	}
	for i := range fw.Rules {
		fw.Rules[i].By = by[fw.Rules[i].ID]
	}
	return fw, nil
}

// Settle finishes what a change left when the core stopped in it: a row still
// opening is dropped, whether its rule is there or not (the core cannot tell
// its own half-made rule from one the administrator made since); a row
// closing is closed (its owner asked for it). It runs at the core's start and
// under the lock at the beginning of each change, never on a read.
//
// Decision: docs/decisions/firewall.md#owners
func (m *Module) Settle(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.settle(ctx)
}

func (m *Module) settle(ctx context.Context) error {
	rows, err := m.store.FirewallRows(ctx)
	if err != nil {
		return err
	}
	for _, r := range rows {
		switch r.State {
		case StateOpening:
			if err := m.store.DeleteFirewallRow(ctx, r.ID); err != nil {
				return err
			}
		case StateClosing:
			if err := m.closeRow(ctx, r); err != nil {
				return err
			}
		}
	}
	return nil
}

// change opens a firewall change: the lock, then whatever an earlier change
// left. The caller unlocks.
func (m *Module) change(ctx context.Context) (func(), error) {
	m.mu.Lock()
	if err := m.settle(ctx); err != nil {
		m.mu.Unlock()
		return nil, err
	}
	return m.mu.Unlock, nil
}

// guard reads what Safe needs and judges after.
func (m *Module) guard(ctx context.Context, after sysinfo.Firewall, removed *sysinfo.Rule) error {
	ls, err := m.listeners(ctx)
	if err != nil {
		return ErrLockoutUnknown
	}
	eps, complete := Endpoints(m.host.SSHFacts(ctx, ls))
	return Safe(after, eps, complete, module.LoginOf(ctx), removed)
}

// AllowAsk is sys.firewall.allow's parameter.
type AllowAsk struct {
	Proto  string `json:"proto"`
	From   int    `json:"from"`
	To     int    `json:"to,omitempty"`
	Source string `json:"source,omitempty"`
	Dest   string `json:"dest,omitempty"`
	Family string `json:"family,omitempty"` // "v4", "v6"; both when empty and no address names one
	Zone   string `json:"zone,omitempty"`   // firewalld's zone
}

// AllowRule is the incoming allow an ask makes, validated: tcp or udp, a
// port or an ordered range, addresses of one family (which is then the rule's).
func AllowRule(a AllowAsk) (sysinfo.Rule, error) {
	if a.To == 0 {
		a.To = a.From
	}
	if (a.Proto != "tcp" && a.Proto != "udp") || a.From < 1 || a.To < a.From || a.To > 65535 {
		return sysinfo.Rule{}, ErrBadAllow
	}
	r := sysinfo.Rule{Action: "allow", Direction: "in", Proto: a.Proto, From: a.From, To: a.To, Scope: a.Zone, Modelled: true}
	fam := a.Family
	for _, s := range []*string{&a.Source, &a.Dest} {
		if *s == "" {
			continue
		}
		n := sysinfo.NormalAddr(*s)
		f, ok := familyOf(n)
		if !ok || (fam != "" && fam != f) {
			return sysinfo.Rule{}, ErrBadAllow
		}
		fam, *s = f, n
	}
	switch fam {
	case "":
		fam = "both"
	case "v4", "v6":
	default:
		return sysinfo.Rule{}, ErrBadAllow
	}
	r.Family, r.Source, r.Dest = fam, a.Source, a.Dest
	return r, nil
}

func familyOf(s string) (string, bool) {
	var a netip.Addr
	if p, err := netip.ParsePrefix(s); err == nil {
		a = p.Addr()
	} else if a, err = netip.ParseAddr(s); err != nil {
		return "", false
	}
	if a.Is4() {
		return "v4", true
	}
	return "v6", true
}

// identityOf is the identity the rule will have once the manager keeps it.
// identityOn is the identity r will have once fw's manager keeps it (an allow
// of both families is IPv4's alone where ufw leaves IPv6 to itself).
func identityOn(fw sysinfo.Firewall, r sysinfo.Rule) string { return identityOf(fw.Kept(r)) }

func identityOf(r sysinfo.Rule) string {
	r.ID, r.Runtime, r.Permanent, r.Raw, r.Note, r.Seq4, r.Seq6, r.By = "", false, false, "", "", 0, 0, ""
	return sysinfo.Identity(r)
}

func find(fw sysinfo.Firewall, id string) (sysinfo.Rule, bool) {
	for _, r := range fw.Rules {
		if r.ID == id {
			return r, true
		}
	}
	return sysinfo.Rule{}, false
}

// managed reports whether AutoPanel can change this host's firewall.
func managed(fw sysinfo.Firewall) bool { return fw.Manager == "ufw" || fw.Manager == "firewalld" }

// unmanaged is the error for a change on a host AutoPanel cannot drive, with
// the commands for the administrator.
func (m *Module) unmanaged(fw sysinfo.Firewall, rules []sysinfo.Rule) error {
	return &Instructed{Err: ErrUnmanaged, Commands: m.host.Commands(fw, Change{Allow: rules})}
}

// Instructed is a refusal that carries the commands for doing it by hand.
type Instructed struct {
	Err      error
	Commands []string
}

func (e *Instructed) Error() string { return e.Err.Error() }
func (e *Instructed) Unwrap() error { return e.Err }
func (e *Instructed) PublicDetail() string {
	if len(e.Commands) == 0 {
		return ""
	}
	return "run: " + strings.Join(e.Commands, "; ")
}

// Allow makes an administrator's rule: it has no row and no owner removes
// it. A rule already there is left as it is.
func (m *Module) Allow(ctx context.Context, a AllowAsk) (sysinfo.Firewall, error) {
	r, err := AllowRule(a)
	if err != nil {
		return sysinfo.Firewall{}, err
	}
	unlock, err := m.change(ctx)
	if err != nil {
		return sysinfo.Firewall{}, err
	}
	defer unlock()
	fw, err := m.host.Read(ctx)
	if err != nil {
		return fw, err
	}
	if !managed(fw) {
		return fw, m.unmanaged(fw, []sysinfo.Rule{r})
	}
	if _, there := find(fw, identityOn(fw, r)); !there {
		if _, err := m.allowAndCheck(ctx, fw, r); err != nil {
			return fw, err
		}
	}
	return m.Read(ctx)
}

// allowAndCheck asks the manager for r, and reads it back: its exit code says
// nothing (ufw exits 0 when it skipped a rule). It answers the rule as the
// manager keeps it.
func (m *Module) allowAndCheck(ctx context.Context, fw sysinfo.Firewall, r sysinfo.Rule) (sysinfo.Rule, error) {
	if err := m.host.Allow(ctx, fw, r); err != nil {
		return sysinfo.Rule{}, err
	}
	after, err := m.host.Read(ctx)
	if err != nil {
		return sysinfo.Rule{}, err
	}
	got, there := find(after, identityOn(after, r))
	if !there {
		return sysinfo.Rule{}, ErrNotApplied
	}
	return got, nil
}

// Revoke deletes a rule by its identity, the guard first. An owner's rule
// loses its row with it.
func (m *Module) Revoke(ctx context.Context, id string) (sysinfo.Firewall, error) {
	unlock, err := m.change(ctx)
	if err != nil {
		return sysinfo.Firewall{}, err
	}
	defer unlock()
	fw, err := m.host.Read(ctx)
	if err != nil {
		return fw, err
	}
	r, ok := find(fw, id)
	if !ok {
		return fw, ErrNoSuchRule
	}
	if !managed(fw) {
		return fw, &Instructed{Err: ErrUnmanaged, Commands: m.host.Commands(fw, Change{Revoke: []sysinfo.Rule{r}})}
	}
	if err := m.revokeGuarded(ctx, fw, r); err != nil {
		return fw, err
	}
	_ = m.store.DeleteFirewallRow(ctx, id)
	return m.Read(ctx)
}

// without is fw after r is taken away.
func without(fw sysinfo.Firewall, r sysinfo.Rule) sysinfo.Firewall {
	out := fw
	out.Rules = nil
	for _, x := range fw.Rules {
		if x.ID != r.ID {
			out.Rules = append(out.Rules, x)
		}
	}
	return out
}

// revokeGuarded passes the guard, revokes r and reads it back gone.
func (m *Module) revokeGuarded(ctx context.Context, fw sysinfo.Firewall, r sysinfo.Rule) error {
	if err := m.guard(ctx, without(fw, r), &r); err != nil {
		return &Instructed{Err: err, Commands: m.host.Commands(fw, Change{Revoke: []sysinfo.Rule{r}})}
	}
	if err := m.host.Revoke(ctx, fw, r); err != nil {
		return err
	}
	after, err := m.host.Read(ctx)
	if err != nil {
		return err
	}
	if _, there := find(after, r.ID); there {
		return ErrNotApplied
	}
	return nil
}

// Want is a port an owner wants open: one port or a range, of one protocol,
// on every address or one.
type Want struct {
	Proto string     `json:"proto"`
	From  int        `json:"from"`
	To    int        `json:"to"`
	Addr  netip.Addr `json:"addr"` // the zero Addr for every address
}

// Key is the want as a plan names it: "tcp/993", "udp/49152-65535",
// "tcp/192.0.2.1:8008".
func (w Want) Key() string {
	k := w.Proto + "/"
	if w.Addr.IsValid() {
		k += w.Addr.String() + ":"
	}
	k += strconv.Itoa(w.From)
	if w.To > w.From {
		k += "-" + strconv.Itoa(w.To)
	}
	return k
}

// rule is the allow that opens w: on its address alone when it has one.
func (w Want) rule() (sysinfo.Rule, error) {
	a := AllowAsk{Proto: w.Proto, From: w.From, To: w.To}
	if w.Addr.IsValid() {
		a.Dest = w.Addr.Unmap().String()
	}
	return AllowRule(a)
}

// PortState is a want's state, for an owner's review: its verdict now, and
// whether it needs a rule, judged as if the firewall were on with its
// default deny (on an inactive firewall every port is allowed now, and the
// rule is still needed for when it is turned on).
type PortState struct {
	Want     Want     `json:"want"`
	Key      string   `json:"key"`
	Verdict  string   `json:"verdict"`
	Why      string   `json:"why"`
	Needs    bool     `json:"needs"`    // no rule allows it from anywhere: ticked by default
	By       string   `json:"by"`       // "": nobody's; the owner; or "other" for a rule not AutoPanel's
	Managed  bool     `json:"managed"`  // AutoPanel can open it here
	Commands []string `json:"commands"` // the manager's commands, when it cannot
}

// Review is each want's state for owner.
//
// Decision: docs/decisions/firewall.md#owners
func (m *Module) Review(ctx context.Context, owner string, wants []Want) ([]PortState, error) {
	fw, err := m.Read(ctx)
	readable := err == nil // a manager AutoPanel reads but does not drive: unknown, with its commands
	out := make([]PortState, 0, len(wants))
	for _, w := range wants {
		addr := w.Addr
		if !addr.IsValid() {
			addr = netip.IPv6Unspecified() // every address, both families
		}
		st := PortState{Want: w, Key: w.Key(), Managed: readable && managed(fw)}
		st.Verdict, st.Why = fw.VerdictRange(w.Proto, addr, w.From, w.To)
		st.Needs = fw.Manager != "none" && fw.NeedsRuleRange(w.Proto, addr, w.From, w.To)
		if !readable {
			st.Verdict, st.Why, st.Needs = sysinfo.VerdictUnknown, "firewall-unread", fw.Manager != "none"
		}
		if r, err := w.rule(); err == nil {
			if x, there := find(fw, identityOn(fw, r)); there {
				st.By = "other"
				if x.By != "" {
					st.By = x.By
				}
			}
			if !st.Managed && st.Needs {
				st.Commands = m.host.Commands(fw, Change{Allow: []sysinfo.Rule{r}})
			}
		}
		out = append(out, st)
	}
	return out, nil
}

// Open makes the rules owner wants, each under the lock and recorded first:
// the row is written opening before the manager is asked, and set open once
// the rule is read back. A rule already there is a no-op: the
// administrator's stays theirs (no row), the owner's keeps its row. On a host
// AutoPanel cannot drive, nothing is made and the commands are returned.
//
// Decision: docs/decisions/firewall.md#owners
func (m *Module) Open(ctx context.Context, owner string, wants []Want) error {
	if !ValidOwner(owner) {
		return fmt.Errorf("firewall: %q owns nothing", owner)
	}
	var rules []sysinfo.Rule
	for _, w := range wants {
		r, err := w.rule()
		if err != nil {
			return err
		}
		rules = append(rules, r)
	}
	unlock, err := m.change(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	fw, err := m.host.Read(ctx)
	if err != nil {
		return err
	}
	if fw.Manager == "none" {
		return nil // nothing on the host filters: there is nothing to open
	}
	if !managed(fw) {
		return m.unmanaged(fw, rules)
	}
	rows, err := m.store.FirewallRows(ctx)
	if err != nil {
		return err
	}
	owned := map[string]Row{}
	for _, r := range rows {
		owned[r.ID] = r
	}
	for _, r := range rules {
		id := identityOn(fw, r)
		if _, there := find(fw, id); there {
			if row, ok := owned[id]; ok && row.Owner == owner && row.State != StateOpen {
				if err := m.store.SetFirewallState(ctx, id, StateOpen); err != nil {
					return err
				}
			}
			continue
		}
		if err := m.store.PutFirewallRow(ctx, Row{ID: id, Owner: owner, Rule: r, State: StateOpening, CreatedAt: m.now().Unix()}); err != nil {
			return err
		}
		x, err := m.allowAndCheck(ctx, fw, r)
		if err != nil {
			_ = m.store.DeleteFirewallRow(context.WithoutCancel(ctx), id)
			return err
		}
		if err := m.store.PutFirewallRow(ctx, Row{ID: id, Owner: owner, Rule: x, State: StateOpen, CreatedAt: m.now().Unix()}); err != nil {
			return err
		}
		fw.Rules = append(fw.Rules, x)
	}
	return nil
}

// Close closes owner's rules: all of them when wants is nil, else those that
// open wants. Each row is set closing first, its rule revoked through the
// guard if it is still there with its identity, then the row deleted. A rule
// someone edited since has another identity: its row goes, nothing is
// deleted.
//
// Decision: docs/decisions/firewall.md#owners
func (m *Module) Close(ctx context.Context, owner string, wants []Want) error {
	unlock, err := m.change(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	rows, err := m.store.FirewallRows(ctx)
	if err != nil {
		return err
	}
	fw, err := m.host.Read(ctx)
	if err != nil {
		return err
	}
	pick := map[string]bool{}
	for _, w := range wants {
		r, err := w.rule()
		if err != nil {
			return err
		}
		pick[identityOn(fw, r)] = true
	}
	for _, r := range rows {
		if r.Owner != owner || (wants != nil && !pick[r.ID]) {
			continue
		}
		if err := m.store.SetFirewallState(ctx, r.ID, StateClosing); err != nil {
			return err
		}
		if err := m.closeRow(ctx, r); err != nil {
			return err
		}
	}
	return nil
}

// closeRow revokes a closing row's rule, or its surviving half, and deletes
// the row. A failure leaves the row closing, for the next change to finish.
func (m *Module) closeRow(ctx context.Context, row Row) error {
	fw, err := m.host.Read(ctx)
	if err != nil {
		return err
	}
	switch {
	case fw.Manager == "none":
		return m.store.DeleteFirewallRow(ctx, row.ID) // no manager: its rules went with it
	case !managed(fw):
		return &Instructed{Err: ErrUnmanaged, Commands: m.host.Commands(fw, Change{Revoke: []sysinfo.Rule{row.Rule}})} // the row stays closing
	}
	r, there := find(fw, row.ID)
	if !there && row.Rule.Family == "both" {
		r, there = survivingHalf(fw, row.Rule)
		if there {
			m.log.Info("firewall: one half of an owned rule was removed by hand; the other is closed", "owner", row.Owner, "rule", row.Rule.Raw, "left", r.Family)
		}
	}
	if there {
		if err := m.revokeGuarded(ctx, fw, r); err != nil {
			return err
		}
	} else {
		m.log.Info("firewall: an owned rule was changed or removed by hand; nothing was deleted", "owner", row.Owner, "rule", row.Rule.Raw)
	}
	return m.store.DeleteFirewallRow(ctx, row.ID)
}

// survivingHalf is the one family's rule left of a both-families rule whose
// other half was removed by hand: alike in every other field.
func survivingHalf(fw sysinfo.Firewall, both sysinfo.Rule) (sysinfo.Rule, bool) {
	for _, r := range fw.Rules {
		if r.Family == "both" || !r.Modelled {
			continue
		}
		c := r
		c.Family, c.ID, c.Seq4, c.Seq6, c.Raw, c.Note, c.By, c.Runtime, c.Permanent = both.Family, both.ID, both.Seq4, both.Seq6, both.Raw, both.Note, both.By, both.Runtime, both.Permanent
		if c == both {
			return r, true
		}
	}
	return sysinfo.Rule{}, false
}

// Owned are owner's rows.
func (m *Module) Owned(ctx context.Context, owner string) ([]Row, error) {
	rows, err := m.store.FirewallRows(ctx)
	if err != nil {
		return nil, err
	}
	var out []Row
	for _, r := range rows {
		if r.Owner == owner {
			out = append(out, r)
		}
	}
	return out, nil
}

// EnablePlan is what an enable would do, against the listeners and rules as
// they are now. Its hash binds the enable to what was shown.
//
// Decision: docs/decisions/firewall.md#enabling
type EnablePlan struct {
	SHA256   string        `json:"sha256"`
	Manager  string        `json:"manager"`
	SSH      []Endpoint    `json:"ssh"`      // allowed first, from anywhere, always
	Complete bool          `json:"complete"` // false refuses the enable
	Blocked  []PlannedPort `json:"blocked"`  // public listeners an enable would block
	Default  string        `json:"default"`  // "deny"
}

// PlannedPort is a listener the plan would block unless ticked.
type PlannedPort struct {
	Key     string `json:"key"` // "tcp/443"
	Use     string `json:"use"`
	Owner   string `json:"owner"`
	Suggest bool   `json:"suggest"`
}

// Plan is what an enable would do now.
func (m *Module) Plan(ctx context.Context) (EnablePlan, error) {
	fw, err := m.host.Read(ctx)
	if err != nil {
		return EnablePlan{}, err
	}
	ls, err := m.listeners(ctx)
	if err != nil {
		return EnablePlan{}, err
	}
	eps, complete := Endpoints(m.host.SSHFacts(ctx, ls))
	p := EnablePlan{Manager: fw.Manager, SSH: eps, Complete: complete, Default: "deny", Blocked: []PlannedPort{}}
	if p.SSH == nil {
		p.SSH = []Endpoint{}
	}
	uses := m.uses(ctx)
	after := simulated(fw, sshRules(eps))
	seen := map[string]bool{}
	for _, l := range ls {
		addr, err := netip.ParseAddr(l.Address)
		if err != nil || addr.IsLoopback() {
			continue
		}
		key := l.Proto + "/" + strconv.Itoa(l.Port)
		if seen[key] || (l.Proto == "tcp" && isSSH(eps, l.Port)) {
			continue
		}
		if v, _ := after.Verdict(l.Proto, addr, l.Port); v != sysinfo.VerdictBlocked {
			continue
		}
		seen[key] = true
		u := uses[key]
		if u.Name == "" {
			u.Name = l.Process
		}
		p.Blocked = append(p.Blocked, PlannedPort{Key: key, Use: u.Name, Owner: u.Owner, Suggest: u.Suggest || u.Owner != ""})
	}
	sort.Slice(p.Blocked, func(i, j int) bool { return p.Blocked[i].Key < p.Blocked[j].Key })
	b, _ := json.Marshal(p)
	sum := sha256.Sum256(b)
	p.SHA256 = hex.EncodeToString(sum[:])
	return p, nil
}

// sshNeedsRule reports whether an SSH port still needs an allow, judged on
// the families its endpoints listen in.
func sshNeedsRule(fw sysinfo.Firewall, eps []Endpoint, port int) bool {
	for _, e := range eps {
		if e.Port != port {
			continue
		}
		addr := netip.IPv4Unspecified()
		if e.Family == "v6" {
			addr = netip.IPv6Unspecified()
		}
		if e.Addr.IsValid() {
			addr = e.Addr
		}
		if fw.NeedsRule("tcp", addr, port) {
			return true
		}
	}
	return false
}

func isSSH(eps []Endpoint, port int) bool {
	for _, e := range eps {
		if e.Port == port {
			return true
		}
	}
	return false
}

// sshRules are the allows an enable adds first: each SSH port from anywhere.
func sshRules(eps []Endpoint) []sysinfo.Rule {
	var out []sysinfo.Rule
	seen := map[int]bool{}
	for _, e := range eps {
		if seen[e.Port] {
			continue
		}
		seen[e.Port] = true
		r, _ := AllowRule(AllowAsk{Proto: "tcp", From: e.Port})
		out = append(out, r)
	}
	return out
}

// simulated is fw turned on with its default deny and the extra allows added
// last, kept for good: what the guard and the plan judge.
func simulated(fw sysinfo.Firewall, extra []sysinfo.Rule) sysinfo.Firewall {
	out := fw
	out.Active = true
	if fw.Default != "deny" && fw.Default != "reject" {
		out.Default = "deny"
	}
	out.Rules = nil
	last4, last6 := 0, 0
	for _, r := range fw.Rules {
		if r.Permanent {
			r.Runtime = true
			out.Rules = append(out.Rules, r)
			last4, last6 = max(last4, r.Seq4), max(last6, r.Seq6)
		}
	}
	for _, r := range extra {
		last4++
		last6++
		r.Runtime, r.Permanent = true, true
		switch r.Family {
		case "v4":
			r.Seq4 = last4
		case "v6":
			r.Seq6 = last6
		default:
			r.Seq4, r.Seq6 = last4, last6
		}
		r = fw.Kept(r)
		switch r.Family {
		case "v4":
			r.Seq6 = 0
		case "v6":
			r.Seq4 = 0
		}
		r.ID = identityOf(r)
		out.Rules = append(out.Rules, r)
	}
	return out
}

// EnableAsk is sys.firewall.enable's parameter.
type EnableAsk struct {
	Plan  string   `json:"plan"`  // the plan's sha256
	Allow []string `json:"allow"` // the plan's port keys to allow
}

// Armed is an enable's answer: when it is undone unless confirmed.
type Armed struct {
	Firewall  sysinfo.Firewall `json:"firewall"`
	ConfirmBy int64            `json:"confirm_by"` // Unix seconds
}

// Enable turns the firewall on as the plan said: the missing SSH allows, the
// ticked ones (an owner's as its rows), the default deny, the undo timer, and
// the enable. A step that fails undoes the ones before it.
//
// Decision: docs/decisions/firewall.md#enabling
func (m *Module) Enable(ctx context.Context, a EnableAsk) (Armed, error) {
	unlock, err := m.change(ctx)
	if err != nil {
		return Armed{}, err
	}
	defer unlock()
	if m.host.UndoArmed(ctx) {
		return Armed{}, ErrUndoArmed
	}
	plan, err := m.Plan(ctx)
	if err != nil {
		return Armed{}, err
	}
	if plan.SHA256 != a.Plan {
		return Armed{}, ErrChanged
	}
	fw, err := m.host.Read(ctx)
	if err != nil {
		return Armed{}, err
	}
	switch {
	case !managed(fw):
		return Armed{}, m.unmanaged(fw, nil)
	case fw.Active:
		return Armed{}, ErrActive
	case !plan.Complete:
		return Armed{}, &Instructed{Err: ErrLockoutUnknown, Commands: m.host.Commands(fw, Change{Allow: sshRules(plan.SSH), Enable: true})}
	}
	planned := map[string]PlannedPort{}
	for _, p := range plan.Blocked {
		planned[p.Key] = p
	}
	type add struct {
		rule  sysinfo.Rule
		owner string
	}
	var adds []add
	for _, r := range sshRules(plan.SSH) {
		if sshNeedsRule(fw, plan.SSH, r.From) {
			adds = append(adds, add{rule: r})
		}
	}
	for _, key := range a.Allow {
		p, ok := planned[key]
		if !ok {
			return Armed{}, ErrNotPlanned
		}
		proto, port, _ := strings.Cut(key, "/")
		n, _ := strconv.Atoi(port)
		r, err := AllowRule(AllowAsk{Proto: proto, From: n})
		if err != nil {
			return Armed{}, err
		}
		adds = append(adds, add{rule: r, owner: p.Owner})
	}
	var extra []sysinfo.Rule
	for _, x := range adds {
		extra = append(extra, x.rule)
	}
	if err := m.guard(ctx, simulated(fw, extra), nil); err != nil {
		return Armed{}, &Instructed{Err: err, Commands: m.host.Commands(fw, Change{Allow: extra, Enable: true})}
	}

	var undo []func(context.Context) error
	fail := func(err error) (Armed, error) {
		bg := context.WithoutCancel(ctx)
		for i := len(undo) - 1; i >= 0; i-- {
			if uerr := undo[i](bg); uerr != nil {
				m.log.Warn("firewall: undoing an enable that failed", "err", uerr)
			}
		}
		return Armed{}, err
	}
	for _, x := range adds {
		id := identityOn(fw, x.rule)
		if x.owner != "" {
			if err := m.store.PutFirewallRow(ctx, Row{ID: id, Owner: x.owner, Rule: x.rule, State: StateOpening, CreatedAt: m.now().Unix()}); err != nil {
				return fail(err)
			}
			undo = append(undo, func(ctx context.Context) error { return m.store.DeleteFirewallRow(ctx, id) })
		}
		kept, err := m.allowAndCheck(ctx, fw, x.rule)
		if err != nil {
			return fail(err)
		}
		undo = append(undo, func(ctx context.Context) error {
			now, err := m.host.Read(ctx)
			if err != nil {
				return err
			}
			if got, there := find(now, id); there {
				return m.host.Revoke(ctx, now, got)
			}
			return nil
		})
		if x.owner != "" { // the row holds the rule as the manager keeps it (C2)
			if err := m.store.PutFirewallRow(ctx, Row{ID: id, Owner: x.owner, Rule: kept, State: StateOpen, CreatedAt: m.now().Unix()}); err != nil {
				return fail(err)
			}
		}
	}
	previous := fw.Default
	if fw.Default != "deny" && fw.Default != "reject" {
		prev, err := m.host.Default(ctx, fw, "deny")
		if err != nil {
			return fail(err)
		}
		previous = prev
		undo = append(undo, func(ctx context.Context) error { _, err := m.host.Default(ctx, fw, prev); return err })
	}
	if err := m.host.ArmUndo(ctx, fw, previous, UndoAfter); err != nil {
		return fail(err)
	}
	undo = append(undo, m.host.DisarmUndo)
	if err := m.host.Enable(ctx, fw, true); err != nil {
		return fail(err)
	}
	on, err := m.host.Read(ctx)
	if err != nil || !on.Active {
		_ = m.host.Enable(context.WithoutCancel(ctx), fw, false)
		if err == nil {
			err = ErrNotApplied
		}
		return fail(err)
	}
	m.enabledBy, m.armedAt = module.LoginOf(ctx), m.now()
	if m.enabledBy == (module.Login{}) {
		m.enabledBy = module.Login{Session: "console"}
	}
	fw, err = m.Read(ctx)
	return Armed{Firewall: fw, ConfirmBy: m.armedAt.Add(UndoAfter).Unix()}, err
}

// Confirm keeps an enable: it must come from another login than the one
// that enabled, and over SSH when the enable came over SSH, since what it
// proves is that a new SSH login gets in.
//
// Decision: docs/decisions/firewall.md#enabling
func (m *Module) Confirm(ctx context.Context) (sysinfo.Firewall, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.host.UndoArmed(ctx) || m.enabledBy == (module.Login{}) {
		return sysinfo.Firewall{}, ErrNotArmed
	}
	me := module.LoginOf(ctx)
	switch {
	case me.Session != "" && me.Session == m.enabledBy.Session:
		return sysinfo.Firewall{}, ErrSameLogin
	case me.Session == "" && m.enabledBy.Session == "console":
		return sysinfo.Firewall{}, ErrSameLogin
	case m.enabledBy.From.IsValid() && !me.From.IsValid():
		return sysinfo.Firewall{}, ErrConfirmBySSH
	}
	if err := m.host.DisarmUndo(ctx); err != nil {
		return sysinfo.Firewall{}, err
	}
	m.enabledBy = module.Login{}
	fw, err := m.Read(ctx)
	if err == nil && !fw.Active {
		return fw, ErrNotArmed // the timer fired before the confirm reached it
	}
	return fw, err
}

// Disable turns the firewall off, and stops an undo timer that waits.
func (m *Module) Disable(ctx context.Context) (sysinfo.Firewall, error) {
	unlock, err := m.change(ctx)
	if err != nil {
		return sysinfo.Firewall{}, err
	}
	defer unlock()
	fw, err := m.host.Read(ctx)
	if err != nil {
		return fw, err
	}
	if !managed(fw) {
		return fw, m.unmanaged(fw, nil)
	}
	if m.host.UndoArmed(ctx) {
		if err := m.host.DisarmUndo(ctx); err != nil {
			return fw, err
		}
		m.enabledBy = module.Login{}
	}
	if fw.Active {
		if err := m.host.Enable(ctx, fw, false); err != nil {
			return fw, err
		}
	}
	return m.Read(ctx)
}
