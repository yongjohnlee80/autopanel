// Package forward is port forwarding: a public port of the host, or a small
// range, sent on to a target through the gate. The rules are here; the gate
// carries the bytes (host/gate/stream.go), and the store keeps the list.
//
// A forward is refused when it would take a port something else holds, move
// or shadow the way in to the host (SSH), or point at a port only the gate
// may reach (mail's inner ports, whose server believes what the gate writes).
//
// Decision: docs/decisions/forwards.md
package forward

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"

	corefw "github.com/yongjohnlee80/autopanel/core/firewall"
	"github.com/yongjohnlee80/autopanel/internal/module"
	"github.com/yongjohnlee80/autopanel/internal/tunnel"
)

// The limits of forwarding. They are small on purpose: every forwarded
// connection is held in the gate's memory beside mail's and the sites'.
const (
	MaxForwards   = 16  // forwards in all
	MaxRange      = 100 // ports in one forward
	MaxPorts      = 128 // public ports over every forward
	Connections   = 64  // forwarded connections at once, every forward together
	minShare      = 4   // the least of them one forward gets
	DefaultIdle   = 600 // seconds a silent connection is kept
	DefaultClient = 8   // connections at once from one client
	maxClient     = 64
	maxIdle       = 24 * 3600
	maxAllow      = 16
)

// Forward is one port forward.
type Forward struct {
	ID        int64
	Name      string   // lower case letters, digits and hyphens: its firewall rule's owner is "forward:<name>"
	Proto     string   // "tcp" or "udp"
	From, To  int      // the public port, or a range; To == From for one
	Target    string   // a literal address and port: "127.0.0.1:25565"; a range keeps its ports from there
	Proxy     bool     // tcp only: each connection starts with a PROXY v2 header naming the client
	Allow     []string // source prefixes; none: any address
	PerClient int      // connections (tcp) or pairings (udp) at once from one client; 0: the default
	IdleSecs  int      // 0: the default (ten minutes for tcp, one for udp)
}

// Tunnelled reports whether f's target is behind a tunnel agent.
func (f Forward) Tunnelled() bool { return strings.HasPrefix(f.Target, tunnel.Scheme) }

func orDefault(n, d int) int {
	if n == 0 {
		return d
	}
	return n
}

// Ports is how many public ports f holds.
func (f Forward) Ports() int { return f.To - f.From + 1 }

// Want is the firewall opening of f's public ports.
func (f Forward) Want() corefw.Want { return corefw.Want{Proto: f.Proto, From: f.From, To: f.To} }

// Owner is the owner of f's firewall rule.
func (f Forward) Owner() string { return corefw.ForwardOwner(f.Name) }

var (
	ErrNotFound  = errors.New("forward: no such forward")
	ErrDuplicate = errors.New("forward: a forward has that name")
	ErrBadName   = errors.New("forward: a name is 1 to 32 lower-case letters, digits and hyphens, starting with a letter")
	ErrBadProto  = errors.New("forward: the protocol is tcp or udp, and only tcp carries a PROXY header")
	ErrBadPorts  = errors.New("forward: a public port is 1 to 65535, and a range at most 100 ports")
	ErrBadTarget = errors.New("forward: a target is a literal address and a port, of an address a connection can be made to")
	ErrBadAllow  = errors.New("forward: an allowed source must be an address prefix")
	ErrBadLimits = errors.New("forward: a limit is out of range")
	ErrPortTaken = errors.New("forward: a public port is in use")
	ErrSSH       = errors.New("forward: SSH's own port is never forwarded, and no forward leads to this host's SSH")
	ErrInner     = errors.New("forward: the target is a port only AutoPanel's gate may reach")
	ErrLoop      = errors.New("forward: the target is a port the gate itself listens on")
	ErrTooMany   = errors.New("forward: no room for another forward")
	ErrChanged   = errors.New("forward: the host changed since the review")
	ErrUnknown   = errors.New("forward: what listens on this host could not be read, so nothing was changed")
)

// Store is where forwards are kept.
type Store interface {
	All(ctx context.Context) ([]Forward, error) // by name
	Add(ctx context.Context, f Forward) (Forward, error)
	Update(ctx context.Context, f Forward) (Forward, error)
	Remove(ctx context.Context, id int64) (Forward, error)
}

// Listener is a port something on the host listens on.
type Listener struct {
	Proto   string // "tcp" or "udp"
	Port    int
	Process string // who holds it, for the refusal's words
}

// Host is what a change must know of the machine, read when it is made.
type Host interface {
	// Listeners are the TCP and UDP ports in use on the host, the gate's included.
	Listeners(ctx context.Context) ([]Listener, error)
	// SSHPorts are the ports SSH listens on. complete is false when a
	// listener of SSH's could not be explained: then nothing is changed.
	SSHPorts(ctx context.Context) (ports []int, complete bool, err error)
	// Local reports whether addr is an address of this host: loopback, or
	// one of its interfaces'.
	Local(addr netip.Addr) bool
}

// Reserved are the ports AutoPanel holds itself, read at every check.
type Reserved struct {
	// Public are public ports with their holder's name: the gate's two
	// listeners, mail's ports.
	Public map[int]string
	// Inner are ports on this host that only the gate may reach: mail's
	// loopback ports and its management port.
	Inner map[int]string
}

// Firewall is the host's firewall, as an owner of rules uses it.
type Firewall interface {
	Review(ctx context.Context, owner string, wants []corefw.Want) ([]corefw.PortState, error)
	Open(ctx context.Context, owner string, wants []corefw.Want) error
	Close(ctx context.Context, owner string, wants []corefw.Want) error
}

// Module is gate.forward.*.
type Module struct {
	store    Store
	host     Host
	reserved func() Reserved
	reload   func(ctx context.Context) error // the gate is told
	firewall Firewall                        // nil: no firewall to ask
	mu       sync.Mutex                      // one change at a time
	stored   []Forward                       // the list as the review in hand read it; mu's
}

// NewModule returns the forward verbs. reload sends the gate the list.
func NewModule(store Store, host Host, reserved func() Reserved, reload func(ctx context.Context) error) *Module {
	return &Module{store: store, host: host, reserved: reserved, reload: reload}
}

// SetReload names how the gate is told. Set once, before the verbs are
// served, when the module had to exist first.
func (m *Module) SetReload(reload func(ctx context.Context) error) { m.reload = reload }

// SetFirewall gives the forwards the firewall. Set once, before the verbs are
// served.
func (m *Module) SetFirewall(f Firewall) { m.firewall = f }

func (m *Module) Name() string { return "forward" }

func (m *Module) Errors() []module.PublicError {
	return []module.PublicError{
		{Err: ErrNotFound, Code: -32250, Name: "gate.forward.not_found", Message: "no such forward"},
		{Err: ErrDuplicate, Code: -32251, Name: "gate.forward.duplicate", Message: "a forward has that name"},
		{Err: ErrBadName, Code: -32252, Name: "gate.forward.bad_name", Message: "a name is 1 to 32 lower-case letters, digits and hyphens, starting with a letter"},
		{Err: ErrBadProto, Code: -32253, Name: "gate.forward.bad_proto", Message: "the protocol is tcp or udp; only a tcp forward carries a PROXY header, and a forward through a tunnel is tcp with none"},
		{Err: ErrBadPorts, Code: -32254, Name: "gate.forward.bad_ports", Message: "a public port is 1 to 65535, a range at most 100 ports, and a forward through a tunnel one port"},
		{Err: ErrBadTarget, Code: -32255, Name: "gate.forward.bad_target", Message: "a target is a literal address and port, such as 127.0.0.1:8080 (not a host name, and not an address no connection can be made to), or tunnel://<agent>/<target>"},
		{Err: ErrBadAllow, Code: -32256, Name: "gate.forward.bad_allow", Message: "an allowed source must be an address prefix, such as 203.0.113.0/24"},
		{Err: ErrBadLimits, Code: -32257, Name: "gate.forward.bad_limits", Message: "a limit is out of range"},
		{Err: ErrPortTaken, Code: -32258, Name: "gate.forward.port_taken", Message: "a public port is in use"},
		{Err: ErrSSH, Code: -32259, Name: "gate.forward.ssh", Message: "SSH's own port is never forwarded, and no forward leads to this host's SSH"},
		{Err: ErrInner, Code: -32260, Name: "gate.forward.inner", Message: "the target is a port only AutoPanel's gate may reach"},
		{Err: ErrLoop, Code: -32261, Name: "gate.forward.loop", Message: "the target is a port the gate itself listens on"},
		{Err: ErrTooMany, Code: -32262, Name: "gate.forward.too_many", Message: "no room for another forward"},
		{Err: ErrChanged, Code: -32263, Name: "gate.forward.changed", Message: "the host changed since the review; review it again"},
		{Err: ErrUnknown, Code: -32264, Name: "gate.forward.unknown", Message: "what listens on this host could not be read, so nothing was changed"},
	}
}

// View is a forward as a client sees it.
type View struct {
	ID        int64    `json:"id"`
	Name      string   `json:"name"`
	Proto     string   `json:"proto"`
	From      int      `json:"from"`
	To        int      `json:"to"`
	Target    string   `json:"target"`
	Proxy     bool     `json:"proxy"`
	Allow     []string `json:"allow"`
	PerClient int      `json:"per_client"`
	IdleSecs  int      `json:"idle_secs"`
}

func view(f Forward) View {
	return View{ID: f.ID, Name: f.Name, Proto: f.Proto, From: f.From, To: f.To, Target: f.Target, Proxy: f.Proxy,
		Allow: append([]string{}, f.Allow...), PerClient: f.PerClient, IdleSecs: f.IdleSecs}
}

// Spec is a forward as a client writes it. ID is set only to update; To
// defaults to From.
type Spec struct {
	ID        int64    `json:"id,omitempty"`
	Name      string   `json:"name"`
	Proto     string   `json:"proto,omitempty"`
	From      int      `json:"from"`
	To        int      `json:"to,omitempty"`
	Target    string   `json:"target"`
	Proxy     bool     `json:"proxy,omitempty"`
	Allow     []string `json:"allow,omitempty"`
	PerClient int      `json:"per_client,omitempty"`
	IdleSecs  int      `json:"idle_secs,omitempty"`
}

// Review is what a forward would be, and its public port's state in the
// firewall. Nothing is changed by it; a change is applied with its sha256.
type Review struct {
	Forward View               `json:"forward"`
	Ports   []corefw.PortState `json:"ports"`
	SHA256  string             `json:"sha256"`
}

// Apply is gate.forward.add's and gate.forward.update's param: the forward,
// the review it was shown as, and whether to open its port in the firewall.
type Apply struct {
	Spec
	Accept string `json:"accept"`
	Open   bool   `json:"open,omitempty"`
}

// Ref names one forward.
type Ref struct {
	ID int64 `json:"id"`
}

func (m *Module) Verbs() []module.Verb {
	return []module.Verb{
		module.Handle(module.Contract{Verb: "gate.forward.list", Area: "gate", Discloses: module.Plain, Since: 9,
			Result: "[{id, name, proto, from, to, target, proxy, allow, per_client, idle_secs}]",
			Doc:    "Every port forward, by name."}, m.list),
		module.Handle(module.Contract{Verb: "gate.forward.check", Area: "gate", Discloses: module.Plain, Since: 9,
			Param: "{id?, name, proto?, from, to?, target, proxy?, allow?, per_client?, idle_secs?}", Result: "{forward, ports: [{key, verdict, why, needs, by, managed, commands}], sha256}",
			Doc: "What a forward would be, or why it is refused, and its public port's state in the firewall. Changes nothing."}, m.check),
		module.Handle(module.Contract{Verb: "gate.forward.add", Area: "gate", Mutates: true, Privileged: true, Since: 9,
			Param: "{name, proto?, from, to?, target, proxy?, allow?, per_client?, idle_secs?, accept, open?}", Result: "the forward",
			Doc: "Adds a forward as gate.forward.check showed it (accept is its sha256) and forwards its port at once; with open, its port is opened in the firewall as the forward's own rule."}, m.add),
		module.Handle(module.Contract{Verb: "gate.forward.update", Area: "gate", Mutates: true, Privileged: true, Since: 9,
			Param: "{id, name, proto?, from, to?, target, proxy?, allow?, per_client?, idle_secs?, accept, open?}", Result: "the forward",
			Doc: "Replaces a forward's ports, target and limits; its name stays. The firewall rule follows its ports."}, m.update),
		module.Handle(module.Contract{Verb: "gate.forward.remove", Area: "gate", Mutates: true, Privileged: true, Since: 9, Param: "{id}", Result: "the forward",
			Doc: "Removes a forward: its port stops being forwarded, and the firewall rule it owned is closed."}, m.remove),
	}
}

// Normalize is s as a forward in canonical form, or why it cannot be one.
// It reads nothing of the host.
func Normalize(s Spec) (Forward, error) {
	f := Forward{ID: s.ID, Name: s.Name, Proto: s.Proto, From: s.From, To: s.To, Proxy: s.Proxy, PerClient: s.PerClient, IdleSecs: s.IdleSecs}
	if !validName(f.Name) {
		return Forward{}, ErrBadName
	}
	if f.Proto == "" {
		f.Proto = "tcp"
	}
	if (f.Proto != "tcp" && f.Proto != "udp") || (f.Proto == "udp" && f.Proxy) {
		return Forward{}, ErrBadProto
	}
	if f.To == 0 {
		f.To = f.From
	}
	if f.From < 1 || f.To > 65535 || f.To < f.From || f.Ports() > MaxRange {
		return Forward{}, ErrBadPorts
	}
	if target := strings.TrimSpace(s.Target); strings.HasPrefix(target, tunnel.Scheme) {
		// A service behind a tunnel agent: one TCP port, to the one target
		// the agent's file names. The agent cannot be told who the client is,
		// so there is no PROXY header to ask for.
		if _, _, ok := tunnel.ParseAddress(target); !ok {
			return Forward{}, ErrBadTarget
		}
		if f.Proto != "tcp" || f.Proxy {
			return Forward{}, ErrBadProto
		}
		if f.Ports() != 1 {
			return Forward{}, ErrBadPorts
		}
		f.Target = target
	} else {
		t, err := netip.ParseAddrPort(target)
		if err != nil || t.Port() == 0 || int(t.Port())+f.Ports()-1 > 65535 || !reachable(t.Addr()) {
			return Forward{}, ErrBadTarget
		}
		f.Target = netip.AddrPortFrom(t.Addr().Unmap(), t.Port()).String()
	}
	if len(s.Allow) > maxAllow {
		return Forward{}, ErrBadAllow
	}
	for _, a := range s.Allow {
		p, err := netip.ParsePrefix(strings.TrimSpace(a))
		if err != nil {
			return Forward{}, ErrBadAllow
		}
		f.Allow = append(f.Allow, p.Masked().String())
	}
	sort.Strings(f.Allow)
	if f.PerClient < 0 || f.PerClient > maxClient || f.IdleSecs < 0 || f.IdleSecs > maxIdle {
		return Forward{}, ErrBadLimits
	}
	return f, nil
}

func validName(n string) bool {
	if n == "" || len(n) > 32 || n[0] < 'a' || n[0] > 'z' {
		return false
	}
	for _, c := range n {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// reachable reports whether a is an address a target may have: one of the
// ranges ordinary hosts live in, and nothing else. For IPv4, any unicast
// address outside 0.0.0.0/8 ("this network") and 240.0.0.0/4 (reserved, and
// broadcast). For IPv6, loopback, the unique local range, and global unicast
// (2000::/3). Link-local, where a cloud's metadata service lives, multicast
// and the unspecified address are out, and so is every special or
// translation prefix (::/96, 64:ff9b::/96): an address the kernel may turn
// into another is not one this check can vouch for.
func reachable(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || a.IsUnspecified() || a.IsMulticast() || a.IsLinkLocalUnicast() ||
		a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast() {
		return false
	}
	if a.Is4() {
		b := a.As4()
		return b[0] != 0 && b[0] < 240
	}
	return a.IsLoopback() || a.IsPrivate() || a.As16()[0]&0xe0 == 0x20
}

// refused is a refusal with the port and who holds it, for the caller.
type refused struct {
	err  error
	what string
}

func (e *refused) Error() string        { return e.err.Error() + ": " + e.what }
func (e *refused) Unwrap() error        { return e.err }
func (e *refused) PublicDetail() string { return e.what }

func refuse(err error, format string, args ...any) error {
	return &refused{err: err, what: fmt.Sprintf(format, args...)}
}

// judge holds f against the host and the other forwards: the refusals that
// need facts. others are every stored forward but f itself.
func (m *Module) judge(ctx context.Context, f Forward, others []Forward) error {
	if len(others)+1 > MaxForwards {
		return refuse(ErrTooMany, "at most %d forwards", MaxForwards)
	}
	ports := f.Ports()
	for _, o := range others {
		if o.Name == f.Name {
			return ErrDuplicate
		}
		ports += o.Ports()
	}
	if ports > MaxPorts {
		return refuse(ErrTooMany, "at most %d public ports over every forward", MaxPorts)
	}
	res := m.reserved()
	ssh, complete, err := m.host.SSHPorts(ctx)
	if err != nil || !complete {
		return ErrUnknown // an SSH listener nobody can explain may be the one the administrator is on
	}
	listeners, err := m.host.Listeners(ctx)
	if err != nil {
		return ErrUnknown
	}
	// SSH, the gate's listeners and mail's ports are TCP: a UDP forward on
	// the same number takes nothing of theirs.
	tcp := f.Proto == "tcp"
	public := func(p int) bool { return p >= f.From && p <= f.To }
	if tcp {
		for _, p := range ssh {
			if public(p) {
				return refuse(ErrSSH, "tcp/%d is SSH's", p)
			}
		}
		for p, who := range res.Public {
			if public(p) {
				return refuse(ErrPortTaken, "tcp/%d is %s's", p, who)
			}
		}
	}
	for _, o := range others {
		if o.Proto == f.Proto && o.From <= f.To && f.From <= o.To {
			return refuse(ErrPortTaken, "the forward %s holds %s/%d", o.Name, f.Proto, max(o.From, f.From))
		}
	}
	// A port this very forward already holds is the gate's listener for it:
	// not somebody else's.
	mine := func(p int) bool {
		for _, o := range m.stored {
			if o.ID == f.ID && f.ID != 0 && o.Proto == f.Proto && p >= o.From && p <= o.To {
				return true
			}
		}
		return false
	}
	for _, l := range listeners {
		if l.Proto == f.Proto && public(l.Port) && !mine(l.Port) {
			return refuse(ErrPortTaken, "%s listens on %s/%d", orSomething(l.Process), f.Proto, l.Port)
		}
	}

	if f.Tunnelled() {
		return nil // where it leads is the agent's file's to say, on the agent's machine
	}
	t := netip.MustParseAddrPort(f.Target)
	if m.host.Local(t.Addr()) {
		first, last := int(t.Port()), int(t.Port())+f.Ports()-1
		target := func(p int) bool { return p >= first && p <= last }
		if tcp {
			for _, p := range ssh {
				if target(p) {
					return refuse(ErrSSH, "tcp/%d on this host is SSH", p)
				}
			}
			for p, who := range res.Inner {
				if target(p) {
					return refuse(ErrInner, "tcp/%d is %s's", p, who)
				}
			}
			for p := range res.Public {
				if target(p) {
					return refuse(ErrLoop, "tcp/%d", p)
				}
			}
		}
		for _, o := range append(others, f) {
			if o.Proto == f.Proto && o.From <= last && first <= o.To {
				return refuse(ErrLoop, "%s/%d is the forward %s's own public port", f.Proto, max(o.From, first), o.Name)
			}
		}
	}
	return nil
}

func orSomething(process string) string {
	if process == "" {
		return "another program"
	}
	return process
}

// review judges s and answers what it would be. The caller holds m.mu.
func (m *Module) review(ctx context.Context, s Spec) (Forward, Review, error) {
	f, err := Normalize(s)
	if err != nil {
		return Forward{}, Review{}, err
	}
	all, err := m.store.All(ctx)
	if err != nil {
		return Forward{}, Review{}, err
	}
	m.stored = all
	var others []Forward
	found := f.ID == 0
	for _, o := range all {
		if o.ID == f.ID && f.ID != 0 {
			found = true
			if o.Name != f.Name {
				return Forward{}, Review{}, refuse(ErrBadName, "a forward keeps its name: %s", o.Name)
			}
			continue
		}
		others = append(others, o)
	}
	if !found {
		return Forward{}, Review{}, ErrNotFound
	}
	if err := m.judge(ctx, f, others); err != nil {
		return Forward{}, Review{}, err
	}
	out := Review{Forward: view(f), Ports: []corefw.PortState{}}
	if m.firewall != nil {
		if out.Ports, err = m.firewall.Review(ctx, f.Owner(), []corefw.Want{f.Want()}); err != nil {
			return Forward{}, Review{}, err
		}
	}
	out.SHA256 = digest(out)
	return f, out, nil
}

// digest is what a review's acceptance names: the forward, and each port's
// verdict and whether AutoPanel would open it.
func digest(r Review) string {
	type port struct {
		Key, Verdict string
		Needs        bool
		By           string
		Managed      bool
	}
	ps := make([]port, 0, len(r.Ports))
	for _, p := range r.Ports {
		ps = append(ps, port{p.Key, p.Verdict, p.Needs, p.By, p.Managed})
	}
	b, _ := json.Marshal(struct {
		F View
		P []port
	}{r.Forward, ps})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func (m *Module) list(ctx context.Context, _ struct{}) ([]View, error) {
	all, err := m.store.All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]View, 0, len(all))
	for _, f := range all {
		out = append(out, view(f))
	}
	return out, nil
}

func (m *Module) check(ctx context.Context, s Spec) (Review, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, r, err := m.review(ctx, s)
	return r, err
}

func (m *Module) add(ctx context.Context, p Apply) (View, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p.ID = 0
	f, r, err := m.review(ctx, p.Spec)
	switch {
	case err != nil:
		return View{}, err
	case p.Accept != r.SHA256:
		return View{}, ErrChanged
	}
	made, err := m.store.Add(ctx, f)
	if err != nil {
		return View{}, err
	}
	if p.Open && m.firewall != nil {
		if err := m.firewall.Open(ctx, f.Owner(), []corefw.Want{f.Want()}); err != nil {
			// The whole change or none of it: a forward whose port the
			// administrator asked to be opened, and is not, is not added.
			_, _ = m.store.Remove(context.WithoutCancel(ctx), made.ID)
			_ = m.firewall.Close(context.WithoutCancel(ctx), f.Owner(), nil)
			return View{}, err
		}
	}
	return view(made), m.reload(ctx) // after the commit only
}

func (m *Module) update(ctx context.Context, p Apply) (View, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p.ID == 0 {
		return View{}, ErrNotFound
	}
	f, r, err := m.review(ctx, p.Spec)
	switch {
	case err != nil:
		return View{}, err
	case p.Accept != r.SHA256:
		return View{}, ErrChanged
	}
	var old Forward
	for _, o := range m.stored {
		if o.ID == f.ID {
			old = o
		}
	}
	moved := old.From != f.From || old.To != f.To
	opened := p.Open && m.firewall != nil
	if opened {
		if err := m.firewall.Open(ctx, f.Owner(), []corefw.Want{f.Want()}); err != nil {
			return View{}, err
		}
	}
	out, err := m.store.Update(ctx, f)
	if err != nil {
		if opened && moved { // nothing stored: the port just opened is closed again
			_ = m.firewall.Close(context.WithoutCancel(ctx), f.Owner(), []corefw.Want{f.Want()})
		}
		return View{}, err
	}
	// The gate first: it binds the new ports and lets the old ones go before
	// the old ports' rule is closed, as a removal does.
	if err := m.reload(ctx); err != nil {
		return view(out), err
	}
	if moved && m.firewall != nil {
		if err := m.firewall.Close(ctx, f.Owner(), []corefw.Want{old.Want()}); err != nil {
			return view(out), err
		}
	}
	return view(out), nil
}

func (m *Module) remove(ctx context.Context, ref Ref) (View, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, err := m.store.Remove(ctx, ref.ID)
	if err != nil {
		return View{}, err
	}
	if err := m.reload(ctx); err != nil { // the port stops being forwarded first
		return view(f), err
	}
	if m.firewall != nil {
		if err := m.firewall.Close(ctx, f.Owner(), nil); err != nil {
			return view(f), err
		}
	}
	return view(f), nil
}

// Stream is one public port of a forward, as the gate carries it.
type Stream struct {
	Name      string // "forward:<name>": the limits are the forward's, over all its ports
	Listen    string // ":25565"
	To        string // "127.0.0.1:25565"
	IdleSecs  int
	PerClient int
	Share     int    // tcp: connections at once for the forward
	Proto     string // "tcp" or "udp"
	Plain     bool   // tcp: no PROXY header
	Allow     string // source prefixes, separated by spaces
}

// Streams are every stored forward as the gate's streams: a stream a public
// port, each forward with an equal share of Connections.
func (m *Module) Streams(ctx context.Context) ([]Stream, error) {
	all, err := m.store.All(ctx)
	if err != nil {
		return nil, err
	}
	return StreamsOf(all), nil
}

// StreamsOf is fs as streams. The TCP forwards share Connections equally; a
// UDP forward's limits are the gate's, over every UDP stream together.
func StreamsOf(fs []Forward) []Stream {
	tcp := 0
	for _, f := range fs {
		if f.Proto == "tcp" {
			tcp++
		}
	}
	var out []Stream
	for _, f := range fs {
		if f.Tunnelled() {
			out = append(out, Stream{Name: f.Owner(), Proto: "tcp", Listen: ":" + strconv.Itoa(f.From), To: f.Target, Plain: true,
				Share: max(Connections/tcp, minShare), IdleSecs: orDefault(f.IdleSecs, DefaultIdle), PerClient: orDefault(f.PerClient, DefaultClient),
				Allow: strings.Join(f.Allow, " ")})
			continue
		}
		t := netip.MustParseAddrPort(f.Target)
		s := Stream{Name: f.Owner(), Proto: f.Proto, IdleSecs: f.IdleSecs, PerClient: f.PerClient, Allow: strings.Join(f.Allow, " ")}
		if f.Proto == "tcp" {
			s.Share, s.Plain = max(Connections/tcp, minShare), !f.Proxy
			if s.IdleSecs == 0 {
				s.IdleSecs = DefaultIdle
			}
			if s.PerClient == 0 {
				s.PerClient = DefaultClient
			}
		}
		for i := 0; i < f.Ports(); i++ {
			s.Listen = ":" + strconv.Itoa(f.From+i)
			s.To = netip.AddrPortFrom(t.Addr(), t.Port()+uint16(i)).String()
			out = append(out, s)
		}
	}
	return out
}
