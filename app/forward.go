package app

import (
	"context"
	"net"
	"net/netip"
	"slices"

	corefw "github.com/yongjohnlee80/autopanel/core/firewall"
	"github.com/yongjohnlee80/autopanel/core/forward"
	"github.com/yongjohnlee80/autopanel/core/mail"
	hostgate "github.com/yongjohnlee80/autopanel/host/gate"
)

// PORT FORWARDS — the forwards' rules (core/forward) on this host: what
// listens here, where SSH is, which addresses are the host's own, the ports
// AutoPanel holds itself, and the gate's streams the forwards become.
//
// Decision: docs/decisions/forwards.md

// forwardHost is forward.Host on this machine.
type forwardHost struct{ fw corefw.Host }

func (forwardHost) Listeners(ctx context.Context) ([]forward.Listener, error) {
	ls, err := readListeners(ctx)
	if err != nil {
		return nil, err
	}
	var out []forward.Listener
	for _, l := range ls {
		if l.Proto == "tcp" || l.Proto == "udp" {
			out = append(out, forward.Listener{Proto: l.Proto, Port: l.Port, Process: l.Process})
		}
	}
	return out, nil
}

// SSHPorts are the ports SSH listens on, as the firewall's lockout guard
// finds them: from sshd's configuration, its socket unit and the listeners.
func (h forwardHost) SSHPorts(ctx context.Context) ([]int, bool, error) {
	ls, err := readListeners(ctx)
	if err != nil {
		return nil, false, err
	}
	eps, complete := corefw.Endpoints(h.fw.SSHFacts(ctx, ls))
	var ports []int
	for _, e := range eps {
		if !slices.Contains(ports, e.Port) {
			ports = append(ports, e.Port)
		}
	}
	return ports, complete, nil
}

// interfaceAddrs is the host's own addresses; a test gives its own.
var interfaceAddrs = net.InterfaceAddrs

// Local reports whether addr is this host's: loopback, or an interface's. An
// interface list that cannot be read makes every address local: the stricter
// answer.
func (forwardHost) Local(addr netip.Addr) bool {
	addr = addr.Unmap()
	if addr.IsLoopback() {
		return true
	}
	addrs, err := interfaceAddrs()
	if err != nil {
		return true
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(ipn.IP); ok && ip.Unmap() == addr {
				return true
			}
		}
	}
	return false
}

// forwardReserved are the ports AutoPanel holds itself: the gate's two
// listeners and mail's public ports, which no forward may take; and mail's
// loopback and management ports, which no forward may lead to. Mail's are
// kept whether or not mail is set up: setting it up later must not find them
// taken.
func forwardReserved(cfg Config) func() forward.Reserved {
	return func() forward.Reserved {
		r := forward.Reserved{Public: map[int]string{}, Inner: map[int]string{}}
		for _, a := range []string{cfg.HTTPAddr, cfg.HTTPSAddr} {
			if p := portOf(a); p != 0 {
				r.Public[p] = "the gate"
			}
		}
		for _, p := range mail.Ports {
			r.Public[p.Public] = "mail"
			r.Inner[p.Loopback] = "mail"
		}
		r.Inner[mail.ManagePort] = "mail"
		return r
	}
}

// forwardStreams sends the gate the forwards as they are stored now.
func forwardStreams(fm *forward.Module, t *streamTable) func(ctx context.Context) error {
	return func(ctx context.Context) error {
		ss, err := fm.Streams(ctx)
		if err != nil {
			return err
		}
		out := make([]hostgate.Stream, 0, len(ss))
		for _, s := range ss {
			out = append(out, hostgate.Stream{Name: s.Name, Proto: udpOnly(s.Proto), Listen: s.Listen, To: s.To, IdleSecs: s.IdleSecs,
				PerClient: s.PerClient, Share: s.Share, Plain: s.Plain, Allow: s.Allow})
		}
		t.SetForwards(out)
		return nil
	}
}

// udpOnly is a stream's protocol as the gate takes it: "udp", or "" for TCP,
// as mail's streams have it.
func udpOnly(proto string) string {
	if proto == "udp" {
		return "udp"
	}
	return ""
}
