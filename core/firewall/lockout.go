package firewall

import (
	"errors"
	"net/netip"
	"strconv"
	"strings"

	"github.com/yongjohnlee80/autopanel/internal/module"
	"github.com/yongjohnlee80/autopanel/internal/sysinfo"
)

// ErrLockoutUnknown is a change the guard cannot judge: it refuses rather
// than guess, and the refusal carries the commands for doing it by hand.
var ErrLockoutUnknown = errors.New("firewall: whether SSH logins would still reach this host after the change cannot be told; do it by hand if you are sure")

// ErrLockout is a change that would leave the administrator's address with no
// SSH endpoint it can reach.
var ErrLockout = errors.New("firewall: the change would stop new SSH logins from your address")

// Endpoint is one address and port that takes SSH logins. The zero Addr is
// every address of Family.
type Endpoint struct {
	Family string     `json:"family"` // "v4" or "v6"
	Addr   netip.Addr `json:"addr"`
	Port   int        `json:"port"`
}

func (e Endpoint) String() string {
	a := e.Addr
	if !a.IsValid() {
		a = netip.IPv4Unspecified()
		if e.Family == "v6" {
			a = netip.IPv6Unspecified()
		}
	}
	return netip.AddrPortFrom(a, uint16(e.Port)).String()
}

// SSHFacts are the three reads the endpoints are found from.
type SSHFacts struct {
	// Socket is the Listen= values of ssh.socket and sshd.socket while one
	// is active ("0.0.0.0:22 (Stream)"); nil when neither is.
	Socket []string
	// Config is sshd -T's output: its port and listenaddress lines.
	Config string
	// Listeners are the host's TCP listeners with who holds them.
	Listeners []sysinfo.Listener
	// Families are the address families the kernel has: an IPv6 sshd -T
	// prints by default needs no listener when IPv6 is off.
	Families map[string]bool
}

// Endpoints finds the SSH endpoints three ways: the active SSH socket unit's
// addresses (a socket-activated sshd's listener is held by PID 1, so its
// holder's name says nothing), listeners held by sshd, and sshd -T's
// addresses. complete does not mean the three agree: before the first login
// on a socket-activated host, or on a socket that starts one sshd per
// connection, sshd holds nothing, and that is normal. complete means every
// endpoint found is explained by the configuration, and every configured one
// has a listener, held by sshd or by PID 1.
//
// Decision: docs/decisions/firewall.md#no-lockout
func Endpoints(f SSHFacts) (eps []Endpoint, complete bool) {
	socket := f.Socket != nil
	if socket {
		for _, l := range f.Socket {
			v, kind, _ := strings.Cut(strings.TrimSpace(l), " ")
			if kind != "" && kind != "(Stream)" {
				continue
			}
			if e, ok := endpointOf(v); ok && f.Families[e.Family] {
				eps = append(eps, e)
			}
		}
	} else {
		var ports []int
		for _, line := range strings.Split(f.Config, "\n") {
			k, v, _ := strings.Cut(strings.TrimSpace(line), " ")
			switch k {
			case "listenaddress":
				if e, ok := endpointOf(v); ok && f.Families[e.Family] {
					eps = append(eps, e)
				}
			case "port":
				if n, err := strconv.Atoi(v); err == nil {
					ports = append(ports, n)
				}
			}
		}
		if len(eps) == 0 {
			for _, p := range ports {
				for _, fam := range []string{"v4", "v6"} {
					if f.Families[fam] {
						eps = append(eps, Endpoint{Family: fam, Port: p})
					}
				}
			}
		}
	}
	if len(eps) == 0 {
		return nil, false
	}
	complete = true
	for _, l := range f.Listeners {
		if l.Proto != "tcp" || !holds(l, "sshd") {
			continue
		}
		if !explained(eps, l) {
			complete = false
		}
	}
	for _, e := range eps {
		if !heard(e, f.Listeners, socket) {
			complete = false
		}
	}
	return eps, complete
}

// endpointOf reads "0.0.0.0:22", "[::]:22", "192.0.2.1:2222".
func endpointOf(s string) (Endpoint, bool) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return Endpoint{}, false
	}
	a := ap.Addr().Unmap()
	e := Endpoint{Family: "v4", Port: int(ap.Port())}
	if a.Is6() {
		e.Family = "v6"
	}
	if !a.IsUnspecified() {
		e.Addr = a
	}
	return e, true
}

// explained reports whether an sshd listener is one of the endpoints.
func explained(eps []Endpoint, l sysinfo.Listener) bool {
	a, err := netip.ParseAddr(l.Address)
	if err != nil {
		return false
	}
	for _, e := range eps {
		if e.Port == l.Port && sameAddr(e, a.Unmap()) {
			return true
		}
	}
	return false
}

// heard reports whether an endpoint has a listener held by sshd, or by PID 1
// through an active socket unit.
func heard(e Endpoint, ls []sysinfo.Listener, socket bool) bool {
	for _, l := range ls {
		a, err := netip.ParseAddr(l.Address)
		if err != nil || l.Proto != "tcp" || l.Port != e.Port || !sameAddr(e, a.Unmap()) {
			continue
		}
		if holds(l, "sshd") || (socket && l.PID == 1) {
			return true
		}
	}
	return false
}

// holds reports whether a program of that name is among a listener's
// holders ("systemd, sshd" once a socket-activated sshd has taken over).
func holds(l sysinfo.Listener, name string) bool {
	for _, n := range strings.Split(l.Process, ", ") {
		if n == name {
			return true
		}
	}
	return false
}

func sameAddr(e Endpoint, a netip.Addr) bool {
	if !e.Addr.IsValid() {
		return a.IsUnspecified() && (a.Is4() == (e.Family == "v4"))
	}
	return e.Addr == a
}

// Safe reports whether, with the firewall as it would be after a change, a
// new SSH login from the administrator's address still gets in. The login is
// the caller's, found by the control socket: over SSH, its own connection's
// two ends are judged; on the console, each family's endpoints must be
// allowed from anywhere. removed is the rule a revoke or a close takes away,
// nil for anything else.
//
// Two changes pass without the rest: when the firewall after is not active
// (it blocks nothing), and when the rule removed is one no SSH packet can
// match and the endpoints were all found.
//
// Decision: docs/decisions/firewall.md#no-lockout
func Safe(after sysinfo.Firewall, eps []Endpoint, complete bool, login module.Login, removed *sysinfo.Rule) error {
	if !after.Active {
		return nil
	}
	if removed != nil && complete && removed.Modelled && !touchesSSH(*removed, eps) {
		return nil
	}
	if !complete {
		return ErrLockoutUnknown
	}
	if login.From.IsValid() {
		return judge(after.Admits("tcp", login.From.Addr(), login.To))
	}
	// The console: each family's endpoints must be reachable from anywhere,
	// by the verdict, which a rule naming its sources does not satisfy. A
	// wildcard endpoint is judged at a documentation address no rule names.
	stand := map[string]netip.Addr{"v4": netip.MustParseAddr("192.0.2.2"), "v6": netip.MustParseAddr("2001:db8::2")}
	for _, fam := range []string{"v4", "v6"} {
		var any, reach, unsure bool
		for _, e := range eps {
			if e.Family != fam {
				continue
			}
			any = true
			addr := e.Addr
			if !addr.IsValid() {
				addr = stand[fam]
			}
			switch v, why := after.Verdict("tcp", addr, e.Port); {
			case v == sysinfo.VerdictAllowed || (v == sysinfo.VerdictLimited && why == sysinfo.WhyRateLimit):
				reach = true
			case v == sysinfo.VerdictUnknown:
				unsure = true
			}
		}
		switch {
		case !any || reach:
		case unsure:
			return ErrLockoutUnknown
		default:
			return ErrLockout
		}
	}
	return nil
}

func judge(answer string) error {
	switch answer {
	case sysinfo.Admit:
		return nil
	case sysinfo.Refuse:
		return ErrLockout
	}
	return ErrLockoutUnknown
}

// touchesSSH reports whether a TCP packet to an SSH endpoint could match r.
func touchesSSH(r sysinfo.Rule, eps []Endpoint) bool {
	if r.Proto == "udp" {
		return false
	}
	for _, e := range eps {
		if r.From == 0 || (e.Port >= r.From && e.Port <= r.To) {
			return true
		}
	}
	return false
}
