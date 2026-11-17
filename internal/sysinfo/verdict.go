package sysinfo

import (
	"net/netip"
	"sort"
	"strings"
)

// The verdicts of a listening socket, and of an allow rule nothing uses.
const (
	VerdictLocal   = "local"
	VerdictAllowed = "allowed"
	VerdictLimited = "limited"
	VerdictBlocked = "blocked"
	VerdictUnknown = "unknown"
	VerdictStale   = "rule: nothing listens"
)

// The constant reasons a verdict carries in its why when it is not a list of
// sources, addresses or interfaces.
const (
	WhyFirewallOff    = "firewall-off"
	WhyManagerUnknown = "manager-unknown"
	WhyNotModelled    = "rule-not-modelled"
	WhyRateLimit      = "rate-limit"
	WhyIPv4Only       = "ipv4-only"
	WhyIPv6Only       = "ipv6-only"
)

// Verdict is what f does to a new connection from anywhere to a listener on
// proto, addr and port: the first rule that decides it, in its family's
// order, else the default. A listener on every IPv6 address takes IPv4 too, so
// both families are judged and their answers combined.
//
// Decision: docs/decisions/firewall.md#verdicts
func (f Firewall) Verdict(proto string, addr netip.Addr, port int) (verdict, why string) {
	addr = addr.Unmap()
	switch {
	case addr.IsLoopback():
		return VerdictLocal, ""
	case f.Manager == "unknown":
		return VerdictUnknown, WhyManagerUnknown
	case !f.Active:
		return VerdictAllowed, WhyFirewallOff
	}
	live := func(r Rule) bool { return r.Runtime }
	return f.judge(live, f.Default, proto, addr, port)
}

// NeedsRule reports whether a listener on proto, addr and port would be
// refused a connection from anywhere if the firewall were on with its default
// deny: whether an owner that wants it open has a rule to make. It is judged
// on the rules that are kept for good: the saved ones, and while the firewall
// runs, only those also in force. A rate limit is an opening.
//
// Decision: docs/decisions/firewall.md#owners
func (f Firewall) NeedsRule(proto string, addr netip.Addr, port int) bool {
	// A rule naming its sources says nothing of a connection from anywhere
	// else: a deny from one address does not make an owner's rule needless.
	kept := func(r Rule) bool { return r.Permanent && (r.Runtime || !f.Active) && r.Source == "" }
	addr = addr.Unmap()
	if addr.Is6() && addr.IsUnspecified() && f.Has(LimitIPv6Unmanaged) {
		addr = netip.IPv4Unspecified() // IPv6 is not ufw's to open: the IPv4 half is the whole rule
	}
	v, why := f.judge(kept, "deny", proto, addr, port)
	return !(v == VerdictAllowed || (v == VerdictLimited && why == WhyRateLimit))
}

// judge combines both families' answers for a listener on every IPv6 address,
// and answers its own family's otherwise.
func (f Firewall) judge(use func(Rule) bool, def, proto string, addr netip.Addr, port int) (string, string) {
	if addr.Is6() && addr.IsUnspecified() {
		v4, w4 := f.family("v4", use, def, proto, netip.IPv4Unspecified(), port)
		v6, w6 := f.family("v6", use, def, proto, addr, port)
		switch {
		case v4 == v6:
			return v4, joinWhy(w4, w6)
		case v4 == VerdictUnknown || v6 == VerdictUnknown:
			return VerdictUnknown, joinWhy(w4, w6)
		case v4 == VerdictAllowed && v6 == VerdictBlocked:
			return VerdictLimited, WhyIPv4Only
		case v6 == VerdictAllowed && v4 == VerdictBlocked:
			return VerdictLimited, WhyIPv6Only
		}
		return VerdictLimited, joinWhy(w4, w6)
	}
	fam := "v4"
	if addr.Is6() {
		fam = "v6"
	}
	return f.family(fam, use, def, proto, addr, port)
}

// family is the verdict for one family. Rules that cover only some of the
// traffic (from some sources, to some of the addresses a wildcard listener
// has, on one interface) do not decide it; they make an answer "limited", and
// name what they cover.
func (f Firewall) family(fam string, use func(Rule) bool, def, proto string, addr netip.Addr, port int) (string, string) {
	if fam == "v6" && f.Has(LimitIPv6Unmanaged) {
		return VerdictUnknown, LimitIPv6Unmanaged
	}
	var partly []string // what a partial allow covers: an allow from them would be "limited"
	var except []string // what a partial deny covers
	for _, r := range f.inOrder(fam, use) {
		if !r.Modelled {
			return VerdictUnknown, WhyNotModelled
		}
		if (r.Proto != "" && r.Proto != proto) || (r.From != 0 && (port < r.From || port > r.To)) {
			continue
		}
		var only string
		switch {
		case r.Dest != "" && !covers(r.Dest, addr):
			if !addr.IsUnspecified() || !sameFamily(r.Dest, fam) {
				continue
			}
			only = "to " + r.Dest // a wildcard listener: the rule covers some of its addresses
		case r.Scope != "":
			only = "on " + r.Scope
		case r.Source != "":
			only = "from " + r.Source
		}
		if only != "" {
			if r.Action == "allow" || r.Action == "limit" {
				partly = append(partly, only)
			} else {
				except = append(except, only)
			}
			continue
		}
		switch r.Action {
		case "allow":
			if len(except) > 0 {
				return VerdictLimited, "not " + strings.Join(except, ", not ")
			}
			return VerdictAllowed, ""
		case "limit":
			return VerdictLimited, WhyRateLimit
		default:
			if len(partly) > 0 {
				return VerdictLimited, strings.Join(partly, ", ")
			}
			return VerdictBlocked, ""
		}
	}
	if def == "allow" {
		if len(except) > 0 {
			return VerdictLimited, "not " + strings.Join(except, ", not ")
		}
		return VerdictAllowed, ""
	}
	if len(partly) > 0 {
		return VerdictLimited, strings.Join(partly, ", ")
	}
	return VerdictBlocked, ""
}

// inOrder is fam's incoming rules that use admits, in fam's order. A rule
// that is not modelled is in every family's list: what it does is not known.
func (f Firewall) inOrder(fam string, use func(Rule) bool) []Rule {
	var out []Rule
	for _, r := range f.Rules {
		if !use(r) || (r.Modelled && r.Direction != "in") {
			continue
		}
		if !r.Modelled || r.Family == fam || r.Family == "both" {
			out = append(out, r)
		}
	}
	seq := func(r Rule) int {
		if fam == "v4" {
			return r.Seq4
		}
		return r.Seq6
	}
	sort.SliceStable(out, func(i, j int) bool { return seq(out[i]) < seq(out[j]) })
	return out
}

// covers reports whether the address or prefix s holds addr.
func covers(s string, addr netip.Addr) bool {
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap() == addr
	}
	p, err := netip.ParsePrefix(s)
	return err == nil && p.Contains(addr)
}

// sameFamily reports whether the address or prefix s is of family fam.
func sameFamily(s, fam string) bool {
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap().Is4() == (fam == "v4")
	}
	p, err := netip.ParsePrefix(s)
	return err == nil && p.Addr().Unmap().Is4() == (fam == "v4")
}

func joinWhy(a, b string) string {
	switch {
	case a == b || b == "":
		return a
	case a == "":
		return b
	}
	return a + "; " + b
}

// The answers of Admits.
const (
	Admit   = "admit"
	Refuse  = "refuse"
	Unknown = "unknown"
)

// Admits is what f does to one new connection: from src, to dst's port over
// proto. It is the lockout guard's question, so it answers Unknown wherever
// it cannot be sure: a rule it does not model, a rule bound to an interface
// (which one the packet arrives on is not known here), IPv6 that is not the
// manager's, a manager it cannot read.
//
// Decision: docs/decisions/firewall.md#no-lockout
func (f Firewall) Admits(proto string, src netip.Addr, dst netip.AddrPort) string {
	src, addr, port := src.Unmap(), dst.Addr().Unmap(), int(dst.Port())
	switch {
	case f.Manager == "unknown":
		return Unknown
	case !f.Active:
		return Admit
	}
	fam := "v4"
	if addr.Is6() {
		fam = "v6"
	}
	if fam == "v6" && f.Has(LimitIPv6Unmanaged) {
		return Unknown
	}
	for _, r := range f.inOrder(fam, func(r Rule) bool { return r.Runtime }) {
		if !r.Modelled {
			return Unknown
		}
		if (r.Proto != "" && r.Proto != proto) || (r.From != 0 && (port < r.From || port > r.To)) {
			continue
		}
		if (r.Dest != "" && !covers(r.Dest, addr)) || (r.Source != "" && !covers(r.Source, src)) {
			continue
		}
		if r.Scope != "" {
			return Unknown
		}
		if r.Action == "allow" || r.Action == "limit" {
			return Admit
		}
		return Refuse
	}
	if f.Default == "allow" {
		return Admit
	}
	return Refuse
}

// Kept is r as this firewall's manager keeps it: an allow of both families
// is kept for IPv4 alone where ufw leaves IPv6 to itself (IPV6=no), so its
// identity is the IPv4 rule's.
//
// Decision: docs/decisions/firewall.md#what-is-read
func (f Firewall) Kept(r Rule) Rule {
	if r.Family == "both" && f.Has(LimitIPv6Unmanaged) {
		r.Family = "v4"
	}
	return r
}

// NeedsRuleRange is NeedsRule for every port of from..to: a rule is needed
// when any of them needs one. A decision changes only where a rule's range
// starts or ends, so those ports, and the range's own ends, are all that is
// judged.
func (f Firewall) NeedsRuleRange(proto string, addr netip.Addr, from, to int) bool {
	for _, p := range f.boundaries(from, to) {
		if f.NeedsRule(proto, addr, p) {
			return true
		}
	}
	return false
}

// VerdictRange is the verdict of the range's worst port: the first port
// judged that is not allowed, else allowed.
func (f Firewall) VerdictRange(proto string, addr netip.Addr, from, to int) (string, string) {
	var first, firstWhy string
	for i, p := range f.boundaries(from, to) {
		v, why := f.Verdict(proto, addr, p)
		if i == 0 {
			first, firstWhy = v, why
		}
		if v != VerdictAllowed {
			return v, why
		}
	}
	return first, firstWhy
}

// boundaries are the ports of from..to where a decision may change.
func (f Firewall) boundaries(from, to int) []int {
	if to < from {
		to = from
	}
	seen := map[int]bool{}
	var out []int
	add := func(p int) {
		if p >= from && p <= to && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	add(from)
	add(to)
	for _, r := range f.Rules {
		if r.From != 0 {
			add(r.From)
			add(r.To)
			add(r.From - 1)
			add(r.To + 1)
		}
	}
	return out
}
