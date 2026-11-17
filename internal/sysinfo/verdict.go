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
	v, why := f.judge(kept, "deny", proto, addr.Unmap(), port)
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
