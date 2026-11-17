package sysinfo

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/netip"
	"strconv"
	"strings"
)

// Firewall is the host's incoming policy, as its manager reports it. A read
// that cannot see everything says so in Limits rather than guess.
//
// Decision: docs/decisions/firewall.md#what-is-read
type Firewall struct {
	Manager string   `json:"manager"` // "ufw", "firewalld", "none", "unknown"
	Active  bool     `json:"active"`
	Default string   `json:"default"` // incoming: "deny", "reject" or "allow"
	Rules   []Rule   `json:"rules"`   // each family's rules in the order the manager evaluates them (Seq4, Seq6)
	Limits  []string `json:"limits"`  // constant ids of what this read cannot see
}

// The ids a Firewall's Limits holds.
const (
	LimitDocker        = "docker-rules"   // Docker filters what it publishes apart from the manager
	LimitOtherTables   = "other-tables"   // the ruleset holds tables neither the manager's nor known ones
	LimitTwoManagers   = "two-managers"   // ufw and firewalld are both active
	LimitIPv6Unmanaged = "ipv6-unmanaged" // ufw has IPV6=no: IPv6 is not ufw's to filter
	LimitUnparsed      = "unparsed-rules" // a rule line this read could not take apart
)

// Has reports whether f's Limits holds id.
func (f Firewall) Has(id string) bool {
	for _, l := range f.Limits {
		if l == id {
			return true
		}
	}
	return false
}

// Rule is one rule, with what is needed to match a packet against it, to find
// it again, and to delete exactly it.
type Rule struct {
	ID        string `json:"id"`        // the canonical identity: Identity's hash of the fields below
	Action    string `json:"action"`    // "allow", "deny", "reject", "limit"
	Log       string `json:"log"`       // ufw: "", "log", "log-all"
	Direction string `json:"direction"` // "in", "out", "route": only "in" is matched against a listener
	Family    string `json:"family"`    // "v4", "v6", "both": from the read, never from a setting
	Proto     string `json:"proto"`     // "tcp", "udp", "" for both
	From      int    `json:"from"`      // the destination port range; 0 and 0 for every port
	To        int    `json:"to"`
	Source    string `json:"source"`    // a masked prefix, or a bare address for a full-length one; "" for anywhere
	Dest      string `json:"dest"`      // the same form; "" for any
	Scope     string `json:"scope"`     // ufw: the interface, or ""; firewalld: the zone
	Service   string `json:"service"`   // ufw: the app profile; firewalld: the service; "" for a port rule
	Runtime   bool   `json:"runtime"`   // in the running configuration (ufw: when active)
	Permanent bool   `json:"permanent"` // in the saved one (ufw: always)
	Modelled  bool   `json:"modelled"`  // false: the manager has a rule this struct cannot express; Raw holds it
	Raw       string `json:"raw"`       // the manager's own text, for display only
	Note      string `json:"note"`      // the rule's comment, for display only
	Seq4      int    `json:"seq4"`      // its place among the IPv4 rules, from 1; 0 when it has no IPv4 half
	Seq6      int    `json:"seq6"`      // the same among the IPv6 rules
	By        string `json:"by"`        // its owner in firewall_rule ("stack:chat", "mail"), or ""
}

// Identity is the rule's canonical identity: the hash of every field that
// makes it the rule it is, never its place or its number, which change when
// another rule is edited. Addresses are compared in their normal form.
func Identity(r Rule) string {
	key := strings.Join([]string{r.Action, r.Log, r.Direction, r.Family, r.Proto,
		strconv.Itoa(r.From), strconv.Itoa(r.To), NormalAddr(r.Source), NormalAddr(r.Dest),
		r.Scope, r.Service, r.Raw0()}, "\x1f")
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:12])
}

// Raw0 is what of Raw the identity carries: the whole text for a rule that
// is not modelled (it is all there is to tell two of them apart), nothing for
// one that is.
func (r Rule) Raw0() string {
	if r.Modelled {
		return ""
	}
	return r.Raw
}

// NormalAddr writes an address or prefix in the form a manager keeps it: a
// prefix masked to its length, a full-length prefix as a bare address, the
// "any" prefixes as "". Text that is neither is returned as it is.
func NormalAddr(s string) string {
	if s == "" {
		return ""
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap().String()
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return s
	}
	p = p.Masked()
	switch {
	case p.Bits() == 0:
		return ""
	case p.Bits() == p.Addr().BitLen():
		return p.Addr().String()
	}
	return p.String()
}

// UfwDefaults is what /etc/default/ufw says.
type UfwDefaults struct {
	IPv6     bool   // IPV6=yes
	Incoming string // "deny", "reject" or "allow", from DEFAULT_INPUT_POLICY
}

// ParseUfwDefaults reads /etc/default/ufw. A value it does not know is left
// at its default: IPv6 off, incoming "deny" (ufw's own).
func ParseUfwDefaults(r io.Reader) UfwDefaults {
	d := UfwDefaults{Incoming: "deny"}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok || strings.HasPrefix(k, "#") {
			continue
		}
		v = strings.Trim(v, `"'`)
		switch k {
		case "IPV6":
			d.IPv6 = strings.EqualFold(v, "yes")
		case "DEFAULT_INPUT_POLICY":
			if p := policyWord(v); p != "" {
				d.Incoming = p
			}
		}
	}
	return d
}

// policyWord maps iptables' and ufw's words for a policy to ours.
func policyWord(v string) string {
	switch strings.ToLower(v) {
	case "drop", "deny":
		return "deny"
	case "reject":
		return "reject"
	case "accept", "allow":
		return "allow"
	}
	return ""
}

// ParseUfwStatus reads `ufw status verbose`: whether ufw is active, and while
// it is, its incoming default ("" when inactive: ufw prints none then).
func ParseUfwStatus(r io.Reader) (active bool, incoming string) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "Status: active":
			active = true
		case strings.HasPrefix(line, "Default:"):
			for _, part := range strings.Split(strings.TrimPrefix(line, "Default:"), ",") {
				word, what, ok := strings.Cut(strings.TrimSpace(part), " ")
				if ok && what == "(incoming)" {
					incoming = policyWord(word)
				}
			}
		}
	}
	return active, incoming
}

// UfwFirewall puts ufw's reads together: its status, /etc/default/ufw, and
// its two rule files. While ufw is inactive its status names no default, so
// the default is the file's; its rules are kept then, not in force.
func UfwFirewall(status, defaults, v4, v6 io.Reader) Firewall {
	f := Firewall{Manager: "ufw", Rules: []Rule{}, Limits: []string{}}
	var incoming string
	f.Active, incoming = ParseUfwStatus(status)
	d := ParseUfwDefaults(defaults)
	f.Default = d.Incoming
	if f.Active && incoming != "" {
		f.Default = incoming
	}
	if !d.IPv6 {
		f.Limits = append(f.Limits, LimitIPv6Unmanaged)
	}
	for _, r := range ParseUfwTuples(v4, v6) {
		r.Runtime = f.Active
		if !r.Modelled && !f.Has(LimitUnparsed) {
			f.Limits = append(f.Limits, LimitUnparsed)
		}
		f.Rules = append(f.Rules, r)
	}
	return f
}

// tupleMark opens each rule line of ufw's rule files.
const tupleMark = "### tuple ### "

// ParseUfwTuples reads ufw's rule files, user.rules (v4) and user6.rules
// (v6): one tuple line per rule and family, in that family's order. A v4 and a
// v6 rule, each from and to anywhere and alike in every other field, are one
// rule of both families. A line that does not parse is kept as a rule that is
// not modelled, so the verdicts say they cannot tell rather than guess.
//
// Decision: docs/decisions/firewall.md#what-is-read
func ParseUfwTuples(v4, v6 io.Reader) []Rule {
	out := ufwTuples(v4, "v4")
	for _, r := range ufwTuples(v6, "v6") {
		if r.Modelled && r.Source == "" && r.Dest == "" {
			if i := pairOf(out, r); i >= 0 {
				out[i].Family, out[i].Seq6 = "both", r.Seq6
				continue
			}
		}
		out = append(out, r)
	}
	for i := range out {
		out[i].ID = Identity(out[i])
	}
	return out
}

// pairOf is the v4-only rule in rules that r, a v6 rule from and to anywhere,
// is the other half of; -1 for none.
func pairOf(rules []Rule, r Rule) int {
	for i, c := range rules {
		if c.Family != "v4" || !c.Modelled || c.Source != "" || c.Dest != "" {
			continue
		}
		c.Family, c.Seq4, c.Seq6, c.Raw, c.Note = r.Family, r.Seq4, r.Seq6, r.Raw, r.Note
		if c == r {
			return i
		}
	}
	return -1
}

// ufwTuples reads one rule file's tuple lines as family's rules.
func ufwTuples(r io.Reader, family string) []Rule {
	if r == nil {
		return nil
	}
	var out []Rule
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line, ok := strings.CutPrefix(strings.TrimSpace(sc.Text()), tupleMark)
		if !ok {
			continue
		}
		rule := parseTuple(line, family)
		if family == "v4" {
			rule.Seq4 = len(out) + 1
		} else {
			rule.Seq6 = len(out) + 1
		}
		out = append(out, rule)
	}
	return out
}

// parseTuple reads one tuple: action proto dport dst sport src [dapp sapp]
// direction [comment=<hex>], as ufw writes it.
func parseTuple(line, family string) Rule {
	r := Rule{Raw: line, Family: family, Permanent: true}
	f := strings.Fields(line)
	if n := len(f); n > 0 && strings.HasPrefix(f[n-1], "comment=") {
		if b, err := hex.DecodeString(strings.TrimPrefix(f[n-1], "comment=")); err == nil {
			r.Note = string(b)
		}
		f = f[:n-1]
	}
	if len(f) != 7 && len(f) != 9 {
		return r
	}
	action, dport, dst, sport, src, dir := f[0], f[2], f[3], f[4], f[5], f[len(f)-1]
	route := strings.HasPrefix(action, "route:")
	action = strings.TrimPrefix(action, "route:")
	action, r.Log, _ = strings.Cut(action, "_")
	switch action {
	case "allow", "deny", "reject", "limit":
		r.Action = action
	default:
		return r
	}
	if r.Log != "" && r.Log != "log" && r.Log != "log-all" {
		return r
	}
	switch f[1] {
	case "any":
	case "tcp", "udp":
		r.Proto = f[1]
	default:
		return r
	}
	if len(f) == 9 {
		if f[6] != "-" {
			r.Service = f[6]
		}
		if f[7] != "-" {
			return r // a source app: not in the model
		}
	}
	var ok bool
	if r.Source, ok = tupleAddr(src, family); !ok {
		return r
	}
	if r.Dest, ok = tupleAddr(dst, family); !ok {
		return r
	}
	if sport != "any" {
		return r // a source port: not in the model
	}
	if r.From, r.To, ok = tuplePorts(dport); !ok {
		return r
	}
	switch {
	case route:
		r.Direction = "route"
	case dir == "in" || dir == "out":
		r.Direction = dir
	case strings.HasPrefix(dir, "in_") && !strings.Contains(dir, "!"):
		r.Direction, r.Scope = "in", strings.TrimPrefix(dir, "in_")
	case strings.HasPrefix(dir, "out_") && !strings.Contains(dir, "!"):
		r.Direction, r.Scope = "out", strings.TrimPrefix(dir, "out_")
	default:
		return r
	}
	r.Modelled = true
	r.Raw = ufwText(r)
	return r
}

// tupleAddr reads a tuple's address: the family's "any" prefix as "", else
// the address in its normal form. Anything else does not parse.
func tupleAddr(s, family string) (string, bool) {
	if (family == "v4" && s == "0.0.0.0/0") || (family == "v6" && s == "::/0") {
		return "", true
	}
	n := NormalAddr(s)
	if _, err := netip.ParseAddr(n); err == nil {
		return n, true
	}
	if _, err := netip.ParsePrefix(n); err == nil {
		return n, true
	}
	return "", false
}

// tuplePorts reads a tuple's destination ports: "any", one port, or a range
// "a:b". A list ("80,443") is not in the model.
func tuplePorts(s string) (from, to int, ok bool) {
	if s == "any" {
		return 0, 0, true
	}
	a, b, isRange := strings.Cut(s, ":")
	from, err := strconv.Atoi(a)
	if err != nil || from < 1 || from > 65535 {
		return 0, 0, false
	}
	to = from
	if isRange {
		if to, err = strconv.Atoi(b); err != nil || to < from || to > 65535 {
			return 0, 0, false
		}
	}
	return from, to, true
}

// ufwText is the rule as ufw's command line would make it, for display.
func ufwText(r Rule) string {
	var b strings.Builder
	b.WriteString(r.Action)
	if r.Log != "" {
		b.WriteString(" " + r.Log)
	}
	if r.Direction != "in" || r.Scope != "" {
		b.WriteString(" " + r.Direction)
		if r.Scope != "" {
			b.WriteString(" on " + r.Scope)
		}
	}
	b.WriteString(" from " + anyOr(r.Source) + " to " + anyOr(r.Dest))
	if r.Service != "" {
		b.WriteString(" app " + r.Service)
		return b.String()
	}
	if r.From != 0 {
		b.WriteString(" port " + strconv.Itoa(r.From))
		if r.To != r.From {
			b.WriteString(":" + strconv.Itoa(r.To))
		}
	}
	if r.Proto != "" {
		b.WriteString(" proto " + r.Proto)
	}
	return b.String()
}

func anyOr(s string) string {
	if s == "" {
		return "any"
	}
	return s
}
