package sysinfo

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ufwFixture reads one of testdata/ufw's cases, captured from Ubuntu 24.04's
// ufw 0.36.2 with LC_ALL=C (addresses moved to the documentation ranges).
func ufwFixture(t *testing.T, name string) Firewall {
	t.Helper()
	open := func(p string) *os.File {
		f, err := os.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { f.Close() })
		return f
	}
	dir := filepath.Join("testdata", "ufw", name)
	defaults := strings.NewReader("IPV6=yes\nDEFAULT_INPUT_POLICY=\"DROP\"\n")
	if name == "active-ipv6-no" {
		defaults = strings.NewReader("IPV6=no\nDEFAULT_INPUT_POLICY=\"DROP\"\n")
	}
	return UfwFirewall(open(filepath.Join(dir, "status-verbose.txt")), defaults,
		open(filepath.Join(dir, "user.rules")), open(filepath.Join(dir, "user6.rules")))
}

// find is the rule of f whose display text is raw and family fam.
func find(t *testing.T, f Firewall, raw, fam string) Rule {
	t.Helper()
	for _, r := range f.Rules {
		if r.Raw == raw && r.Family == fam {
			return r
		}
	}
	var have []string
	for _, r := range f.Rules {
		have = append(have, r.Family+" "+r.Raw)
	}
	t.Fatalf("no %s rule %q among:\n%s", fam, raw, strings.Join(have, "\n"))
	return Rule{}
}

// TestUfwRulesAreReadWhole: every rule of the variety comes back with its
// fields, one rule for a pair of halves from and to anywhere, its family from
// the files, an app profile with its ports, a comment, the outgoing and
// forwarding rules marked as such, and each family's order.
func TestUfwRulesAreReadWhole(t *testing.T) {
	f := ufwFixture(t, "active-variety")
	if f.Manager != "ufw" || !f.Active || f.Default != "deny" || len(f.Limits) != 0 {
		t.Fatalf("firewall = %+v", f)
	}
	if len(f.Rules) != 20 { // 19 IPv4 lines and 14 IPv6 lines, 13 of them halves of an IPv4 one
		t.Fatalf("%d rules", len(f.Rules))
	}
	ssh := find(t, f, "allow from any to any port 22 proto tcp", "both")
	if ssh.Seq4 != 2 || ssh.Seq6 != 1 || !ssh.Runtime || !ssh.Permanent || !ssh.Modelled || ssh.Direction != "in" {
		t.Errorf("22/tcp = %+v", ssh)
	}
	deny := find(t, f, "deny from 203.0.113.7 to any", "v4")
	if deny.Seq4 != 1 || deny.From != 0 || deny.Proto != "" || deny.Source != "203.0.113.7" {
		t.Errorf("the inserted deny = %+v", deny)
	}
	app := find(t, f, "allow from any to any app OpenSSH", "both")
	if app.Service != "OpenSSH" || app.From != 22 || app.To != 22 || app.Proto != "tcp" {
		t.Errorf("the app profile = %+v", app)
	}
	if r := find(t, f, "allow from any to any port 8086 proto tcp", "both"); r.Note != "a note here" {
		t.Errorf("the comment = %q", r.Note)
	}
	if r := find(t, f, "allow from any to any port 8089", "both"); r.Proto != "" {
		t.Errorf("both protocols = %q", r.Proto)
	}
	if r := find(t, f, "allow from 2001:db8::/32 to any port 8084 proto tcp", "v6"); r.Seq4 != 0 || r.Seq6 == 0 {
		t.Errorf("the IPv6 source = %+v", r)
	}
	if r := find(t, f, "allow in on eth0 from any to any port 8085 proto tcp", "both"); r.Scope != "eth0" {
		t.Errorf("the interface = %+v", r)
	}
	if r := find(t, f, "allow from 192.0.2.20 to 192.0.2.10 port 8090:8092 proto udp", "v4"); r.From != 8090 || r.To != 8092 {
		t.Errorf("the range = %+v", r)
	}
	if r := find(t, f, "deny out from any to any port 6667 proto tcp", "both"); r.Direction != "out" {
		t.Errorf("the outgoing rule = %+v", r)
	}
	if r := find(t, f, "allow route from any to 198.51.100.2 port 80 proto tcp", "v4"); r.Direction != "route" || !r.Modelled {
		t.Errorf("the route rule = %+v", r)
	}
	ids := map[string]bool{}
	for _, r := range f.Rules {
		if ids[r.ID] || r.ID != Identity(r) {
			t.Errorf("identity of %q: %s", r.Raw, r.ID)
		}
		ids[r.ID] = true
	}
}

// TestUfwInactiveKeepsItsRules: an inactive ufw prints no default, so the
// file's is used; its rules are kept, not in force.
func TestUfwInactiveKeepsItsRules(t *testing.T) {
	f := ufwFixture(t, "inactive-rules")
	if f.Active || f.Default != "deny" || len(f.Rules) == 0 {
		t.Fatalf("firewall = %+v", f)
	}
	for _, r := range f.Rules {
		if r.Runtime || !r.Permanent {
			t.Fatalf("an inactive ufw's rule %q: runtime %v permanent %v", r.Raw, r.Runtime, r.Permanent)
		}
	}
	if e := ufwFixture(t, "inactive-empty"); e.Active || len(e.Rules) != 0 {
		t.Errorf("empty = %+v", e)
	}
}

// TestUfwIPv6Off: with IPV6=no the IPv6 file is empty (a reload empties it),
// every rule is IPv4's, and the read says IPv6 is not ufw's.
func TestUfwIPv6Off(t *testing.T) {
	f := ufwFixture(t, "active-ipv6-no")
	if !f.Has(LimitIPv6Unmanaged) {
		t.Fatalf("limits = %v", f.Limits)
	}
	for _, r := range f.Rules {
		if r.Family != "v4" || r.Seq6 != 0 {
			t.Fatalf("rule %q is %s", r.Raw, r.Family)
		}
	}
	if v, why := f.Verdict("tcp", netip.MustParseAddr("2001:db8::1"), 22); v != VerdictUnknown || why != LimitIPv6Unmanaged {
		t.Errorf("an IPv6 listener: %s %s", v, why)
	}
}

// TestUfwVerdicts: the first deciding rule in the family's order, partial
// rules naming what they cover, the default, and the two families of a
// wildcard IPv6 listener.
func TestUfwVerdicts(t *testing.T) {
	f := ufwFixture(t, "active-variety")
	v4any, v6any := netip.MustParseAddr("0.0.0.0"), netip.MustParseAddr("::")
	cases := []struct {
		proto string
		addr  netip.Addr
		port  int
		want  string
		why   string
	}{
		{"tcp", netip.MustParseAddr("127.0.0.1"), 9999, VerdictLocal, ""},
		{"tcp", netip.MustParseAddr("::1"), 9999, VerdictLocal, ""},
		{"tcp", v4any, 22, VerdictLimited, "not from 203.0.113.7"}, // the inserted deny comes first for IPv4
		{"tcp", netip.MustParseAddr("2001:db8::5"), 22, VerdictAllowed, ""},
		{"tcp", v4any, 8082, VerdictLimited, "from 192.0.2.0/24"},
		{"tcp", v4any, 8083, VerdictLimited, "to 192.0.2.10"},
		{"tcp", netip.MustParseAddr("192.0.2.10"), 8083, VerdictLimited, "not from 203.0.113.7"},
		{"tcp", netip.MustParseAddr("2001:db8::5"), 2223, VerdictLimited, WhyRateLimit},
		{"tcp", netip.MustParseAddr("2001:db8::5"), 8087, VerdictBlocked, ""},
		{"tcp", netip.MustParseAddr("2001:db8::5"), 9999, VerdictBlocked, ""},
		{"udp", netip.MustParseAddr("2001:db8::5"), 8089, VerdictAllowed, ""},
		{"tcp", netip.MustParseAddr("2001:db8::5"), 8093, VerdictAllowed, ""},
		{"tcp", netip.MustParseAddr("2001:db8::5"), 8084, VerdictLimited, "from 2001:db8::/32"},
		{"tcp", netip.MustParseAddr("2001:db8::5"), 8085, VerdictLimited, "on eth0"},
		{"tcp", netip.MustParseAddr("2001:db8::5"), 6667, VerdictBlocked, ""}, // an outgoing rule does not open it
		{"tcp", v6any, 9999, VerdictBlocked, ""},
	}
	for _, c := range cases {
		v, why := f.Verdict(c.proto, c.addr, c.port)
		if v != c.want || why != c.why {
			t.Errorf("%s %s:%d = %s %q, want %s %q", c.proto, c.addr, c.port, v, why, c.want, c.why)
		}
	}
}

// TestVerdictSpecialCases: the firewall off, a manager that cannot be read, a
// rule that is not modelled, a default of allow with a partial deny, and a
// wildcard listener whose families disagree.
func TestVerdictSpecialCases(t *testing.T) {
	any4 := netip.MustParseAddr("0.0.0.0")
	if v, why := (Firewall{Manager: "ufw"}).Verdict("tcp", any4, 25); v != VerdictAllowed || why != WhyFirewallOff {
		t.Errorf("off: %s %s", v, why)
	}
	if v, why := (Firewall{Manager: "unknown", Active: true}).Verdict("tcp", any4, 25); v != VerdictUnknown || why != WhyManagerUnknown {
		t.Errorf("unknown: %s %s", v, why)
	}
	raw := Firewall{Manager: "firewalld", Active: true, Default: "deny", Rules: []Rule{{Raw: "rule something", Runtime: true}}}
	if v, why := raw.Verdict("tcp", any4, 25); v != VerdictUnknown || why != WhyNotModelled {
		t.Errorf("not modelled: %s %s", v, why)
	}
	open := Firewall{Manager: "ufw", Active: true, Default: "allow", Rules: []Rule{
		{Action: "deny", Direction: "in", Family: "v4", Source: "198.51.100.0/24", Modelled: true, Runtime: true, Seq4: 1},
	}}
	if v, why := open.Verdict("tcp", any4, 25); v != VerdictLimited || why != "not from 198.51.100.0/24" {
		t.Errorf("default allow: %s %s", v, why)
	}
	v4only := Firewall{Manager: "ufw", Active: true, Default: "deny", Rules: []Rule{
		{Action: "allow", Direction: "in", Family: "v4", Proto: "tcp", From: 25, To: 25, Modelled: true, Runtime: true, Seq4: 1},
	}}
	if v, why := v4only.Verdict("tcp", netip.MustParseAddr("::"), 25); v != VerdictLimited || why != WhyIPv4Only {
		t.Errorf("one family: %s %s", v, why)
	}
}

// TestNeedsRuleIgnoresWhetherTheFirewallIsOn: what an owner must open is
// judged as if the firewall were on with its default deny, whatever it is
// now, on the rules kept for good.
func TestNeedsRuleIgnoresWhetherTheFirewallIsOn(t *testing.T) {
	f := ufwFixture(t, "inactive-rules")
	any4 := netip.MustParseAddr("0.0.0.0")
	if f.NeedsRule("tcp", any4, 8088) {
		t.Error("8088 has a rule, kept while ufw is off")
	}
	if !f.NeedsRule("tcp", any4, 8094) {
		t.Error("8094 has none")
	}
	if v, _ := f.Verdict("tcp", any4, 8094); v != VerdictAllowed {
		t.Errorf("while off, 8094 is %s now", v)
	}
	runtimeOnly := Firewall{Manager: "firewalld", Active: true, Default: "deny", Rules: []Rule{
		{Action: "allow", Direction: "in", Family: "both", Proto: "tcp", From: 993, To: 993, Modelled: true, Runtime: true, Seq4: 1, Seq6: 1},
	}}
	if v, _ := runtimeOnly.Verdict("tcp", any4, 993); v != VerdictAllowed {
		t.Errorf("a running rule passes now: %s", v)
	}
	if !runtimeOnly.NeedsRule("tcp", any4, 993) {
		t.Error("a rule only in the running set is lost at the next start: it still needs one")
	}
}

// TestNormalAddr: addresses in the form ufw keeps them.
func TestNormalAddr(t *testing.T) {
	for in, want := range map[string]string{
		"": "", "0.0.0.0/0": "", "::/0": "", "10.2.3.4/32": "10.2.3.4", "10.2.3.4": "10.2.3.4",
		"10.3.3.3/16": "10.3.0.0/16", "2001:db8::1/128": "2001:db8::1", "2001:db8:1::5/48": "2001:db8:1::/48",
		"::ffff:10.0.0.1": "10.0.0.1", "nonsense": "nonsense",
	} {
		if got := NormalAddr(in); got != want {
			t.Errorf("NormalAddr(%q) = %q, want %q", in, got, want)
		}
	}
	a := Rule{Action: "allow", Direction: "in", Family: "both", Proto: "tcp", From: 1, To: 1, Source: "10.2.3.4/32", Modelled: true}
	b := a
	b.Source = "10.2.3.4"
	if Identity(a) != Identity(b) {
		t.Error("a host and its /32 are one rule")
	}
	c := a
	c.Family = "v4"
	if Identity(a) == Identity(c) {
		t.Error("a surviving half is another identity")
	}
}

// TestUfwTuplesThatDoNotParse are kept as rules that are not modelled.
func TestUfwTuplesThatDoNotParse(t *testing.T) {
	v4 := strings.NewReader(strings.Join([]string{
		"### tuple ### allow tcp 80,443 0.0.0.0/0 any 0.0.0.0/0 in",
		"### tuple ### allow tcp 22 0.0.0.0/0 53 0.0.0.0/0 in",
		"### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 - Foo in",
		"### tuple ### frobnicate tcp 22 0.0.0.0/0 any 0.0.0.0/0 in",
		"### tuple ### allow tcp 70000 0.0.0.0/0 any 0.0.0.0/0 in",
		"### tuple ### allow_log tcp 21 0.0.0.0/0 any 0.0.0.0/0 in",
	}, "\n"))
	rs := ParseUfwTuples(v4, nil)
	if len(rs) != 6 {
		t.Fatalf("%d rules", len(rs))
	}
	for i, r := range rs[:5] {
		if r.Modelled {
			t.Errorf("line %d modelled: %+v", i+1, r)
		}
	}
	if !rs[5].Modelled || rs[5].Log != "log" {
		t.Errorf("a logged rule = %+v", rs[5])
	}
}

// TestAdmitsOneConnection: the guard's question, from one address to one
// endpoint, sure or not.
func TestAdmitsOneConnection(t *testing.T) {
	f := ufwFixture(t, "active-variety")
	ap := netip.MustParseAddrPort
	cases := []struct {
		src  string
		dst  string
		want string
	}{
		{"203.0.113.7", "192.0.2.10:22", Refuse}, // the inserted deny
		{"192.0.2.20", "192.0.2.10:22", Admit},
		{"2001:db8::9", "[2001:db8::10]:22", Admit},
		{"192.0.2.20", "192.0.2.10:8082", Admit},     // from the allowed network
		{"198.51.100.1", "192.0.2.10:8082", Refuse},  // from elsewhere: the default
		{"198.51.100.1", "192.0.2.99:8083", Refuse},  // to another address than the rule's
		{"198.51.100.1", "192.0.2.10:8085", Unknown}, // a rule bound to an interface
		{"198.51.100.1", "192.0.2.10:2223", Admit},   // a rate limit admits
		{"198.51.100.1", "192.0.2.10:8087", Refuse},  // a reject
	}
	for _, c := range cases {
		if got := f.Admits("tcp", netip.MustParseAddr(c.src), ap(c.dst)); got != c.want {
			t.Errorf("%s → %s: %s, want %s", c.src, c.dst, got, c.want)
		}
	}
	src := netip.MustParseAddr("2001:db8::9")
	if got := ufwFixture(t, "active-ipv6-no").Admits("tcp", src, ap("[2001:db8::10]:22")); got != Unknown {
		t.Errorf("IPv6 not ufw's: %s", got)
	}
	if got := (Firewall{Manager: "ufw"}).Admits("tcp", src, ap("[2001:db8::10]:22")); got != Admit {
		t.Errorf("off: %s", got)
	}
	if got := (Firewall{Manager: "unknown", Active: true}).Admits("tcp", src, ap("[2001:db8::10]:22")); got != Unknown {
		t.Errorf("unknown: %s", got)
	}
	if got := (Firewall{Manager: "ufw", Active: true, Default: "allow"}).Admits("tcp", src, ap("[2001:db8::10]:22")); got != Admit {
		t.Errorf("default allow: %s", got)
	}
	raw := Firewall{Manager: "firewalld", Active: true, Rules: []Rule{{Raw: "x", Runtime: true}}}
	if got := raw.Admits("tcp", src, ap("[2001:db8::10]:22")); got != Unknown {
		t.Errorf("not modelled: %s", got)
	}
}

// TestIPv6OffKeepsAnAllowForIPv4 (C1): with IPV6=no ufw keeps an allow of both
// families as IPv4's; the IPv4 rule is the whole rule, and nothing more is
// needed on a wildcard listener.
func TestIPv6OffKeepsAnAllowForIPv4(t *testing.T) {
	f := ufwFixture(t, "active-ipv6-no")
	r := Rule{Action: "allow", Direction: "in", Family: "both", Proto: "tcp", From: 22, To: 22, Modelled: true}
	if k := f.Kept(r); k.Family != "v4" {
		t.Fatalf("kept = %+v", k)
	}
	if f.NeedsRule("tcp", netip.IPv6Unspecified(), 22) {
		t.Error("22 is allowed for IPv4, all ufw manages here")
	}
	if !f.NeedsRule("tcp", netip.IPv6Unspecified(), 9999) {
		t.Error("9999 has no rule")
	}
	on := ufwFixture(t, "active-variety")
	if k := on.Kept(r); k.Family != "both" {
		t.Fatalf("with IPv6 managed, kept = %+v", k)
	}
}

// TestRangesAreJudgedWhole (C4): a range needs a rule when any of its ports
// does; its verdict is its worst port's.
func TestRangesAreJudgedWhole(t *testing.T) {
	f := ufwFixture(t, "active-variety")
	any := netip.IPv6Unspecified()
	if f.NeedsRuleRange("udp", any, 60000, 60010) {
		t.Error("60000-60010/udp is allowed whole")
	}
	if !f.NeedsRuleRange("udp", any, 59990, 60010) || !f.NeedsRuleRange("udp", any, 60005, 60020) {
		t.Error("a range reaching past the rule needs one")
	}
	if v, _ := f.VerdictRange("udp", netip.MustParseAddr("2001:db8::5"), 60000, 60010); v != VerdictAllowed {
		t.Errorf("the allowed range = %s", v)
	}
	if v, _ := f.VerdictRange("udp", netip.MustParseAddr("2001:db8::5"), 60005, 60020); v != VerdictBlocked {
		t.Errorf("a range half outside = %s", v)
	}
}
