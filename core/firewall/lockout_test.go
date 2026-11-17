package firewall

import (
	"errors"
	"net/netip"
	"reflect"
	"testing"

	"github.com/yongjohnlee80/autopanel/internal/module"
	"github.com/yongjohnlee80/autopanel/internal/sysinfo"
)

var both = map[string]bool{"v4": true, "v6": true}

func tcp(addr string, port, pid int, process string) sysinfo.Listener {
	return sysinfo.Listener{Proto: "tcp", Address: addr, Port: port, PID: pid, Process: process}
}

// TestEndpointsAsTheUbuntuTestsSawThem: the cases step 4.1 ran on Ubuntu
// 24.04 (ssh.socket before the first login and after, two ports, IPv6 off in
// the kernel), and the cases of a host without a socket unit.
func TestEndpointsAsTheUbuntuTestsSawThem(t *testing.T) {
	socket := []string{"0.0.0.0:22 (Stream)", "[::]:22 (Stream)"}
	v4 := Endpoint{Family: "v4", Port: 22}
	v6 := Endpoint{Family: "v6", Port: 22}
	cases := []struct {
		name     string
		f        SSHFacts
		want     []Endpoint
		complete bool
	}{
		{"before the first login: PID 1 alone holds them", SSHFacts{Socket: socket, Families: both,
			Listeners: []sysinfo.Listener{tcp("0.0.0.0", 22, 1, "systemd"), tcp("::", 22, 1, "systemd")}}, []Endpoint{v4, v6}, true},
		{"after it: systemd and sshd", SSHFacts{Socket: socket, Families: both,
			Listeners: []sysinfo.Listener{tcp("0.0.0.0", 22, 1, "systemd, sshd"), tcp("::", 22, 1, "systemd, sshd")}}, []Endpoint{v4, v6}, true},
		{"two ports through the generator", SSHFacts{Socket: append(socket, "0.0.0.0:2200 (Stream)", "[::]:2200 (Stream)"), Families: both,
			Listeners: []sysinfo.Listener{tcp("0.0.0.0", 22, 1, "systemd"), tcp("::", 22, 1, "systemd"), tcp("0.0.0.0", 2200, 1, "systemd"), tcp("::", 2200, 1, "systemd")}},
			[]Endpoint{v4, v6, {Family: "v4", Port: 2200}, {Family: "v6", Port: 2200}}, true},
		{"IPv6 off in the kernel: sshd -T's [::] is not wanted", SSHFacts{Families: map[string]bool{"v4": true},
			Config: "port 22\nlistenaddress [::]:22\nlistenaddress 0.0.0.0:22\n", Listeners: []sysinfo.Listener{tcp("0.0.0.0", 22, 900, "sshd")}}, []Endpoint{v4}, true},
		{"no socket: sshd holds them", SSHFacts{Families: both, Config: "port 22\nlistenaddress [::]:22\nlistenaddress 0.0.0.0:22\n",
			Listeners: []sysinfo.Listener{tcp("0.0.0.0", 22, 900, "sshd"), tcp("::", 22, 900, "sshd")}}, []Endpoint{v6, v4}, true},
		{"a configured endpoint nothing listens on", SSHFacts{Families: both, Config: "listenaddress 0.0.0.0:22\nlistenaddress 0.0.0.0:2222\n",
			Listeners: []sysinfo.Listener{tcp("0.0.0.0", 22, 900, "sshd")}}, []Endpoint{v4, {Family: "v4", Port: 2222}}, false},
		{"an sshd listener the configuration does not explain", SSHFacts{Families: both, Config: "listenaddress 0.0.0.0:22\n",
			Listeners: []sysinfo.Listener{tcp("0.0.0.0", 22, 900, "sshd"), tcp("0.0.0.0", 2022, 901, "sshd")}}, []Endpoint{v4}, false},
		{"a socket's datagram line and a stranger's", SSHFacts{Socket: []string{"0.0.0.0:22 (Stream)", "0.0.0.0:22 (Datagram)", "nonsense"}, Families: both,
			Listeners: []sysinfo.Listener{tcp("0.0.0.0", 22, 1, "systemd")}}, []Endpoint{v4}, true},
		{"nothing at all", SSHFacts{Families: both}, nil, false},
		{"only ports: both families", SSHFacts{Families: both, Config: "port 22\n",
			Listeners: []sysinfo.Listener{tcp("0.0.0.0", 22, 900, "sshd"), tcp("::", 22, 900, "sshd")}}, []Endpoint{v4, v6}, true},
		{"one address", SSHFacts{Families: both, Config: "listenaddress 192.0.2.10:22\n",
			Listeners: []sysinfo.Listener{tcp("192.0.2.10", 22, 900, "sshd")}}, []Endpoint{{Family: "v4", Addr: netip.MustParseAddr("192.0.2.10"), Port: 22}}, true},
	}
	for _, c := range cases {
		eps, complete := Endpoints(c.f)
		if !reflect.DeepEqual(eps, c.want) || complete != c.complete {
			t.Errorf("%s: %v %v, want %v %v", c.name, eps, complete, c.want, c.complete)
		}
	}
	if s := (Endpoint{Family: "v6", Port: 22}).String(); s != "[::]:22" {
		t.Errorf("String = %s", s)
	}
}

func allowFrom(seq int, source string, port int) sysinfo.Rule {
	fam := "both"
	if source != "" {
		fam = "v4"
	}
	return sysinfo.Rule{Action: "allow", Direction: "in", Family: fam, Proto: "tcp", From: port, To: port, Source: source,
		Modelled: true, Runtime: true, Permanent: true, Seq4: seq, Seq6: seq}
}

// TestSafeJudgesTheAdministratorsOwnLogin: over SSH, the login's own two ends;
// on the console, every family from anywhere; unsure is a refusal of its own.
func TestSafeJudgesTheAdministratorsOwnLogin(t *testing.T) {
	eps := []Endpoint{{Family: "v4", Port: 22}, {Family: "v6", Port: 22}}
	ssh := module.Login{Session: "43", From: netip.MustParseAddrPort("192.0.2.20:54042"), To: netip.MustParseAddrPort("192.0.2.10:22")}
	console := module.Login{Session: "2"}
	fw := func(rules ...sysinfo.Rule) sysinfo.Firewall {
		return sysinfo.Firewall{Manager: "ufw", Active: true, Default: "deny", Rules: rules, Limits: []string{}}
	}
	cases := []struct {
		name     string
		after    sysinfo.Firewall
		login    module.Login
		complete bool
		removed  *sysinfo.Rule
		want     error
	}{
		{"SSH allowed from anywhere", fw(allowFrom(1, "", 22)), ssh, true, nil, nil},
		{"SSH from the administrator's subnet", fw(allowFrom(1, "192.0.2.0/24", 22)), ssh, true, nil, nil},
		{"SSH from another subnet only", fw(allowFrom(1, "198.51.100.0/24", 22)), ssh, true, nil, ErrLockout},
		{"no SSH rule", fw(allowFrom(1, "", 443)), ssh, true, nil, ErrLockout},
		{"endpoints not found completely", fw(allowFrom(1, "", 22)), ssh, false, nil, ErrLockoutUnknown},
		{"a rule not modelled before it", fw(sysinfo.Rule{Raw: "rich rule", Runtime: true}, allowFrom(2, "", 22)), ssh, true, nil, ErrLockoutUnknown},
		{"the firewall off after", sysinfo.Firewall{Manager: "ufw"}, ssh, false, nil, nil},
		{"the console: both families from anywhere", fw(allowFrom(1, "", 22)), console, true, nil, nil},
		{"the console: a source-limited SSH rule", fw(allowFrom(1, "192.0.2.0/24", 22)), console, true, nil, ErrLockout},
	}
	for _, c := range cases {
		if err := Safe(c.after, eps, c.complete, c.login, c.removed); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
	// Removing a rule no SSH packet matches passes even when the rest
	// cannot be judged (a hand-written rule for SSH) - but not with the
	// endpoints unknown, or when the rule covers an SSH port.
	unsure := fw(sysinfo.Rule{Raw: "rich rule for ssh", Runtime: true})
	mail := allowFrom(2, "", 993)
	if err := Safe(unsure, eps, true, ssh, &mail); err != nil {
		t.Errorf("closing 993 beside a rule for SSH it cannot read: %v", err)
	}
	if err := Safe(unsure, eps, false, ssh, &mail); !errors.Is(err, ErrLockoutUnknown) {
		t.Errorf("closing 993 with the endpoints unknown: %v", err)
	}
	udp := allowFrom(2, "", 22)
	udp.Proto = "udp"
	if err := Safe(unsure, eps, true, ssh, &udp); err != nil {
		t.Errorf("a UDP rule on 22: %v", err)
	}
	everyPort := sysinfo.Rule{Action: "allow", Direction: "in", Family: "both", Modelled: true, Runtime: true}
	if err := Safe(fw(), eps, true, ssh, &everyPort); !errors.Is(err, ErrLockout) {
		t.Errorf("removing an allow of every port that was SSH's only way in: %v", err)
	}
}
