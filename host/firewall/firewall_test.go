package firewall

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	corefw "github.com/yongjohnlee80/autopanel/core/firewall"
	"github.com/yongjohnlee80/autopanel/internal/hostcmd"
	"github.com/yongjohnlee80/autopanel/internal/sysinfo"
)

func rule(action, family, proto string, from, to int) sysinfo.Rule {
	return sysinfo.Rule{Action: action, Direction: "in", Family: family, Proto: proto, From: from, To: to, Modelled: true}
}

// TestUfwCommands: the argument lists, in the forms the step 4.1 tests ran
// against ufw 0.36.2 (an allow and its delete for both families, a range, a
// source, a destination, a single family, both protocols, an interface, an
// app profile, an outgoing rule, a rule for every port).
func TestUfwCommands(t *testing.T) {
	src := rule("allow", "v4", "tcp", 8106, 8106)
	src.Source = "10.1.0.0/16"
	dst := rule("allow", "v4", "tcp", 8107, 8107)
	dst.Dest = "192.0.2.10"
	host := rule("allow", "v4", "tcp", 8115, 8115)
	host.Source = "10.2.3.4/32"
	iface := rule("allow", "both", "tcp", 8085, 8085)
	iface.Scope = "eth0"
	app := rule("allow", "both", "tcp", 22, 22)
	app.Service = "OpenSSH"
	out := rule("deny", "both", "tcp", 6667, 6667)
	out.Direction = "out"
	every := rule("deny", "v4", "", 0, 0)
	every.Source = "203.0.113.7"
	logged := rule("allow", "both", "tcp", 21, 21)
	logged.Log = "log"
	cases := []struct {
		name string
		r    sysinfo.Rule
		want string
	}{
		{"both families", rule("allow", "both", "tcp", 8100, 8100), "allow proto tcp from any to any port 8100"},
		{"a range", rule("allow", "both", "udp", 8101, 8105), "allow proto udp from any to any port 8101:8105"},
		{"a source", src, "allow proto tcp from 10.1.0.0/16 to any port 8106"},
		{"a destination", dst, "allow proto tcp from any to 192.0.2.10 port 8107"},
		{"a host's /32", host, "allow proto tcp from 10.2.3.4 to any port 8115"},
		{"IPv4 alone", rule("allow", "v4", "tcp", 25, 25), "allow proto tcp from 0.0.0.0/0 to 0.0.0.0/0 port 25"},
		{"IPv6 alone", rule("allow", "v6", "tcp", 25, 25), "allow proto tcp from ::/0 to ::/0 port 25"},
		{"both protocols", rule("allow", "both", "", 8111, 8111), "allow from any to any port 8111"},
		{"an interface", iface, "allow in on eth0 proto tcp from any to any port 8085"},
		{"an app", app, "allow from any to any app OpenSSH"},
		{"outgoing", out, "deny out proto tcp from any to any port 6667"},
		{"every port", every, "deny from 203.0.113.7 to any"},
		{"logged", logged, "allow log proto tcp from any to any port 21"},
	}
	for _, c := range cases {
		args, err := ufwRule(c.r)
		if err != nil || strings.Join(args, " ") != c.want {
			t.Errorf("%s: %q, %v; want %q", c.name, strings.Join(args, " "), err, c.want)
		}
		del, err := UfwRevoke(c.r)
		if err != nil || strings.Join(del, " ") != "delete "+c.want {
			t.Errorf("%s: revoke %q, %v", c.name, strings.Join(del, " "), err)
		}
	}
	if args, err := UfwAllow(rule("allow", "both", "tcp", 993, 993)); err != nil || strings.Join(args, " ") != "allow proto tcp from any to any port 993" {
		t.Errorf("allow: %q %v", args, err)
	}
}

// TestUfwRefusesWhatItCannotWrite: AutoPanel's own allows name a protocol and
// nothing ufw would read as an option; a rule the read did not model, or a
// forwarding rule, is never deleted by AutoPanel.
func TestUfwRefusesWhatItCannotWrite(t *testing.T) {
	bad := []sysinfo.Rule{
		rule("deny", "both", "tcp", 1, 1),       // AutoPanel allows only
		rule("allow", "both", "", 25, 25),       // no protocol
		rule("allow", "both", "sctp", 25, 25),   // not tcp or udp
		rule("allow", "both", "tcp", 0, 25),     // a broken range
		rule("allow", "both", "tcp", 30, 25),    // backwards
		rule("allow", "both", "tcp", 25, 70000), // past the last port
		func() sysinfo.Rule { r := rule("allow", "both", "tcp", 25, 25); r.Source = "192.0.2.1"; return r }(), // an address is one family's
		func() sysinfo.Rule { r := rule("allow", "v6", "tcp", 25, 25); r.Source = "192.0.2.1"; return r }(),   // of the other family
		func() sysinfo.Rule { r := rule("allow", "v4", "tcp", 25, 25); r.Source = "nonsense"; return r }(),
		func() sysinfo.Rule { r := rule("allow", "both", "tcp", 25, 25); r.Scope = "-x"; return r }(),
		func() sysinfo.Rule { r := rule("allow", "both", "tcp", 25, 25); r.Scope = "eth0 to any"; return r }(),
		func() sysinfo.Rule { r := rule("allow", "both", "tcp", 25, 25); r.Direction = "sideways"; return r }(),
		func() sysinfo.Rule { r := rule("allow", "both", "tcp", 25, 25); r.Family = "v5"; return r }(),
	}
	for i, r := range bad {
		if args, err := UfwAllow(r); err == nil {
			t.Errorf("case %d: allowed %q", i, args)
		}
	}
	if _, err := UfwRevoke(sysinfo.Rule{Raw: "something", Modelled: false}); !errors.Is(err, ErrNotModelled) {
		t.Errorf("a rule not modelled: %v", err)
	}
	route := rule("allow", "v4", "tcp", 80, 80)
	route.Direction = "route"
	if _, err := UfwRevoke(route); !errors.Is(err, ErrNotModelled) {
		t.Errorf("a route rule: %v", err)
	}
	if _, err := UfwDefault("open"); err == nil {
		t.Error("a default that is no policy")
	}
	if d, _ := UfwDefault("deny"); strings.Join(d, " ") != "default deny incoming" {
		t.Errorf("default: %q", d)
	}
	if strings.Join(UfwEnable(true), " ") != "--force enable" || strings.Join(UfwEnable(false), " ") != "disable" {
		t.Error("enable")
	}
}

// fakeHost is a machine with ufw installed: its rule files from sysinfo's
// fixtures, and a runner that answers what a test says and records each call.
type fakeHost struct {
	answers map[string]string // "tool args..." prefix → output
	fail    map[string]error
	calls   []string
}

func (f *fakeHost) run(_ context.Context, tool hostcmd.Tool, args ...string) ([]byte, error) {
	call := strings.Join(append([]string{tool.Path()}, args...), " ")
	f.calls = append(f.calls, call)
	for prefix, err := range f.fail {
		if strings.HasPrefix(call, prefix) {
			return nil, err
		}
	}
	for prefix, out := range f.answers {
		if strings.HasPrefix(call, prefix) {
			return []byte(out), nil
		}
	}
	return nil, errors.New("exit status 1")
}

func newHost(t *testing.T, fixture string, tools ...hostcmd.Tool) (*Host, *fakeHost) {
	t.Helper()
	root := t.TempDir()
	for _, tool := range tools {
		p := filepath.Join(root, tool.Path())
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, nil, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	src := filepath.Join("..", "..", "internal", "sysinfo", "testdata", "ufw", fixture)
	for from, to := range map[string]string{"user.rules": "etc/ufw/user.rules", "user6.rules": "etc/ufw/user6.rules"} {
		b, err := os.ReadFile(filepath.Join(src, from))
		if err != nil {
			t.Fatal(err)
		}
		_ = os.MkdirAll(filepath.Join(root, filepath.Dir(to)), 0o755)
		if err := os.WriteFile(filepath.Join(root, to), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.MkdirAll(filepath.Join(root, "etc/default"), 0o755)
	if err := os.WriteFile(filepath.Join(root, "etc/default/ufw"), []byte("IPV6=yes\nDEFAULT_INPUT_POLICY=\"DROP\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	status, err := os.ReadFile(filepath.Join(src, "status-verbose.txt"))
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeHost{answers: map[string]string{
		"/usr/sbin/ufw status verbose":  string(status),
		"/usr/bin/systemctl is-active":  "inactive\n",
		"/usr/sbin/nft -j list ruleset": `{"nftables":[]}`,
		"/usr/bin/firewall-cmd --state": "not running\n",
		"/usr/bin/systemd-run --wait":   "",
	}}
	return &Host{Root: root, Run: fake.run}, fake
}

// TestReadIsTheManagersView: an Ubuntu host's ufw, read from its status and
// its files; a host with neither manager reads as none; firewalld is read as
// unsupported until its reader lands.
func TestReadIsTheManagersView(t *testing.T) {
	h, _ := newHost(t, "active-variety", hostcmd.Ufw)
	fw, err := h.Read(context.Background())
	if err != nil || fw.Manager != "ufw" || !fw.Active || fw.Default != "deny" || len(fw.Rules) != 20 {
		t.Fatalf("read = %+v, %v", fw, err)
	}
	h, _ = newHost(t, "inactive-rules", hostcmd.Ufw)
	if fw, err := h.Read(context.Background()); err != nil || fw.Manager != "ufw" || fw.Active || len(fw.Rules) == 0 {
		t.Fatalf("inactive = %+v, %v", fw, err)
	}
	h, _ = newHost(t, "inactive-empty")
	if fw, err := h.Read(context.Background()); err != nil || fw.Manager != "none" || fw.Active || len(fw.Rules) != 0 {
		t.Fatalf("nothing = %+v, %v", fw, err)
	}
	h, fake := newHost(t, "inactive-empty", hostcmd.FirewallCmd)
	fake.answers["/usr/bin/firewall-cmd --state"] = "running\n"
	if fw, err := h.Read(context.Background()); !errors.Is(err, ErrUnsupported) || fw.Manager != "firewalld" {
		t.Fatalf("firewalld = %+v, %v", fw, err)
	}
}

// TestChangesRunOutsideTheSandbox: every change goes through systemd-run as a
// transient unit that waits, with the manager's tool and its argument list.
func TestChangesRunOutsideTheSandbox(t *testing.T) {
	h, fake := newHost(t, "active-variety", hostcmd.Ufw)
	ctx := context.Background()
	fw, _ := h.Read(ctx)
	fake.calls = nil
	if err := h.Allow(ctx, fw, rule("allow", "both", "tcp", 993, 993)); err != nil {
		t.Fatal(err)
	}
	want := "/usr/bin/systemd-run --wait --pipe --collect --quiet --service-type=exec --setenv=LC_ALL=C " +
		"--description=AutoPanel: a firewall change -- /usr/sbin/ufw allow proto tcp from any to any port 993"
	if !reflect.DeepEqual(fake.calls, []string{want}) {
		t.Fatalf("calls = %q", fake.calls)
	}
	if prev, err := h.Default(ctx, fw, "deny"); err != nil || prev != "deny" {
		t.Errorf("default: %q %v", prev, err)
	}
	if err := h.Enable(ctx, fw, true); err != nil || !strings.HasSuffix(fake.calls[len(fake.calls)-1], "/usr/sbin/ufw --force enable") {
		t.Errorf("enable: %v %q", err, fake.calls)
	}
	if err := h.Revoke(ctx, fw, fw.Rules[1]); err != nil || !strings.HasSuffix(fake.calls[len(fake.calls)-1], "/usr/sbin/ufw delete allow proto tcp from any to any port 22") {
		t.Errorf("revoke: %v %q", err, fake.calls[len(fake.calls)-1])
	}
	fake.fail = map[string]error{"/usr/bin/systemd-run": errors.New("exit status 1")}
	if err := h.Allow(ctx, fw, rule("allow", "both", "tcp", 993, 993)); err == nil {
		t.Error("a failed change answered nil")
	}
	other := sysinfo.Firewall{Manager: "unknown"}
	if h.Allow(ctx, other, rule("allow", "both", "tcp", 1, 1)) != ErrUnsupported || h.Revoke(ctx, other, fw.Rules[1]) != ErrUnsupported ||
		h.Enable(ctx, other, true) != ErrUnsupported {
		t.Error("a manager AutoPanel does not drive")
	}
	if _, err := h.Default(ctx, other, "deny"); err != ErrUnsupported {
		t.Error("default on another manager")
	}
}

// TestSSHFactsReadTheSocketAndSshd: the active socket unit's Listen lines,
// sshd -T, and IPv6 when the kernel has it.
func TestSSHFactsReadTheSocketAndSshd(t *testing.T) {
	h, fake := newHost(t, "inactive-empty")
	fake.answers["/usr/bin/systemctl show ssh.socket"] = "ActiveState=active\nListen=0.0.0.0:22 (Stream)\nListen=[::]:22 (Stream)\n"
	fake.answers["/usr/bin/systemctl show sshd.socket"] = "ActiveState=inactive\n"
	fake.answers["/usr/sbin/sshd -T"] = "port 22\n"
	f := h.SSHFacts(context.Background(), nil)
	if !reflect.DeepEqual(f.Socket, []string{"0.0.0.0:22 (Stream)", "[::]:22 (Stream)"}) || f.Config != "port 22\n" || f.Families["v6"] {
		t.Fatalf("facts = %+v", f)
	}
	_ = os.MkdirAll(filepath.Join(h.Root, "proc/net"), 0o755)
	_ = os.WriteFile(filepath.Join(h.Root, "proc/net/if_inet6"), nil, 0o644)
	fake.answers["/usr/bin/systemctl show ssh.socket"] = "ActiveState=inactive\n"
	if f := h.SSHFacts(context.Background(), nil); f.Socket != nil || !f.Families["v6"] {
		t.Fatalf("no socket, IPv6 = %+v", f)
	}
}

// TestTheUndoTimer: one fixed unit name, the previous default put back after
// the disable, and the confirm's stop.
func TestTheUndoTimer(t *testing.T) {
	h, fake := newHost(t, "inactive-empty", hostcmd.Ufw)
	ctx := context.Background()
	ufw := sysinfo.Firewall{Manager: "ufw"}
	fake.answers["/usr/bin/systemctl reset-failed"] = ""
	fake.answers["/usr/bin/systemd-run --unit="] = ""
	fake.answers["/usr/bin/systemctl stop"] = ""
	if err := h.ArmUndo(ctx, ufw, "allow", 120*time.Second); err != nil {
		t.Fatal(err)
	}
	want := "/usr/bin/systemd-run --unit=autopanel-firewall-undo --on-active=120s --timer-property=AccuracySec=1s --collect " +
		"--setenv=LC_ALL=C --description=AutoPanel: turn off a firewall enable nobody confirmed " +
		"--property=ExecStartPost=/usr/sbin/ufw default allow incoming -- /usr/sbin/ufw disable"
	if got := fake.calls[len(fake.calls)-1]; got != want {
		t.Fatalf("arm = %q", got)
	}
	if err := h.ArmUndo(ctx, ufw, "deny", time.Minute); err != nil || strings.Contains(fake.calls[len(fake.calls)-1], "ExecStartPost") {
		t.Fatalf("a deny default needs nothing put back: %q %v", fake.calls[len(fake.calls)-1], err)
	}
	if err := h.ArmUndo(ctx, sysinfo.Firewall{Manager: "firewalld"}, "deny", time.Minute); err != ErrUnsupported {
		t.Fatal(err)
	}
	if h.UndoArmed(ctx) {
		t.Fatal("armed while systemctl says inactive")
	}
	fake.answers["/usr/bin/systemctl is-active autopanel-firewall-undo.timer"] = "active\n"
	if !h.UndoArmed(ctx) {
		t.Fatal("not armed while systemctl says active")
	}
	if err := h.DisarmUndo(ctx); err != nil || fake.calls[len(fake.calls)-1] != "/usr/bin/systemctl stop autopanel-firewall-undo.timer" {
		t.Fatalf("disarm: %v %q", err, fake.calls[len(fake.calls)-1])
	}
}

// TestCommandsForTheAdministrator: the same argument lists as the core's
// own calls, for ufw; firewalld's saved set first; both, labelled, when the
// manager cannot be read; none without a manager.
func TestCommandsForTheAdministrator(t *testing.T) {
	h := New()
	src := rule("allow", "v4", "tcp", 22, 22)
	src.Source = "192.0.2.0/24"
	c := corefw.Change{Allow: []sysinfo.Rule{rule("allow", "both", "tcp", 993, 993), src}, Revoke: []sysinfo.Rule{rule("allow", "both", "udp", 3478, 3480)}, Enable: true}
	got := h.Commands(sysinfo.Firewall{Manager: "ufw"}, c)
	want := []string{"sudo ufw allow proto tcp from any to any port 993", "sudo ufw allow proto tcp from 192.0.2.0/24 to any port 22",
		"sudo ufw delete allow proto udp from any to any port 3478:3480", "sudo ufw enable"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ufw:\n%q\nwant\n%q", got, want)
	}
	got = h.Commands(sysinfo.Firewall{Manager: "firewalld"}, c)
	want = []string{"sudo firewall-cmd --permanent --add-port=993/tcp", "sudo firewall-cmd --add-port=993/tcp",
		`sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.0.2.0/24" port port="22" protocol="tcp" accept'`,
		`sudo firewall-cmd --add-rich-rule='rule family="ipv4" source address="192.0.2.0/24" port port="22" protocol="tcp" accept'`,
		"sudo firewall-cmd --permanent --remove-port=3478-3480/udp", "sudo firewall-cmd --remove-port=3478-3480/udp",
		"sudo systemctl enable --now firewalld"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("firewalld:\n%q\nwant\n%q", got, want)
	}
	if got := h.Commands(sysinfo.Firewall{Manager: "unknown"}, corefw.Change{Allow: c.Allow[:1]}); len(got) != 3 ||
		got[0] != "with ufw: sudo ufw allow proto tcp from any to any port 993" || got[1] != "with firewalld: sudo firewall-cmd --permanent --add-port=993/tcp" {
		t.Fatalf("unknown: %q", got)
	}
	if got := h.Commands(sysinfo.Firewall{Manager: "none"}, c); got != nil {
		t.Fatalf("none: %q", got)
	}
}
