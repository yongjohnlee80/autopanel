package mail

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yongjohnlee80/autopanel/internal/hostcmd"
)

func testRule(root string) Loopback {
	return Loopback{Root: root, GateUser: "autopanel", GateUID: 997, StackUID: 990,
		Forwarded: []int{10993, 10025, 10587, 10465}, Manage: 18480}
}

func TestRules(t *testing.T) {
	got := testRule("/").Rules()
	for _, want := range []string{
		"table inet autopanel_loopback\ndelete table inet autopanel_loopback\ntable inet autopanel_loopback {\n",
		"type filter hook output priority 0; policy accept;",
		`oifname "lo" tcp dport { 10025, 10465, 10587, 10993 } meta skuid != "autopanel" drop`,
		`oifname "lo" tcp dport 18480 meta skuid != 0 drop`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the rule lacks %q:\n%s", want, got)
		}
	}
}

func TestUnitAndDropIn(t *testing.T) {
	l := testRule("/")
	u := l.Unit()
	for _, want := range []string{"After=nftables.service", "PartOf=nftables.service", "Before=user@990.service",
		"Type=oneshot", "RemainAfterExit=yes", "ExecStart=/usr/sbin/nft -f /etc/autopanel/mail-loopback.nft"} {
		if !strings.Contains(u, want) {
			t.Errorf("the unit lacks %q", want)
		}
	}
	d := l.DropIn()
	if !strings.Contains(d, "Wants="+UnitName) || !strings.Contains(d, "After="+UnitName) {
		t.Errorf("the drop-in must order the stack's systemd after the rule: %s", d)
	}
	if strings.Contains(d, "Requires=") {
		t.Error("Requires= would restart the mail stack whenever nftables restarts")
	}
}

func TestWriteFiles(t *testing.T) {
	root := t.TempDir()
	if err := testRule(root).WriteFiles(); err != nil {
		t.Fatal(err)
	}
	for rel, mode := range map[string]os.FileMode{
		"etc/autopanel/mail-loopback.nft":                           0o600,
		"etc/systemd/system/autopanel-mail-loopback.service":        0o644,
		"etc/systemd/system/user@990.service.d/autopanel-mail.conf": 0o644,
	} {
		fi, err := os.Stat(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("%s: %v", rel, err)
		}
		if fi.Mode().Perm() != mode {
			t.Errorf("%s: mode %o, want %o", rel, fi.Mode().Perm(), mode)
		}
	}
}

func TestValid(t *testing.T) {
	for name, mut := range map[string]func(*Loopback){
		"quote in user": func(l *Loopback) { l.GateUser = `autopanel" accept #` },
		"root as stack": func(l *Loopback) { l.StackUID = 0 },
		"no ports":      func(l *Loopback) { l.Forwarded = nil },
		"low port":      func(l *Loopback) { l.Forwarded = []int{25} },
	} {
		l := testRule(t.TempDir())
		mut(&l)
		if err := l.WriteFiles(); err == nil {
			t.Errorf("%s: written, want refused", name)
		}
	}
}

// listing is `nft -j list table inet autopanel_loopback` from nftables 1.0.9,
// with the rule loaded and the gate's user resolved to 997.
const listing = `{"nftables": [{"metainfo": {"version": "1.0.9", "release_name": "Old Doc Yak #3", "json_schema_version": 1}}, {"table": {"family": "inet", "name": "autopanel_loopback", "handle": 8}}, {"chain": {"family": "inet", "table": "autopanel_loopback", "name": "output", "handle": 1, "type": "filter", "hook": "output", "prio": 0, "policy": "accept"}}, {"rule": {"family": "inet", "table": "autopanel_loopback", "chain": "output", "handle": 3, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "lo"}}, {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": {"set": [10025, 10465, 10587, 10993]}}}, {"match": {"op": "!=", "left": {"meta": {"key": "skuid"}}, "right": 997}}, {"drop": null}]}}, {"rule": {"family": "inet", "table": "autopanel_loopback", "chain": "output", "handle": 4, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "lo"}}, {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 18480}}, {"match": {"op": "!=", "left": {"meta": {"key": "skuid"}}, "right": 0}}, {"drop": null}]}}]}`

func TestCompare(t *testing.T) {
	l := testRule("/")
	if st, err := l.compare([]byte(listing)); err != nil || st != StateOK {
		t.Fatalf("the rule as loaded: %s, %v; want ok", st, err)
	}
	for name, edit := range map[string][2]string{
		"another gate uid":   {`"right": 997`, `"right": 1000`},
		"accept, not drop":   {`{"drop": null}]}}, {"rule"`, `{"accept": null}]}}, {"rule"`},
		"a port missing":     {`[10025, 10465, 10587, 10993]`, `[10025, 10465, 10587]`},
		"another hook":       {`"hook": "output"`, `"hook": "input"`},
		"management for all": {`"right": 18480}}, {"match": {"op": "!=", "left": {"meta": {"key": "skuid"}}, "right": 0}}, `, `"right": 18480}}, `},
	} {
		changed := strings.Replace(listing, edit[0], edit[1], 1)
		if changed == listing {
			t.Fatalf("%s: the edit did not apply", name)
		}
		if st, err := l.compare([]byte(changed)); err != nil || st != StateDifferent {
			t.Errorf("%s: %s, %v; want different", name, st, err)
		}
	}
}

// TestOnThisHost loads, checks, flushes and restores the real table. It
// changes the kernel's rules, so it runs only where asked to, as root, on a
// throwaway machine: AUTOPANEL_TEST_NFT=throwaway.
func TestOnThisHost(t *testing.T) {
	if os.Getenv("AUTOPANEL_TEST_NFT") != "throwaway" || os.Geteuid() != 0 {
		t.Skip("changes the kernel's nftables: set AUTOPANEL_TEST_NFT=throwaway, as root, on a throwaway machine")
	}
	ctx := context.Background()
	l := testRule(t.TempDir())
	l.GateUser, l.GateUID = "nobody", 65534 // a user every host has; the check reads ids
	if err := l.WriteFiles(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Remove(ctx) })
	found, reloaded, err := l.Ensure(ctx)
	if err != nil || !reloaded {
		t.Fatalf("first ensure: found %s, reloaded %v, %v", found, reloaded, err)
	}
	if st, err := l.Check(ctx); err != nil || st != StateOK {
		t.Fatalf("after loading: %s, %v", st, err)
	}
	if _, reloaded, err := l.Ensure(ctx); err != nil || reloaded {
		t.Fatalf("a held rule should not be loaded again: reloaded %v, %v", reloaded, err)
	}
	if _, err := hostcmd.Run(ctx, hostcmd.Nft, "delete", "table", "inet", Table); err != nil {
		t.Fatal(err)
	}
	if st, err := l.Check(ctx); err != nil || st != StateMissing {
		t.Fatalf("after a flush: %s, %v; want missing", st, err)
	}
	if found, reloaded, err := l.Ensure(ctx); err != nil || !reloaded || found != StateMissing {
		t.Fatalf("ensure after a flush: found %s, reloaded %v, %v", found, reloaded, err)
	}
}
