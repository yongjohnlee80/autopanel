package app

import (
	"context"
	"errors"
	"github.com/yongjohnlee80/autopanel/core/mail"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/yongjohnlee80/autopanel/core/gate"
	"github.com/yongjohnlee80/autopanel/internal/hostcmd"
	"github.com/yongjohnlee80/autopanel/internal/sysinfo"
)

// fakeHostReads gives sys.checks a host of the test's making: files that
// exist, and what each host tool prints.
func fakeHostReads(t *testing.T, files map[string]string, tools map[string]string) {
	t.Helper()
	r, s, x := readHostFile, statHostFile, runHostTool
	t.Cleanup(func() { readHostFile, statHostFile, runHostTool = r, s, x })
	readHostFile = func(p string) ([]byte, error) {
		if c, ok := files[p]; ok {
			return []byte(c), nil
		}
		return nil, fs.ErrNotExist
	}
	statHostFile = func(p string) (os.FileInfo, error) {
		if _, ok := files[p]; ok {
			return nil, nil
		}
		return nil, fs.ErrNotExist
	}
	runHostTool = func(_ context.Context, tool hostcmd.Tool, args ...string) ([]byte, error) {
		call := strings.Join(append([]string{tool.Path()}, args...), " ")
		if out, ok := tools[call]; ok {
			return []byte(out), nil
		}
		return nil, errors.New("exit status 1")
	}
}

func checkModule(fw sysinfo.Firewall, fwErr error, ls []sysinfo.Listener) *sysModule {
	return &sysModule{
		cfg: Config{HTTPAddr: ":80", HTTPSAddr: ":443"}, table: gate.NewTable[http.Handler](), counts: &counters{},
		log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		listeners: func(context.Context) ([]sysinfo.Listener, error) { return ls, nil },
		firewall:  func(context.Context) (sysinfo.Firewall, error) { return fw, fwErr },
	}
}

func ids(cs []Check) []string {
	var out []string
	for _, c := range cs {
		out = append(out, c.ID+"="+c.Detail)
	}
	return out
}

// TestHostChecksFindThePosture: a host with every finding this read knows,
// alerts first; a clean host has none.
func TestHostChecksFindThePosture(t *testing.T) {
	fakeHostReads(t, map[string]string{
		"/var/run/reboot-required": "",
		"/etc/group":               "root:x:0:\ndocker:x:998:johno,ci\n",
	}, map[string]string{
		"/usr/bin/systemctl --failed --plain --no-legend --no-pager": "a.service loaded failed failed A\nb.service loaded failed failed B\n",
		"/usr/bin/systemctl is-active " + undoTimer:                  "active\n",
		"/usr/bin/systemctl is-active docker.service docker.socket":  "active\ninactive\n",
		"/usr/bin/systemctl is-enabled podman.socket":                "enabled\n",
		"/usr/sbin/sshd -T": "port 22\npasswordauthentication yes\n",
	})
	fw := sysinfo.Firewall{Manager: "ufw", Active: true, Default: "deny", Limits: []string{sysinfo.LimitDocker, sysinfo.LimitIPv6Unmanaged},
		Rules: []sysinfo.Rule{{Action: "allow", Direction: "in", Family: "v4", Proto: "tcp", From: 8443, To: 8443, Modelled: true, Runtime: true, Seq4: 1, Raw: "allow 8443"}}}
	m := checkModule(fw, nil, []sysinfo.Listener{
		{Proto: "tcp", Address: "0.0.0.0", Port: 443, UID: sysinfo.NoUID},
		{Proto: "tcp", Address: "0.0.0.0", Port: 22, UID: 0, Process: "sshd"},
	})
	got, err := m.checks(context.Background(), struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"unit-failed=a.service, b.service", "gate-port-blocked=tcp/443", "firewall-unconfirmed=",
		"docker-group=johno, ci", "ssh-password=",
		"reboot-required=", "firewall-partial=docker-rules", "ufw-ipv6-off=", "firewall-stale=tcp/8443",
		"docker-present=", "podman-system-socket=",
	}
	if !reflect.DeepEqual(ids(got), want) {
		t.Fatalf("checks =\n%q\nwant\n%q", ids(got), want)
	}

	fakeHostReads(t, map[string]string{"/etc/group": "docker:x:998:\n"}, map[string]string{
		"/usr/sbin/sshd -T": "passwordauthentication no\n",
	})
	clean := checkModule(sysinfo.Firewall{Manager: "ufw", Active: true, Default: "deny", Limits: []string{}}, nil, nil)
	if got, _ := clean.checks(context.Background(), struct{}{}); len(got) != 0 {
		t.Fatalf("a clean host: %q", ids(got))
	}
}

// TestHostChecksOnTheFirewallsState: off is an alert; a manager AutoPanel
// cannot read is not called off; more checks from other modules join in.
func TestHostChecksOnTheFirewallsState(t *testing.T) {
	fakeHostReads(t, nil, nil)
	ctx := context.Background()
	for _, c := range []struct {
		fw   sysinfo.Firewall
		want []string
	}{
		{sysinfo.Firewall{Manager: "ufw", Limits: []string{}}, []string{"firewall-off=ufw"}},
		{sysinfo.Firewall{Manager: "none", Limits: []string{}}, []string{"firewall-off=none"}},
		{sysinfo.Firewall{Manager: "unknown", Active: true, Limits: []string{}}, nil},
	} {
		got, _ := checkModule(c.fw, nil, nil).checks(ctx, struct{}{})
		if !reflect.DeepEqual(ids(got), c.want) {
			t.Errorf("%s: %q, want %q", c.fw.Manager, ids(got), c.want)
		}
	}
	m := checkModule(sysinfo.Firewall{}, errors.New("unreadable"), nil)
	m.moreChecks = func(context.Context, sysinfo.Firewall) []Check {
		return []Check{{ID: "cert-expiring", Severity: notice, Detail: "example.com"}}
	}
	if got, _ := m.checks(ctx, struct{}{}); len(got) != 0 {
		t.Errorf("an unreadable firewall gives the others nothing to judge: %q", ids(got))
	}
	m.firewall = func(context.Context) (sysinfo.Firewall, error) {
		return sysinfo.Firewall{Manager: "unknown", Active: true}, nil
	}
	if got, _ := m.checks(ctx, struct{}{}); !reflect.DeepEqual(ids(got), []string{"cert-expiring=example.com"}) {
		t.Errorf("one more check: %q", ids(got))
	}
}

// TestMailsFindingsAreHostChecks: what mail finds wrong is listed with the
// rest, an alert as an alert, and whether or not the firewall could be read.
func TestMailsFindingsAreHostChecks(t *testing.T) {
	fakeHostReads(t, nil, nil)
	for _, fwErr := range []error{nil, errors.New("the firewall could not be read")} {
		m := checkModule(sysinfo.Firewall{Manager: "unknown", Active: true, Limits: []string{}}, fwErr, nil)
		m.mailFindings = func(context.Context) []mail.Finding {
			return []mail.Finding{{ID: "mail-ptr", Detail: "192.0.2.10 → nothing, not mail.example.com"}, {ID: "mail-port-25", Alert: true}}
		}
		got, err := m.checks(context.Background(), struct{}{})
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"mail-port-25=", "mail-ptr=192.0.2.10 → nothing, not mail.example.com"}
		if !reflect.DeepEqual(ids(got), want) || got[0].Severity != alert || got[1].Severity != notice {
			t.Errorf("with the firewall read failing %v: %+v, want %q", fwErr != nil, got, want)
		}
	}
}
