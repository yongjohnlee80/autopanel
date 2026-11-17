package sysinfo

import (
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// fakeLogins writes a process table: each pid's sessionid, environ and parent.
func fakeLogins(t *testing.T, procs map[int][3]string) {
	t.Helper()
	root := t.TempDir()
	old := procRoot
	procRoot = root
	t.Cleanup(func() { procRoot = old })
	for pid, p := range procs {
		dir := filepath.Join(root, strconv.Itoa(pid))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for name, content := range map[string]string{"sessionid": p[0], "environ": p[1], "status": "Name:\tx\nPPid:\t" + p[2] + "\n"} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// TestLoginOfThroughSudo: the panel under sudo has no SSH_CONNECTION, its
// parent sudo has the login's; the audit session is the panel's own.
func TestLoginOfThroughSudo(t *testing.T) {
	fakeLogins(t, map[int][3]string{
		300: {"43", "PATH=/usr/bin\x00HOME=/root\x00", "200"},
		200: {"43", "SSH_CONNECTION=192.0.2.20 54042 192.0.2.10 22\x00USER=admin\x00", "100"},
		100: {"43", "SSH_CONNECTION=198.51.100.9 1 192.0.2.10 22\x00", "1"},
		400: {"4294967295", "", "1"},
		500: {"7", "", "500"}, // a loop: bounded
	})
	l := LoginOf(300)
	if l.Session != "43" || !l.SSH() || l.Client != netip.MustParseAddrPort("192.0.2.20:54042") || l.Server != netip.MustParseAddrPort("192.0.2.10:22") {
		t.Fatalf("through sudo = %+v", l)
	}
	if l := LoginOf(400); l.Session != "" || l.SSH() {
		t.Fatalf("a service = %+v", l)
	}
	if l := LoginOf(500); l.Session != "7" || l.SSH() {
		t.Fatalf("a loop = %+v", l)
	}
	if l := LoginOf(999); l.Session != "" || l.SSH() {
		t.Fatalf("a process that is gone = %+v", l)
	}
	for _, bad := range []string{"", "1.2.3.4 22 5.6.7.8", "x 1 5.6.7.8 22", "1.2.3.4 70000 5.6.7.8 22"} {
		if _, _, ok := ParseSSHConnection(bad); ok {
			t.Errorf("%q parsed", bad)
		}
	}
}
