package sysinfo

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
)

type fakeProc struct {
	exe string
	fds []string
}

// procTree writes a process table of the test's own: the socket tables, and
// for each process its executable and its open files.
func procTree(t *testing.T, procs map[int]fakeProc) string {
	t.Helper()
	root := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(root, "net"), 0o755))
	must(os.WriteFile(filepath.Join(root, "net", "tcp"), []byte(procTCP), 0o644))
	must(os.WriteFile(filepath.Join(root, "net", "udp"), []byte(procUDP), 0o644))
	must(os.WriteFile(filepath.Join(root, "uptime"), []byte("1 1\n"), 0o644)) // an entry that is no process
	for pid, p := range procs {
		dir := filepath.Join(root, strconv.Itoa(pid))
		must(os.MkdirAll(filepath.Join(dir, "fd"), 0o755))
		if p.exe != "" {
			must(os.Symlink(p.exe, filepath.Join(dir, "exe")))
		}
		for i, target := range p.fds {
			must(os.Symlink(target, filepath.Join(dir, "fd", strconv.Itoa(i))))
		}
	}
	return root
}

// TestListenersNameWhoHoldsEachSocket: a socket is matched to the processes
// that hold it by its inode, and a process is named by its executable, never
// by a name it chose. Workers sharing a socket are one row under the lowest
// PID; a socket no readable process holds keeps its user and has no process.
func TestListenersNameWhoHoldsEachSocket(t *testing.T) {
	defer func(r string) { procRoot = r }(procRoot)
	procRoot = procTree(t, map[int]fakeProc{
		612: {"/usr/sbin/sshd", []string{"/dev/null", "socket:[1234]", "socket:[99999]"}},
		1:   {"/usr/lib/systemd/systemd", []string{"socket:[1234]"}},
		177: {"/usr/local/bin/autopanel (deleted)", []string{"socket:[1237]", "pipe:[77]", "socket:[1237]"}},
		701: {"/usr/sbin/ng\x1b[31minx", []string{"socket:[1235]"}},
		700: {"/usr/sbin/ng\x1b[31minx", []string{"socket:[1235]"}},
		900: {"", []string{"socket:[3234]"}}, // its executable cannot be read
		// 3235 (udp 53) is held by a process this one may not read: it has no entry.
	})
	got, err := Listeners(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []Listener{
		{Proto: "tcp", Address: "0.0.0.0", Port: 22, UID: 0, Process: "systemd, sshd", PID: 1, inode: 1234},
		{Proto: "udp", Address: "127.0.0.53", Port: 53, UID: 101, inode: 3235},
		{Proto: "tcp", Address: "0.0.0.0", Port: 443, UID: 999, Process: "autopanel", PID: 177, inode: 1237},
		{Proto: "udp", Address: "0.0.0.0", Port: 3478, UID: 110, Process: "?", PID: 900, inode: 3234},
		{Proto: "tcp", Address: "127.0.0.1", Port: 8080, UID: 999, Process: "ng[31minx", PID: 700, inode: 1235},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("listeners =\n%+v\nwant\n%+v", got, want)
	}
}

// TestListenersWithoutATableAreUnsupported: a host with no socket table has
// no source, and says so.
func TestListenersWithoutATableAreUnsupported(t *testing.T) {
	defer func(r string) { procRoot = r }(procRoot)
	procRoot = t.TempDir()
	if _, err := Listeners(context.Background()); err != ErrUnsupported {
		t.Fatalf("Listeners = %v; want ErrUnsupported", err)
	}
}
