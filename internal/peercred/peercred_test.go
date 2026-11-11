package peercred

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// playAnotherUser makes this process expect another uid than its own (PlayUser), so every real peer
// (this test's own connections) is "another user's", until the restore it answers with, or the
// test's end.
func playAnotherUser(t *testing.T) (restore func()) {
	t.Helper()
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("no peer credentials on " + runtime.GOOS)
	}
	restore = PlayUser(os.Getuid() + 1)
	t.Cleanup(restore)
	return restore
}

// socketIn listens on a unix socket in a fresh short directory.
func socketIn(t *testing.T) (net.Listener, string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "pc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "s.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	return ln, path
}

// serve accepts on ln until it closes, handing each connection to accepted; the returned wait
// closes ln and waits for the loop to end.
func serve(ln net.Listener, accepted chan<- net.Conn) (wait func()) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	return func() { _ = ln.Close(); <-done }
}

// TestTheDaemonDropsAnotherUsersConnection: a connection whose peer is another user's process is
// closed before a byte is read, said to refused, and never returned by Accept. The control: the
// same listener, expecting this user, hands the same kind of connection on.
func TestTheDaemonDropsAnotherUsersConnection(t *testing.T) {
	raw, path := socketIn(t)
	refused := make(chan error, 1)
	accepted := make(chan net.Conn, 1)
	ln := Listener(raw, func(err error) { refused <- err })

	restore := playAnotherUser(t)
	wait := serve(ln, accepted)
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	select {
	case err := <-refused:
		if !errors.Is(err, ErrOtherUser) {
			t.Fatalf("refused with %v, want ErrOtherUser", err)
		}
	case a := <-accepted:
		_ = a.Close()
		t.Fatal("another user's connection was accepted")
	case <-time.After(5 * time.Second):
		t.Fatal("the connection was neither accepted nor refused")
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := c.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
		t.Errorf("the refused connection read %d, %v; want it closed (EOF)", n, err)
	}
	wait()

	restore() // the control: this user's connection is handed on
	raw2, path2 := socketIn(t)
	wait2 := serve(Listener(raw2, func(err error) { t.Errorf("this user's connection refused: %v", err) }), accepted)
	defer wait2()
	c2, err := net.Dial("unix", path2)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	select {
	case a := <-accepted:
		_ = a.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("this user's connection was not accepted")
	}
}

// TestAClientRefusesAnotherUsersDaemon: Dial closes and refuses a socket whose listener is another
// user's process (a socket put at the daemon's path first); this user's is dialled.
func TestAClientRefusesAnotherUsersDaemon(t *testing.T) {
	raw, path := socketIn(t)
	accepted := make(chan net.Conn, 4)
	wait := serve(raw, accepted)
	defer wait()
	ctx := context.Background()

	c, err := Dial(ctx, "unix", path)
	if err != nil {
		t.Fatalf("this user's daemon: %v", err)
	}
	_ = c.Close()

	playAnotherUser(t)
	if c, err := Dial(ctx, "unix", path); !errors.Is(err, ErrOtherUser) {
		if c != nil {
			_ = c.Close()
		}
		t.Fatalf("another user's daemon: %v, want ErrOtherUser", err)
	}
}

// TestCheckDir: a socket's folder that its group or others can write, sticky or not, is refused,
// as is one of another owner and a file; a folder only its owner writes is taken.
func TestCheckDir(t *testing.T) {
	dir := t.TempDir()
	for _, mode := range []os.FileMode{0o700, 0o755, 0o750} {
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		if err := CheckDir(dir); err != nil {
			t.Errorf("mode %#o: %v", mode, err)
		}
	}
	var unsafe *UnsafeDirError
	for _, mode := range []os.FileMode{0o770, 0o707, 0o777, 0o777 | os.ModeSticky} {
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		if err := CheckDir(dir); !errors.As(err, &unsafe) {
			t.Errorf("mode %v: %v, want an UnsafeDirError", mode, err)
		}
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckDir(file); !errors.As(err, &unsafe) {
		t.Errorf("a file: %v, want an UnsafeDirError", err)
	}
	if os.Getuid() == 0 {
		// run as root (a container), the folder is root's, which CheckDir accepts by design: make it
		// another, unprivileged user's
		if err := os.Chown(dir, 54321, -1); err != nil {
			t.Fatal(err)
		}
	}
	playAnotherUser(t)
	if err := CheckDir(dir); !errors.As(err, &unsafe) {
		t.Errorf("another user's folder: %v, want an UnsafeDirError", err)
	}
}

// PeerPID names the process at the other end, from each end of a unix connection (here this test's
// own process at both), and refuses a connection that is not a unix socket's rather than pass.
func TestPeerPIDNamesTheProcessAtTheOtherEnd(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("no peer process record on " + runtime.GOOS)
	}
	ln, path := socketIn(t)
	accepted := make(chan net.Conn, 1)
	defer serve(ln, accepted)()
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	server := <-accepted
	defer server.Close()
	for end, conn := range map[string]net.Conn{"client": c, "server": server} {
		if pid, err := PeerPID(conn); err != nil || pid != os.Getpid() {
			t.Errorf("PeerPID at the %s's end: %d, %v; want this process, %d", end, pid, err, os.Getpid())
		}
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if _, err := PeerPID(a); err == nil {
		t.Error("PeerPID of a pipe answered a process, rather than refusing")
	}
}
