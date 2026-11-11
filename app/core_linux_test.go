//go:build linux

package app

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// networkListeners are this process's listening sockets that are not unix
// sockets, by address.
func networkListeners(t *testing.T) map[string]bool {
	t.Helper()
	fds, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, e := range fds {
		fd, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if on, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ACCEPTCONN); err != nil || on == 0 {
			continue // not a socket, or not listening
		}
		sa, err := unix.Getsockname(fd)
		if err != nil {
			continue
		}
		switch a := sa.(type) {
		case *unix.SockaddrInet4:
			out["tcp4:"+strconv.Itoa(a.Port)] = true
		case *unix.SockaddrInet6:
			out["tcp6:"+strconv.Itoa(a.Port)] = true
		}
	}
	return out
}

// TestTheCoreListensOnNoNetwork starts the core alone and looks at the
// sockets the process then listens on: the core holds the store, the vault
// and the administrative rights, so nothing of it may be reachable but its
// two unix sockets.
func TestTheCoreListensOnNoNetwork(t *testing.T) {
	cfg := testConfig(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := Init(ctx, cfg, "root", strings.NewReader("a long master passphrase\n")); err != nil {
		t.Fatal(err)
	}
	before := networkListeners(t)
	done := make(chan error, 1)
	go func() { done <- CoreContext(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), nil) }()
	coreUp(t, cfg, done)
	time.Sleep(200 * time.Millisecond) // anything the core starts after its sockets
	for addr := range networkListeners(t) {
		if !before[addr] {
			t.Errorf("the core listens on %s", addr)
		}
	}
	for _, sock := range []string{cfg.Socket, cfg.LinkSocket} {
		if fi, err := os.Stat(sock); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v, mode %v; want a socket only this user can open", sock, err, fi.Mode().Perm())
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the core stopped with %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the core did not stop")
	}
}
