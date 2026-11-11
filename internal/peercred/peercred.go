// Interim copy of AutoDoc's internal/peercred (same author, Apache-2.0), kept
// until golib ships it as server/peercred (ADR Q7, tracked by AutoPanel M1.8).
// Change it there, not here; this copy is deleted when AutoPanel moves over.
//
// Package peercred keeps the daemon's unix socket between processes of one user. The socket is
// the daemon's only access control: no login, no token. Whoever connects can call every verb,
// every route the gate serves among them. So both ends check who is at the other end:
//
//   - the daemon drops a connection whose peer runs as another user (Listener), and a client
//     refuses a daemon that runs as another user (Dial), from the kernel's own record of the peer
//     (SO_PEERCRED on Linux, LOCAL_PEERCRED on macOS), not from a file mode that a umask, a chmod
//     race or a wider directory can open;
//   - the daemon binds only in a directory no other user can write (CheckDir), where nobody can
//     replace its socket, or put their own at its path first, for a client to dial.
//
// The default socket (systemd's 0700 RuntimeDirectory) passes every check; they bite on a socket
// configured into a shared directory such as /tmp.
//
// Concurrency: every function is safe for concurrent use; a Listener is as safe as the listener it
// wraps.
package peercred

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"syscall"
)

// ErrOtherUser is a peer that runs as another user than this process.
var ErrOtherUser = errors.New("peercred: the other end of the socket is another user's process")

// played is the uid a test plays (PlayUser), plus one; 0 while none is played.
var played atomic.Int64

// ourUID is the user both ends must run as: this process's, or the one a test plays.
func ourUID() int {
	if u := played.Load(); u != 0 {
		return int(u - 1)
	}
	return os.Getuid()
}

// PlayUser makes this process expect uid, instead of its own, at the other end of its sockets and
// as their folder's owner, until restore: every real peer is then another user's. It is a test's
// seam, in any package, to show the daemon and its clients refusing another user's process; nothing
// else calls it. A daemon or client running meanwhile reads the new uid at its next check.
// NOTE: process-wide, as the uid it stands for: never from a parallel test (t.Parallel), whose
// neighbours' sockets would see another user too.
func PlayUser(uid int) (restore func()) {
	played.Store(int64(uid) + 1)
	return func() { played.Store(0) }
}

// Check refuses a unix connection whose peer runs as another user than this process. A connection
// that is not a unix socket's is not checked: its peer has no user.
func Check(c net.Conn) error {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return nil
	}
	uid, err := peerUID(uc)
	if errors.Is(err, errUnsupported) {
		return nil // NOTE: no peer record on this platform: the socket's 0600 mode is the lock
	}
	if err != nil {
		return fmt.Errorf("peercred: reading the peer's user: %w", err)
	}
	if uid != ourUID() {
		return fmt.Errorf("%w (uid %d)", ErrOtherUser, uid)
	}
	return nil
}

// PeerPID is the process at the other end of a unix connection, from the kernel's record of it
// when it connected: what binds a socket to the process that was meant to hold it (a waker checks
// it before every wake). Unlike Check, it never passes for want of a record: a connection that is
// not a unix socket's, or a platform with no record, answers an error.
func PeerPID(c net.Conn) (int, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, errors.New("peercred: not a unix socket's connection: no peer process")
	}
	pid, err := peerPID(uc)
	if err != nil {
		return 0, fmt.Errorf("peercred: reading the peer's process: %w", err)
	}
	return pid, nil
}

// Dial connects to addr on network, refusing (and closing) a unix connection whose listener runs
// as another user. Its signature is golib rpc's WithConnDialer's.
func Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	if err := Check(c); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	return c, nil
}

// Listener is ln that drops, without a byte, each connection Check refuses; refused, when not nil,
// is told why. Accept returns only the connections of this user's processes, and ln's own errors.
func Listener(ln net.Listener, refused func(error)) net.Listener {
	return &listener{Listener: ln, refused: refused}
}

type listener struct {
	net.Listener
	refused func(error)
}

func (l *listener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if err := Check(c); err != nil {
			_ = c.Close()
			if l.refused != nil {
				l.refused(err)
			}
			continue
		}
		return c, nil
	}
}

// UnsafeDirError is a socket directory another user could write in.
type UnsafeDirError struct {
	Dir, Why string
}

func (e *UnsafeDirError) Error() string {
	return fmt.Sprintf("the socket's folder %s %s: another user could replace the socket there, or bind its own first; "+
		"set server.socket in a folder only you can write (the default, $XDG_RUNTIME_DIR, is one)", e.Dir, e.Why)
}

// CheckDir refuses dir as a socket's folder unless it is a folder owned by this user (or by root),
// that neither its group nor others can write. A sticky world-writable folder such as /tmp is
// refused too: the sticky bit stops another user from removing the socket, not from binding at its
// path before the daemon does.
func CheckDir(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return &UnsafeDirError{Dir: dir, Why: "is not a folder"}
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != ourUID() && st.Uid != 0 {
		return &UnsafeDirError{Dir: dir, Why: fmt.Sprintf("belongs to another user (uid %d)", st.Uid)}
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return &UnsafeDirError{Dir: dir, Why: fmt.Sprintf("can be written by its group or by others (mode %#o)", fi.Mode().Perm())}
	}
	return nil
}
