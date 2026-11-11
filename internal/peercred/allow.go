package peercred

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
)

// AutoPanel's addition to the interim copy (see peercred.go): AutoPanel runs as two processes of
// two users, so a socket names who may be at its other end instead of assuming this process's own
// user. Check, Dial and Listener keep that assumption, for the sockets a single user holds.

// Checker decides whether a connection's peer may stay.
type Checker func(net.Conn) error

// Allow admits a unix connection whose peer runs as one of uids. A connection that is not a unix
// socket's is not checked: its peer has no user.
func Allow(uids ...int) Checker {
	return func(c net.Conn) error {
		uc, ok := c.(*net.UnixConn)
		if !ok {
			return nil
		}
		uid, err := peerUID(uc)
		if errors.Is(err, errUnsupported) {
			return nil // NOTE: no peer record on this platform: the socket's mode is the lock
		}
		if err != nil {
			return fmt.Errorf("peercred: reading the peer's user: %w", err)
		}
		for _, u := range uids {
			if u == uid {
				return nil
			}
		}
		return fmt.Errorf("%w (uid %d)", ErrOtherUser, uid)
	}
}

// PeerUID is the user at the other end of a unix connection when it connected. Where the platform
// keeps no record, or c is no unix socket's, it answers this process's own user: the one a private
// socket admits.
func PeerUID(c net.Conn) int {
	if uc, ok := c.(*net.UnixConn); ok {
		if uid, err := peerUID(uc); err == nil {
			return uid
		}
	}
	return os.Getuid()
}

// DialFor is Dial with check in place of Check: it refuses (and closes) a connection whose
// listener check does not admit.
func DialFor(check Checker) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		c, err := d.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		if err := check(c); err != nil {
			_ = c.Close()
			return nil, fmt.Errorf("dial %s: %w", addr, err)
		}
		return c, nil
	}
}

// ListenerFor is Listener with check in place of Check.
func ListenerFor(ln net.Listener, check Checker, refused func(error)) net.Listener {
	return &checkedListener{Listener: ln, check: check, refused: refused}
}

type checkedListener struct {
	net.Listener
	check   Checker
	refused func(error)
}

func (l *checkedListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if err := l.check(c); err != nil {
			_ = c.Close()
			if l.refused != nil {
				l.refused(err)
			}
			continue
		}
		return c, nil
	}
}
