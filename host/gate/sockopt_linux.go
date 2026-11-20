//go:build linux

package gate

import (
	"errors"
	"net"
	"syscall"
	"unsafe"
)

// socketBuffers fixes a socket's kernel buffers before it is used: on a
// listening socket, every connection it accepts inherits them from its first
// byte; on a dialling one, they hold from the connect. Setting them turns the
// kernel's own growth off for that socket.
func socketBuffers(recv, send int) func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			if recv > 0 { // 0: left to the caller, to set once the connection exists
				if serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, recv); serr != nil {
					return
				}
			}
			serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, send)
		}); err != nil {
			return err
		}
		return serr
	}
}

// socketBuffersOf reads a connection's kernel buffers back, as the kernel
// counts them (twice what was set).
func socketBuffersOf(c syscall.RawConn) (recv, send int, err error) {
	var serr error
	if err := c.Control(func(fd uintptr) {
		if recv, serr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF); serr != nil {
			return
		}
		send, serr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF)
	}); err != nil {
		return 0, 0, err
	}
	return recv, send, serr
}

// shortBacklog sets how many finished connections the kernel keeps waiting to
// be accepted on ln. (Listening again on a listening socket changes only
// that.)
func shortBacklog(ln net.Listener, n int) error {
	sc, ok := ln.(syscall.Conn)
	if !ok {
		return errors.New("gate: the listener is no socket")
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if err := raw.Control(func(fd uintptr) { serr = syscall.Listen(int(fd), n) }); err != nil {
		return err
	}
	return serr
}

// widenWindow lets a connection's receive window grow to what its receive
// buffer now holds. The kernel fixed the most it would advertise when the
// connection was made, from the buffer it had then; with a buffer set by
// hand it never revisits that by itself.
func widenWindow(c syscall.Conn, recvBuffer int) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if err := raw.Control(func(fd uintptr) {
		serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_WINDOW_CLAMP, recvBuffer)
	}); err != nil {
		return err
	}
	return serr
}

// sendQueued is how many bytes a socket still has to send: written to it and
// not yet acknowledged by its peer (SIOCOUTQ).
func sendQueued(c syscall.Conn) (int, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var n int32
	var errno syscall.Errno
	if err := raw.Control(func(fd uintptr) {
		_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TIOCOUTQ, uintptr(unsafe.Pointer(&n)))
	}); err != nil {
		return 0, err
	}
	if errno != 0 {
		return 0, errno
	}
	return int(n), nil
}
