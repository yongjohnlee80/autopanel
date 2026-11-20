//go:build !linux

package gate

import (
	"errors"
	"net"
	"syscall"
)

// socketBuffers refuses: the gate's bounds are not held on this system, and a
// gate that cannot hold them does not listen.
func socketBuffers(int, int) func(network, address string, c syscall.RawConn) error {
	return func(string, string, syscall.RawConn) error {
		return errors.New("gate: fixed socket buffers are not supported on this system")
	}
}

func socketBuffersOf(syscall.RawConn) (int, int, error) {
	return 0, 0, errors.New("gate: socket buffers cannot be read on this system")
}

func shortBacklog(net.Listener, int) error {
	return errors.New("gate: the accept queue cannot be bounded on this system")
}

func widenWindow(syscall.Conn, int) error { return nil }

func sendQueued(syscall.Conn) (int, error) {
	return 0, errors.New("gate: a socket's queue cannot be read on this system")
}
