//go:build !linux && !darwin

package peercred

import "net"

// peerUID has no form here: AutoPanel is built for Linux (and macOS for development).
func peerUID(*net.UnixConn) (int, error) { return 0, errUnsupported }

// peerPID has no form here either.
func peerPID(*net.UnixConn) (int, error) { return 0, errUnsupported }
