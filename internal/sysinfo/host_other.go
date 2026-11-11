//go:build !linux

package sysinfo

import "context"

// Listeners has no source on this platform.
func Listeners() ([]Listener, error) { return nil, ErrUnsupported }

// SSHLogins has no source on this platform.
func SSHLogins(context.Context, int) ([]SSHLogin, error) { return nil, ErrUnsupported }

// ReadHost has no source on this platform.
func ReadHost(string) Host { return Host{} }
