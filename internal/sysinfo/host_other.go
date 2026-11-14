//go:build !linux

package sysinfo

import (
	"context"
	"time"
)

// Listeners has no source on this platform.
func Listeners(context.Context) ([]Listener, error) { return nil, ErrUnsupported }

// SSHLogins has no source on this platform.
func SSHLogins(context.Context, int) ([]SSHLogin, error) { return nil, ErrUnsupported }

// ReadHost has no source on this platform.
func ReadHost(string) Host { return Host{} }

// NewSampler has no source on this platform: every read is empty.
func NewSampler() *Sampler {
	return &Sampler{now: time.Now, read: func() (CPUTime, int, []Iface, uint64, uint64, int64) { return CPUTime{}, 0, nil, 0, 0, 0 }}
}
