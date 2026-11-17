package app

import (
	"context"
	"time"

	corefw "github.com/yongjohnlee80/autopanel/core/firewall"
	"github.com/yongjohnlee80/autopanel/internal/sysinfo"
)

// fakeFirewall is a host firewall a test sets: its reads answer fw, its
// changes do nothing. A test of the core reads no real firewall.
type fakeFirewall struct{ fw sysinfo.Firewall }

func (f *fakeFirewall) Read(context.Context) (sysinfo.Firewall, error)               { return f.fw, nil }
func (f *fakeFirewall) Allow(context.Context, sysinfo.Firewall, sysinfo.Rule) error  { return nil }
func (f *fakeFirewall) Revoke(context.Context, sysinfo.Firewall, sysinfo.Rule) error { return nil }
func (f *fakeFirewall) Default(_ context.Context, fw sysinfo.Firewall, _ string) (string, error) {
	return fw.Default, nil
}
func (f *fakeFirewall) Enable(context.Context, sysinfo.Firewall, bool) error { return nil }
func (f *fakeFirewall) SSHFacts(context.Context, []sysinfo.Listener) corefw.SSHFacts {
	return corefw.SSHFacts{}
}
func (f *fakeFirewall) ArmUndo(context.Context, sysinfo.Firewall, string, time.Duration) error {
	return nil
}
func (f *fakeFirewall) DisarmUndo(context.Context) error                  { return nil }
func (f *fakeFirewall) UndoArmed(context.Context) bool                    { return false }
func (f *fakeFirewall) Commands(sysinfo.Firewall, corefw.Change) []string { return nil }

// useFirewall makes the cores a test starts read fw.
func useFirewall(fw sysinfo.Firewall) (restore func()) {
	old := firewallHost
	firewallHost = func() corefw.Host { return &fakeFirewall{fw: fw} }
	return func() { firewallHost = old }
}
