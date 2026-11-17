package firewall

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/yongjohnlee80/autopanel/internal/hostcmd"
	"github.com/yongjohnlee80/autopanel/internal/sysinfo"
)

// ErrUnsupported is a manager AutoPanel reads but does not change yet.
var ErrUnsupported = errors.New("firewall: this host's firewall manager is not one AutoPanel can change here")

// Runner runs one of the host's tools: hostcmd.Run on the machine, a fake in a
// test.
type Runner func(ctx context.Context, tool hostcmd.Tool, args ...string) ([]byte, error)

// Host is the firewall of this machine. It must run as root.
type Host struct {
	Root string // "/"; a test's directory, for the files read
	Run  Runner
}

// New is the host's firewall.
func New() *Host { return &Host{Root: "/", Run: hostcmd.Run} }

func (h *Host) path(p string) string { return filepath.Join(h.Root, p) }

func (h *Host) installed(tool hostcmd.Tool) bool {
	_, err := os.Stat(h.path(tool.Path()))
	return err == nil
}

// facts are what decides the host's manager.
func (h *Host) facts(ctx context.Context) (sysinfo.Facts, []byte) {
	var f sysinfo.Facts
	var status []byte
	if f.UfwInstalled = h.installed(hostcmd.Ufw); f.UfwInstalled {
		status, _ = h.Run(ctx, hostcmd.Ufw, "status", "verbose")
		f.UfwActive, _ = sysinfo.ParseUfwStatus(bytes.NewReader(status))
	}
	if f.FirewalldInstalled = h.installed(hostcmd.FirewallCmd); f.FirewalldInstalled {
		out, err := h.Run(ctx, hostcmd.FirewallCmd, "--state")
		f.FirewalldActive = err == nil && strings.TrimSpace(string(out)) == "running"
	}
	out, _ := h.Run(ctx, hostcmd.Systemctl, "is-active", "docker.service")
	f.DockerActive = strings.TrimSpace(string(out)) == "active"
	if js, err := h.Run(ctx, hostcmd.Nft, "-j", "list", "ruleset"); err == nil {
		if rs, err := sysinfo.ParseRuleset(bytes.NewReader(js), f.UfwActive); err == nil {
			f.Ruleset = rs
		}
	}
	return f, status
}

// Read is the host's firewall as its manager reports it. The reads run in the
// core: none of them changes anything.
//
// Decision: docs/decisions/firewall.md#what-is-read
func (h *Host) Read(ctx context.Context) (sysinfo.Firewall, error) {
	facts, status := h.facts(ctx)
	manager, active, limits := facts.Manager()
	fw := sysinfo.Firewall{Manager: manager, Active: active, Default: "allow", Rules: []sysinfo.Rule{}, Limits: limits}
	switch manager {
	case "ufw":
		v4, _ := os.ReadFile(h.path("/etc/ufw/user.rules"))
		v6, _ := os.ReadFile(h.path("/etc/ufw/user6.rules"))
		defaults, _ := os.ReadFile(h.path("/etc/default/ufw"))
		u := sysinfo.UfwFirewall(bytes.NewReader(status), bytes.NewReader(defaults), bytes.NewReader(v4), bytes.NewReader(v6))
		fw.Default, fw.Rules = u.Default, u.Rules
		fw.Limits = append(fw.Limits, u.Limits...)
	case "firewalld":
		return fw, ErrUnsupported
	}
	return fw, nil
}

// Transient is the systemd-run prefix that runs a manager's change as a
// transient system unit, outside the core's sandbox: under the core's
// ProtectKernelTunables, ufw enable skips its kernel settings without a word.
// The unit waits, passes the tool's output and exit code back, and is
// collected when it ends.
//
// Decision: docs/decisions/firewall.md#writes-run-outside-the-sandbox
func Transient(tool hostcmd.Tool, args ...string) []string {
	return append([]string{"--wait", "--pipe", "--collect", "--quiet", "--service-type=exec",
		"--setenv=LC_ALL=C", "--description=AutoPanel: a firewall change", "--", tool.Path()}, args...)
}

// change runs one manager command outside the core's sandbox. Its exit code
// says little (ufw exits 0 when it skipped a rule or found none to delete):
// the caller reads the firewall back to know what happened.
func (h *Host) change(ctx context.Context, tool hostcmd.Tool, args []string) error {
	_, err := h.Run(ctx, hostcmd.SystemdRun, Transient(tool, args...)...)
	return err
}

// Allow makes r on the host's manager.
func (h *Host) Allow(ctx context.Context, fw sysinfo.Firewall, r sysinfo.Rule) error {
	if fw.Manager != "ufw" {
		return ErrUnsupported
	}
	args, err := UfwAllow(r)
	if err != nil {
		return err
	}
	return h.change(ctx, hostcmd.Ufw, args)
}

// Revoke deletes r, a rule read back just before, by its fields.
func (h *Host) Revoke(ctx context.Context, fw sysinfo.Firewall, r sysinfo.Rule) error {
	if fw.Manager != "ufw" {
		return ErrUnsupported
	}
	args, err := UfwRevoke(r)
	if err != nil {
		return err
	}
	return h.change(ctx, hostcmd.Ufw, args)
}

// Default sets the incoming default and answers the one it replaces.
func (h *Host) Default(ctx context.Context, fw sysinfo.Firewall, policy string) (string, error) {
	if fw.Manager != "ufw" {
		return "", ErrUnsupported
	}
	args, err := UfwDefault(policy)
	if err != nil {
		return "", err
	}
	return fw.Default, h.change(ctx, hostcmd.Ufw, args)
}

// Enable turns the manager on or off.
func (h *Host) Enable(ctx context.Context, fw sysinfo.Firewall, on bool) error {
	if fw.Manager != "ufw" {
		return ErrUnsupported
	}
	return h.change(ctx, hostcmd.Ufw, UfwEnable(on))
}
