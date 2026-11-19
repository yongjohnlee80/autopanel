package app

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yongjohnlee80/autopanel/internal/hostcmd"
	"github.com/yongjohnlee80/autopanel/internal/module"
	"github.com/yongjohnlee80/autopanel/internal/sysinfo"
)

// HOST CHECKS — the host's posture, as findings that hold now: each one a
// cheap read by the root core, never a scan of the file system.
//
// Decision: docs/decisions/firewall.md#host-checks

// Check is one posture finding. ID is constant and is the panel's message;
// Detail is data for it (unit names, ports, a count), never prose.
type Check struct {
	ID       string `json:"id"`
	Severity string `json:"severity"` // "notice" or "alert"
	Detail   string `json:"detail"`
}

// The checks' severities.
const (
	notice = "notice"
	alert  = "alert"
)

// The host reads behind sys.checks. They are variables so a test gives its
// own: a test reads no real host file and runs no host tool.
var (
	readHostFile = os.ReadFile
	statHostFile = os.Stat
	runHostTool  = hostcmd.Run
)

// undoTimer is the transient timer an enable arms to turn the firewall off
// unless it is confirmed.
const undoTimer = "autopanel-firewall-undo.timer"

// checks answers the findings that hold now, alerts first. A read that fails
// leaves its check out: Host checks reports what it saw, and the failure goes
// to the log.
func (m *sysModule) checks(ctx context.Context, _ struct{}) ([]Check, error) {
	out := []Check{}
	add := func(id, severity, detail string) {
		out = append(out, Check{ID: id, Severity: severity, Detail: detail})
	}

	if _, err := statHostFile("/var/run/reboot-required"); err == nil {
		add("reboot-required", notice, "")
	}
	if units := failedUnits(ctx); len(units) > 0 {
		add("unit-failed", alert, strings.Join(units, ", "))
	}

	fw, fwErr := m.firewallRead(ctx)
	ports, _ := m.portRows(ctx, fw, fwErr)
	if fwErr == nil {
		if fw.Manager == "none" || (fw.Manager != "unknown" && !fw.Active) {
			add("firewall-off", alert, fw.Manager)
		}
		var partial []string
		for _, l := range fw.Limits {
			if l != sysinfo.LimitIPv6Unmanaged {
				partial = append(partial, l)
			}
		}
		if len(partial) > 0 {
			add("firewall-partial", notice, strings.Join(partial, ", "))
		}
		if fw.Manager == "ufw" && fw.Has(sysinfo.LimitIPv6Unmanaged) {
			add("ufw-ipv6-off", notice, "")
		}
	}
	var stale, gateBlocked []string
	for _, p := range ports {
		switch {
		case p.Firewall == sysinfo.VerdictStale:
			stale = append(stale, portKey(p))
		case p.Firewall == sysinfo.VerdictBlocked && strings.HasPrefix(p.Use, "AutoPanel: HTTP"):
			gateBlocked = append(gateBlocked, portKey(p))
		}
	}
	if len(stale) > 0 {
		add("firewall-stale", notice, strings.Join(stale, ", "))
	}
	if len(gateBlocked) > 0 {
		add("gate-port-blocked", alert, strings.Join(uniq(gateBlocked), ", "))
	}
	if out, err := runHostTool(ctx, hostcmd.Systemctl, "is-active", undoTimer); err == nil && strings.TrimSpace(string(out)) == "active" {
		add("firewall-unconfirmed", alert, "")
	}

	if dockerPresent(ctx) {
		add("docker-present", notice, "")
	}
	if members := groupMembers("docker"); len(members) > 0 {
		add("docker-group", alert, strings.Join(members, ", "))
	}
	if out, _ := runHostTool(ctx, hostcmd.Systemctl, "is-enabled", "podman.socket"); strings.TrimSpace(string(out)) == "enabled" {
		add("podman-system-socket", notice, "")
	}
	if sshdSays(ctx, "passwordauthentication", "yes") {
		add("ssh-password", alert, "")
	}
	if m.certRows != nil {
		out = append(out, certChecks(m.certRows(ctx), time.Now())...)
	}
	if m.mailFindings != nil {
		for _, f := range m.mailFindings(ctx) {
			severity := notice
			if f.Alert {
				severity = alert
			}
			add(f.ID, severity, f.Detail)
		}
	}
	if m.tunnelChecks != nil {
		out = append(out, m.tunnelChecks(ctx)...)
	}
	if m.moreChecks != nil && fwErr == nil {
		out = append(out, m.moreChecks(ctx, fw)...)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Severity == alert && out[j].Severity != alert })
	return out, nil
}

// portKey names a port row: "tcp/443", or "tcp/60000-60010" for a range.
func portKey(p Port) string {
	k := p.Proto
	if k == "" {
		k = "tcp+udp"
	}
	k += "/" + strconv.Itoa(p.Port)
	if p.To > p.Port {
		k += "-" + strconv.Itoa(p.To)
	}
	return k
}

func uniq(ss []string) []string {
	var out []string
	for _, s := range ss {
		if len(out) == 0 || out[len(out)-1] != s {
			out = append(out, s)
		}
	}
	return out
}

// failedUnits are the system units systemd reports failed, three at most and
// a count of the rest.
func failedUnits(ctx context.Context) []string {
	out, err := runHostTool(ctx, hostcmd.Systemctl, "--failed", "--plain", "--no-legend", "--no-pager")
	if err != nil {
		return nil
	}
	var units []string
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		if f := strings.Fields(sc.Text()); len(f) > 0 {
			units = append(units, f[0])
		}
	}
	if len(units) > 3 {
		units = append(units[:3], "+"+strconv.Itoa(len(units)-3))
	}
	return units
}

// dockerPresent reports whether Docker is installed or running. systemctl
// exits non-zero when either unit is not active; its lines still say which.
func dockerPresent(ctx context.Context) bool {
	if _, err := statHostFile("/usr/bin/docker"); err == nil {
		return true
	}
	out, _ := runHostTool(ctx, hostcmd.Systemctl, "is-active", "docker.service", "docker.socket")
	for _, line := range strings.Split(string(out), "\n") {
		if line == "active" {
			return true
		}
	}
	return false
}

// groupMembers are the members /etc/group names for group.
func groupMembers(group string) []string {
	raw, err := readHostFile("/etc/group")
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Split(line, ":")
		if len(f) == 4 && f[0] == group && f[3] != "" {
			return strings.Split(f[3], ",")
		}
	}
	return nil
}

// sshdSays reports whether sshd's effective configuration (sshd -T) sets key
// to value. A host without sshd, or a configuration sshd will not print, says
// nothing.
func sshdSays(ctx context.Context, key, value string) bool {
	out, err := runHostTool(ctx, hostcmd.Sshd, "-T")
	if err != nil {
		return false
	}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), " "); ok && k == key {
			return v == value
		}
	}
	return false
}

func (m *sysModule) checkVerbs() []module.Verb {
	return []module.Verb{
		module.Handle(module.Contract{Verb: "sys.checks", Public: true, Discloses: module.Plain, Since: 7, Result: "[{id, severity, detail}]",
			Doc: "The host's posture findings that hold now, alerts first: each a constant id, its severity, and data for its message."}, m.checks),
	}
}
