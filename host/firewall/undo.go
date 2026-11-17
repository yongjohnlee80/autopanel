package firewall

import (
	"context"
	"strconv"
	"strings"
	"time"

	corefw "github.com/yongjohnlee80/autopanel/core/firewall"
	"github.com/yongjohnlee80/autopanel/internal/hostcmd"
	"github.com/yongjohnlee80/autopanel/internal/sysinfo"
)

// UndoUnit is the transient unit an enable arms: one name, so the confirm,
// a disable and Host checks all reach the same one.
const UndoUnit = "autopanel-firewall-undo"

// ArmUndo arms a transient timer that turns the firewall off after d and puts
// the incoming default back to previous. It is a system unit: it fires even if
// the core restarts or stops in between.
//
// Decision: docs/decisions/firewall.md#enabling
func (h *Host) ArmUndo(ctx context.Context, fw sysinfo.Firewall, previous string, d time.Duration) error {
	if fw.Manager != "ufw" {
		return ErrUnsupported
	}
	_, _ = h.Run(ctx, hostcmd.Systemctl, "reset-failed", UndoUnit+".timer", UndoUnit+".service")
	args := []string{"--unit=" + UndoUnit, "--on-active=" + strconv.Itoa(int(d/time.Second)) + "s",
		"--timer-property=AccuracySec=1s", "--collect", "--setenv=LC_ALL=C",
		"--description=AutoPanel: turn off a firewall enable nobody confirmed"}
	if def, err := UfwDefault(previous); err == nil && previous != "deny" {
		args = append(args, "--property=ExecStartPost="+hostcmd.Ufw.Path()+" "+strings.Join(def, " "))
	}
	args = append(args, "--", hostcmd.Ufw.Path())
	_, err := h.Run(ctx, hostcmd.SystemdRun, append(args, UfwEnable(false)...)...)
	return err
}

// DisarmUndo stops the timer: the enable is kept.
func (h *Host) DisarmUndo(ctx context.Context) error {
	_, err := h.Run(ctx, hostcmd.Systemctl, "stop", UndoUnit+".timer")
	return err
}

// UndoArmed reports whether the timer waits.
func (h *Host) UndoArmed(ctx context.Context) bool {
	out, _ := h.Run(ctx, hostcmd.Systemctl, "is-active", UndoUnit+".timer")
	return strings.TrimSpace(string(out)) == "active"
}

// Commands are the command lines that would make c by hand, built by the
// same code as the core's own calls. For a host whose manager AutoPanel
// cannot read, each line is given for both managers, labelled.
//
// Decision: docs/decisions/firewall.md#instructions
func (h *Host) Commands(fw sysinfo.Firewall, c corefw.Change) []string {
	switch fw.Manager {
	case "ufw":
		return ufwLines(c)
	case "firewalld":
		return firewalldLines(c)
	case "unknown":
		var out []string
		for _, l := range ufwLines(c) {
			out = append(out, "with ufw: "+l)
		}
		for _, l := range firewalldLines(c) {
			out = append(out, "with firewalld: "+l)
		}
		return out
	}
	return nil
}

func ufwLines(c corefw.Change) []string {
	var out []string
	for _, r := range c.Allow {
		if args, err := ufwRule(r); err == nil {
			out = append(out, "sudo ufw "+strings.Join(args, " "))
		}
	}
	for _, r := range c.Revoke {
		if args, err := UfwRevoke(r); err == nil {
			out = append(out, "sudo ufw "+strings.Join(args, " "))
		}
	}
	if c.Enable {
		out = append(out, "sudo ufw enable")
	}
	return out
}

// firewalldLines write each rule into the default zone, saved and running:
// the saved set first.
func firewalldLines(c corefw.Change) []string {
	var out []string
	add := func(verb string, r sysinfo.Rule) {
		what, ok := firewalldWhat(verb, r)
		if !ok {
			return
		}
		out = append(out, "sudo firewall-cmd --permanent "+what, "sudo firewall-cmd "+what)
	}
	for _, r := range c.Allow {
		add("add", r)
	}
	for _, r := range c.Revoke {
		add("remove", r)
	}
	if c.Enable {
		out = append(out, "sudo systemctl enable --now firewalld")
	}
	return out
}

// firewalldWhat is the --add or --remove argument for r: a port, or a rich
// rule when it names an address or a single family.
func firewalldWhat(verb string, r sysinfo.Rule) (string, bool) {
	if (r.Proto != "tcp" && r.Proto != "udp") || r.From < 1 || r.To < r.From {
		return "", false
	}
	ports := strconv.Itoa(r.From)
	if r.To != r.From {
		ports += "-" + strconv.Itoa(r.To)
	}
	if r.Source == "" && r.Dest == "" && r.Family == "both" {
		return "--" + verb + "-port=" + ports + "/" + r.Proto, true
	}
	fam := map[string]string{"v4": "ipv4", "v6": "ipv6"}[r.Family]
	if fam == "" {
		return "", false
	}
	rule := `rule family="` + fam + `"`
	if r.Source != "" {
		rule += ` source address="` + r.Source + `"`
	}
	if r.Dest != "" {
		rule += ` destination address="` + r.Dest + `"`
	}
	rule += ` port port="` + ports + `" protocol="` + r.Proto + `" accept`
	return "--" + verb + "-rich-rule='" + rule + "'", true
}

var _ corefw.Host = (*Host)(nil)
