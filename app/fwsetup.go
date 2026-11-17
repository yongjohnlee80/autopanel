package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	corefw "github.com/yongjohnlee80/autopanel/core/firewall"
	hostfirewall "github.com/yongjohnlee80/autopanel/host/firewall"
	"github.com/yongjohnlee80/autopanel/internal/sysinfo"
)

// firewallSetup is install.sh's firewall step: `autopanel --firewall-setup
// --ports 80,443`. It runs before the core, so it cannot ask the lockout
// guard; its policy needs none. On a host where no firewall is on, it allows
// every port SSH listens on and the gate's ports, from anywhere, then turns
// the firewall on: nothing else is added, nothing removed. Each rule is read
// back. A step that fails takes back the rules this run made and leaves the
// firewall off. Exit 0: on, or left as it was on purpose; 1: it failed and
// changed nothing; 2: bad arguments; 3: no manager is installed.
//
// Decision: docs/decisions/firewall.md#the-installer
func firewallSetup(args []string, stdout, stderr io.Writer) int {
	if len(args) != 2 || args[0] != "--ports" {
		fmt.Fprintln(stderr, "usage: autopanel --firewall-setup --ports <port>[,<port>…]")
		return 2
	}
	var gatePorts []int
	for _, s := range strings.Split(args[1], ",") {
		n, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil || n < 1 || n > 65535 {
			fmt.Fprintf(stderr, "autopanel --firewall-setup: %q is not a port\n", s)
			return 2
		}
		gatePorts = append(gatePorts, n)
	}
	ctx := context.Background()
	h := firewallHost()
	fw, err := h.Read(ctx)
	switch {
	case errors.Is(err, hostfirewall.ErrUnsupported):
		fmt.Fprintf(stdout, "%s is installed and off: AutoPanel does not turn it on here yet. Turn it on with its own tools, allowing SSH and ports %s.\n",
			fw.Manager, args[1])
		return 0
	case err != nil:
		fmt.Fprintln(stderr, "autopanel --firewall-setup: reading the firewall:", err)
		return 1
	case fw.Manager == "unknown":
		fmt.Fprintln(stdout, "Firewall rules not from ufw or firewalld filter this host: left as they are.")
		return 0
	case fw.Active:
		fmt.Fprintf(stdout, "A firewall is on (%s): left as it is. System → Firewall shows it.\n", fw.Manager)
		return 0
	case fw.Manager == "none":
		fmt.Fprintln(stderr, "autopanel --firewall-setup: no firewall manager is installed")
		return 3
	}

	ls, err := readListeners(ctx)
	if err != nil {
		fmt.Fprintln(stderr, "autopanel --firewall-setup: reading the listeners:", err)
		return 1
	}
	eps, complete := corefw.Endpoints(h.SSHFacts(ctx, ls))
	if !complete && len(eps) > 0 {
		// An sshd listener the configuration does not explain may be the one
		// the administrator is on: turning the firewall on could cut it.
		fmt.Fprintln(stderr, "autopanel --firewall-setup: SSH's ports could not all be found; the firewall is left off")
		return 1
	}
	ports := map[int]bool{}
	var sshPorts []int
	for _, e := range eps {
		if !ports[e.Port] {
			ports[e.Port] = true
			sshPorts = append(sshPorts, e.Port)
		}
	}
	if len(sshPorts) == 0 {
		fmt.Fprintln(stderr, "autopanel --firewall-setup: no SSH port was found; the firewall is left off")
		return 1
	}
	for _, p := range gatePorts {
		ports[p] = true
	}
	all := make([]int, 0, len(ports))
	for p := range ports {
		all = append(all, p)
	}
	sort.Ints(all)

	var made []string // identities this run made
	previous := ""    // the incoming default before this run, when it changed it
	undo := func() {
		if previous != "" {
			now, _ := h.Read(context.WithoutCancel(ctx))
			_, _ = h.Default(context.WithoutCancel(ctx), now, previous)
		}
		now, err := h.Read(context.WithoutCancel(ctx))
		if err != nil {
			return
		}
		for _, id := range made {
			for _, r := range now.Rules {
				if r.ID == id {
					_ = h.Revoke(context.WithoutCancel(ctx), now, r)
				}
			}
		}
	}
	any := netip.IPv6Unspecified()
	for _, p := range all {
		if !fw.NeedsRule("tcp", any, p) {
			continue // a rule there already allows it: the administrator's
		}
		r, _ := corefw.AllowRule(corefw.AllowAsk{Proto: "tcp", From: p})
		if err := h.Allow(ctx, fw, r); err != nil {
			undo()
			fmt.Fprintf(stderr, "autopanel --firewall-setup: allowing tcp/%d: %v; the firewall is left off\n", p, err)
			return 1
		}
		after, err := h.Read(ctx)
		id := ""
		for _, x := range after.Rules {
			if x.Modelled && x.Direction == "in" && x.Action == "allow" && x.Proto == "tcp" && x.From == p && x.To == p && x.Source == "" && x.Dest == "" {
				id = x.ID
			}
		}
		if err != nil || id == "" {
			undo()
			fmt.Fprintf(stderr, "autopanel --firewall-setup: tcp/%d was not allowed (read back); the firewall is left off\n", p)
			return 1
		}
		made, fw = append(made, id), after
	}
	// Turned on, the firewall must refuse what no rule allows, and let every
	// one of these ports in: a deny saved earlier in the rules could shadow an
	// allow added after it.
	if fw.Default != "deny" && fw.Default != "reject" {
		prev, err := h.Default(ctx, fw, "deny")
		if err != nil {
			undo()
			fmt.Fprintln(stderr, "autopanel --firewall-setup: setting the default:", err, "; the firewall is left off")
			return 1
		}
		previous = prev
		if fw, err = h.Read(ctx); err != nil {
			undo()
			fmt.Fprintln(stderr, "autopanel --firewall-setup: reading the firewall:", err, "; it is left off")
			return 1
		}
	}
	for _, p := range all {
		if fw.NeedsRule("tcp", any, p) {
			undo()
			fmt.Fprintf(stderr, "autopanel --firewall-setup: a rule already there would still block tcp/%d; the firewall is left off\n", p)
			return 1
		}
	}
	if err := h.Enable(ctx, fw, true); err != nil {
		undo()
		fmt.Fprintln(stderr, "autopanel --firewall-setup: turning it on:", err, "; the firewall is left off")
		return 1
	}
	if on, err := h.Read(ctx); err != nil || !on.Active {
		_ = h.Enable(context.WithoutCancel(ctx), fw, false)
		undo()
		fmt.Fprintln(stderr, "autopanel --firewall-setup: the firewall did not come on; it is left off")
		return 1
	}
	names := make([]string, len(all))
	for i, p := range all {
		names[i] = "tcp/" + strconv.Itoa(p)
	}
	fmt.Fprintf(stdout, "%s is on: incoming connections are refused but for %s (SSH: %s). To undo: %s\n",
		fw.Manager, strings.Join(names, ", "), joinInts(sshPorts), undoCommand(fw))
	return 0
}

func joinInts(ns []int) string {
	s := make([]string, len(ns))
	for i, n := range ns {
		s[i] = strconv.Itoa(n)
	}
	return strings.Join(s, ", ")
}

// undoCommand is how the administrator turns the manager off again.
func undoCommand(fw sysinfo.Firewall) string {
	if fw.Manager == "firewalld" {
		return "systemctl disable --now firewalld"
	}
	return "ufw disable"
}
