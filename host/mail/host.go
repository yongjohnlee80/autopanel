package mail

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	coremail "github.com/yongjohnlee80/autopanel/core/mail"
	"github.com/yongjohnlee80/autopanel/core/services"
	"github.com/yongjohnlee80/autopanel/internal/hostcmd"
)

// Host is core/mail's Host on this machine. It must run as root.
type Host struct {
	Root     string // "/"; a test's directory
	Stacks   string // the stacks' definitions: /etc/autopanel/stacks
	Services string // the stacks' homes: /var/lib/autopanel-services
	GateUser string // the gate's user: the one the loopback rule lets through
	CPUInfo  string // /proc/cpuinfo
}

// New is the host for the units' layout.
func New(stacks, servicesRoot, gateUser string) *Host {
	return &Host{Root: "/", Stacks: stacks, Services: servicesRoot, GateUser: gateUser, CPUInfo: "/proc/cpuinfo"}
}

// x86v2 are the flags of x86-64-v2 as /proc/cpuinfo names them (pni is SSE3).
var x86v2 = []string{"pni", "ssse3", "sse4_1", "sse4_2", "popcnt", "cx16", "lahf_lm"}

// CPU: Stalwart's x86 build needs x86-64-v2, and exits at once on less.
func (h *Host) CPU() error {
	if runtime.GOARCH != "amd64" {
		return nil
	}
	raw, err := os.ReadFile(h.CPUInfo)
	if err != nil {
		return err
	}
	var flags map[string]bool
	for _, line := range strings.Split(string(raw), "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(k) == "flags" {
			flags = map[string]bool{}
			for _, f := range strings.Fields(v) {
				flags[f] = true
			}
			break
		}
	}
	var missing []string
	for _, f := range x86v2 {
		if !flags[f] {
			missing = append(missing, f)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("the processor lacks %s (on a virtual machine, set its CPU type to host or x86-64-v2)", strings.Join(missing, ", "))
	}
	return nil
}

// WriteDefinition writes the mail stack's compose.yaml, root's alone.
func (h *Host) WriteDefinition(_ context.Context, compose []byte) error {
	dir := filepath.Join(h.Stacks, coremail.Stack)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	p := filepath.Join(dir, "compose.yaml")
	tmp := p + ".autopanel-new"
	if err := os.WriteFile(tmp, compose, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// StackUID is the mail stack user's id.
func (h *Host) StackUID(context.Context) (int, error) {
	u, err := user.Lookup(services.UserOf(coremail.Stack))
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(u.Uid)
}

// ErrNoPassword is a start that printed no one-time password: Stalwart is set
// up already, or has not printed it yet.
var ErrNoPassword = errors.New("mail: Stalwart printed no one-time password")

// bannerPassword is the line of Stalwart's first-start banner that holds the
// one-time password: "   password: <it>".
var bannerPassword = regexp.MustCompile(`^\s*password:\s*(\S+)\s*$`)

// FirstPassword reads the one-time password Stalwart printed at or after
// since from the stack user's journal: the last one, which is the current
// start's. It is never logged or kept; the caller uses it at once.
func (h *Host) FirstPassword(ctx context.Context, since time.Time) (string, error) {
	uid, err := h.StackUID(ctx)
	if err != nil {
		return "", err
	}
	deadline := time.Now().Add(30 * time.Second) // the banner comes a moment after the start
	for {
		out, err := hostcmd.Run(ctx, hostcmd.Journalctl, "_UID="+strconv.Itoa(uid), "--since", "@"+strconv.FormatInt(since.Unix(), 10), "-o", "cat", "--no-pager")
		if err != nil {
			return "", err
		}
		found := ""
		for _, line := range strings.Split(string(out), "\n") {
			if m := bannerPassword.FindStringSubmatch(line); m != nil {
				found = m[1]
			}
		}
		if found != "" {
			return found, nil
		}
		if time.Now().After(deadline) {
			return "", ErrNoPassword
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// ErrNotAlone is a mail stack network that holds more than Stalwart's
// container: its subnet cannot be trusted.
var ErrNotAlone = errors.New("mail: the mail stack's network holds containers other than Stalwart's")

// ErrNoForwarder is a stack network Podman does not describe.
var ErrNoForwarder = errors.New("mail: Podman names no subnet for the mail stack's network")

// Forwarder is the subnet of the mail stack's own network, as Podman
// describes it. Rootless forwarding delivers every connection to Stalwart from
// inside that network (with netavark, from the container's own address), and
// the network holds the mail stack's container alone, so it is the one source
// Stalwart may trust PROXY headers from. Read from Podman, never assumed: a
// Podman with pasta, or another network, forwards from elsewhere.
func (h *Host) Forwarder(ctx context.Context) (string, error) {
	uid, err := h.StackUID(ctx)
	if err != nil {
		return "", err
	}
	home := filepath.Join(h.Services, coremail.Stack)
	out, err := hostcmd.Run(ctx, hostcmd.Runuser, "-u", services.UserOf(coremail.Stack), "--", "/usr/bin/env", "-C", home,
		"XDG_RUNTIME_DIR=/run/user/"+strconv.Itoa(uid), "/usr/bin/podman", "network", "inspect", coremail.Stack,
		"--format", "{{range .Subnets}}{{.Subnet}} {{end}}")
	if err != nil {
		return "", err
	}
	// The subnet is trusted because the mail container is alone on it: a
	// second container there could forge a PROXY header past the gate.
	ps, err := hostcmd.Run(ctx, hostcmd.Runuser, "-u", services.UserOf(coremail.Stack), "--", "/usr/bin/env", "-C", home,
		"XDG_RUNTIME_DIR=/run/user/"+strconv.Itoa(uid), "/usr/bin/podman", "ps", "-a", "--filter", "network="+coremail.Stack, "--format", "{{.Names}}")
	if err != nil {
		return "", err
	}
	if names := strings.Fields(string(ps)); len(names) != 1 || names[0] != coremail.Stack+"-stalwart" {
		return "", fmt.Errorf("%w: it holds %v", ErrNotAlone, names)
	}
	for _, f := range strings.Fields(string(out)) {
		p, err := netip.ParsePrefix(f)
		if err != nil || !p.Addr().IsPrivate() || p.Bits() < 8 {
			continue
		}
		if p.Addr().Is4() { // the IPv4 subnet: forwarded connections arrive over IPv4
			return p.Masked().String(), nil
		}
	}
	return "", ErrNoForwarder
}

func (h *Host) loopback(stackUID int) (Loopback, error) {
	if h.GateUser == "" {
		return Loopback{}, errors.New("mail: the gate runs as no user of its own here; the loopback rule needs one")
	}
	u, err := user.Lookup(h.GateUser)
	if err != nil {
		return Loopback{}, err
	}
	gateUID, err := strconv.Atoi(u.Uid)
	if err != nil {
		return Loopback{}, err
	}
	return Loopback{Root: h.Root, GateUser: h.GateUser, GateUID: gateUID, StackUID: stackUID,
		Forwarded: coremail.LoopbackPorts(), Manage: coremail.ManagePort}, nil
}

// InstallLoopback writes the loopback rule, its unit and drop-in, and loads it.
func (h *Host) InstallLoopback(ctx context.Context, stackUID int) error {
	l, err := h.loopback(stackUID)
	if err != nil {
		return err
	}
	return l.Install(ctx)
}

// EnsureLoopback checks the rule and loads it again if the kernel lost it.
func (h *Host) EnsureLoopback(ctx context.Context, stackUID int) (bool, error) {
	l, err := h.loopback(stackUID)
	if err != nil {
		return false, err
	}
	_, reloaded, err := l.Ensure(ctx)
	return reloaded, err
}
