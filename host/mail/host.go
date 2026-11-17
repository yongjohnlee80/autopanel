package mail

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
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

// CPU is the processor: its architecture and its /proc/cpuinfo flags (none
// on an architecture whose cpuinfo names none). Whether the mail server runs
// on it is its product's to say.
func (h *Host) CPU() (string, map[string]bool, error) {
	flags := map[string]bool{}
	raw, err := os.ReadFile(h.CPUInfo)
	if err != nil {
		return runtime.GOARCH, nil, err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(k) == "flags" {
			for _, f := range strings.Fields(v) {
				flags[f] = true
			}
			break
		}
	}
	return runtime.GOARCH, flags, nil
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

// RemoveDefinition takes the mail stack's folder out of the stacks'
// directory: the undo of WriteDefinition when a setup fails before its stack
// is registered. The folder holds only what WriteDefinition wrote.
func (h *Host) RemoveDefinition(context.Context) error {
	return os.RemoveAll(filepath.Join(h.Stacks, coremail.Stack))
}

// StackUID is the mail stack user's id.
func (h *Host) StackUID(context.Context) (int, error) {
	u, err := user.Lookup(services.UserOf(coremail.Stack))
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(u.Uid)
}

// Journal is what the mail stack's user printed at or after since, line by
// line. It may hold a secret (a first start's credential): the caller reads
// it and keeps nothing.
func (h *Host) Journal(ctx context.Context, since time.Time) ([]string, error) {
	uid, err := h.StackUID(ctx)
	if err != nil {
		return nil, err
	}
	out, err := hostcmd.Run(ctx, hostcmd.Journalctl, "_UID="+strconv.Itoa(uid), "--since", "@"+strconv.FormatInt(since.Unix(), 10), "-o", "cat", "--no-pager")
	if err != nil {
		return nil, err
	}
	return strings.Split(string(out), "\n"), nil
}

// ErrNotAlone is a mail stack network that holds more than the mail
// server's container: its subnet cannot be trusted.
var ErrNotAlone = errors.New("mail: the mail stack's network holds containers other than the mail server's")

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

// RemoveLoopback takes the rule out of the kernel and its files off the host:
// the undo of InstallLoopback when a setup fails.
func (h *Host) RemoveLoopback(ctx context.Context, stackUID int) error {
	l, err := h.loopback(stackUID)
	if err != nil {
		return err
	}
	return l.Remove(ctx)
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

// PublicIPv4 is the host's one global IPv4 address, for the mail host's A
// record: "" when it has none (behind NAT) or several (which one mail leaves
// from is then not known), so the record is left to the administrator.
func (h *Host) PublicIPv4(context.Context) (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}
	var found []string
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipn.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		if ip.Is4() && ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !cgnat.Contains(ip) {
			found = append(found, ip.String())
		}
	}
	if len(found) != 1 {
		return "", nil
	}
	return found[0], nil
}

// cgnat is the shared address space (RFC 6598): never a public address.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// publicResolvers answer what the world sees of a zone, not this host's cache.
var publicResolvers = []string{"1.1.1.1:53", "8.8.8.8:53"}

// ResolveTXT asks public resolvers for a name's TXT records: each in turn,
// the first that answers.
func (h *Host) ResolveTXT(ctx context.Context, name string) ([]string, error) {
	var last error
	for _, server := range publicResolvers {
		r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, network, server)
		}}
		cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		txt, err := r.LookupTXT(cctx, name)
		cancel()
		if err == nil {
			return txt, nil
		}
		last = err
	}
	return nil, last
}
