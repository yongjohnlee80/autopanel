package firewall

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"strings"

	corefw "github.com/yongjohnlee80/autopanel/core/firewall"
	"github.com/yongjohnlee80/autopanel/internal/hostcmd"
	"github.com/yongjohnlee80/autopanel/internal/sysinfo"
)

// sshSockets are the socket units a socket-activated sshd uses: Debian's and
// Ubuntu's, and Fedora's.
var sshSockets = []string{"ssh.socket", "sshd.socket"}

// SSHFacts reads what the lockout guard finds SSH's endpoints from: the
// active socket unit's Listen lines, sshd -T, the listeners, and the
// families the kernel has.
//
// Decision: docs/decisions/firewall.md#no-lockout
func (h *Host) SSHFacts(ctx context.Context, listeners []sysinfo.Listener) corefw.SSHFacts {
	f := corefw.SSHFacts{Listeners: listeners, Families: map[string]bool{"v4": true}}
	if _, err := os.Stat(h.path("/proc/net/if_inet6")); err == nil {
		f.Families["v6"] = true
	}
	for _, unit := range sshSockets {
		out, _ := h.Run(ctx, hostcmd.Systemctl, "show", unit, "-p", "ActiveState", "-p", "Listen")
		active, listen := parseShow(out)
		if active {
			f.Socket = append(f.Socket, listen...)
			if f.Socket == nil {
				f.Socket = []string{}
			}
		}
	}
	if out, err := h.Run(ctx, hostcmd.Sshd, "-T"); err == nil {
		f.Config = string(out)
	}
	return f
}

// parseShow reads systemctl show's ActiveState and Listen lines.
func parseShow(out []byte) (active bool, listen []string) {
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		k, v, _ := strings.Cut(sc.Text(), "=")
		switch k {
		case "ActiveState":
			active = v == "active"
		case "Listen":
			listen = append(listen, v)
		}
	}
	return active, listen
}
