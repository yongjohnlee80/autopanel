package sysinfo

import (
	"net/netip"
	"strconv"
	"strings"
)

// Login is the login a process belongs to: the kernel's audit session, which
// a login gets once and keeps across sudo, and the SSH connection it came in
// on, when it did. The firewall's lockout guard reads it from the panel's
// process: sudo clears SSH_CONNECTION from the environment it passes on, so
// the panel cannot report it itself.
//
// Decision: docs/decisions/firewall.md#no-lockout
type Login struct {
	Session string         // the audit session id; "" when the process has none (a service, not a login)
	Client  netip.AddrPort // the SSH client's address and port; zero when the login is not over SSH
	Server  netip.AddrPort // the address and port it connected to
}

// SSH reports whether the login came in over SSH.
func (l Login) SSH() bool { return l.Client.IsValid() }

// unsetSession is the kernel's audit session id for a process no login made.
const unsetSession = "4294967295"

// ParseSSHConnection reads SSH_CONNECTION's value: the client's address and
// port, then the server's.
func ParseSSHConnection(s string) (client, server netip.AddrPort, ok bool) {
	f := strings.Fields(s)
	if len(f) != 4 {
		return client, server, false
	}
	ca, err1 := netip.ParseAddr(f[0])
	sa, err2 := netip.ParseAddr(f[2])
	cp, err3 := strconv.ParseUint(f[1], 10, 16)
	sp, err4 := strconv.ParseUint(f[3], 10, 16)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		return client, server, false
	}
	return netip.AddrPortFrom(ca.Unmap(), uint16(cp)), netip.AddrPortFrom(sa.Unmap(), uint16(sp)), true
}

// sshFromEnviron is SSH_CONNECTION's value in a process's NUL-separated
// environment, "" for none.
func sshFromEnviron(env []byte) string {
	for _, kv := range strings.Split(string(env), "\x00") {
		if v, ok := strings.CutPrefix(kv, "SSH_CONNECTION="); ok {
			return v
		}
	}
	return ""
}

// ppidOf reads the PPid line of /proc/<pid>/status; 0 when there is none.
func ppidOf(status []byte) int {
	for _, line := range strings.Split(string(status), "\n") {
		if v, ok := strings.CutPrefix(line, "PPid:"); ok {
			n, _ := strconv.Atoi(strings.TrimSpace(v))
			return n
		}
	}
	return 0
}
