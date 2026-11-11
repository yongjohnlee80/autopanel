// Package sysinfo reads what the panel's System menu shows of the host: the
// listening sockets, the SSH logins the journal recorded, the load, memory
// and disk. The parsers are pure, over text the host files hold; the reads
// are per platform (host_linux.go), and answer ErrUnsupported elsewhere.
package sysinfo

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ErrUnsupported is a read this platform, or this host, has no source for.
var ErrUnsupported = errors.New("sysinfo: not available on this host")

// Listener is one listening socket: a TCP socket in LISTEN, or a bound UDP
// socket.
type Listener struct {
	Proto   string `json:"proto"`   // "tcp" or "udp"
	Address string `json:"address"` // the local address: "0.0.0.0", "127.0.0.1", "::"
	Port    int    `json:"port"`
}

// procAddr reads /proc/net's address form: the address in hex, each 32-bit
// word in host byte order (little-endian on every platform AutoPanel is built
// for), then ":" and the port in hex.
func procAddr(s string) (netip.Addr, int, bool) {
	host, port, ok := strings.Cut(s, ":")
	if !ok || (len(host) != 8 && len(host) != 32) {
		return netip.Addr{}, 0, false
	}
	p, err := strconv.ParseUint(port, 16, 16)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	b := make([]byte, len(host)/2)
	for i := range b {
		v, err := strconv.ParseUint(host[2*i:2*i+2], 16, 8)
		if err != nil {
			return netip.Addr{}, 0, false
		}
		b[i] = byte(v)
	}
	for w := 0; w < len(b); w += 4 { // each word is little-endian
		b[w], b[w+1], b[w+2], b[w+3] = b[w+3], b[w+2], b[w+1], b[w]
	}
	a, ok := netip.AddrFromSlice(b)
	return a, int(p), ok
}

// tcpListen is /proc/net/tcp's state for a listening socket.
const tcpListen = "0A"

// ParseListeners reads one /proc/net table (tcp, tcp6, udp, udp6) as proto.
// For TCP only sockets in LISTEN are kept; a UDP socket has no such state, so
// every bound one is. A line that does not parse is skipped: the table's
// format is the kernel's, and a new column must not empty the panel.
func ParseListeners(proto string, r io.Reader) []Listener {
	var out []Listener
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 4 || !strings.HasSuffix(f[0], ":") {
			continue // the header
		}
		if proto == "tcp" && f[3] != tcpListen {
			continue
		}
		a, port, ok := procAddr(f[1])
		if !ok || port == 0 {
			continue
		}
		out = append(out, Listener{Proto: proto, Address: a.String(), Port: port})
	}
	return out
}

// SortListeners orders ls by port, then protocol, then address, and drops
// repeats (a socket shared by several processes is listed once each).
func SortListeners(ls []Listener) []Listener {
	sort.Slice(ls, func(i, j int) bool {
		a, b := ls[i], ls[j]
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		if a.Proto != b.Proto {
			return a.Proto < b.Proto
		}
		return a.Address < b.Address
	})
	out := ls[:0]
	for i, l := range ls {
		if i == 0 || l != ls[i-1] {
			out = append(out, l)
		}
	}
	return out
}

// SSHLogin is one SSH login attempt the journal recorded.
type SSHLogin struct {
	At     int64  `json:"at"`     // Unix seconds
	User   string `json:"user"`   // the account asked for
	From   string `json:"from"`   // the client's address
	Result string `json:"result"` // "ok", "failed" or "closed"
	Detail string `json:"detail"` // how: "publickey", "password", "invalid user", "closed before login"
}

// sshd's lines, as OpenSSH writes them. A user name holds no space; the
// address is taken as written, never resolved.
var (
	sshAccepted = regexp.MustCompile(`^Accepted (\S+) for (\S+) from (\S+) port \d+`)
	sshFailed   = regexp.MustCompile(`^Failed (\S+) for (invalid user )?(\S+) from (\S+) port \d+`)
	sshInvalid  = regexp.MustCompile(`^Invalid user (\S*) from (\S+)`)
	sshClosed   = regexp.MustCompile(`^Connection closed by authenticating user (\S+) (\S+) port \d+ \[preauth\]`)
)

// sshLine reads one sshd message, if it is a login attempt.
func sshLine(msg string) (SSHLogin, bool) {
	if m := sshAccepted.FindStringSubmatch(msg); m != nil {
		return SSHLogin{User: m[2], From: m[3], Result: "ok", Detail: m[1]}, true
	}
	if m := sshFailed.FindStringSubmatch(msg); m != nil {
		detail := m[1]
		if m[2] != "" {
			detail += ", invalid user"
		}
		return SSHLogin{User: m[3], From: m[4], Result: "failed", Detail: detail}, true
	}
	if m := sshInvalid.FindStringSubmatch(msg); m != nil {
		return SSHLogin{User: m[1], From: m[2], Result: "failed", Detail: "invalid user"}, true
	}
	if m := sshClosed.FindStringSubmatch(msg); m != nil {
		return SSHLogin{User: m[1], From: m[2], Result: "closed", Detail: "closed before login"}, true
	}
	return SSHLogin{}, false
}

// ParseSSHJournal reads journalctl's JSON lines (-o json) for sshd, keeping
// the login attempts, in the order given, at most limit of them. A line that
// is not JSON, or whose message is not text, is skipped.
func ParseSSHJournal(r io.Reader, limit int) []SSHLogin {
	var out []SSHLogin
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() && len(out) < limit {
		var e struct {
			At      string `json:"__REALTIME_TIMESTAMP"`
			Message any    `json:"MESSAGE"`
		}
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			continue
		}
		msg, ok := e.Message.(string)
		if !ok {
			continue
		}
		l, ok := sshLine(msg)
		if !ok {
			continue
		}
		if us, err := strconv.ParseInt(e.At, 10, 64); err == nil {
			l.At = us / 1_000_000
		}
		out = append(out, l)
	}
	return out
}

// Load is /proc/loadavg's three averages.
type Load struct {
	One     float64 `json:"one"`
	Five    float64 `json:"five"`
	Fifteen float64 `json:"fifteen"`
}

// ParseLoad reads /proc/loadavg.
func ParseLoad(s string) (Load, bool) {
	f := strings.Fields(s)
	if len(f) < 3 {
		return Load{}, false
	}
	var l Load
	var err error
	for i, p := range []*float64{&l.One, &l.Five, &l.Fifteen} {
		if *p, err = strconv.ParseFloat(f[i], 64); err != nil {
			return Load{}, false
		}
	}
	return l, true
}

// ParseMeminfo reads /proc/meminfo's MemTotal and MemAvailable, in bytes.
func ParseMeminfo(r io.Reader) (total, available uint64) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 {
			continue
		}
		kb, err := strconv.ParseUint(f[1], 10, 64)
		if err != nil {
			continue
		}
		switch f[0] {
		case "MemTotal:":
			total = kb << 10
		case "MemAvailable:":
			available = kb << 10
		}
	}
	return total, available
}

// Host is the host's load, memory and the disk a path is on.
type Host struct {
	Load         Load   `json:"load"`
	MemTotal     uint64 `json:"mem_total"`
	MemAvailable uint64 `json:"mem_available"`
	DiskTotal    uint64 `json:"disk_total"`
	DiskFree     uint64 `json:"disk_free"`
}
