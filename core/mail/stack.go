// Package mail is mail.*: Stalwart, run as a stack of its own behind the
// gate, set up and managed through its JMAP API. AutoPanel writes the stack's
// definition, keeps every key and setting of mail sealed in its store, and
// tells the gate which ports to forward.
//
// Decision: docs/decisions/mail.md
package mail

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
)

// Stack is the mail stack's name: reserved, its definition AutoPanel's.
const Stack = "mail"

// Image is the Stalwart AutoPanel runs, pinned by digest. A new Stalwart is a
// new AutoPanel release, applied through the usual review. v1.x keeps its
// schema, so a v1 upgrade needs no migration.
const Image = "docker.io/stalwartlabs/stalwart@sha256:f772aa6ef8cd8018969fa491640f1436b0270eb14e2c219b5f37f1a77020837e" // v1.1.0

// Port is one of mail's ports: the public one the gate binds, the loopback
// port it forwards to, and Stalwart's own inside its container.
type Port struct {
	Name      string // the gate stream's and Stalwart listener's name
	Public    int    // the gate binds it on every address
	Loopback  int    // the stack publishes it on 127.0.0.1; only the gate may open it
	Inside    int    // Stalwart listens on it inside the container
	IdleSecs  int    // a connection silent this long either way is closed
	PerClient int    // connections at once from one client
	Share     int    // at most this many of TotalConnections; 0: all
}

// Ports are mail's four public ports. IMAP holds IDLE connections (a client
// re-issues IDLE within 29 minutes, RFC 2177), so its idle limit is 31
// minutes, it may take most of the total, and a household behind one address
// gets more of them.
var Ports = []Port{
	{Name: "smtp", Public: 25, Loopback: 10025, Inside: 2525, IdleSecs: 600, PerClient: 20},
	{Name: "submissions", Public: 465, Loopback: 10465, Inside: 4465, IdleSecs: 600, PerClient: 20},
	{Name: "submission", Public: 587, Loopback: 10587, Inside: 5587, IdleSecs: 600, PerClient: 20},
	{Name: "imaps", Public: 993, Loopback: 10993, Inside: 9993, IdleSecs: 1860, PerClient: 50, Share: 150},
}

// TotalConnections is the forwarded connections at once, every port together.
const TotalConnections = 200

// ManagePort is the management API's loopback port: the core's alone, never
// forwarded or routed. ManageInside is Stalwart's own.
const (
	ManagePort   = 18480
	ManageInside = 8080
)

// LoopbackPorts are the mail stack's forwarded loopback ports, in order.
func LoopbackPorts() []int {
	out := make([]int, len(Ports))
	for i, p := range Ports {
		out[i] = p.Loopback
	}
	return out
}

// ManageURL is where the core reaches Stalwart's management API.
func ManageURL() string { return "http://127.0.0.1:" + strconv.Itoa(ManagePort) }

// Compose is the definition AutoPanel writes: Stalwart pinned, as user 2000
// (keep-id: its files are the stack user's on the host), with a read-only
// root, its three writable folders as data, every port on loopback only, and
// one capability, which the binary carries as a file capability and without
// which the kernel refuses to run it (Stalwart binds no port below 1024).
func Compose() []byte {
	var b strings.Builder
	b.WriteString(`# Mail: Stalwart, written by AutoPanel. It is changed from Mail, not by hand.
services:
  stalwart:
    image: ` + Image + `
    user: "2000:2000"
    volumes:
      - ./etc:/etc/stalwart
      - ./data:/var/lib/stalwart
      - ./log:/var/log/stalwart
    ports:
`)
	for _, p := range Ports {
		b.WriteString(`      - "127.0.0.1:` + strconv.Itoa(p.Loopback) + ":" + strconv.Itoa(p.Inside) + `"
`)
	}
	b.WriteString(`      - "127.0.0.1:` + strconv.Itoa(ManagePort) + ":" + strconv.Itoa(ManageInside) + `"
    mem_limit: 250m
    read_only: true
    tmpfs:
      - /tmp
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    restart: unless-stopped
`)
	return []byte(b.String())
}

// ComposeSHA256 is the digest of Compose, hex.
func ComposeSHA256() string {
	sum := sha256.Sum256(Compose())
	return hex.EncodeToString(sum[:])
}
