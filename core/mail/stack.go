// Package mail is mail.*: the rules of AutoPanel's mail, independent of the
// mail server that carries them out. The server runs as a stack of its own
// behind the gate; this package reaches it only through provider.Product and
// provider.Server, which a server's SDK (sdk/...) implements. AutoPanel writes
// the stack's definition (the product's), keeps every key and setting of mail
// sealed in its store, and tells the gate which ports to forward.
//
// Decision: docs/decisions/mail.md
package mail

import (
	"strconv"

	"github.com/yongjohnlee80/autopanel/core/mail/provider"
)

// Stack is the mail stack's name: reserved, its definition AutoPanel's.
const Stack = "mail"

// Port is one of mail's ports: the public one the gate binds, and the
// loopback port it forwards to. Where the server listens inside its container
// is the product's.
type Port struct {
	Name      string // the gate stream's name, and the product's for the port
	Public    int    // the gate binds it on every address
	Loopback  int    // the stack publishes it on 127.0.0.1; only the gate may open it
	IdleSecs  int    // a connection silent this long either way is closed
	PerClient int    // connections at once from one client
	Share     int    // at most this many of TotalConnections; 0: all
	// Greets marks a port on which the server speaks first, in the clear
	// (SMTP's greeting): the gate can tell there whether the server still
	// waits for the header that names the client.
	Greets bool
}

// Ports are mail's four public ports. IMAP holds IDLE connections (a client
// re-issues IDLE within 29 minutes, RFC 2177), so its idle limit is 31
// minutes, it may take most of the total, and a household behind one address
// gets more of them.
var Ports = []Port{
	{Name: "smtp", Public: 25, Loopback: 10025, IdleSecs: 600, PerClient: 20, Greets: true},
	{Name: "submissions", Public: 465, Loopback: 10465, IdleSecs: 600, PerClient: 20},
	{Name: "submission", Public: 587, Loopback: 10587, IdleSecs: 600, PerClient: 20, Greets: true},
	{Name: "imaps", Public: 993, Loopback: 10993, IdleSecs: 1860, PerClient: 50, Share: 150},
}

// TotalConnections is the forwarded connections at once, every port together.
const TotalConnections = 200

// ManagePort is the management API's loopback port: the core's alone, never
// forwarded or routed.
const ManagePort = 18480

// LoopbackPorts are the mail stack's forwarded loopback ports, in order.
func LoopbackPorts() []int {
	out := make([]int, len(Ports))
	for i, p := range Ports {
		out[i] = p.Loopback
	}
	return out
}

// ManageURL is where the core reaches the mail server's management API.
func ManageURL() string { return "http://127.0.0.1:" + strconv.Itoa(ManagePort) }

// compose is the definition AutoPanel writes: the product's, with mail's
// loopback ports.
func (m *Module) compose() []byte {
	ports := make([]provider.PortMap, len(Ports))
	for i, p := range Ports {
		ports[i] = provider.PortMap{Name: p.Name, Loopback: p.Loopback}
	}
	return m.product.Compose(provider.Stack{Name: Stack, Ports: ports, Manage: ManagePort})
}
