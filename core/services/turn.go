package services

import (
	"fmt"
	"strings"
)

// coturnImage is coturn 4.18.0 (Debian), every architecture, by digest.
const coturnImage = "docker.io/coturn/coturn@sha256:bbefd3e1fdfdc0d58770fe01b581fd8b00d9f3a5580d00acb77cf719a6bc78e3"

// TURN is a TURN relay (coturn) that authenticates with a shared secret: the
// application that hands out TURN credentials makes them from it (the TURN
// REST API), so the relay keeps no user list.
var TURN = Template{
	Name: "turn", Title: "autopanel.services.turn", Image: coturnImage,
	Options: []Option{
		{Key: "realm", Label: "autopanel.services.turn.realm", Kind: HostName},
		{Key: "port", Label: "autopanel.services.turn.port", Kind: Port, Default: "3478"},
		{Key: "relay_ports", Label: "autopanel.services.turn.relayPorts", Kind: PortRange, Default: "49152-49999"},
	},
	// The host's network: a relay hands out hundreds of UDP ports, and each
	// one forwarded through a rootless container's user-space proxy costs
	// more than the isolation is worth for a relay. Every port is above 1023,
	// so the service's user can bind it.
	Network: HostNetwork,
	Ports: func(v Values) []PortUse {
		from, to := v.Range("relay_ports")
		p := v.Port("port")
		return []PortUse{{Proto: "udp", From: p, To: p}, {Proto: "tcp", From: p, To: p}, {Proto: "udp", From: from, To: to}}
	},
	Secrets: []string{"auth-secret"},
	Files: func(v Values, secrets map[string]string) []File {
		return []File{{Path: "config/turnserver.conf", Mode: 0o400, Body: []byte(turnConf(v, secrets["auth-secret"]))}}
	},
	Mounts: map[string]string{"config": "/etc/coturn"},
	Args:   func(Values) []string { return []string{"-c", "/etc/coturn/turnserver.conf"} },
	Memory: "128M",
}

// turnDenied are the peers the relay refuses: this host and every private or
// link-local network, so the relay cannot be used to reach what the host can
// and the internet cannot.
var turnDenied = []string{
	"0.0.0.0-0.255.255.255", "10.0.0.0-10.255.255.255", "100.64.0.0-100.127.255.255", "127.0.0.0-127.255.255.255",
	"169.254.0.0-169.254.255.255", "172.16.0.0-172.31.255.255", "192.168.0.0-192.168.255.255",
	"::1", "fc00::-fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "fe80::-febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
}

// turnConf is coturn's configuration. Every value in it is a validated option
// or the generated secret (hex): none can carry a line break.
func turnConf(v Values, secret string) string {
	from, to := v.Range("relay_ports")
	var b strings.Builder
	fmt.Fprintf(&b, "# Written by AutoPanel. Changed through the panel, not here: a deploy writes it again.\n")
	fmt.Fprintf(&b, "listening-port=%d\n", v.Port("port"))
	fmt.Fprintf(&b, "min-port=%d\nmax-port=%d\n", from, to)
	fmt.Fprintf(&b, "realm=%s\n", v.Get("realm"))
	fmt.Fprintf(&b, "use-auth-secret\nstatic-auth-secret=%s\n", secret)
	b.WriteString("fingerprint\nno-cli\nno-tls\nno-dtls\nno-multicast-peers\n")
	for _, d := range turnDenied {
		fmt.Fprintf(&b, "denied-peer-ip=%s\n", d)
	}
	// The container's root is read-only: what coturn writes goes to its /tmp.
	b.WriteString("log-file=stdout\npidfile=/tmp/turnserver.pid\nuserdb=/tmp/turndb\n")
	return b.String()
}
