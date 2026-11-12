package services

import "fmt"

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
	Files: func(_ Values, secrets map[string]string) []File {
		return []File{{Path: "config/turnserver.conf", Mode: 0o400, Body: []byte(turnConf(secrets["auth-secret"]))}}
	},
	Mounts: map[string]string{"config": "/etc/coturn"},
	Args:   turnArgs,
	Memory: "128M",
	// The image's turnserver carries NET_BIND_SERVICE as a file capability,
	// and the kernel refuses to run such a file when the capability is
	// dropped. Kept, it is held in the container's own user namespace, where
	// it opens no port of the host's below 1024.
	Keeps: []string{"NET_BIND_SERVICE"},
}

// turnDenied are the peers the relay refuses: this host and every private or
// link-local network, so the relay cannot be used to reach what the host can
// and the internet cannot.
var turnDenied = []string{
	"0.0.0.0-0.255.255.255", "10.0.0.0-10.255.255.255", "100.64.0.0-100.127.255.255", "127.0.0.0-127.255.255.255",
	"169.254.0.0-169.254.255.255", "172.16.0.0-172.31.255.255", "192.168.0.0-192.168.255.255",
	"::1", "fc00::-fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "fe80::-febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
}

// turnArgs is coturn's command line: every setting but the secret. They are
// here and not in the configuration file because coturn starts on its
// defaults when it cannot read that file, and its defaults are a relay that
// asks for no credentials. With these on the command line, a relay that
// lost its file has no secret and authenticates nobody.
//
// Every value is a validated option or a constant: none has a space or a
// character the image's entrypoint, a shell, would expand.
func turnArgs(v Values) []string {
	from, to := v.Range("relay_ports")
	args := []string{
		"-c", "/etc/coturn/turnserver.conf",
		fmt.Sprintf("--listening-port=%d", v.Port("port")),
		fmt.Sprintf("--min-port=%d", from), fmt.Sprintf("--max-port=%d", to),
		"--realm=" + v.Get("realm"),
		// No certificate is given, so coturn opens no TLS or DTLS listener.
		// --no-tls says so; coturn 4.18 takes no --no-dtls on its command
		// line, and refuses to start when given one.
		"--use-auth-secret", "--fingerprint", "--no-tls", "--no-multicast-peers",
	}
	for _, d := range turnDenied {
		args = append(args, "--denied-peer-ip="+d)
	}
	// The container's root is read-only: what coturn writes goes to its /tmp.
	return append(args, "--log-file=stdout", "--pidfile=/tmp/turnserver.pid", "--userdb=/tmp/turndb")
}

// turnConf is coturn's configuration file: the secret, which must not be on
// a command line, where every user of the host could read it. The secret is
// hex: it cannot carry a line break.
func turnConf(secret string) string {
	return "# Written by AutoPanel. Changed through the panel, not here: a deploy writes it again.\n" +
		"# The relay's other settings are on its command line, in its unit.\n" +
		"static-auth-secret=" + secret + "\n"
}
