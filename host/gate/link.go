package gate

import core "github.com/yongjohnlee80/autopanel/core/gate"

// THE LINK — what the gate process asks of the core, over the link socket.
// The gate holds no store and no key but the private keys of the sites it is
// serving: its listen addresses, its routes, each certificate and each ACME
// challenge answer come from these five verbs. The gate dials; the core never
// does. Both ends are one binary, so the shapes change together.

// The link's verbs.
const (
	VerbHello     = "link.hello"
	VerbRoutes    = "link.routes"
	VerbCert      = "link.cert"
	VerbChallenge = "link.challenge"
	VerbReport    = "link.report"
	VerbStreams   = "link.streams"
)

// Stream is one port the gate forwards byte for byte to a loopback port, each
// connection preceded by a PROXY protocol v2 header naming the client.
type Stream struct {
	Name      string `json:"name"`       // "smtp": for the log and the limits
	Listen    string `json:"listen"`     // the address the gate binds: ":25"
	To        string `json:"to"`         // the loopback address it forwards to: "127.0.0.1:10025"
	IdleSecs  int    `json:"idle_secs"`  // a connection with no byte either way for this long is closed
	PerClient int    `json:"per_client"` // connections at once from one client (an IPv4 address, an IPv6 /64); 0: no limit of its own
	Share     int    `json:"share"`      // at most this many of Total; 0: Total
}

// Streams is link.streams's answer: every stream, the limit they share, and
// the revision. No streams is the usual answer: only mail has them.
type Streams struct {
	Rev     int64    `json:"rev"`
	Total   int      `json:"total"` // forwarded connections at once, every stream together
	Streams []Stream `json:"streams"`
}

// Hello is link.hello's answer: the gate's whole configuration.
type Hello struct {
	Version string   `json:"version"` // the core's, for the log
	HTTPS   string   `json:"https"`   // the TLS listener's address
	HTTP    string   `json:"http"`    // the plain listener's address
	Trusted []string `json:"trusted"` // the proxies whose CF-Connecting-IP is believed, as prefixes
}

// After is link.routes's param: the revision the gate holds, 0 for none.
type After struct {
	After int64 `json:"after"`
}

// Routes is link.routes's answer: the whole table, and its revision.
type Routes struct {
	Rev    int64            `json:"rev"`
	Routes []core.RouteView `json:"routes"`
}

// Name is link.cert's param. With ALPN the gate asks for the TLS-ALPN-01
// challenge certificate of an order in flight for Name.
type Name struct {
	Name string `json:"name"`
	ALPN bool   `json:"alpn,omitempty"`
}

// Cert is link.cert's answer: the chain (DER, leaf first) and the private key
// (PKCS #8, DER).
type Cert struct {
	Chain    [][]byte `json:"chain"`
	Key      []byte   `json:"key"`
	NotAfter int64    `json:"not_after"` // Unix seconds
}

// ChallengeAsk is link.challenge's param: an HTTP-01 request the gate got.
type ChallengeAsk struct {
	Host string `json:"host"`
	Path string `json:"path"`
}

// ChallengeAnswer is link.challenge's answer. Handled is false for a request
// that is no challenge of the core's: the gate serves it as any other.
type ChallengeAnswer struct {
	Handled bool   `json:"handled"`
	Status  int    `json:"status"`
	Body    []byte `json:"body"`
}

// Report is link.report's param: the gate's request counts since it started,
// its process and the memory it holds now.
type Report struct {
	HTTPSRequests int64  `json:"https_requests"`
	HTTPRequests  int64  `json:"http_requests"`
	PID           int    `json:"pid"`
	MemoryBytes   uint64 `json:"memory_bytes"` // resident memory; what the runtime holds where that cannot be read

	StreamsOpen    int64 `json:"streams_open"`    // forwarded connections now
	StreamsServed  int64 `json:"streams_served"`  // forwarded since the gate started
	StreamsRefused int64 `json:"streams_refused"` // closed by a limit since the gate started
}
