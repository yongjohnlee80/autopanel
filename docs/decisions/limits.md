# The gate's limits

What the gate may spend on HTTP and HTTPS, and why its memory limit is what it is. The gate is the
one process every site, mail port, forward and tunnel passes through, so nothing it holds may grow
with the load.

## Every part is bounded, and the unit's limit is their sum

**Decided:** each thing the gate holds has a fixed number and a fixed worst cost, the sum is kept in
the code (`WorstBytes`), and the unit's `MemoryMax` is that sum with room. A test reads the unit
file and the constants together, so a limit cannot be raised without the memory to hold it.

| Part | Limit |
| --- | --- |
| Requests being proxied | 96 at once, 24 of one client |
| Connections on the HTTPS listener | 192, 32 of one peer that is no trusted proxy |
| Connections on the HTTP listener | 32 |
| Connections waiting to be accepted | 64 on a public port, 256 on a forwarded one |
| A larger send buffer for a large download | 6 connections, 3 of one client |
| Tunnel streams | 128 ([Port forwards](forwards.md#tunnels)) |
| Forwarded TCP connections, mail's included | 200 ([Port forwards](forwards.md)) |
| UDP pairings | 256 |
| API calls | 8 ([The HTTPS API](api.md)) |

- **Each thing is counted by what holds it:** a socket's buffers by sockets, whether in use or not;
  a proxied request by requests; and an allowance for sockets closed and not yet freed. The heap
  figures are measured on a test host and rounded up.
- **A connection waiting to be accepted is not the gate's:** until it is accepted, the kernel holds
  it in the host's memory, outside the gate's limit. The queue's length bounds how many there are.
- `MemoryHigh` is below `MemoryMax`: the kernel reclaims and slows the gate before it would end it.
  `GOMEMLIMIT` is the runtime's own part of the sum.
- An idle gate uses a few megabytes. These are ceilings, not reservations.

**In the code:** `host/gate/bounds.go`, `deploy/autopanel-gate.service`,
`TestTheUnitsLimitsHoldTheLedger`.

## A socket's kernel buffers are fixed

**Decided:** every socket of the two listeners and every socket to an upstream has its buffers
set: for a client, 160 KiB to receive and 64 KiB to send; for an upstream, 32 KiB each way (the
kernel counts twice what is set). A client's are the listening socket's, so a connection has them
from its first byte, before the gate has accepted it.

**Why:** a socket's memory is the gate's, and a fixed buffer is a bound that is arithmetic.

**The cost is speed over a far link.** A transfer moves about half a buffer a round trip: about
1 MiB/s at 100 ms, either way. Next to the host, or behind a proxy near it (Cloudflare), the round
trip is a few milliseconds and nothing is lost.

**So a large download may take a wider send buffer.** A connection whose answer has sent 512 KiB
takes one of 6 grants if one is free: up to 1 MiB to send, until it closes. The host's
`net.core.wmem_max` caps what the kernel gives (208 KiB by default: about 3.5 MiB/s at 100 ms);
raising it on the host raises what a grant is worth. It is best effort: a client can hold a grant
idle, and then the others' downloads are slower, not refused.

- A grant is its connection's until the connection closes. It is the next connection's at once
  when the socket had nothing left to send; otherwise two minutes later, since what a closed
  socket had queued is the kernel's a while longer.
- A connection's receive buffer never changes: the window a connection may offer is settled when
  it is made. An upload is not widened.
- A forwarded port's listening socket has a small receive buffer, which a connection keeps until
  it is accepted; then it has the forwarder's own.

## Requests in flight, and connections

**Decided:** at most 96 requests are being proxied at once. One more is answered `503` with
`Retry-After: 1`, at once. It is not queued: a queue of waiting requests is memory held too.

- A request is counted, not a connection: each HTTP/2 stream takes a place, and a WebSocket holds
  its place while it is open.
- **One client has 24 places.** A client is the peer, or what `CF-Connecting-IP` names when the
  peer is a trusted proxy and the header is one plain address: an IPv4 address, or an IPv6 /64.
- **The share is for fairness, never for knowing who someone is.** A client with many addresses is
  many clients. The total holds whoever they are.
- **A listener holds a fixed number of connections,** and one peer that is not a trusted proxy (an
  address, or an IPv6 /64) 32 of them, so one address cannot fill the listener. A trusted proxy carries many clients and
  has no share of its own.
- The API and the tunnel agents arrive on the same listener. Many machines together can still fill
  it: that is a flood, which a host answers at its network's edge, not in the gate.
- HTTP/2: 16 streams a connection, frames of at most 16 KiB, and 128 KiB of unread upload held for
  one stream, 256 KiB for one connection.
- A request's headers: 32 KiB. An upstream's answer's headers: 64 KiB, and a larger answer is `502`.
- The gate speaks HTTP/1.1 to an upstream, so one request is one connection's cost.

**A host check, `gate-busy`,** says when the gate turned requests or connections away in the last
ten minutes, and how many.

## A request that stops moving is ended

**Decided:** a proxied request with no byte in either direction for five minutes is ended, and its
place freed: the wait for an upstream's answer included. Once a connection is upgraded (a
WebSocket) the limit is ten minutes, as for a forwarded TCP connection.

- One clock for both directions: an upload that is moving keeps a slow answer's wait alive.
- It bounds nothing. A client that sends a byte a minute keeps its place, at the fixed cost of a
  place. The limit only gives places back sooner.
- An answer's last bytes are sent under the same clock, and a refusal has ten seconds to be taken:
  a client that takes nothing does not keep either waiting.
- A WebSocket silent for ten minutes is closed. Clients and servers that keep one open send a ping
  far more often than that.

**In the code:** `host/gate/bounds.go` (`proxied`, `progress`), `host/gate/bounds_test.go`.

## Not decided here

- Limits set from the panel, or sized from the host's memory at install.
- A limit on how often one client may ask a route (requests a minute).
