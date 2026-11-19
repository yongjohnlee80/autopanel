# Port forwards

How a public port of the host that is not HTTPS or mail is sent on to a service: a game server, a
database for one client, SSH to a machine behind.

## A forward is a public port sent to a literal target

**Decided:** a forward has a name, a public TCP port or a range of up to a hundred, and a target:
a literal address and port. A range keeps its ports in order from the target's. The gate carries
the bytes; the core keeps the list and decides what may be one.

**A target is never a host name.** A name is resolved when a connection is made. Whoever controls
that name later controls where a public port of this host leads, and the review the administrator
read no longer describes it. A stack's port on loopback and a machine on the LAN are both literal.

**Only an address ordinary hosts have.** For IPv4, a unicast address outside `0.0.0.0/8` and
`240.0.0.0/4`. For IPv6, loopback, the unique local range (`fc00::/7`) and global unicast
(`2000::/3`). Out: the unspecified address, multicast, broadcast, link-local (where a cloud's
metadata service lives), and every special or translation prefix, such as `::/96` and
`64:ff9b::/96`. The refusals below ask "is this target this host?"; an address the kernel may
turn into another is one that question cannot be answered for, so it is not taken at all.

**TCP or UDP.** A UDP forward has its own forwarder in the gate and its own limits
([UDP](#udp)); it carries no PROXY header, which UDP has no standard place for.

**In the code:** `core/forward/forward.go` (`Normalize`), `store/forwards.go`,
`sql/deployments/*/000008_update_forwards.sql`.

## What a forward may never do

**Decided:** a forward is refused when it would:

| It would | Why |
| --- | --- |
| take a port SSH listens on | the way in to the host is not something a form can move |
| lead to this host's own SSH, from any public port | every login through it would reach `sshd` from 127.0.0.1: the login list, and the firewall's lockout guard that reads it, would no longer know where anyone came from. Another machine's port 22 is fine |
| take a port the gate, mail, another forward or another program holds | one holder a port |
| lead to one of mail's loopback ports or its management port | only the gate's user may open those, because the mail server believes the client address the gate writes in front of a connection. A forward runs as the gate too: pointed there, it would let a stranger write that address himself |
| lead to the gate's own ports or a forward's public port on this host | a loop |

"This host" is loopback and every address of its interfaces. If the interfaces cannot be read,
every address is taken for the host's: the stricter answer.

**A host that cannot be read changes nothing.** SSH's ports are found as the firewall's lockout
guard finds them. If a listener of SSH's cannot be explained, or the listeners cannot be read, no
forward is judged safe (`gate.forward.unknown`): the unexplained listener may be the one the
administrator is on.

**In the code:** `core/forward/forward.go` (`judge`), `app/forward.go` (`forwardHost`,
`forwardReserved`).

## Reviewed, then applied

**Decided:** `gate.forward.check` answers what a forward would be, or why it is refused, and its
public port's state in the firewall; it changes nothing. `gate.forward.add` and
`gate.forward.update` take that review's digest and are refused if the forward or the firewall's
answer changed since. A forward keeps its name: it is the owner of its firewall rule.

**In the panel** the review is the confirmation: **Add…** shows what the forward would be and
what adding it does to the firewall, and applies that review on Yes. When the firewall blocks the
port and AutoPanel can open it, Yes opens it as the forward's rule; when AutoPanel cannot change
this firewall, the manager's own commands are shown.

**In the code:** `core/forward/forward.go` (`review`, `digest`), `internal/ui/forwards.go`
(`addForward`, `confirmForward`).

## A forward owns its firewall rule

**Decided:** asked to (`open`), AutoPanel opens the forward's public port as the forward's own
rule (`forward:<name>`), as a stack's and mail's are theirs. The rule follows the forward's ports
and is closed when the forward is removed; a rule that was there already stays its maker's. A
firewall that refuses to open the port leaves no forward behind. The lockout guard runs on every
such change, as on any other.

Two host checks: `forward-port-blocked` when the firewall blocks a forward's port, and the
existing `firewall-owned-missing` when its rule was removed by hand. The plan to turn the
firewall on names a forward's port as that forward's.

**In the code:** `core/firewall/rows.go` (`ForwardOwner`), `core/forward/forward.go` (`add`,
`update`, `remove`), `app/firewall.go` (`ownerChecks`, `firewallUses`).

## The gate's one forwarder, and its limits

**Decided:** a forward is carried by the forwarder that carries mail's ports
([Mail](mail.md#the-gate-forwards-the-mail-ports)), told what to forward over the same link call.
A forward's stream differs in two ways it chooses: it may carry no PROXY header (most services do
not read one), and it may take connections only from named source prefixes. A source list the gate
cannot read lets nobody in.

| Limit | Value |
| --- | --- |
| Forwards | 16 |
| Public ports over every forward | 128 |
| Forwarded connections, every forward together | 64, shared equally, never fewer than 4 each |
| Connections at once from one client (an IPv4 address, an IPv6 /64) | 8 unless set, 64 at most |
| A silent connection is kept | 10 minutes unless set, a day at most |

**Why so few connections:** every forwarded connection is held in the gate's memory beside mail's
and the sites', under one total of 200. Forwards may take 64 of it, so mail keeps at least 136.
The total is not raised for forwards: the gate's memory is sized for it.

**Adding or removing a forward changes every forward's share, and cuts nobody off.** A stream
whose share alone changed keeps its listener and its open connections; the new share holds from
the next connection.

**In the code:** `host/gate/stream.go` (`lets`, the `Plain` stream, `sameButShare`), `core/forward/forward.go`
(`StreamsOf`, the constants at its top), `app/streams.go` (`SetForwards`).

## UDP

**Decided:** UDP has no connection, so the gate keeps a pairing for each client that sent a
datagram: a socket of its own to the target. The kernel then brings the target's answers back to
that pairing alone, and **an answer is only ever sent to the client whose datagram opened it**.
The target sees the gate's address, not the client's.

**A source address can be forged,** since nothing is shaken hands on. So a pairing is unanswered
until the target has answered and the client has sent again, which someone who forged the address
and does not see the answers cannot do. Until then a pairing:

- lives five seconds;
- is sent at most four datagrams;
- is the first to go when the table is full.

So forged sources cannot hold the table against real clients, and a forged address can be aimed
at with only a handful of the target's answers. An answered pairing ends after a minute without a
datagram either way, unless the forward says otherwise.

| Limit | Value |
| --- | --- |
| Pairings, every UDP forward together | 256 |
| Pairings of one client (an IPv4 address, an IPv6 /64) | 16 unless set |
| A datagram's payload | 1,500 bytes; a larger one is dropped, never cut |

**What differs from a TCP forward's rules:** SSH, the gate's listeners and mail's ports are TCP,
so a UDP forward on the same number takes nothing of theirs. It is held to the UDP ports other
programs and other UDP forwards hold, and to no loop. A TCP and a UDP forward may share a number.

**The gate's memory.** Measured on a test host with the table full, 256 pairings from forty
client addresses, each sending and being answered: the gate went from 4 MB to 12, with a peak of
13. With the API's calls at their worst (about 21 MB) and 200 forwarded connections' socket
buffers (about 19 MB), the most the gate can hold at once is about 49 MB, so its unit's limit is
64 MB, raised from 40. Its file limit is 8,192.

**In the code:** `host/gate/udp.go`, `core/forward/forward.go` (`judge`, `StreamsOf`),
`deploy/autopanel-gate.service`.

## SSH to a machine behind

**Decided:** it is a forward like any other: a public port of its own to that machine's port 22.
SSH carries no host name in its first bytes, so several machines cannot share one public port by
name; each gets a port. The gate carries the bytes and never judges an SSH login. A jump host is
not built.

## Tunnels

**Decided:** a machine with no open port reaches AutoPanel, not the other way round. A small
program on it, `autopanel-agent`, dials the gate on the HTTPS port and holds one connection
open; a route or a TCP forward then reaches a service on that machine as
`tunnel://<agent>/<target>`.

**The agent's file is the only list of what can be reached.** The gate asks for a target by name.
The agent dials what its own file says for that name, or refuses. Nothing AutoPanel sends can add
a target, change an address or reach a port the file does not list, and the agent tells AutoPanel
its targets' names, never where they lead. So an AutoPanel that is broken into reaches the
services already published through it, and nothing else on that network.

**Who an agent is.** A key pair made on its own machine; the private key never leaves it.

- The administrator adds an agent by name and is given a token, once: 256 random bits, good for
  ten minutes and for one use. Only its hash is stored.
- On the machine, `autopanel-agent enroll <server>` makes the key and offers the token; the key is
  kept only once the server has taken it.
- Whoever uses a token first becomes that agent. So the agent prints its key's fingerprint, the
  panel lists the fingerprint and the address the agent enrolled from, and the administrator
  compares them before routing anything to it.
- Removing an agent closes its tunnel at once. A tunnel is also closed when the key it came in
  with is no longer its agent's.

**On the HTTPS port, and no browser is asked for a certificate.** An agent's TLS handshake offers
one protocol name and nothing else. Only such a handshake gets the tunnel's settings: TLS 1.3 and
a client certificate, whose signature proves the agent holds its key. Every other handshake is
served as before.

- The name is read and not agreed: Go's HTTP server closes a connection whose agreed protocol it
  has no handler for. The connection is served as HTTP/1.1 for two requests only, one to enrol
  and one that becomes the tunnel.
- A request that carries a client certificate is the tunnel's. It reaches no site and no API.
- An enrolment is limited at the gate: 5 a minute from one client, 60 from everyone. A refused one
  writes nothing, so a stranger can fill no log.

**Inside the tunnel: HTTP/2 with the roles turned round.** The agent, which dialled, serves; the
gate opens a stream for each connection it needs. Flow control and keep-alive pings are HTTP/2's
own, and both ends are the standard library's.

| Limit | Value |
| --- | --- |
| Agents | 16 |
| Streams through one agent | 64, or fewer if the agent's file says |
| Streams through all of them | 128 |
| A stream's window | 64 KiB: what a reader that stops costs the other end |

- A target that speaks first (SSH) is heard at once: the stream is open before the client sends.
- A target that closes its sending side ends the stream. A protocol in which the target
  half-closes and then expects more is not carried.

**A route through a tunnel** sends each request as a stream, and the target sees an ordinary HTTP
request with the forwarded headers the gate sets. No connection is kept idle on one of the
agent's streams. With the agent away the answer is `502`, on a page that names neither the agent
nor the target.

**A forward through a tunnel** is one TCP port with no PROXY header: the agent is not told who
the client is. Its public port keeps every rule of a forward; its target is not checked as an
address is, since where a name leads is the agent's file's to say. With the agent away the
connection is closed.

**A host check, `tunnel-down`,** names an agent that a site or a forward depends on and that
holds no tunnel.

**Not built:** UDP through a tunnel, an agent for Windows or macOS, a PROXY header from the
agent, and tunnels to whole networks (this reaches named services).

**In the code:** `internal/tunnel` (the streams), `internal/agent` and `cmd/autopanel-agent` (the
far end), `core/tunnel` (the agents and their enrolment), `host/gate/tunnel.go` (the gate's side),
`deploy/autopanel-agent.service`.
