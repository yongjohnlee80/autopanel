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

**UDP is refused for now.** It is a separate forwarder with its own limits, and the next step.

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

**In the code:** `core/forward/forward.go` (`review`, `digest`).

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
The total is not raised for forwards: the gate's 40 MB is sized for it.

**Adding or removing a forward changes every forward's share, and cuts nobody off.** A stream
whose share alone changed keeps its listener and its open connections; the new share holds from
the next connection.

**In the code:** `host/gate/stream.go` (`lets`, the `Plain` stream, `sameButShare`), `core/forward/forward.go`
(`StreamsOf`, the constants at its top), `app/streams.go` (`SetForwards`).

## SSH to a machine behind

**Decided:** it is a forward like any other: a public port of its own to that machine's port 22.
SSH carries no host name in its first bytes, so several machines cannot share one public port by
name; each gets a port. The gate carries the bytes and never judges an SSH login. A jump host is
not built.
