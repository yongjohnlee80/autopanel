# Processes

How AutoPanel is divided into processes, and what each one may reach.

## Two processes

**Decided:** AutoPanel is one binary that runs as two services.

| | gate | core |
| --- | --- | --- |
| mode | `autopanel --gate` | `autopanel --core` |
| unit | `autopanel-gate.service` | `autopanel-core.service` |
| user | `autopanel`, sandboxed | root |
| listens on | the two public ports | two unix sockets, no network |
| holds | the routing table and the certificates it is serving, in memory | the store, the vault, the ACME account, the audit log, every administrative right |

**Why:** the process that accepts connections from the internet is the one most likely to be
broken into. As one process it also held the master key, the store and the control socket, and
every right that monitoring or deploying needs had to be given to it. Divided, a gate that is
compromised yields the private keys of the sites it is serving and nothing else, and the rights
live in a process no network can reach.

**The cost, accepted:** the core runs as root, with no sandbox to speak of. Its protection is
that it listens on no network and offers a fixed set of verbs.

**In the code:** `app/core.go` (the core), `host/gate/process.go` (the gate),
`deploy/autopanel-core.service`, `deploy/autopanel-gate.service`.
`TestTheCoreListensOnNoNetwork` and `TestTheGateReachesNoStoreVaultOrACMEClient` hold the two
halves of the rule.

## The link

**Decided:** the gate dials the core, on a unix socket only the gate's user can open; the core
never dials the gate. The socket offers five verbs and no others:

| Verb | What the gate gets |
| --- | --- |
| `link.hello` | its listen addresses and the proxies it trusts |
| `link.routes` | the routing table; the call stays open until the table changes |
| `link.cert` | the certificate and key for a name a route holds |
| `link.challenge` | the answer to an ACME HTTP-01 request it received |
| `link.report` | nothing: it sends its request counts |

**Why the gate dials:** a core that connected out to the gate would need the gate to listen for
it, and a second listener on the exposed process is a second way in. With the gate dialling, the
kernel's record of the peer's user is all the authentication the link needs.

**Why one open call for routes:** a change must reach the gate at once, and the core cannot call
it. The gate keeps one `link.routes` call open, and the core answers it when the table changes.

**Certificates:** the gate asks for a certificate on a handshake for a name its table holds, and
keeps it for an hour. A name no route holds is refused by the gate itself, so a stranger's SNI
costs the core nothing. The core runs ACME; a challenge that arrives at the gate is answered with
what the core says.

**In the code:** `host/gate/link.go` (the shapes), `app/link.go` (the core's side),
`host/control/control.go` (`Access`: who may open a socket).

## The gate outlives the core

**Decided:** a core that stops or restarts leaves the gate serving the routes and certificates it
holds, past a certificate's hour too. The gate reconnects when the core is back and takes whatever
table it then holds.

**Decided:** the gate is the core's to run. Its unit has no `[Install]` section: the core starts
it once its own sockets answer, and restarts or stops it through `sys.gate.restart` and
`sys.gate.stop`. A host whose core cannot start has no gate.

**Why:** one owner of the gate's lifecycle. The gate reads no configuration of its own, so there
is nothing for it to serve before the core has answered once.

**In the code:** `host/gate/process.go` (`follow`, `certCache.get`), `app/core.go` (`GateControl`).

## Host commands

**Decided:** the core runs the host's tools through one package, `internal/hostcmd`, which names
each tool by absolute path. No other package imports `os/exec`, there is no shell, and no verb
takes a command from its caller.

**Why:** the core is root. A fixed table of tools, each called with arguments the verb has
validated, is what keeps "a verb of the panel" from meaning "any command as root".

**In the code:** `internal/hostcmd/hostcmd.go`; `TestThisIsTheOnlyPackageThatRunsCommands`.

## The control socket is root's

**Decided:** the panel and the CLI run as root (`sudo autopanel --ui`). Root alone can open the
control socket; a panel user then logs in with a passphrase, as before.

**Why:** the socket leads to a process with root's rights, so the right to open it is root's. A
group that could open it would be root by another name.

**In the code:** `app/core.go` (`hostcontrol.Access{}`), `app/main.go` (`dial`).
