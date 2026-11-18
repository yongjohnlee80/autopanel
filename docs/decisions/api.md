# The HTTPS API

How a script on another machine calls AutoPanel: JSON over HTTPS, with an API token.

## The gate serves it; the core still listens on no network

**Decided:** the API is served by the gate, on one host name of its own that the administrator
sets (`sys.api.set`). It is off until then. The gate passes each call to the core over the link,
as `link.api`; the core listens on no network, as before.

**Why:** the core runs as root and holds the vault. An HTTP listener there, even on loopback
behind a route, would put a request parser in a root process one hop from the internet, and any
local user could reach its port. Through the gate, the core receives a typed message of bounded
size from a peer the kernel has identified.

**The cost, accepted:** tokens pass through the gate's memory. A gate that is broken into can read
the tokens of calls made while it is, and use them. Each is capped by its owner's role and reaches
only the public verbs; an administrator who suspects the gate revokes tokens.

**The API's host:**

- is under a registered domain, like a route's; no route may hold it (`gate.host_reserved`), and
  its domain cannot be removed while that would leave it under none (`gate.domain_holds_host`);
- gets its certificate as a route's host does, though no route names it;
- is the gate's own: a request for it never reaches the routing table;
- is not served without TLS: on the plain listener it is refused, not redirected, so a client that
  sent its token in the clear is not asked to send it again.

**In the code:** `host/gate/api.go` (the gate's side), `app/api.go` (the core's side and
`sys.api.*`), `internal/ui/api.go` (System → HTTPS API…), `host/gate/link.go` (`APIAsk`, `APIAnswer`, `API`), `core/gate/domain.go`
(`routable`, `SetReserved`).

## The shape of a call

| Request | Answer |
| --- | --- |
| `POST /v1/call/<verb>` with a JSON body (the verb's one parameter, or none) | `200` and the verb's result as JSON |
| `GET /v1/contracts` | the public contracts this token's role may call |
| `GET /v1/health` | `200 {"status":"ok"}`, or `503`; no token |

```sh
curl -s https://api.example.com/v1/call/gate.route.list \
     -X POST -H "Authorization: Bearer $(cat /root/monitor.token)"
```

- The verb, its parameter, its result and its errors are the ones `autopanel --call` has: one
  catalog for every surface.
- `Authorization: Bearer apt_<id>_<secret>` on every request but `/v1/health`. Nothing else is
  read as a credential: not a cookie, not a query parameter.
- A refusal is `{"error": {"code", "name", "message"}}`. Statuses: `400` a body the verb does not
  take, `401` no valid token, `403` the role may not (or the address may not), `404` no such public
  verb, `405`, `413`, `415`, `422` the verb refused with a declared error, `429` the rate, `503`
  busy or the core does not answer.
- `X-Request-Id`: at most 64 characters of `[A-Za-z0-9-_]`, or the gate makes one. It is echoed and
  is on the audit entry.
- The path is matched as it was sent: nothing is cleaned, so nothing is ever redirected. No
  `Access-Control-*` header is sent, and every answer is `Cache-Control: no-store`.

## The core decides

**Decided:** the gate checks a request's source, rate, shape and size, and decides nothing about
who may do what. The core resolves the token, looks the verb up among the public ones, checks the
role by the policy every surface uses, and runs the verb through the chain the control socket
uses (`control.Invoke`): a privileged verb's audit entry first, its outcome after, declared errors
only.

**One answer without a token:** the token is checked before the verb is looked up, and the gate
checks the header's shape before anything a verb decides. Without a good token a public verb, a
private one and one that does not exist all answer the same `401`, so neither catalog is told to a
stranger. With one, a private verb and an unknown verb are both `404`.

**What is audited** is what the control socket audits: a failed token check, a refusal, a verb
that changes the host. A successful read writes nothing but the token's last use, once a minute at
most, so a monitor that polls leaves the audit log alone. The actor is the token's owner, with the
client's address, the token's number and the request id.

**A flood of bad tokens:** every token is verified (a key lookup and one SHA-256: nothing costly),
so bad tokens never stop a good one. Of the failures, twenty a minute are written to the audit
log, then one `auth.token.burst` entry, then none until the minute has passed. A token id is never
locked.

**A token's owner:** a disabled owner's token is a bad token at the next call. An owner told to
change its passphrase keeps its tokens: that rule is the passphrase login's.

**In the code:** `app/api.go` (`call`), `internal/auth/verbs.go` (`APIToken`),
`host/control/control.go` (`Invoke`, `Refused`).

## What is public

**Decided:** a verb is served only when its contract says `Public`. A test holds the list, so
adding one is a reviewed change, and requires of each that its answer is `Plain`: a verb whose
answer may hold logs, the host's files or people's data cannot be marked public. An open verb or a
login can never be public; the core does not start with such a contract.

The first set is seven reads: `sys.status`, `sys.checks`, `gate.route.list`, `gate.domain.list`,
`certs.list`, `services.list` and `sys.firewall.get` (the admin's; a viewer's token reaches the
other six).

**In the code:** `app/api_test.go` (`TestThePublicVerbsAreExactlyThese`), `app/api.go` (`serve`).

## Limits

| Limit | Value |
| --- | --- |
| Source ranges allowed | `allow` in `sys.api.set`; none means any address |
| Requests from one client (an IPv4 address, an IPv6 /64) | 60 a minute, a burst of 20; then `429` with `Retry-After` |
| Calls in flight | 8; one more waits two seconds, then `503` |
| of which to a verb with a larger body | 2 |
| Request body | 64 KiB, or what the verb's contract declares (`MaxBody`, at most 2 MiB + 64 KiB; only a public verb may) |
| Answer | 1 MiB; 64 KiB from a verb with a larger body |
| Time for one call | 30 seconds |

**Why these numbers:** the gate's unit allows it 64 MB (40 when the API was built), and an API call must never cost the sites
and the mail streams the gate serves. Each body and answer is held once as JSON and once in the
link's framing: six ordinary calls and two large ones at their largest come to about 21 MB. A verb
whose answer could be larger is not made public without redoing this sum.

**The rate is the gate's own token bucket,** kept for a bounded number of clients. It is a limit
against the internet, not against a gate that has been broken into; what the core guards itself is
its audit log.

**`/v1/health`** is answered from what the gate already knows (whether the core answered last time
it was asked). It costs no call, so it needs no token and is not counted against the rate.

**In the code:** `host/gate/api.go` (the constants at its top, `enter`, `rateTable`).
