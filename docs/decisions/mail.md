# Mail

How AutoPanel runs mail: Stalwart, as a stack of its own, behind the gate. This page grows with the
mail work; what is here is what the code already relies on.

## The gate forwards the mail ports

**Decided:** the gate, which already binds 80 and 443 without root, also binds the mail ports (25,
465, 587, 993) and forwards each connection byte for byte to the mail stack's port on loopback,
sending a PROXY protocol v2 header first so Stalwart sees the client's address. The core names the
ports over the link (`link.streams`); there are none until mail is set up.

**Why the gate:** the mail ports are below 1024, and the gate is already the one process allowed
to bind such ports, in AutoPanel's tightest sandbox. Lowering `ip_unprivileged_port_start` would let
every user bind them; a root container would undo what rootless stacks are for. The gate never reads
a byte after the header: 25 and 587 start in clear text and upgrade with STARTTLS, so the TLS is
Stalwart's.

**Limits:** at most 200 forwarded connections for every mail port together, with IMAP allowed up
to 150 of them (phones hold IDLE connections). Each port has its own limit per client (an IPv4
address, an IPv6 /64), 20 on the SMTP ports and 50 on IMAP (a household behind one address). A
connection with no byte either way is closed after its idle limit: 31 minutes on IMAP, which
clients re-issue within 29 (RFC 2177), and 10 on the others. The check runs every quarter of the
limit, so a silent connection ends between the limit and a quarter past it.

**Memory:** each direction is one splice between two TCP connections, so the gate holds no buffer
of its own per connection. The kernel charges socket buffers to the gate's memory, and autotuned
ones grow to megabytes: unbounded, 200 connections pushing at once took the gate far past its 40 MB.
Each forwarded socket's buffers are therefore capped, smaller on the client's side (the internet's,
where a small window is enough for mail) than on the service's (loopback, whose large segments need
more). Measured under the gate's own unit: 200 connections across the four ports beside plain HTTP
traffic peak at 17 MB; 150 clients uploading to a service that has stopped reading peak at 36 MB.

**A write deadline is never set while splicing:** it could expire with bytes inside the splice's
pipe, and they would be lost. Only a read deadline is used, which ends a wait for bytes and never a
transfer; a peer that stops reading is ended by the idle limit, which closes both sides.

**In the code:** `host/gate/stream.go` (the forwarder, the limits, `pipe`, `proxyHeader`),
`host/gate/link.go` (`Stream`, `Streams`), `app/streams.go` and `app/link.go` (the core's side).

## Only the gate reaches the mail ports

**Decided:** an nftables table of AutoPanel's, `inet autopanel_loopback`, drops every loopback
connection to the mail stack's forwarded ports that the gate's user did not make, and every one to
its management port that root did not make. A oneshot unit loads it at boot, ordered after the
distribution's nftables and before the mail stack user's systemd, and loads it again whenever
nftables restarts. The core checks it at its start and at every reconcile, and loads it again when
it is missing or changed.

**Why:** rootless port forwarding delivers every connection to the stack from the same address,
whoever made it. Stalwart trusts PROXY headers from that address, so without the rule any local user
or container could name any client: pass SPF with a forged address, escape rate limits, or relay
through Stalwart by claiming a local one. The rule makes the set of processes that can send a header
the gate alone.

**Not a firewall policy:** the table lets nothing in and opens nothing; it only refuses some
loopback connections. The firewall itself stays ufw's or firewalld's.

**Wants, not Requires:** the stack user's systemd only `Wants` the rule's unit. `Requires` passes a
restart on, so every nftables restart would restart the mail stack. The cost of `Wants` is that a
rule that fails to load at boot does not hold the stack back, which is why the core's check runs
first thing at its start.

**A set of ports, not a range:** the table lists the forwarded ports one by one, so a stack that
publishes another loopback port between them is not caught by it.

**In the code:** `host/mail/loopback.go` (`Rules`, `Unit`, `DropIn`, `Install`, `Check`,
`Ensure`, `Remove`), `internal/hostcmd` (`Nft`).

## The mail stack is AutoPanel's

**Decided:** the stack named `mail` is written by AutoPanel (`mail.setup`), from a definition
compiled into it: Stalwart pinned by digest, as user 2000 under keep-id, a read-only root, its
`etc`, `data` and `log` folders as data, every port on loopback only, a 250 MB memory limit, and one
capability. It is then reviewed and applied as any stack. No other stack may be named `mail` or
publish its loopback ports, and an import of that name is refused (`services.reserved`). A mail
definition edited by hand is reviewed with a warning, since Mail may no longer manage it.

**Why AutoPanel writes it:** Mail's panels depend on the stack's shape: its ports, its management
port, its folders. A definition the administrator wrote could move any of them.

**The one capability:** Stalwart's binary carries `NET_BIND_SERVICE` as a file capability, and
with every capability dropped the kernel refuses to run it. It is kept; in a rootless container it
reaches only the container's own namespaces, and Stalwart binds no port below 1024 (it listens on
2525, 4465, 5587 and 9993 inside its container).

**How the services module knows:** the mail module is its `Guard`: it names the stack it owns,
adds its findings to that stack's review, reserves its ports, and masks what its logs must not show.
`core/services` imports nothing of mail's.

**In the code:** `core/mail/stack.go` (`Compose`, `Ports`), `core/mail/module.go` (`Owns`,
`Review`, `Reserved`, `Mask`), `core/services/module.go` (`Guard`).

## Setting Stalwart up

**Decided:** once the mail stack runs, the core sets Stalwart up through its API, with no secret in
a file:

1. It reads the one-time password Stalwart printed at its first start from the stack user's
   journal, and sets Stalwart up with it (the `Bootstrap` object: the host name, the first domain,
   no certificate of Stalwart's own, no DKIM key yet).
2. Stalwart answers with its permanent administrator, which the core seals at once. A restart ends
   the one-time password.
3. As the administrator, the core moves the listeners to their ports, has the four forwarded ones
   trust PROXY headers from the mail stack's network, drops the listeners mail does not use (POP3,
   ManageSieve, Stalwart's own HTTPS), and makes an API key for itself, sealed. A restart applies
   the listeners.
4. Only then is mail marked set up, and the gate starts forwarding.

Each step checks what the one before left, so a bootstrap interrupted anywhere carries on from
there.

**The trusted source is read from Podman:** with netavark, rootless forwarding delivers every
connection to Stalwart from inside the stack's own network (from its container's address). The
network holds the mail container alone, so its subnet, as Podman reports it, is what Stalwart
trusts. It is never written into the code: another network backend (pasta) forwards from elsewhere.

**So the mail stack runs Stalwart alone:** a second service in it would share that network, and
could send Stalwart a forged PROXY header container to container, past the gate and the loopback
rule. Its review refuses a second service (`mail-one-service`), and the bootstrap trusts the subnet
only when Podman lists Stalwart's container alone on it. Webmail, when it comes, is a stack of its
own.

**Sealed under the master key:** mail's settings, Stalwart's administrator and the core's API key,
in the store's secret table, as the Cloudflare token is. With the vault locked, set-up and the
verbs that need Stalwart wait for root's login.

**The one-time password in the logs:** it is in the stack's journal while it is valid (root, the
stack's user and the journal's groups can read that). `services.logs` shows it as `[hidden]`, and
only the core can reach the management port it works on.

**Stalwart's administrator is not a mailbox:** it is how AutoPanel manages Stalwart. Mail's account
verbs leave it out, and refuse to change or remove it (`mail.admin_account`).

**In the code:** `core/mail/module.go` (`Run`, `bootstrap`), `core/mail/jmap.go`,
`host/mail/host.go` (`FirstPassword`, `Forwarder`), `store/mail.go`,
`sql/deployments/*/000005_update_mail.sql`.

## Mail domains are registry domains

**Decided:** a domain receives mail only if the registry holds it by its exact name. Removing a
registry domain that receives mail is refused (`gate.domain_has_mail`): the gate asks the mail
module through `DomainUsers`, and imports nothing of it. A mail domain with accounts is not removed.

**In the code:** `core/gate/domain.go` (`DomainUsers`), `core/mail/module.go` (`Uses`,
`domainRemove`).

## The mail host's certificate is AutoPanel's

**Decided:** the mail host's certificate comes from AutoPanel's own certificate manager, which
admits the mail host's name though no route holds it, and is handed to Stalwart through its API:
the first one is made and Stalwart restarted once (a new certificate is served only after a
restart); a renewal is an update, served at once after `ReloadTlsCertificates`. Stalwart's own ACME
stays off: its challenges would need the gate's ports, or a second copy of the DNS token.

**In the code:** `core/mail/sync.go` (`syncCertificate`), `app/certswitch.go` (`also`),
`app/mail.go` (`mailCerts`).

## DNS is kept by AutoPanel

**Decided:** every record a mail domain needs is published to its zone by the core, through the
sealed Cloudflare token, and kept in step every hour and after each change:

- MX, SPF (`v=spf1 a:<mail host> -all`), DMARC with AutoPanel's policy (`p=quarantine` at first),
  TLS reporting, the SRV records for the ports it serves (IMAPS, submissions and submission), each
  DKIM key's record when its rotation says so, and the mail host's own A record and SPF.
- Not published: what needs Stalwart's own HTTPS, which the gate does not route to it (MTA-STS,
  autoconfig, autodiscover, JMAP, CalDAV and CardDAV), and POP3.
- **Only its own records:** each record AutoPanel publishes is kept in the store with the provider's
  id, and only those are ever changed or deleted. A record of the same name and kind that AutoPanel
  did not write (another provider's MX, a DMARC record already there) is never touched or given a
  sibling: the record shows `different` until the administrator takes it over
  (`mail.records.takeover`). A second MX would split the domain's mail, and a second DMARC record
  makes DMARC fail everywhere.
- **SPF is merged, not replaced:** taking an SPF record over adds `a:<mail host>` to it before its
  `all` term, refusing a merge past SPF's limit of ten DNS lookups.
- **With no token,** every record is shown with its value to publish by hand (`manual`).

**In the code:** `core/mail/dns.go` (`served`, `keep`, `takeover`, `mergeSPF`),
`internal/cloudflare`, `app/mail.go` (`mailDNS`), `store/mail.go`.

## DKIM is rotated by AutoPanel

**Decided:** Stalwart makes no DKIM key on request, and rotates its keys itself only when it
publishes DNS itself. So the core runs the rotation, a pair at a time (Ed25519 and RSA 2048, each
its own selector, `ap<year><month>e` and `…r`):

1. It makes the keys and hands them to Stalwart, not yet signing.
2. It publishes their records.
3. Once the records have had ten minutes and public resolvers answer them with the right key, it
   has Stalwart sign with them, and stop signing with the pair before.
4. The old pair's records stay published for a week, for mail in flight, then go with their keys.
5. Ninety days on, the next pair starts.

A domain signs nothing until its first pair's records resolve, so no mail is signed with a key no
receiver can find. Each key's step is kept in the store, so a restart carries on from it. The
private keys are in the core's memory only to be handed over: they are Stalwart's to keep.

**In the code:** `core/mail/dkim.go` (`rotate`), `host/mail/host.go` (`ResolveTXT`).
