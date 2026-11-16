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

**Decided:** the stack named `mail` is written by AutoPanel (`mail.setup.apply`), from a definition
compiled into it: Stalwart pinned by digest, as user 2000 under keep-id, a read-only root, its
`etc`, `data` and `log` folders as data, every port on loopback only, a 250 MB memory limit, and one
capability. It is then reviewed and applied as any stack. No other stack may be named `mail` or
publish its loopback ports, and an import of that name is refused (`services.reserved`). A mail
definition edited by hand is reviewed with a warning, since Mail may no longer manage it. Mail is
recorded only when its stack is added, so while a setup is open (being reviewed, or waiting for
Add and start) the guard admits the stack `mail` with AutoPanel's own definition, and still
refuses any other.

**Why AutoPanel writes it:** Mail's panels depend on the stack's shape: its ports, its management
port, its folders. A definition the administrator wrote could move any of them.

**The one capability:** Stalwart's binary carries `NET_BIND_SERVICE` as a file capability, and
with every capability dropped the kernel refuses to run it. It is kept; in a rootless container it
reaches only the container's own namespaces, and Stalwart binds no port below 1024 (it listens on
2525, 4465, 5587 and 9993 inside its container).

**How the services module knows:** the mail module is its `Guard`: it names the stack it owns,
adds its findings to that stack's review, reserves its ports, and masks what its logs must not show.
`core/services` imports nothing of mail's.

**In the code:** `core/mail/stack.go` (`compose`, `Ports`), `sdk/stalwart/product.go` (`Compose`), `core/mail/module.go` (`Owns`,
`Review`, `Reserved`, `Mask`), `core/services/module.go` (`Guard`).

## Setting mail up is one transaction

**Decided:** **Mail → Set up mail** (`mail.setup`) checks the host and the first domain and
answers the mail stack's review, reviewed from the definition in memory; it writes nothing. The
answers wait in the core's memory. **Add and start** on that review (`mail.setup.apply`, given the
review's sha256) makes every write, in this order: the stack's user, the loopback rule, the
definition in the stacks' directory, the stack added and started, the sealed settings, and last the
`mail` row that makes mail set up. A step that fails undoes the ones before it (the rule and the
definition are taken off again). Once the stack is registered, its apply keeps its own journal and
is not undone: asking again finishes it, and the record follows.

- Leaving the review, quitting the panel or restarting the core leaves no trace: Set up mail opens
  again, and the panel offers the answers it was given.
- A `mail` row with Stalwart never set up and no stack (what v0.2.6 left when its review was quit)
  is half a setup: the next Set up mail drops it.
- The stack's user, once made, stays after a failed apply: it owns nothing, and the next apply
  makes it again.

**Why:** v0.2.6 recorded mail as set up before its stack was reviewed. Quitting at the review left
mail "set up" with no stack, and the panel offered no way back.

**In the code:** `core/mail/module.go` (`setup`, `apply`, `untaken`), `core/services/apply.go`
(`CheckDraft`), `host/services/stage.go` (`StageDraft`), `internal/ui/mail.go` (`runMailSetup`).

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

**In the code:** `core/mail/module.go` (`Run`, `bootstrap`), `core/mail/bootenv.go`,
`sdk/stalwart/product.go` (`Bootstrap`), `sdk/stalwart/jmap.go`,
`host/mail/host.go` (`Journal`, `Forwarder`), `store/mail.go`,
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
- **With no token,** every record is shown with its value to publish by hand (`manual`). The panel
  lists the mail host's own records (its address and SPF) as a last row beside the domains, since
  they too are entered by hand then.

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
receiver can find. With the DNS by hand the rotation runs the same way: a new pair is made every 90
days and waits, the old one signing, until its records are entered and resolve. Each key's step is kept in the store, so a restart carries on from it. The
private keys are in the core's memory only to be handed over: they are Stalwart's to keep.

**In the code:** `core/mail/dkim.go` (`rotate`), `host/mail/host.go` (`ResolveTXT`).

## Mail apps sign in with app passwords

**Decided:** every device signs in with an app password of its own, made by Stalwart at AutoPanel's
request (`x:AppPassword`; its API generates the secret and refuses one supplied). The secret is
shown once, with the settings a mail app needs, and is in no store, log or audit entry of
AutoPanel's. A mailbox's own password is 32 random bytes the core generates, hashes (argon2id at
golib's least cost: no one can guess 256 bits, and Stalwart pays the cost at every failed sign-in)
and forgets, so mail apps sign in with app passwords only. Mailboxes made with a typed password keep
it until Lock password.

**Kept only once the device is set up:** a new app password expires ten minutes after it is made;
Done clears the expiry. Escape, a closed panel or a lost connection leaves it to expire, and
Cancel revokes it. Stalwart enforces the expiry itself, so it holds with the core down; the hourly
pass destroys expired ones, which otherwise count toward the account's limit.

**What Stalwart does that the code relies on** (tested against the pinned v1.1.0):

- The secret is `app_` and 36 of `[a-z0-9]`. AutoPanel refuses, and destroys, one under 128 bits
  or with fewer than 12 different characters: a weakened generator stops the feature.
- The user name is the full address: a bare local part signs in only to the default domain's
  account.
- **An expired app password whose expiry is cleared works again.** So keep reads it first, and
  destroys one within five seconds of its expiry instead of keeping it.
- **App passwords are entries of the account's `credentials` map**, beside its password. Replacing
  the map deletes them all (and two-factor's `otpUrl`). So a password change patches the password
  entry's `secret`, found by its `@type`, and a quota change patches `quotas/maxDiskQuota`; neither
  ever sends a whole map.
- The limit is 5 app passwords unless `quotas/maxAppPasswords` says otherwise; AutoPanel sets 20.
- Stalwart keeps no last use of an app password, so the list shows the device and when it was made.

**No expiry, no address limits:** a device far away whose app password expired could not be set up
again without someone there; phones move between networks. Revocation is the control.

**In the code:** `core/mail/apppassword.go` (the verbs, the strength check, the sweep),
`sdk/stalwart/server.go` and `jmap.go` (`AddAppPassword`, `KeepAppPassword`, `RevokeAppPassword`, `SetSecret`),
`internal/ui/apppassword.go` (the dialog and its QR code).

## Mail's rules name no mail server

**Decided:** mail's business logic (`core/mail`: the verbs, the setup transaction, DNS ownership,
DKIM rotation, the app-password lifecycle, the store and the vault) reaches the mail server only
through two interfaces of its own, in neutral terms (`core/mail/provider`):

- **`Server`** is a running server: domains, the records a domain needs, accounts (a password
  given as a hash), app passwords, DKIM keys, certificates. It answers the provider's errors
  (`ErrRefused` with the server's words, `ErrOverLimit`, `ErrUnauthorized`).
- **`Product`** is the server as AutoPanel runs it: its stack definition (with mail's loopback
  ports), its CPU needs, the line of its first start that holds a one-time credential, what to
  mask in its logs, its bootstrap (through an environment that reads the journal, restarts the
  stack and seals values under `mail/`), and its client.

Stalwart is one implementation, `sdk/stalwart`: JMAP, its image and inside ports, `x:Bootstrap`,
the zone file and every quirk recorded above live there and nowhere else. The app's wiring
(`app/core.go`) is the one place that names it. **Moving to another mail server is a new SDK
package and no change to `core/mail`.** Moving the mailboxes themselves is its own design.

**The contract is a test suite,** `core/mail/provider/conformance`. It runs against the server in
memory (`provider/memory`, on which `core/mail`'s own tests run) and against a real Stalwart on a
throwaway machine (`sdk/stalwart`'s `TestStalwartConforms`, `TestBootstrapAgainstStalwart`). A
new SDK ships when it passes it against its real server.

**The boundary is tested:** `core/mail/boundary_test.go` fails when `core/mail` or
`core/mail/provider` depends on an `sdk/` package, or names a server in an identifier or a string.

**Rules any server is held to, kept in `core/mail`:** an app password's secret of fewer than 128
bits is destroyed and refused; an expired app password is never kept (a server may revive it); a
mailbox's own password is a hash of one no one knows.

