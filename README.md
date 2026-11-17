# AutoPanel

A lightweight control plane for self-hosted web services, written in Go: a reverse-proxy gate with
automatic TLS certificates, your own services as compose stacks under rootless Podman, and mail
with Stalwart, all run from one terminal panel.

**Status: early, and in daily use on a real server.** It serves sites over HTTPS with certificates
it obtains itself, runs stacks, and sends and receives mail that passes SPF, DKIM and DMARC. Its
interfaces will change before the beta (v0.3.0). [Progress](#progress) lists what is built and what
is next. Decisions are recorded under [docs/decisions](docs/decisions/README.md) as they are made.

## Install

AutoPanel runs on a Linux server with systemd. Point a name's DNS at the server and make sure
ports 80 and 443 reach it. On a server with no firewall on, a first install offers to turn one on,
allowing only SSH and those two ports (`--firewall yes|no` answers it ahead).

**Install or upgrade, in one line:**

```sh
curl -fsSL https://raw.githubusercontent.com/yongjohnlee80/autopanel/main/install.sh | sudo sh
```

**Or read the script before you run it:**

```sh
curl -fsSLO https://raw.githubusercontent.com/yongjohnlee80/autopanel/main/install.sh
less install.sh
sudo sh install.sh
```

A first install asks three things on the terminal:

1. **A contact email** for the Let's Encrypt account that issues the certificates. It is sent only
   to Let's Encrypt.
2. **Staging or production certificates.** Choose staging for the first install on a new server,
   and switch once the site answers: see [Staging and production certificates](#staging-and-production-certificates).
3. **A master passphrase** of at least 12 characters, twice. It is the `root` login for the admin
   TUI and the only way to open the stored secrets without the server's keyfile, so keep it.

The installer downloads the latest release for the machine and checks its SHA-256. When there is
no release to download, it builds from source on the server, which needs git and Go 1.26 or later.
It then creates the `autopanel` system user, installs the binary and two systemd units, and starts
them. Running it again upgrades the binary and keeps the configuration, the store and the keys.

**Upgrading from v0.1.4 or earlier** moves the one `autopanel` service to the two described in
[How it runs](#how-it-runs). The sites are down for the few seconds between the old service
stopping and the new ones starting. If the new services do not start, the installer puts the old
one back and says so. The admin command changes from `sudo -u autopanel autopanel --ui` to
`sudo autopanel --ui`.

**With no terminal** (a provisioning script), give the answers as options. The passphrase file
must be mode 0600, and you can delete it afterwards. Without `--ca`, a no-terminal install uses
staging:

```sh
sudo sh install.sh --email admin@example.com --ca production --passphrase-file /root/autopanel-passphrase
```

| Option | Meaning |
| --- | --- |
| `--email <address>` | the Let's Encrypt contact, instead of being asked |
| `--passphrase-file <path>` | read the master passphrase from a 0600 file |
| `--version <tag>` | install that release (for example `v0.1.0`) instead of the latest |
| `--source` | build from source on the server instead of downloading |
| `--binary <path>` | install a binary you built yourself |
| `--ca staging\|production` | which Let's Encrypt service issues the certificates, instead of being asked |
| `--http <addr>`, `--https <addr>` | the listeners; `:80` and `:443` by default |
| `--restart always\|on-failure\|no` | the core's restart policy |
| `--no-start` | install without starting the services |

### How it runs

AutoPanel is one binary that runs as two services:

| Service | Runs as | What it does |
| --- | --- | --- |
| `autopanel-gate` | the `autopanel` user, sandboxed | faces the internet on ports 80 and 443; holds only the routes and the certificates it is serving |
| `autopanel-core` | root | holds the store, the keys and the settings; gets the certificates; listens on no network |

The gate asks the core for its routes and certificates over a socket only it can open. If the
gate is ever broken into, the store, the master key and the Cloudflare token are out of its
reach. The core starts the gate, so `systemctl start autopanel-core` starts both. If the core
stops, the gate keeps serving what it has.

The admin TUI and the `--call` command talk to the core, so they run as root.

### Serve your first site

Open the admin TUI on the server:

```sh
sudo autopanel --ui
```

It opens on a sign-in dialog. The user is `root`; type the master passphrase, press Enter, leave
the two-factor code empty until you have enrolled one (below), and press Enter again. Quit or Esc
leaves.

**The main screen** is a set of tiled widgets that read the server every five seconds:

| Widget | What it shows |
| --- | --- |
| Host | processor use, memory, swap, disk, load and uptime |
| Network | each interface's traffic in and out per second, its totals and its errors |
| Stacks | each stack's containers: state, health and memory |
| Traffic | the requests the gate has served, and each domain with its routes |
| Ports | the sockets listening on the server |
| Certificates | the certificate service in use, and the names it certifies |
| Activity | the newest entries of the audit log |

Drag a widget with Alt (Option) and the left mouse button to put it elsewhere or swap it with
another; drag the border between two with Alt and the right button. The icons at the right of the
menu bar are the dock: one per widget and per open panel, dimmed while it is hidden; a click hides
or shows it. **View** does the same by name, hides the status bar, and puts the layout back.

**The menus** open with Alt and the marked letter of their name, or with F10. A button names its
key by its marked letter (`Remove` with its R in the accent colour); **Help → Keys** (F1) lists
every key. `r` reads the screen again and `q` quits.

| Menu | What it holds |
| --- | --- |
| System | **Metrics**, **Audit log**, **Login attempts**, **Open ports**, **Firewall**, **Host checks**; **Theme** and **Language** |
| Routes | **Proxy routes**: the names AutoPanel serves and where each goes; **Domains**: the domains you own |
| Certs | **Certificates**: each name's certificate, when it expires and why its last order failed; **Type**: which Let's Encrypt service issues them, staging or production; **Cloudflare token**: lets AutoPanel write DNS records |
| Services | **Stacks** and **Add a stack**: your services, below |
| Mail | **Set up mail**, **Domains**, **Accounts**, **Server**, **DNS records**: mail with Stalwart, below |
| Users | **Manage users**, **Passphrase**, **Two-factor**, **API tokens**, below |
| Go | **Terminal**: shells on the server, a tab each |
| View | the widgets, the status bar, and the layout |
| Help | **Keys** and **About** |

**Panels** open over the main screen: the list on the left, the selected row's details on the right,
the buttons under both. Drag a panel with Alt and the left button, resize it with Alt and the right
button; `q` or Esc closes it.

To serve a site, first register the domain it belongs to: **Routes → Domains**, `a`, and its name
(`example.com`). A route's name must be a domain you registered or a name under one; one under none
is refused. Then open **Routes → Proxy routes** and press `a` to add a route: a subdomain (`www`, or
nothing for the domain itself) and the domain, a path prefix (`/`), and the upstream it forwards to
(`http://127.0.0.1:8080`, or one of your stacks' ports, offered in the form). AutoPanel gets the
certificate for a routed name on its first HTTPS request, and redirects plain HTTP to HTTPS.

A domain is removed only when no route would be left under none. Upgrading from v0.2.3 or earlier
registers each name your routes already have as a domain, so nothing stops serving.

### Watch the server

The **System** menu shows the server as it is now. Each panel reads when it opens, and `r` reads
it again.

| Panel | What it shows |
| --- | --- |
| Metrics | the core's uptime and memory; the gate's request counts since it started, its process and its memory, or that it is not reporting; the host's load, memory, and the disk the store is on |
| Audit log | the newest 200 changes made through AutoPanel: who, what, and when |
| Login attempts | logins to the panel, and logins to the server over SSH: accepted, failed, and closed before logging in |
| Open ports | every listening TCP port and bound UDP port, the address it listens on, the process that holds it (named by its executable, with its number) and the user it belongs to, and what it is for when AutoPanel knows: its own listeners, a route's upstream, or, for a socket whose process could not be read, the port's usual service. Each says what the firewall does to a new connection from anywhere: allowed, limited (to whom), blocked, local, or unknown when AutoPanel cannot tell; an allow rule nothing listens behind is a row of its own |
| Firewall | the host's firewall through ufw (a host running firewalld is shown as such, its verdicts unknown, until firewalld is supported): its rules, and whom AutoPanel made each for. Allow a port, revoke a rule, turn it on or off. Turning it on shows first what it would block, and undoes itself after 120 seconds unless you confirm from a new login in a second terminal. A change that would stop new SSH logins from your address is refused, with the commands for doing it by hand if you are sure. An admin's |
| Host checks | the server's posture: a pending reboot, failed units, the firewall off or partial, ports the gate, mail or a stack need that the firewall blocks, Docker and its group, SSH taking passwords, and what to do about each |

SSH logins come from the system journal, which the core reads. The gate has no access to it.

### Open a shell

**Go → Terminal** opens a terminal on the server, inside the panel. Choosing it again hides the
terminal; its shells keep running, and the row is checked while it is open.

Each shell is a tab. `+` on the tab strip starts another, and `≡` (or a right click on the strip)
opens the tab's menu: go to a shell, start one, close this one, maximize or hide the terminal. At
the right of the strip, `_` minimizes the terminal, the box maximizes it, and `x` stops every shell
and closes it, asking first while one is running.

The panel runs as root, but a new tab is a login shell of **the user who ran `sudo`**, named on
the tab. Use `sudo` there as you would in any terminal, or choose **New root shell** in the tab's
menu. If you logged in as root itself, every shell is root's.

While a shell has the keyboard, every key goes to its program. The exceptions:

| Key | What it does |
| --- | --- |
| Ctrl+T | leaves the program for the scrollback: move, search (`/`), select (`v`) and copy (`y`) as in vim; `i` goes back to typing |
| F11 | maximizes the terminal, or restores it |
| Ctrl+Tab, Ctrl+Shift+Tab | the next shell, the one before. Many terminals do not send these keys; the tab's menu and the mouse always work |

In the scrollback, `q` or Esc hides the terminal. A shell ends when its program exits, when its
tab is closed, or when the panel quits: nothing started in a tab outlives the panel unless you
detach it yourself (`nohup`, `tmux`).

What is typed in a shell is not in AutoPanel's audit log. The shells are ordinary processes of
the panel, and the daemon neither starts nor sees them.

### Run a stack

AutoPanel runs your services as **stacks**. A stack is a compose file you write: the format
projects already publish. AutoPanel reads it itself and runs its containers under rootless
Podman, as systemd units of an unprivileged user of the stack's own. No compose program and no
Docker is used.

1. Write the stack's definition into a folder of its own, anywhere on the server: a
   `compose.yaml`, a `.env` when the file uses `${VARIABLES}`, and any configuration files the
   containers mount. For example:

   ```sh
   mkdir -p ~/services/site
   cp -r docs/examples/static-site/. ~/services/site/
   ```

2. In the panel (`sudo autopanel --ui`), **Services → Add a stack…** opens a file browser: the
   folders on the left, a preview of the file under the cursor on the right. A folder that holds a
   `compose.yaml` is marked ◆. The preview hides every value of a `.env` file and the value of each
   setting whose name says it is a secret.

3. On the stack's folder, **Import…** asks the stack's name (the folder's own, unless you change it:
   a lower-case letter, then letters, digits and hyphens) and **imports** it: AutoPanel copies the
   definition (`compose.yaml`, `.env`, the `env_file`s and the read-only mounts, not the data) into
   `/etc/autopanel/stacks/<name>/`, which only root can change, and remembers the folder it came
   from. Then it shows a **review**: every file that defines the stack, each container it would run
   (its image, user, ports, mounts and memory limit), and what AutoPanel refuses or warns of.

4. Confirm. AutoPanel makes the stack's user (`ap-<name>`), copies the definition into that user's
   directory (`/var/lib/autopanel-services/<name>`), pulls the images, writes the units and starts
   them. **Prepare only** does all of that but start them, so data can be put in place first.

A definition copied into `/etc/autopanel/stacks/<name>/` by hand works too; it has no source.

**Why a copy:** AutoPanel runs as root. A stack that read your folder on every apply would let
anyone who can write that folder decide what root runs. The copy is root's, and the stack runs on
if the folder is moved or deleted.

**Services → Stacks…** lists each stack, its containers under it, with their state and health;
the details of the selected one are on the right: its image and digest, ports, restarts, when it
started, processor time, memory, and the folder it was imported from. A button acts on the selected
row: a container's row on that service, a stack's row on the whole stack.

| Button | Key | What it does |
| --- | --- | --- |
| Add… | `a` | add a stack from a folder |
| Apply… | `p` or Enter | review the stack's definition as it is now, and apply it |
| Start | `t` | start the service, or the stack |
| Stop | `x` | stop it, after asking; it stays stopped across a reboot |
| Restart | `e` | restart it |
| Logs | `o` | its newest log lines |
| Pull images | `u` | pull its images again, and restart what changed |
| Update from source | `s` | copy the definition from its folder again, then review and apply it |
| Remove… | `r` | remove the stack, after asking: keep its directory and data, as root's, or delete them |

A stack whose definition changed is marked `*`; one whose source folder changed says so, and
**Update from source** brings the change in.

The same from the command line:

```sh
sudo autopanel --call services.browse '{"path":"/home/admin/services"}'          # a folder, for the browser
sudo autopanel --call services.import '{"from":"/home/admin/services/site"}'    # copy the definition in
sudo autopanel --call services.check '{"name":"site"}'            # the review; changes nothing
sudo autopanel --call services.add '{"name":"site","accept":"<the review's sha256>"}'
sudo autopanel --call services.list                               # each stack and its containers
sudo autopanel --call services.logs '{"name":"site","service":"web"}'
```

Stacks need **Podman 4.9 or newer** on the server. `install.sh` installs it (skip that with
`--no-podman`). Without it the panel and the gate work as before, and a stack is refused with the
reason.

#### Changing a stack

Edit the files in the stack's source folder, then **Update from source** (`s`) in the panel, or
`services.reimport` then `services.check` and `services.apply`. A definition you keep in
`/etc/autopanel/stacks/<name>/` by hand is edited there and applied with `p`. Nothing changes until
you apply: an apply shows the review again, and then:

- stops and removes the services the file no longer has;
- replaces the stack's configuration with what you reviewed;
- restarts the containers whose unit, image or configuration changed, and no others.

A stack whose definition differs from what is running is marked in the list.

An apply that fails part-way leaves the stack marked incomplete, with the step it stopped at and
why. Apply again to finish it.

#### What an apply reviews, and what it never touches

The review covers every file that defines the stack: `compose.yaml`, `.env`, every `env_file`,
and every file under a mount marked `:ro`. Its hash is what `services.add` and `services.apply`
must be given, so a file edited between the review and the apply is refused, and you are shown
the new review.

A mount **without** `:ro` is the stack's **data**: a database, uploaded files. AutoPanel makes
that folder when it is not there, and never writes into it again. An apply cannot overwrite it,
and a definition that would turn a data folder into configuration is refused. To put data into a
new stack before it first starts, use **Prepare only** in the review (`services.prepare`): it
makes the user, copies the definition and pulls the images, and starts nothing. Copy the data
into `/var/lib/autopanel-services/<name>/stack/`, then add the stack.

A file a container must read as a user that is not the stack's (most images that do not run as
root) has to be readable by all in the definition folder (`chmod 644`). The folder itself is
root's, and the stack's own directory is its user's alone, so no other user of the server reads
it. `.env` is always kept readable by the stack's user only.

#### The compose keys AutoPanel takes

`image`, `command`, `entrypoint`, `environment`, `env_file`, `ports`, `volumes`,
`network_mode: host`, `depends_on`, `restart`, `user` (two numbers, as `"991:991"`), `read_only`,
`cap_add`, `cap_drop`, `tmpfs`, `working_dir`, `hostname`, `mem_limit`, `healthcheck`, and named
`volumes` with no options. `labels` and `container_name` are read and not used: a container is
named `<stack>-<service>`.

Any other key is refused by its name, never dropped: `build`, `privileged`, `devices`,
`networks`, `secrets`, `security_opt`, `sysctls` and the rest. So is:

- a mount from outside the stack's folder (an absolute path, or one with `..`);
- a capability beyond Podman's rootless defaults;
- a host port below 1024: a stack's user cannot bind one, and web traffic goes through a route;
- a port another stack has, or another program listens on;
- a `depends_on` condition other than `service_started`;
- a `${VARIABLE}` that `.env` does not have. The server's own environment is never used.

The review warns, and lets you go on, when: an image is named by a tag and not a digest; a port
is published on every address; a service uses the host's network; a service has no memory limit,
a writable root or no `user`; a value from `.env` is used in a command, where every user of the
server can read it (use `environment` for a secret: it reaches the container through a file).

#### What every stack gets

- Its own unprivileged user, and a directory only that user can open.
- A network of its own: its containers reach each other by service name, and no other stack's
  container is on it. This is not a wall around the stack: a container can still reach what the
  server publishes, another stack's published ports included.
- No way for a container to gain a privilege.
- Each image runs by the digest its pull resolved. A restart or a reboot cannot change the image;
  only `services.pull` (`u`) asks the registry again.
- A service you stop stays stopped across a reboot, with the services that depend on it, until
  you start it.

Each change is written to the audit log **before** it runs, with the review it accepted and how
it ended. If the entry cannot be written, the change is refused and nothing is done. **System →
Audit log** shows them.

#### Removing a stack

**Remove…** (`r`) in the panel, or `services.remove '{"name":"site"}'`, stops the stack and deletes
its units and its user. Its directory, with its data, is kept as root's, under a name no later
stack takes. Choosing to delete the data when the panel asks, or `"purge":true`, deletes the
directory too. The definition folder under
`/etc/autopanel/stacks` is never deleted.

#### Examples

- [`docs/examples/static-site`](docs/examples/static-site): nginx serving a folder of pages on a
  loopback port, for a route to point at.
- [`docs/examples/turn`](docs/examples/turn): a TURN relay ([coturn](https://github.com/coturn/coturn))
  on the host's network. Open its port and its relay range in your firewall. The relay
  authenticates with a shared secret your application makes short-lived credentials from; the
  secret is in a file the relay alone reads, and its other settings are on its command line, so
  a relay that lost its file serves nobody.

#### Coming from v0.2.2

The TURN template and its form are gone, with `services.templates`, `services.deploy`,
`services.update` and `services.secret`. A relay deployed from the template is still listed, and
can only be removed: remove it, then add the example stack above with the same settings.

### Run mail

AutoPanel runs [Stalwart](https://stalw.art) as a stack of its own, behind the gate: the gate binds
25, 465, 587 and 993 and forwards each connection to Stalwart with a PROXY header, so Stalwart sees
each client's real address. Every key and setting of mail is sealed under the master key, and DKIM
keys rotate by themselves. The DNS records mail needs are published and kept for you when the
domain's DNS is at Cloudflare; anywhere else, the panel lists them for you to enter.

**[MAIL.md](MAIL.md) is the full guide:** every Mail screen and key, taking over DNS records a
domain already has, setting up a mail app, checking from outside, and troubleshooting. The reasons
behind the design are in [docs/decisions/mail.md](docs/decisions/mail.md).

**Before you start:**

- The host's processor must run Stalwart's build: x86-64-v2 (on a virtual machine, a CPU type of
  `host` or `x86-64-v2`), or arm64. Setting mail up refuses otherwise.
- Port 25 must reach out from the host: many providers block it until asked. And the provider sets
  the host address's reverse name (PTR): point it at the mail host, or receivers will distrust it.
- Decide who writes the DNS records (below): AutoPanel, through a Cloudflare token, or you, by
  hand at your DNS provider.
- The domain is in **Routes → Domains** by its exact name.

#### DNS: what mail needs

An A record that points a domain at the server does not bring it mail: mail goes where the domain's
**MX** record says, and receivers check **SPF**, **DKIM** and **DMARC** before they trust it. So
every mail domain needs these records, whoever writes them. With `example.com` receiving mail on
the mail host `mail.example.com` at `192.0.2.10`:

| Record | Name | Value | Needed |
| --- | --- | --- | --- |
| A | `mail.example.com` | `192.0.2.10` | yes: the mail host's address. Not proxied |
| MX | `example.com` | `10 mail.example.com` | yes: where the domain's mail goes |
| TXT (SPF) | `example.com` | `v=spf1 a:mail.example.com -all` | yes: who may send as the domain |
| TXT (DKIM) | `ap202611e._domainkey.example.com`, `ap202611r._domainkey.example.com` | `v=DKIM1; k=ed25519; …`, `v=DKIM1; k=rsa; …` | yes: the keys mail is signed with. Copy the values from the panel; they change every 90 days |
| TXT (DMARC) | `_dmarc.example.com` | `v=DMARC1; p=quarantine; rua=mailto:postmaster@example.com` | yes: what receivers do with mail that fails |
| TXT (SPF) | `mail.example.com` | `v=spf1 a -all` | recommended: for mail the server sends as itself (bounces) |
| TXT | `_smtp._tls.example.com` | `v=TLSRPTv1; rua=mailto:postmaster@example.com` | optional: TLS failure reports |
| SRV | `_imaps._tcp`, `_submissions._tcp`, `_submission._tcp` (each `.example.com`) | `0 1 993 mail.example.com`, `0 1 465 …`, `0 1 587 …` | optional: lets mail apps find the server by themselves |

**Mail → Domains** lists every one, with its exact value, for each mail domain and, as the last row,
for the mail host itself. `sudo autopanel --call mail.records '{"domain":"example.com"}'` prints the
same.

One record is not in a zone at all: the **reverse name (PTR)** of the server's address, which the
hosting provider sets. Ask it to point the address back at the mail host (`mail.example.com`);
without it many receivers treat the server's mail as spam.

#### With Cloudflare: AutoPanel writes them

When the domain's DNS is hosted at Cloudflare, give AutoPanel an API token, and it publishes every
record above itself, keeps them in step, and rotates the DKIM keys without you:

1. In Cloudflare, **My Profile → API Tokens → Create Token**, from the **Edit zone DNS** template:
   permission *Zone · DNS · Edit*, add *Zone · Zone · Read*, and under *Zone Resources* the zone of
   **every** domain under Routes → Domains, not only the mail domains (see below).
2. Give it to AutoPanel: **Certs → Cloudflare token…**, as an admin, and paste it. It is typed
   unseen, checked with Cloudflare (a mistyped or inactive token is refused and not kept), then
   sealed under the master key. **Certs → Remove Cloudflare token…** forgets it.

   **The token changes how every certificate is obtained:** with it, AutoPanel obtains them all
   through DNS (DNS-01), so a domain whose zone the token does not reach fails at its next renewal.
   If the token cannot be put to use, the one before it is kept.
3. Set mail up (below). The records appear in Cloudflare within the first pass, a minute or two after
   Stalwart is ready; **Sync** runs a pass at once.

AutoPanel writes only the records it needs, and changes or deletes only those it wrote (it keeps
their Cloudflare ids). A record of the same kind that was there before, such as another provider's
MX or an existing DMARC record, is left alone and shown as `different` until you **Take over** it.
The mail host's A record is never proxied: mail does not pass through Cloudflare.

#### Without Cloudflare: you enter them

With the DNS anywhere else (Namecheap, your registrar, your own server), there is no token to give
and AutoPanel cannot write the zone. Mail works the same, but every record shows `manual`, and you
enter each one at your DNS provider:

1. Set mail up (below), and wait for **Mail → Server** to say `ready`.
2. Open **Mail → Domains**. For each domain, and for the mail host's row at the bottom, copy each
   record's name and value from the right side.
3. Enter them at the provider. At **Namecheap**, that is **Domain List → Manage → Advanced DNS**:
   - First, under **Mail Settings**, choose **Custom MX**: the MX records can only be added then.
   - The **Host** field takes the name *without* the domain: `@` for `example.com` itself, `mail`
     for `mail.example.com`, `_dmarc`, `ap202611e._domainkey`, and so on.
   - Paste TXT values as they are, without quotes. The RSA DKIM value is long; paste it whole.
   - An SRV record's fields are split up: Service `_imaps`, Protocol `_tcp`, Priority `0`, Weight
     `1`, Port `993`, Target `mail.example.com`.
   - Leave the TTL automatic.
4. Check what the world sees, for instance `dig +short MX example.com` and
   `dig +short TXT ap202611e._domainkey.example.com`.

The records keep showing `manual`: AutoPanel does not watch a zone it cannot write. What it does
watch is DKIM. A domain signs nothing until its DKIM records answer from public resolvers, and then
switches to signing by itself; **Mail → Domains** shows each key's step move from `published` to
`signing` once you have entered them.

**Every 90 days** a new DKIM pair is made and shows under the domain's records with new names (the
selector carries the month: `ap202702e`). The old pair keeps signing until you enter the new
records; then the new pair takes over, and a week later the old records can be deleted. With the
DNS by hand, look at **Mail → Domains** every few months for new DKIM rows, or move the domain's DNS
to Cloudflare (its free plan is enough), which takes the work away.

#### Setting it up

**Mail → Set up mail** asks the mail host and the first domain, and opens the mail stack's review.
Nothing is written until you confirm it: leave the review, or quit, and Set up mail opens again with
your answers. The review lists mail's four ports (25, 465, 587, 993) with what the firewall does to
each, ticked when they need a rule; where AutoPanel cannot open them it shows the commands that
would, with a Copy button, and a reminder that a provider's firewall in front of the server needs
them too. **Add and start** makes the whole setup at once (the stack's user, its loopback rule,
its files, the stack started, the ticked ports opened, and the record); if a step fails, the ones
before it are undone. **Mail → Server** shows each port, and **Open ports** opens the blocked ones
for a server where they were not opened at set-up.
AutoPanel then sets Stalwart up through its API, by itself, within a minute or two: **Mail → Server**
says `ready` when it is done, and from then on the gate forwards the mail ports.

The mail host's certificate comes from AutoPanel's own certificate service, once the mail host's A
record resolves to this server: **Mail → Server** shows it (`ok until …`), and **Sync** asks for it
again after you have entered the record. A certificate from Let's Encrypt's staging service works
but mail apps warn about it; switch to production (below) once mail runs.

#### The panels

**Domains** lists the domains that receive mail; the right side shows each record the selected one
needs and its state:

| State | Means |
| --- | --- |
| ok | the zone holds it as AutoPanel wrote it |
| publishing | just published; resolvers will have it within minutes |
| different | the zone holds a record of that kind AutoPanel did not write (another provider's MX, a DMARC record already there). Nothing is published beside it: **Take over** replaces it after showing it (an SPF record is merged instead) |
| manual | no Cloudflare token: enter the value at your DNS provider yourself (above) |
| failed | Cloudflare refused it; the error says why |

A domain's DKIM keys are listed under its records: a new pair is published, then signs once public
resolvers answer its records; every 90 days the next pair takes over.

**Accounts** makes mailboxes (`name@domain`, 5 GB by default) and deletes them. Mail apps sign
in with **app passwords**, one per device:

1. Select the mailbox and press **New app password…** (`n`), and name the device ("Ana's phone").
2. The dialog shows the password once: as one line to type or paste, in groups of four to check
   it, and as a QR code a phone's camera can read. Beside it are the settings: the user name (the
   full address), IMAP on 993 (SSL/TLS), SMTP on 465 (SSL/TLS) or 587 (STARTTLS).
   **Copy password** (`p`) puts it on the clipboard of the computer you use the panel from (the
   terminal does the copy, so it works over SSH), and closing the dialog empties the clipboard.
3. Set the device up, and once it signs in press **Done**. An app password not kept within ten
   minutes stops working; **Cancel** revokes it at once.

Stalwart generates each app password (`app_` and 36 random letters and digits); AutoPanel refuses
one weaker than 128 bits and keeps none. **Revoke** (`v`) stops one device without touching the
others. App passwords do not expire on their own.

A mailbox's own password is generated by AutoPanel, sent to Stalwart as a hash, and told to no
one, so only app passwords sign in. Mailboxes made before v0.2.9 keep the password they were given
until **Lock password…** (`o`) replaces it the same way; set their devices up with app passwords
first.

**Not yet:** webmail (a stack of its own, later), forwarding mail to an outside address, and aliases
from the panel; Stalwart's own web interface (through an SSH tunnel to its management port, as
root) does them meanwhile.

### Users, two-factor and API tokens

Root is the first admin. Under **Users** you can give other people their own login, turn on a
second factor, and make tokens for scripts.

**Roles.** Every user has one:

| Role | May |
| --- | --- |
| admin | everything, including users, the gate's settings and setting mail up; holds the master key |
| operator | run routes, stacks and mail, read their logs and the host's files; not users, certificates' settings or the gate's settings |
| mail | manage mail domains and accounts; read routes, domains and the server's status; not stacks or certificates |
| viewer | read what the screen shows, change nothing; never logs, files or who logged in |

Everyone may change their own passphrase, two-factor and tokens. Menus a role cannot use are greyed
out, and the daemon refuses them regardless. Only admins hold a copy of the master key. The
server's keyfile opens the vault when the core starts; without it (removed, or a store restored on
another server), only an admin's login unlocks the vault, and until then the sign-in dialog says the
vault is locked and users with two-factor cannot sign in yet.

**Users → Manage users…** (admins) lists everyone with role, two-factor and state. **Add** asks a
name, a role (viewer unless you change it) and a first passphrase; **Reset** sets a new passphrase;
**Role** changes the role (with a new passphrase, since an admin's login holds the key and anyone
else's does not). In every case the user must choose their own passphrase at their next login, and
can do nothing else first. **Disable**, **Unlock** (after ten failed logins an account is locked for
15 minutes) and **Remove** do what they say. Root and the last admin cannot be demoted, disabled or
removed. A passphrase is at least 12 characters, does not contain the user's name, and is not one
of the 10,000 most common passwords.

**Users → Two-factor…** shows a secret and an `otpauth://` link for any authenticator app (Aegis,
Google Authenticator, 1Password and the like), then asks a code from it, then shows ten recovery
codes once: each signs you in once in place of a code if you lose the app. From then on, type the
code in the sign-in dialog's second field. Turning it off takes a code. If someone loses both their
phone and their codes, an admin turns it off for them:

```sh
sudo autopanel --call auth.totp.disable '{"name": "ana"}'
```

**Users → API tokens…** makes a token for a script: a name, a role (viewer unless you ask for
more, and never above your own) and how many days it lasts (90 by default, 365 at most). It is
shown once; put it in a file only root can read and pass the file:

```sh
sudo install -m 0600 /dev/null /root/backup.token   # then paste the token into it
sudo autopanel --call --token-file /root/backup.token services.list
```

The file must be root's and mode 0600, or it is refused; a token is never read from the command line
or the environment. A token never manages users, tokens or passphrases, follows its owner (a
demoted owner's tokens are demoted, a removed owner's stop), and is named on the audit log as
`token <name> of <user>`. **Revoke** ends one at once.

**Sessions.** The panel asks for the login again after 30 minutes without a key, and the daemon
ends any login after 12 hours.

### Themes and languages

**System → Theme** offers ten themes, and **System → Language** six languages: English, Korean,
Japanese, Simplified Chinese, Spanish and Brazilian Portuguese. Both take effect at once and are
kept in AutoPanel's store, so the panel opens the same way next time.

### Certificates and their renewal

**Certs → Certificates** lists every name AutoPanel serves, and the mail host, with the certificate
it holds for each:

| State | Means |
| --- | --- |
| none yet | no certificate yet: the first HTTPS request for the name orders one |
| valid | nothing to do |
| renewing | in the last third of its life: the next request for the name renews it |
| expired | the next request must obtain a new one first; until that works, browsers refuse the site |
| unknown | the stored certificate could not be read; with the vault locked, log in first |

The right side shows who issued the selected certificate, when it expires, when its renewal
starts, and, if the last order for the name failed, when and why. Opening the panel orders
nothing. `sudo autopanel --call certs.list` prints the same.

A certificate is renewed when a request for its name arrives in the last 30 days of its 90. A name
nobody asks for is not renewed, and gets a new certificate at its next request.

Every order is in the audit log (**System → Audit log**) as `certs.obtained`, `certs.renewed` or
`certs.failed`. **System → Host checks** raises an alert when a certificate has expired or is
within 7 days of its end, and a notice when a name's last order failed. See
[docs/decisions/certs.md](docs/decisions/certs.md).

### Staging and production certificates

Let's Encrypt runs two services, and the installer asks which one to use:

| | Staging | Production |
| --- | --- | --- |
| Certificates | test certificates | real certificates |
| Trusted by browsers | **no**: a browser shows a certificate error | yes |
| Limits | loose: a mistake costs nothing | strict: a name that keeps failing its check is refused for an hour or more, and the same certificate is issued only a few times a week |
| Use it | first, on a new server or a new name | once the site answers on staging |

Both check the name the same way, so a certificate from staging proves that DNS points at the
server, that ports 80 and 443 are reachable, and that AutoPanel can answer the challenge. That is
why staging comes first: a wrong DNS record or a closed port fails there for free, where it would
use up the production limits.

**Check a staging site** with a client that skips verification:

```sh
curl -kI https://example.com
```

The certificate's issuer then starts with `(STAGING)`. A browser will refuse the page, and for a
name under a domain that browsers force to HTTPS (`.app`, `.dev`), it offers no way past the error.

**Switch to production** when the site answers: in the panel, open **Certs → Type** and choose
**Production**. It takes effect at once, with no restart, and AutoPanel gets the real certificate
on the next HTTPS request for each routed name. The same menu switches back to staging.

The menu marks the service in use, and the panel's overview names it. From a script:

```sh
sudo autopanel --call certs.ca.set '{"ca":"production"}'
sudo autopanel --call sys.status
```

The installer's choice (`AUTOPANEL_ACME_CA` in `/etc/autopanel/autopanel.env`) is what a new
install starts with. A choice made in the panel or with `certs.ca.set` is kept in AutoPanel's store
and replaces it from then on.

If you know the server is set up correctly, install with production from the start: answer `2` at
the prompt, or pass `--ca production`.

### Check and remove

```sh
systemctl status autopanel-core autopanel-gate
journalctl -u autopanel-core -u autopanel-gate -e
sudo autopanel-uninstall --check     # lists what a removal would take; changes nothing
sudo autopanel-uninstall --apply     # removes the services and the binary; keeps data, config and keys
sudo autopanel-uninstall --purge     # removes everything, after backing the store up
```

A deployed service is stopped by `--apply`, and its user and directory are deleted by `--purge`.
`--keep-services` leaves the deployed services running, with their users and directories.

## Progress

**Built and released** (v0.2.11):

| Area | What works |
| --- | --- |
| Proxy gate | routes by host and path, changed without a restart; a request in flight finishes on the route it started with. HTTP/2, WebSocket upgrades, streamed answers and large uploads pass through. Behind Cloudflare, the client's address is believed only from Cloudflare's ranges |
| Certificates | Let's Encrypt, staging or production, by HTTP-01 and TLS-ALPN-01, or by DNS-01 with a Cloudflare token. Kept in the store. A name no route holds gets no certificate |
| Two processes | a sandboxed gate that faces the network, and a core that listens on no network and holds the store and the keys. The gate keeps serving while the core restarts |
| Store | SQLite by default, PostgreSQL as an option; migrations for both, tested on both |
| Users | four roles, two-factor codes with recovery codes, lockout after failed logins, API tokens for scripts |
| Stacks | a compose file, reviewed before it runs, under rootless Podman as a user of its own |
| Mail | Stalwart behind the gate; DNS records published and kept through Cloudflare, or listed to enter by hand; DKIM keys rotated; app passwords per device. See [MAIL.md](MAIL.md) |
| Monitoring | metrics, the audit log, login attempts, open ports and who holds them |
| Panel | a terminal UI over SSH: menus, movable panels, a dashboard, shells in tabs, themes, six languages |
| Install | one line, from a release with its checksum verified; upgrade and uninstall scripts |

**In progress:**

1. **The server's firewall** from the panel (ufw first, then firewalld): what is allowed and why,
   a guard against locking yourself out of SSH, ports opened for mail and for stacks, and host
   checks.
2. Tests that prove the gate's promises under load.

**Next:**

1. A public HTTPS surface for the panel and its API, with cookie sessions and passkeys.
2. Port forwarding (TCP and UDP) through the gate.
3. Certificate expiry and renewals shown in the panel; health checks per upstream.
4. For mail: webmail, aliases and forwarding from the panel, and repairing a broken setup.

## Design principles

- **The core holds the business rules; adapters reach the outside world.** The operating system,
  network, store and clock are reached through interfaces, so the rules never depend on them.
- **Nothing is public by default.** The panel's control plane is private, and every call reachable
  from the internet is declared explicitly.
- **Built on [golib](https://github.com/yongjohnlee80/golib):** shared building blocks come from
  golib, which grows when AutoPanel needs something it lacks.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
