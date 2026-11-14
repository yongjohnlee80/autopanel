# AutoPanel

A lightweight control plane for self-hosted web services, written in Go: a reverse-proxy gate with
automatic TLS certificates first, with mail, storage and container deploys planned to follow.

**Status: early.** The first slice runs: the proxy gate, automatic certificates, the control socket,
an admin TUI and an installer, stacks under rootless Podman, and mail with Stalwart. Its interfaces
will change before the beta. Decisions
are recorded under [docs/decisions](docs/decisions/README.md) as they are made.

## Install

AutoPanel runs on a Linux server with systemd. Point a name's DNS at the server and open ports 80
and 443 first.

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

It opens on a sign-in dialog. The user is `root`; type the master passphrase and press Enter.
Quit or Esc leaves.

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
| System | **Metrics**, **Audit log**, **Login attempts**, **Open ports**; **Theme** and **Language** |
| Routes | **Proxy routes**: the names AutoPanel serves and where each goes; **Domains**: the domains you own |
| Certs | **Type**: which Let's Encrypt service issues the certificates, staging or production |
| Services | **Stacks** and **Add a stack**: your services, below |
| Mail | **Set up mail**, **Domains**, **Accounts**, **Server**: mail with Stalwart, below |
| Users | not built yet; its row is greyed out |
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
| Open ports | every listening TCP port and bound UDP port, the address it listens on, the process that holds it (named by its executable, with its number) and the user it belongs to, and what it is for when AutoPanel knows: its own listeners, a route's upstream, or, for a socket whose process could not be read, the port's usual service |

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

`d` in the panel, or `services.remove '{"name":"site"}'`, stops the stack and deletes its units
and its user. Its directory, with its data, is kept as root's, under a name no later stack takes.
`Shift+D`, or `"purge":true`, deletes the directory too. The definition folder under
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
each client's real address. Every key and setting of mail is sealed under the master key, DNS
records are published and kept for you through the Cloudflare token, and DKIM keys rotate by
themselves. See [docs/decisions/mail.md](docs/decisions/mail.md).

**Before you start:**

- The host's processor must run Stalwart's build: x86-64-v2 (on a virtual machine, a CPU type of
  `host` or `x86-64-v2`), or arm64. Setting mail up refuses otherwise.
- Port 25 must reach out from the host: many providers block it until asked. And the provider sets
  the host address's reverse name (PTR): point it at the mail host, or receivers will distrust it.
- For records to be published for you, set the Cloudflare token first
  (`sudo autopanel --call certs.cloudflare.set '{"token":"…"}'`), with DNS edit rights on each mail
  domain's zone. Without it every record is shown with its value, to publish by hand.
- The domain is in **Routes → Domains** by its exact name, and the mail host (say
  `mail.example.com`) has an A record pointing at this host, not proxied.

**Setting it up:** **Mail → Set up mail** asks the mail host and the first domain, writes the mail
stack, and opens its review; **Add and start** runs it. AutoPanel then sets Stalwart up through its
API, by itself, within a minute or two: **Mail → Server** says `ready` when it is done, and from then
on the gate forwards the mail ports.

**Domains** lists the domains that receive mail; the right side shows each record the selected one
needs and its state:

| State | Means |
| --- | --- |
| ok | the zone holds it as AutoPanel wrote it |
| publishing | just published; resolvers will have it within minutes |
| different | the zone holds a record of that kind AutoPanel did not write (another provider's MX, a DMARC record already there). Nothing is published beside it: **Take over** replaces it after showing it (an SPF record is merged instead) |
| manual | no Cloudflare token: publish the value by hand |
| failed | Cloudflare refused it; the error says why |

A domain's DKIM keys are listed under its records: a new pair is published, then signs once public
resolvers answer its records; every 90 days the next pair takes over.

**Accounts** makes mailboxes (`name@domain`, 5 GB by default), sets their passwords and deletes
them. A password is typed unseen, goes to Stalwart, and is kept nowhere else. Mail apps connect to
the mail host on 993 (IMAP, TLS) and 465 (submission, TLS) or 587 (STARTTLS).

**Not yet:** webmail (a stack of its own, later), forwarding mail to an outside address, and aliases
from the panel; Stalwart's own web interface (through an SSH tunnel to its management port, as
root) does them meanwhile.

### Themes and languages

**System → Theme** offers ten themes, and **System → Language** six languages: English, Korean,
Japanese, Simplified Chinese, Spanish and Brazilian Portuguese. Both take effect at once and are
kept in AutoPanel's store, so the panel opens the same way next time.

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

## Planned first features

1. **A proxy gate:** a reverse proxy whose routes can change without dropping requests in flight.
2. **Certificates:** ACME (Let's Encrypt, ZeroSSL), including DNS-01 for wildcard certificates.
3. **Authentication** for the panel and its API: hashed passwords, sessions, a second factor, and
   scoped API tokens.
4. **An internal store:** SQLite by default, with PostgreSQL as an option.

## Design principles

- **The core holds the business rules; adapters reach the outside world.** The operating system,
  network, store and clock are reached through interfaces, so the rules never depend on them.
- **Nothing is public by default.** The panel's control plane is private, and every call reachable
  from the internet is declared explicitly.
- **Built on [golib](https://github.com/yongjohnlee80/golib):** shared building blocks come from
  golib, which grows when AutoPanel needs something it lacks.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
