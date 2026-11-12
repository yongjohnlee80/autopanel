# AutoPanel

A lightweight control plane for self-hosted web services, written in Go: a reverse-proxy gate with
automatic TLS certificates first, with mail, storage and container deploys planned to follow.

**Status: early.** The first slice runs: the proxy gate, automatic certificates, the control socket,
an admin TUI and an installer. It has not been released, and its interfaces will change. Decisions
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
Cancel or Esc quits.

The panel has a menu bar: open a menu with Alt and its letter (Alt+R for Routes), or press F10 and
move with the arrow keys. `r` refreshes and `q` quits.

| Menu | What it holds |
| --- | --- |
| System | **Metrics**, **Audit log**, **Login attempts**, **Open ports**; **Theme** and **Language** |
| Routes | **Proxy routes**: the host names AutoPanel serves and where each one goes |
| Certs | **Type**: which Let's Encrypt service issues the certificates, staging or production |
| Services, Users | not built yet; their rows are greyed out |
| Go | **Terminal**: shells on the server, a tab each |
| Help | **About**: the panel's version and the running service's |

To serve a site, open **Routes → Proxy routes** and press `a` to add a route: the host name
(`example.com`), a path prefix (`/`), and the upstream it forwards to (`http://127.0.0.1:8080`).
`e` or Enter edits the selected route, `d` removes it and `q` closes the list. AutoPanel gets the
certificate for a routed name on its first HTTPS request, and redirects plain HTTP to HTTPS.

**Panels float.** Proxy routes and the System panels open as windows over the screen, each with
three controls in its top row: minimize, maximize and close. Drag a panel with Alt (Option) and
the left mouse button, and resize it with Alt and the right button. A minimized panel is listed
at the bottom of the screen; its menu row brings it back. `q` or Esc closes the panel that has
the keyboard.

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

### Deploy a service

AutoPanel can run a service for you from a template. The first template is a TURN relay
([coturn](https://github.com/coturn/coturn)).

In the panel (`sudo autopanel --ui`), **Services → Deploy a TURN relay…** opens a form: a name,
the realm, the port and the relay ports. **Services → Deployed services…** lists each service
with its state, its memory, its user and its ports. The keys there:

| Key | What it does |
| --- | --- |
| `a` | deploy a TURN relay |
| `e` or Enter | change the selected service's options, and restart it |
| `s`, `x`, `t` | start, stop, restart its unit |
| `o` | its newest log lines |
| `c` | its generated secrets; they leave the screen when the window closes |
| `d` | remove it, after a question; its directory is kept, as root's |
| `Shift+D` | remove it and delete its directory, after a question |
| `r` | read the list again |

The same from the command line:

```sh
sudo autopanel --call services.templates                 # what can be deployed, and each one's options
sudo autopanel --call services.deploy '{"template":"turn","options":{"realm":"turn.example.com"}}'
sudo autopanel --call services.list                      # each service, and whether it is running
sudo autopanel --call services.logs '{"name":"turn"}'
```

Deploying needs **Podman 4.4 or newer** on the server (`apt install podman`; Debian 12's is too
old). AutoPanel does not install it. Without it the panel and the gate work as before, and
`services.deploy` says what is missing.

A new service is `activating` in `services.list` while its image is pulled, then `active`.

What a deploy does, in order:

1. Creates a system user for the service, `ap-<name>`, with no login shell, and a directory only
   that user can open: `/var/lib/autopanel-services/<name>`.
2. Generates the service's secret and seals it in AutoPanel's store.
3. Writes the service's configuration and a Podman unit file into that directory.
4. Starts the service as a systemd unit of that user, under rootless Podman.

Every service runs as its own user, with a read-only root filesystem, no way to gain a
privilege, a memory limit, and every capability dropped but the ones its template names. The
TURN relay keeps one, `NET_BIND_SERVICE`: coturn's program in the image is marked with it, and
Linux refuses to start such a program without it. The relay holds it inside its own user
namespace, where it opens no port of the server's below 1024. Its image is pinned by digest in AutoPanel's code: no command takes an image, a
command line or a path.

| Command | What it does |
| --- | --- |
| `services.update '{"name":"turn","options":{…}}'` | changes the options and restarts the service; the secret is kept |
| `services.stop`, `services.start`, `services.restart` `'{"name":"turn"}'` | the unit |
| `services.secret '{"name":"turn","key":"auth-secret"}'` | prints a generated secret |
| `services.remove '{"name":"turn"}'` | stops the service and deletes its user and its secret; its directory is kept, as root's, without the pulled image |
| `services.remove '{"name":"turn","purge":true}'` | also deletes the directory |

Each of these is written to the audit log **before** it runs, with how it ended once it has. If
the entry cannot be written, the command is refused and nothing is done. **System → Audit log**
shows them.

#### The TURN relay

| Option | Default | What it is |
| --- | --- | --- |
| `realm` | none: required | the relay's name, such as `turn.example.com` |
| `port` | `3478` | where it listens, on UDP and TCP |
| `relay_ports` | `49152-49999` | the UDP ports it relays on |

Open the port and the relay range in your firewall. A service's user cannot bind a port below
1024, so no option takes one.

The relay authenticates with a shared secret (coturn's `use-auth-secret`): your application
makes short-lived TURN credentials from it, and the relay keeps no list of users. Read the secret
with `c` in the panel or `services.secret`, and give it to the application. Each read is in the
audit log.

The relay refuses to relay to this server itself and to private and link-local addresses, so it
cannot be used to reach what the server can and the internet cannot.

The relay's settings are on its command line, in its unit; its configuration file holds only the
secret. coturn starts on its defaults when it cannot read its file, and its defaults are a relay
that asks for no credentials. Set up this way, a relay that lost its file has no secret and
serves nobody.

The relay uses the host's network, not a network of its own. A relay hands out hundreds of UDP
ports, and passing each through a rootless container's port forwarder costs more than the
separation is worth for a relay. Its other limits are those of every service.

TURN over TLS is not offered yet.

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
