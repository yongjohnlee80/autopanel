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
It then creates the `autopanel` system user, installs the binary and the systemd unit, and starts
the service. Running it again upgrades the binary and keeps the configuration, the store and the
keys.

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
| `--restart always\|on-failure\|no` | the service's restart policy |
| `--no-start` | install without starting the service |

### Serve your first site

Open the admin TUI on the server:

```sh
sudo -u autopanel autopanel --ui
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
| Metrics | the service's uptime, memory and request counts since it started; the host's load, memory, and the disk the store is on |
| Audit log | the newest 200 changes made through AutoPanel: who, what, and when |
| Login attempts | logins to the panel, and logins to the server over SSH: accepted, failed, and closed before logging in |
| Open ports | every listening TCP port and bound UDP port, the address it listens on, and what it is for when AutoPanel knows: its own listeners, a route's upstream, or the port's usual service |

SSH logins come from the system journal, so the service runs with the `systemd-journal` group.
That group can read every unit's log on the server. To run without it, remove the
`SupplementaryGroups=` line from `/etc/systemd/system/autopanel.service` and restart the service:
the panel then lists only its own logins, and says why.

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
sudo -u autopanel autopanel --call certs.ca.set '{"ca":"production"}'
sudo -u autopanel autopanel --call sys.status
```

The installer's choice (`AUTOPANEL_ACME_CA` in `/etc/autopanel/autopanel.env`) is what a new
install starts with. A choice made in the panel or with `certs.ca.set` is kept in AutoPanel's store
and replaces it from then on.

If you know the server is set up correctly, install with production from the start: answer `2` at
the prompt, or pass `--ca production`.

### Check and remove

```sh
systemctl status autopanel
journalctl -u autopanel -e
sudo autopanel-uninstall --check     # lists what a removal would take; changes nothing
sudo autopanel-uninstall --apply     # removes the service and the binary; keeps data, config and keys
sudo autopanel-uninstall --purge     # removes everything, after backing the store up
```

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
