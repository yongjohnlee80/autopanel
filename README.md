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

Open the admin TUI on the server, and log in as `root` with the master passphrase:

```sh
sudo -u autopanel autopanel --ui
```

Press `a` to add a route: the host name (`example.com`), a path prefix (`/`), and the upstream it
forwards to (`http://127.0.0.1:8080`). `e` edits the selected route, `d` removes it, `r` refreshes
and `q` quits. AutoPanel gets the certificate for a routed name on its first HTTPS request, and
redirects plain HTTP to HTTPS.

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

**Switch to production** when the site answers:

```sh
sudo sed -i 's/^AUTOPANEL_ACME_CA=.*/AUTOPANEL_ACME_CA=production/' /etc/autopanel/autopanel.env
sudo systemctl restart autopanel
```

AutoPanel gets the real certificate on the next HTTPS request for each routed name. To see which
service a server uses:

```sh
grep AUTOPANEL_ACME_CA /etc/autopanel/autopanel.env
```

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
