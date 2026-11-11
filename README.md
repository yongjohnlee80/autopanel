# AutoPanel

A lightweight control plane for self-hosted web services, written in Go: a reverse-proxy gate with
automatic TLS certificates first, with mail, storage and container deploys planned to follow.

**Status: early.** The first slice runs: the proxy gate, automatic certificates, the control socket,
an admin TUI and an installer. It has not been released, and its interfaces will change. Decisions
are recorded under [docs/decisions](docs/decisions/README.md) as they are made.

## Install

On a Linux server with systemd, as root:

```sh
curl -fsSLO https://raw.githubusercontent.com/yongjohnlee80/autopanel/main/install.sh
less install.sh    # read it first
sudo sh install.sh --email admin@example.com
```

The installer downloads the latest release for the machine and checks its SHA-256. When there is
no release to download, it builds from source on the host, which needs git and Go 1.26 or later.
`--version v0.1.0` names a release, and `--source` always builds. It asks for a master passphrase,
which is the login for the admin TUI:

```sh
sudo -u autopanel autopanel --ui
```

`sudo autopanel-uninstall --check` lists what a removal would take.

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
