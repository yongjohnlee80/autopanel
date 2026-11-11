# AutoPanel: notes for AI agents and contributors

## Where the design lives

- Decisions the code relies on: [docs/decisions](docs/decisions/README.md), one page per area. Cite
  one from code as `Decision: docs/decisions/<page>.md#<decision>`.
- The maintainer's design records (ADRs) are kept outside this repository. Never cite them from
  code or docs here: the public decision pages carry everything the code needs.

## Rules from the first commit

- **This repository is public.** Never commit host names, IP addresses, ports of real
  deployments, credentials, tokens or keys. Examples use `example.com` and the documentation
  ranges (`192.0.2.0/24`, `2001:db8::/32`).
- **Secrets come from the environment or a secret store,** never from a file in the repository or
  the image. No line of output, log or test may print one.
- **Loopback by default.** A shipped configuration binds `127.0.0.1`; only a deployment widens it.
- **Dependencies are admitted, not added.** The standard library and golib come first. A new
  module, CI action or binary is named and approved before it lands.
- **CI actions are pinned by commit SHA.** `gofmt`, `go vet`, govulncheck and the tests run on every
  change, and `test -z "$(gofmt -l .)"` is the format gate.
- **Tests never touch the developer's environment:** no real home directory, socket, network
  service or store.
