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
- **Every operation is a transaction; never write half a configuration.** An operation either
  completes or leaves the host as it found it. A flow of several steps (prompts, then a review,
  then a confirmation) holds its answers in memory and writes nothing until its last step is
  confirmed; quitting at any step leaves no trace, and the flow can be started again. The
  confirming step makes every write in an order that lets each be undone, and undoes the ones
  before a step that fails. Where a step cannot be undone (a stack's apply, a published DNS
  record), it is journaled so that asking again finishes it, never blocks it. A store row that
  says a thing exists is written last. New code is reviewed for this; a flow that writes before
  its confirmation is a bug.
- **Two modules that call each other are tested together.** A fake answers for one module only:
  where a module's port is another of AutoPanel's modules (mail's `Stacks` is the services
  module, the services module's `Guard` is mail), at least one test wires the real modules and
  fakes only the machine under them. A test whose fake plays the other module cannot catch the
  two disagreeing (v0.2.7's mail guard refused its own setup). A change to one side runs the
  other side's tests.
