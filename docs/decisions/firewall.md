# The firewall

How AutoPanel reads the host's firewall, shows what it lets in, changes it, and keeps an
administrator from locking themselves out. AutoPanel drives the manager the host already has (ufw,
or firewalld); it never writes a ruleset of its own for the policy.

## Which manager

**Decided:** one function decides which manager a host has, from what is installed, what runs,
and the kernel's ruleset (`nft -j list ruleset`). Every verb and the installer use its answer.
The first row that holds:

| The host has | Manager | Active |
| --- | --- | --- |
| firewalld running and ufw active | unknown (`two-managers`) | yes |
| firewalld running | firewalld (`other-tables` beside foreign rules) | yes |
| ufw active | ufw (`other-tables` beside foreign rules) | yes |
| foreign rules, and no manager active | unknown | yes |
| ufw installed and inactive | ufw | no |
| firewalld installed and not running | firewalld | no |
| neither, and no foreign rules | none | no |

**Foreign rules** are the ruleset's filtering rules that are nobody's the read knows: not ufw's
chains (`ufw-*`, `ufw6-*`, and the input chains ufw sets to drop while it is active), not Docker's
(`DOCKER*`), not firewalld's table, not AutoPanel's own loopback table (mail's), not a base chain's
rule that only jumps to one of those, and not a chain of type nat.

**Why an inactive manager over a live ruleset is unknown, not off:** a host with ufw installed and
off, and a hand-written `/etc/nftables.conf`, filters. Calling it off would show every port as
open, and the installer would turn ufw on over the administrator's rules.

**In the code:** `internal/sysinfo/nft.go` (`ParseRuleset`, `Facts.Manager`),
`host/firewall/host.go` (`Read`); `TestWhichManager`, `TestRulesetKnowsUfwDockerAndAutoPanel`.

## What is read

**Decided:** ufw's rules are read from the `### tuple ###` lines of its rule files,
`/etc/ufw/user.rules` and `/etc/ufw/user6.rules`: one line per rule and family, in each family's
order. A rule from and to anywhere in both files, alike in every other field, is one rule of
both families. `ufw status verbose` says whether ufw is active, and its incoming default while
it is; `/etc/default/ufw` gives the default while it is not, and whether ufw manages IPv6.

**Why the rule files, not `ufw show added`:** only they say each rule's family exactly. After
one half of a rule is deleted by hand, `show added` prints the survivor the same as the pair. They
also give an app profile's ports, and each family's own order. They are file reads, so they work
with ufw inactive and inside the core's sandbox.

**A rule that does not parse** is kept as one that is not modelled: shown as written, and every
verdict it could touch is unknown.

**Addresses are compared in ufw's form:** a prefix masked, a full-length prefix as a bare address
(`192.0.2.4/32` is `192.0.2.4`). The family's any-prefix (`0.0.0.0/0`, `::/0`) is no address.

**ufw with `IPV6=no`:** IPv6 is not ufw's, and its IPv6 verdicts are unknown. AutoPanel never edits
that setting, because a reload with `IPV6=no` empties `user6.rules`.

**firewalld** is not read or changed yet. A host that runs it is shown as such, and its verdicts
are unknown, until its reader lands with its tests on a host that runs it.

**In the code:** `internal/sysinfo/firewall.go` (`UfwFirewall`, `ParseUfwTuples`, `NormalAddr`,
`Identity`); fixtures in `internal/sysinfo/testdata/ufw`; `TestUfwRulesAreReadWhole`,
`TestUfwIPv6Off`.

## Verdicts

**Decided:** Open ports gives each listening socket the firewall's verdict on a new connection
from anywhere:

| Verdict | When |
| --- | --- |
| local | the socket is on a loopback address |
| allowed | the first rule that decides it allows it; or none does and the default allows; or the firewall is off |
| limited | only some sources, addresses or an interface are allowed (named), or a rate limit applies |
| blocked | the first rule that decides it denies or rejects it; or none does and the default denies |
| unknown | a rule AutoPanel cannot model could match; Docker publishes it; the manager is unknown; IPv6 is not ufw's |
| rule: nothing listens | an allow rule no socket uses: a stale rule, not a claim that the port is reachable |

A socket on every IPv6 address takes IPv4 as well, so both families are judged and combined: one
allowed and the other blocked is `limited`.

**Why "unknown" is a verdict:** a guess that reads as a fact is worse than saying the read cannot
tell. The provider's firewall in front of the host is out of sight altogether, and the panel says
so.

**In the code:** `internal/sysinfo/verdict.go` (`Verdict`, `NeedsRule`, `Admits`),
`app/monitor.go` (`withFirewall`, `staleRules`); `TestUfwVerdicts`, `TestVerdictSpecialCases`.

## Writes run outside the sandbox

**Decided:** every change to the manager (allow, revoke, the default, enable, disable) runs as a
transient system unit: `systemd-run --wait --pipe --collect`, with no sandbox properties. Reads run
in the core. A write is judged by reading the firewall back, never by the tool's exit code.

**Why outside:** the core's unit has `ProtectKernelTunables`. Under it, `ufw enable` skips its
kernel settings without a word (exit 0), and the firewall comes on without them.

**Why the read-back:** ufw exits 0 when it skipped a rule that was already there, and when it
found no rule to delete.

**In the code:** `host/firewall/host.go` (`Transient`, `change`), `host/firewall/ufw.go` (the
argument lists); `TestChangesRunOutsideTheSandbox`, `TestUfwCommands`.

## No lockout

**Decided:** every path that can take access away goes through one guard, `Safe`: a revoke, an
enable, a stack's removal or an apply that closes a port, and mail's removal. It judges the
firewall as it would be after the change, against the caller's own login:

- Over SSH, the caller's own connection, both ends, must still be admitted.
- On the console, each family's SSH endpoints must be allowed from anywhere.
- Where it cannot be sure, it refuses with `firewall.lockout_unknown`. That covers a rule it
  cannot model, endpoints not all found, and IPv6 that is not ufw's.

Two changes pass at once: a firewall left off, and taking away a rule no SSH packet can match
while the endpoints were all found.

**The endpoints** come from the active SSH socket unit's `Listen=` lines, from listeners `sshd`
holds, and from `sshd -T`. They are complete when the configuration explains every listener, and
every configured endpoint is heard by `sshd`, or by PID 1 through its socket unit. Before the
first login, a socket-activated `sshd`'s listener is held by PID 1 alone.

**The caller's login** is found by the control socket from the peer's process, never from what
the caller sends. The kernel's audit session (`/proc/<pid>/sessionid`) is kept across `sudo`. The
SSH connection comes from the nearest process up the line whose environment names
`SSH_CONNECTION`: `sudo` clears it from the panel's own environment, but its own process keeps it.

**In the code:** `core/firewall/lockout.go` (`Endpoints`, `Safe`), `host/firewall/ssh.go`,
`internal/sysinfo/login.go` (`LoginOf`), `host/control/control.go` (`peer`);
`TestEndpointsAsTheUbuntuTestsSawThem`, `TestSafeJudgesTheAdministratorsOwnLogin`,
`TestAVerbKnowsItsCallersLogin`.

## Enabling

**Decided:** turning the firewall on is planned first. `sys.firewall.plan` lists the SSH ports,
which are always allowed first, and every listening port the firewall would block. The gate's
ports and every owner's are ticked. `sys.firewall.enable` takes the plan's hash and the ports
chosen, then makes, in order, under the firewall lock:

1. the SSH allows that are missing;
2. the chosen allows, an owner's recorded as its own;
3. the default deny;
4. a transient timer, `autopanel-firewall-undo`, that turns the firewall off and puts the
   default back after 120 seconds;
5. the enable.

A step that fails undoes the ones before it. `sys.firewall.confirm` stops the timer. It is
accepted only from another login than the one that enabled the firewall, and over SSH when the
enable came over SSH. What it must prove is that a new SSH login still gets in.

**Why a timer:** the guard judges what it can model, and a firewall turned on can drop something
it did not. The timer is a system unit, so it fires even if the core restarts in between.

**In the code:** `core/firewall/module.go` (`Plan`, `Enable`, `Confirm`), `host/firewall/undo.go`;
`TestEnableIsPlannedConfirmedOrUndone`, `TestAnEnableThatFailsLeavesNothing`, `TestTheUndoTimer`.

## Owners

**Decided:** a rule AutoPanel makes for a stack (`stack:<name>`) or for mail (`mail`) is recorded
in `firewall_rule`, with its identity: the hash of its fields, never its number. Owned means
created: a rule that was there before the owner asked has no row, is the administrator's, and
stays when the owner goes. Rules made in System › Firewall have no row either.

- **What an owner needs opened** is judged as if the firewall were on with its default deny. So
  on an inactive firewall the ports are still offered and opened, and turning the firewall on
  later does not cut the owner off.
- **The apply's `open`** admits any of the owner's public or declared ports. A port already
  allowed is a no-op, so a retry passes the same list.
- **A port bound to one address** is opened on that address only.
- **Record first.** A row is written `opening` before the manager is asked, and set `open` once
  the rule is read back. Closing sets it `closing`, revokes through the guard, then deletes it.
- **What a change left** is settled at the core's start and at the beginning of each change. An
  `opening` row is dropped, because the core cannot tell its own half-made rule from one made by
  hand since. A `closing` row is finished, because its owner asked for it.
- **A rule edited by hand** has another identity: its row goes and nothing is deleted. A
  both-families rule with one half removed by hand has the other half closed.
- **A stack's apply** opens the chosen ports last, after its containers are up, and closes the
  ones it drops before anything new starts. A removal closes its rules before anything goes.

**In the code:** `core/firewall/module.go` (`Review`, `Open`, `Close`, `Settle`),
`core/firewall/rows.go`, `store/firewall.go`, `core/services/apply.go` (`PublicWants`, `open`),
`sql/deployments/*/000007_*`; `TestOwnersOpenOnAnInactiveFirewall`,
`TestAnAdministratorsRuleIsNeverAnOwners`, `TestClosingFindsWhatIsLeft`,
`TestSettleFinishesWhatAChangeLeft`, `TestAStackOpensWhatItChoseAndClosesWhatItDrops`.

## Mail's ports

**Decided:** mail's four public ports (25, 465, 587, 993) are the gate's listeners and are owned by
`mail`. Set up mail's review lists them, ticked when they need a rule. `mail.setup.apply` opens
the ticked ones after the stack is added and before the record that makes mail set up. A failure
there leaves the stack registered: asking again reviews the registered stack and finishes.
`mail.ports.open` opens them later. That covers a host where they were unticked, a firewall turned
on since, or mail set up before the firewall work. `mail.remove` closes them, and
`services.remove` refuses the mail stack.

**In the code:** `core/mail/module.go` (`wants`, `apply`, `portsOpen`, `remove`);
`TestMailOpensItsPortsAtSetUp`, `TestASetUpThatFailedAtItsPortsIsFinishedByAskingAgain`,
`TestMailIsRemovedWholeAndOnlyByMail`.

## Instructions

**Decided:** wherever AutoPanel will not make a change, it gives the manager's own commands. That
covers a manager it cannot drive, a port the administrator left unticked, and a refusal by the
guard. The commands are built by the same code as the calls it would make, never from text a
person typed. On a host whose manager it cannot read, it gives both managers' commands, labelled.
The panel shows them with a Copy button. Beside any public port it adds two lines: that a
provider's firewall in front of the host needs the same ports, and a command to test from another
machine. AutoPanel never probes its own reachability: from the host, a connection to its own
address passes neither the provider's firewall nor, often, its own.

**In the code:** `host/firewall/undo.go` (`Commands`), `core/firewall/module.go` (`Instructed`),
`internal/ui/firewall.go`, `internal/ui/services.go` (`portDetailOf`);
`TestCommandsForTheAdministrator`, `TestARefusalCarriesItsCommands`.

## Host checks

**Decided:** System › Host checks lists the host's posture findings that hold now. Each is a
constant id with data for its message, alerts first, and each is one cheap read:

- a pending reboot;
- failed units;
- the firewall off, partial, or leaving IPv6 to itself;
- rules nothing listens behind;
- an enable waiting for its confirm;
- the gate's, mail's or a stack's ports blocked;
- an owned rule removed by hand;
- Docker and its group;
- Podman's system-wide socket;
- `sshd` taking passwords.

None is a scan of the file system.

**In the code:** `app/checks.go`, `app/firewall.go` (`ownerChecks`); `TestHostChecksFindThePosture`.

## The installer

**Decided:** on a first install with no firewall on, the installer asks whether to turn one on
(Enter is yes). With no terminal, or on an upgrade, the answer is no unless `--firewall yes` says
otherwise. A firewall that is on is never changed. With no manager installed, it installs the
distribution's own: ufw, or firewalld where `dnf` is. The step itself is the binary's
(`autopanel --firewall-setup --ports …`):

1. allow every SSH port the guard's finder finds, and the gate's ports, from anywhere;
2. read each back;
3. turn the firewall on.

A step that fails takes back the rules this run made, and leaves the firewall off.

**Why no guard and no timer here:** the installer runs before the core, from a root shell that is
already open, and its policy needs no judging: SSH and the gate from anywhere, nothing else.

**In the code:** `install.sh` (`firewall_step`, `ask_firewall`), `app/fwsetup.go`;
`TestTheInstallersFirewallStep`.
