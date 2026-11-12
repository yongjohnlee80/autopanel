# Services

How AutoPanel deploys a service, and what a deployed service may reach.

## A privileged verb leaves its record first

**Decided:** a verb that changes the host, or reveals a secret, is marked `Privileged` in its
contract. The control socket writes its audit entry before the verb runs, with the outcome
`attempt`. When the verb ends, the outcome becomes `ok` or the name of its error. If the entry
cannot be written, the verb is refused and nothing is done.

**Why:** the core is root, and the audit log is the one place that says what it did. An entry
written afterwards is missing exactly when it matters: when the action failed half-way, or the
core died during it. An entry that still says `attempt` is an action the core did not see finish.

**Why in the socket's handler, not in each verb:** a verb cannot forget it, and a new privileged
verb gets it by setting one field. A socket that offers a privileged verb and has no audit log
refuses to start.

**The subject** of an entry is the `name` or `template` the caller sent, quoted and cut short:
it is recorded before the verb has validated it.

**In the code:** `internal/module/module.go` (`Contract.Privileged`), `host/control/control.go`
(`handler`, `Auditor`), `store/settings.go` (`AuditAttempt`, `AuditResult`);
`TestAPrivilegedVerbLeavesItsRecordFirst`.

## A template is code

**Decided:** a kind of service is a `Template` compiled into the binary: its image (pinned by
digest), its options, its ports, its configuration files and its command line. `services.deploy`
takes a template's name and option values, and nothing else.

**Why:** the core is root, and a deploy ends with a container running. If a caller could supply
the image, the command or a mount, "deploy a service" would mean "run anything". A template is
reviewed as code is, and changes by a release.

**Options are typed.** Each has a kind (a host name, a port, a port range, a choice), and a value
its kind refuses is refused by name before anything is written. A port is 1024 or above: a
service's user cannot bind a lower one. Every value that reaches a configuration file or a unit
file has passed its kind, so none can carry a line break.

**In the code:** `core/services/template.go`, `core/services/turn.go`.

## Each service is its own user, under rootless Podman

**Decided:** a service named `turn` runs as the system user `ap-turn`, which has no login shell
and no password. Its directory, `/var/lib/autopanel-services/turn`, is that user's alone. Its
container runs under that user's own Podman, started by that user's own systemd from a Podman
unit file (Quadlet) in its directory.

**Why rootless, per user:** a container that is broken out of lands in an unprivileged user that
owns one directory. It cannot read the store, the keyfile or another service's files. There is no
daemon with root's rights for it to talk to.

**Why a unit of the user's own systemd:** the service starts at boot, restarts when it fails and
is limited in memory by the same machinery as everything else on the host, and AutoPanel keeps no
process of its own watching it.

**What every unit gets, whatever its template:** a read-only root filesystem, no new privileges,
the template's memory limit, its directories mounted read-only, and every capability dropped but
the ones the template names. The process inside is the service's own user, the same outside.

**Why the process is the service's user, not the image's:** an image's own user is one of the
service user's sub-ids on the host. It cannot read a file only the service's user may read, and
Open ports and the journal would show a number, not the service.

**A template may keep a capability** only when its image cannot start without it. The TURN
template keeps `NET_BIND_SERVICE`: the image's `turnserver` carries it as a file capability, and
the kernel refuses to run such a file once the capability is dropped. The container holds it in
its own user namespace, where it opens no port of the host's below 1024.

**What is kept:** the store holds what was asked for: the template, the options, and whether the
deploy finished. Whether a service is running is read from systemd when asked, never kept.

**In the code:** `core/services/module.go` (`quadlet`, `apply`), `host/services/host.go`.

## The row comes first

**Decided:** a deploy writes the service's row, in the state `deploying`, before it touches the
host. The row becomes `deployed` when the unit has been asked to start.

**Why:** a deploy that fails half-way, or a core that dies during one, leaves a row the panel
shows. `services.update` finishes it and `services.remove` clears it. Without the row there
would be a user and a directory nobody knows about.

**Removing** stops the unit, ends the user's systemd and deletes the user, then the secrets and
the row. Each step tolerates the one before having already happened, so a removal that was
interrupted is run again. Without `purge` the directory is kept, as root's and closed, under a
name no later service takes: a deleted user's number may be given to another user later.

**In the code:** `core/services/module.go` (`deploy`, `remove`), `host/services/host.go`
(`Uninstall`).

## Files are written inside the service's directory, whatever is in it

**Decided:** the core writes a service's files through a handle on the service's directory that
no path can leave (`os.Root`), and moves each file into place after writing it beside its place.

**Why:** the directory belongs to the service's user. If that user were taken over, it could put
a link where the core is about to write, and a write by root that followed it would land anywhere
on the host.

**In the code:** `host/services/host.go` (`writeFiles`);
`TestFilesStayInsideTheServicesDirectory`.

## The TURN relay uses the host's network

**Decided:** the TURN template runs with the host's network, not a network of the container's own.

**Why:** a relay hands out hundreds of UDP ports. A rootless container's ports are forwarded by a
process in user space, one socket per port, and that cost is paid on every relayed packet. The
relay's other limits are unchanged: its own user, a read-only root, and no capability over the
host.

**Decided:** every setting of the relay but its secret is on its command line; the configuration
file holds the secret alone.

**Why:** coturn starts on its defaults when it cannot read its configuration file, and says so
only in its log. Its defaults are a relay that asks for no credentials and refuses no peer. This
happened on the first real deploy: the file was readable by the service's user and the process
was not that user. With the settings on the command line, a relay without its file has no secret,
so it authenticates nobody, and it still refuses private peers. The secret stays in the file
because a command line is readable by every user of the host.

**What it costs:** the relay can open connections from the host's address. Its configuration
refuses to relay to the host itself and to private and link-local addresses.

**In the code:** `core/services/turn.go` (`TURN`, `turnDenied`).
