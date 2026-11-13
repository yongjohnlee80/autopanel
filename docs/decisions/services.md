# Services

How AutoPanel runs a stack of containers, and what a stack may reach.

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

**The subject** of an entry is the `name` the caller sent, with the `service` and the review
(`accept`) when the call names them, each quoted and cut short: it is recorded before the verb
has validated any of it.

**In the code:** `internal/module/module.go` (`Contract.Privileged`), `host/control/control.go`
(`handler`, `subject`, `Auditor`), `store/settings.go` (`AuditAttempt`, `AuditResult`);
`TestAPrivilegedVerbLeavesItsRecordFirst`, `TestStacksThroughTheControlSocket`.

## A stack is a compose file, and the core reads it itself

**Decided:** a service is a **stack**: a `compose.yaml` the administrator writes into
`/etc/autopanel/stacks/<name>/`, with a `.env` and configuration files beside it when it needs
them. The core parses the file, checks it, and writes one Podman unit file (Quadlet) per
container. No compose program is installed or run, and Docker is never used.

**Why a compose file:** it is the format people and projects already publish. A service is no
longer a release of AutoPanel: before this, each kind of service was a template compiled into the
binary.

**Why the core reads it itself:** the core is root, and an apply ends with containers running.
A compose runtime would take the whole format, and with it `privileged`, host paths and devices.
The core takes a subset it can check line by line, and what Podman runs is Podman's own standard:
units of the stack user's systemd.

**A key outside the subset is refused by its name,** never dropped: `build`, `privileged`,
`devices`, `pid`, `ipc`, `security_opt`, `sysctls`, `networks`, `secrets`, `configs`, `deploy`,
`extends`, `profiles`, the long forms of `ports` and `volumes`, a `depends_on` condition other
than `service_started`, and anything else the code does not name. What the review shows is all
that the file says. A weaker contract is never put in a stronger one's place.

**The folder is named, never a path.** No verb takes a path, an image or a command: the
definition folder is root's (0700), so writing a stack's definition already takes root.

**`${KEY}` is filled from the folder's `.env` only,** never from the core's own environment. A
variable `.env` does not have is refused.

**In the code:** `core/services/compose.go` (`Parse`, `ParseEnv`, `interpolate`);
`TestWhatTheSubsetDoesNotTakeIsRefusedByName`, `TestVariablesAreFilledFromEnvAlone`.

## What a stack may not do, and what it is warned of

**Refused,** before anything is written: a mount source that is absolute or leaves the stack's
folder (this also refuses a container socket); a capability outside Podman's rootless default
set; a host port below 1024 (the stack's user cannot bind it, and web traffic goes through the
gate); a port another stack has, or that another program listens on; a link in the definition; a
value with a line break (it would become a second line of a unit file).

**The capability list is the code's own.** A host that widened its Podman defaults does not widen
a stack's.

**Warned of,** and shown in the review: an image named by a tag, a port on every address, the
host's network, no memory limit, a writable root, the image's own user, and a value of `.env` in
a command (a container's command line can be read by every user of the host).

**The default is Podman's rootless capability set, not none.** Stock images do not start with
every capability dropped, and those capabilities are held inside an unprivileged user's own
namespace. A stack that draws no warning sets `user`, `read_only`, `cap_drop: [ALL]`, a digest, a
memory limit and loopback ports; the examples are written that way.

**In the code:** `core/services/check.go` (`check`, `defaultCaps`); `TestThePolicyRefuses`,
`TestThePolicyAccepts`.

## A review comes first, and an apply names it

**Decided:** `services.check` answers a review: every file that defines the stack, by its hash;
each container it would run; and what the policy refuses or warns of. The review has one hash
over all of it. `services.add` and `services.apply` take that hash (`accept`) and are refused
when the definition is no longer the one reviewed.

**Why every file:** an edit of `.env` can turn a loopback port into a public one, and an edit of
a mounted configuration file changes what runs, without a byte of the compose file changing. So
the hash covers `compose.yaml`, `.env`, every `env_file` and every file under a read-only mount.

**An apply works from a staged copy.** It reads each file of the definition once, into a folder
only root reaches, hashes what it copied, and applies that copy. There is no gap between what was
hashed and what runs.

**Which ports are free is a fact of the moment:** the review reads it, and the apply reads it
again under one lock before it claims them.

**In the code:** `core/services/manifest.go` (`Manifest`), `core/services/apply.go` (`review`,
`run`), `host/services/stage.go` (`Stage`, `StagePaths`); `TestAStackIsReviewedThenAdded`,
`TestADefinitionIsStagedThenCommitted`.

## An apply never writes a stack's data

**Decided:** the files of a stack are of two kinds, told apart by the compose file. **Managed:**
`compose.yaml`, `.env`, every `env_file`, and the source of every read-only mount; an apply
replaces them. **Data:** the source of every writable mount; an apply makes it when it is not
there, and never writes, replaces or deletes it afterwards.

**Data stays data.** A path that was data, or that is in the stack's folder and was not put there
by an apply, is never made a managed file: a definition that would do so (the same mount turned
read-only, a read-only mount of a folder inside it) is refused. Otherwise one edit of a compose
file would have an apply copy an old seed over a live database.

**Putting data back** (a restore) is done by hand, as root, with the stack stopped. No verb
overwrites data. `services.prepare` exists for the first time: it makes the stack's user, copies
its definition and pulls its images, and starts nothing, so the data can be put in place before
the first start.

**`stack/.autopanel/` is the core's own:** the files it generates. It is never data, never in a
review, and never a mount's source.

**In the code:** `core/services/check.go` (`managedPaths`, `dataPaths`, the `data-overlap`
refusals), `host/services/stage.go` (`commit`); `TestAnApplyNeverWritesData`,
`TestPrepareStartsNothing`.

## An apply removes what the file no longer has, and can be finished

**Decided:** before an apply changes the host it records, with the stack's row, everything the
stack had before together with everything the apply may make. When it ends, that record is
replaced by what was applied. An apply that fails leaves the record, and the stack is shown as
incomplete, with the step it stopped at.

**Why:** an apply writes unit files, and a unit file on disk starts at the next boot. A service
the new file no longer has is stopped and its unit deleted. A service that a failed apply added,
and that the administrator then took out again, has a unit on disk that nothing applied names:
only the record of the failed apply knows it. The record is kept whole through any number of
failures, until an apply finishes.

**A failed apply is finished by applying again,** never by the core on its own: a stack does not
start with nobody asking.

**An apply restarts what its change touches:** a container whose unit, image digest, or a
managed file it mounts or reads differs from what was last applied. A changed configuration file
leaves the unit's text as it was, and a file mounted into a container keeps showing its old
content after it is replaced, so without the restart what was reviewed would not be what runs.
"Changed" is measured against what was applied, never against the disk, which after a failure
already holds the new files.

**In the code:** `core/services/apply.go` (`run`, `base`, `sameInputs`), `core/services/manifest.go`
(`Pending`, `union`); `TestAnApplyRemovesWhatTheFileNoLongerHas`, `TestARetryRestartsWhatChanged`,
`TestAnApplyRestartsWhatItsChangeTouches`.

## An image runs by its digest

**Decided:** a pull resolves the image's reference to a digest, the digest is recorded, and the
unit names the image by it. An apply pulls only an image whose reference is new or changed;
`services.pull` is the one verb that asks the registry what a tag points to now.

**Why:** a unit that names a tag can run another image after any restart that pulls. And an apply
that changes only configuration must not change an image the review did not show.

**A pull runs as a unit of the stack user's own systemd,** not as a child of the core: unpacking
an image takes more memory than the core's limit allows.

**In the code:** `core/services/apply.go` (`run`, `pull`), `core/services/units.go`
(`containerUnit`), `host/services/host.go` (`Pull`).

## A stop is remembered

**Decided:** a service stopped through AutoPanel stays stopped across a boot, whatever its
`restart` says, until it is started. Its unit is written without its `[Install]` section, and the
stop is in the stack's row. Stopping a service also stops, and records, every service that
depends on it; starting a service whose requirement is stopped is refused.

**Why the dependants too:** `depends_on` becomes `Requires=`, and a unit that starts pulls in what
it requires. A dependant left enabled would start at the next boot and start the stopped service
with it.

**A stopped unit may read `failed`:** a container that ends on the stop signal with an error code
leaves its unit so. The panel shows a recorded stop as stopped, whatever systemd calls it.

**In the code:** `core/services/module.go` (`stop`, `start`, `remember`, `unitFiles`),
`core/services/check.go` (`dependants`); `TestAStopIsRememberedAndCoversWhatDependsOnIt`.

## Each stack is its own user, under rootless Podman

**Decided:** a stack named `chat` runs as the system user `ap-chat`, which has no login shell and
no password. Its directory, `/var/lib/autopanel-services/chat`, is that user's alone. Its
containers run under that user's own Podman, started by that user's own systemd from the unit
files in its directory. The containers of one stack share a network of their own, and reach each
other by service name.

**Why rootless, per user:** a container that is broken out of lands in an unprivileged user that
owns one directory. It cannot read the store, the keyfile or another stack's files. There is no
daemon with root's rights for it to talk to.

**Why units of the user's own systemd:** the stack starts at boot, restarts when it fails and is
limited in memory by the same machinery as everything else on the host, and AutoPanel keeps no
process of its own watching it.

**What every unit gets, whatever its file says:** no new privileges, and a start that is tried
again every ten seconds for as long as it takes (a unit whose address is not there yet after a
boot would otherwise run into systemd's start limit and stay failed).

**`user: "U:G"` makes the container's user the stack's user on the host,** so what it writes is
`ap-<name>`'s. Without `user`, the image's own user applies: when that is root, it is the stack's
user on the host; when it is not, it is one of the stack user's subordinate ids.

**A value that `.env` filled goes to the container through a file,** never through the unit's
`Environment=`: that would put it on `podman run`'s command line, which every user of the host
can read.

**What is not promised:** a stack's private network keeps other stacks' containers out of it. It
does not keep the stack out of what the host publishes, another stack's published ports
included, and a `network_mode: host` container shares the host's network outright. The review
says so, of every stack.

**A service on the host's network publishes nothing,** so its `ports` only declare what it
listens on: they are claimed, checked and shown like published ones, and write no `PublishPort=`.

**What is kept:** the store holds what was applied: the definition by its hashes, the units, and
the digests. Whether a container is running is read from systemd when asked, never kept.

**In the code:** `core/services/units.go` (`units`, `containerUnit`, `word`),
`host/services/host.go`; `TestAStackBecomesItsUnits`,
`TestAUnitWordIsWrittenSoTheContainerGetsItAsItIs`.

## The row comes first

**Decided:** an add writes the stack's row, in the state `deploying`, and the record of what it
may make, before it touches the host. The row becomes `deployed` when the units have been asked
to start.

**Why:** an add that fails half-way, or a core that dies during one, leaves a row the panel
shows. `services.apply` finishes it and `services.remove` clears it. Without the row there would
be a user and a directory nobody knows about.

**Removing** ends the user's systemd, and every unit with it, and deletes the user, then the row.
Each step tolerates the one before having already happened, so a removal that was interrupted is
run again. Without `purge` the directory, with the stack's data, is kept, as root's and closed,
under a name no later stack takes: a deleted user's number may be given to another user later.
The definition folder is never deleted.

**A row an older AutoPanel made from a template** is shown, and can only be removed.

**In the code:** `core/services/apply.go` (`run`), `core/services/module.go` (`remove`),
`host/services/host.go` (`Uninstall`).

## Files are written inside the stack's directory, whatever is in it

**Decided:** the core writes a stack's files through a handle on the stack's directory that no
path can leave (`os.Root`), and moves each file into place after writing it beside its place. It
reads a definition the same way, and follows no link in it.

**Why:** the directory belongs to the stack's user. If that user were taken over, it could put a
link where the core is about to write, and a write by root that followed it would land anywhere
on the host.

**In the code:** `host/services/host.go` (`writeFiles`), `host/services/stage.go` (`commit`,
`linked`); `TestFilesStayInsideTheServicesDirectory`, `TestALinkInADefinitionIsNotFollowed`.
