# Users, roles, two-factor and API tokens

Who may log in to AutoPanel, what each person may do, and how scripts call it. What is here is
what the code relies on.

## Users have one of four roles

**Decided:** every panel user has a role, `admin`, `operator`, `mail` or `viewer`. Each verb is
allowed to a role by its contract: its **area** (`sys`, `sys.admin`, `gate`, `certs`, `services`,
`mail`, `mail.admin`, `auth`), whether it **mutates**, and whether its answer is **sensitive**.

| Area | admin | operator | mail | viewer |
|---|---|---|---|---|
| sys (status, metrics, ports, one's own preferences) | all | all | read | read |
| sys.admin (the gate's settings; the firewall when it lands) | all | none | none | none |
| gate (routes, domains) | all | all | read | read |
| certs | all | read | none | read |
| services (stacks) | all | all | none | read |
| mail (domains, accounts, records) | all | all | all | read |
| mail.admin (setting mail up, repairing it) | all | all | none | none |
| auth (users, tokens) | all | own account | own account | own account |

- **Read** means a verb that changes nothing and is not sensitive.
- **Sensitive** is the default: a verb nobody marked is kept from the read-only roles, so a new
  verb fails closed. Stack logs (a journal can hold a secret a service printed), the file browser and
  preview (the host's files), login sources (people's addresses) and the audit log are sensitive:
  the admin's and the operator's only. Every other read verb is marked plain, one by one.
- **Own account** is `auth.whoami`, changing one's own passphrase, one's own two-factor, and one's
  own API tokens.

**Why four:** a mail manager should reach Mail and nothing else, a viewer should change nothing,
and an operator runs the services without administering the host. Composed permissions were set
aside until a job fits none of these.

**How it is checked:** the control socket asks the auth module on every call. The session holds
only who logged in (`user:7`, `token:12`), never a role: the role, whether the user is disabled,
and whether a token is revoked or expired are read from the store at each call, so a demotion takes
effect at the next one. A refusal is `auth.forbidden` and says nothing about whether the thing
asked for exists; it is on the audit log. A socket with verbs that change things refuses to start
without this check. A test holds every verb's area, mutation and sensitivity in one table, so no
verb lands without a decision on each.

**What this is on the control socket:** only root opens it, so roles there are guard rails (an
operator cannot drop the Cloudflare token by a slip) and accountability (the audit log names who),
not a boundary against someone who is root on the host. They become a boundary on the HTTPS
surface, which will serve only public verbs with the same roles and tokens.

**In the code:** `internal/auth/policy.go` (`Allows`, `Effective`), `internal/module` (`Area`,
`Discloses`), `host/control/control.go` (`Authorizer`), `app/policy_test.go` (the table).

## Only admins hold the master key

**Decided:** an admin's login is a passphrase slot, a copy of the master key sealed under the
admin's passphrase, as root's has always been. Every other user's login is an argon2id verifier,
which opens nothing. A non-admin's login therefore never unlocks the vault.

- Making an admin needs the vault open and a passphrase the admin chooses for them; demoting one
  drops the slot and sets a verifier. Either way the user must change the passphrase at the next
  login, and until then every verb but the passphrase and two-factor enrolment is refused.
- The last admin, and root (the user `--init` made), can never be demoted, disabled or removed;
  the store checks it in the same transaction as the change.
- Removing an admin removes its slot; the master key itself is not re-keyed.
- A passphrase is refused when it is shorter than 12 characters, holds the user's name, or is on a
  list of the 10,000 most common passwords embedded in the binary.

**Why:** the master key opens every sealed secret (the Cloudflare token, Stalwart's administrator,
certificate keys). A helper who manages mailboxes has no need of it.

**In the code:** `internal/auth/auth.go` (`checkPassphrase`, `loginOf`, `Weak`),
`internal/auth/verbs.go` (the `auth.user.*` verbs), `store/users.go` (the last-admin guard),
`internal/auth/data/common-passwords.txt`.

## Two-factor: TOTP, and one answer for every failure

**Decided:** any user may enrol a TOTP authenticator app (RFC 6238: SHA-1, 6 digits, 30-second
steps, one step either side). Its secret is sealed under the master key; ten recovery codes are
stored as SHA-256 hashes. A code is spent once: the last step used is written by a conditional
update, and a recovery code is deleted by its hash, so two logins at once cannot both use one.

- **The login always sends a code** (empty without two-factor), and every failure (no such user,
  a wrong passphrase, a missing or wrong code, a disabled user) is the one `auth.bad_login`, after
  the same cost, and counts toward the lockout. An answer that said "now the code" would say the
  passphrase was right.
- **The vault is unlocked only after the second factor passes:** an admin's right passphrase with a
  wrong code leaves a locked vault locked.
- A non-admin's secret is opened through the vault, so while it is locked a non-admin with
  two-factor cannot log in. The login screen says the vault is locked before anyone types, so they do
  not spend their tries finding out.
- Turning two-factor off takes a current code. An admin can turn it off for another user who lost
  their phone and codes (`auth.totp.disable` with the user's name).
- The panel warns on Users while any admin has no two-factor.

**In the code:** golib's `auth/totp`, `internal/auth/totp.go`, `internal/auth/verbs.go`
(`secondFactor`, the `auth.totp.*` verbs).

## Login limits

**Decided:** every attempt is on the audit log before it is checked; one derivation runs at a
time; a user's wait doubles from 1 second to a minute; ten failures in a row lock the account for
15 minutes, kept in the store so a restart does not lift it. A name with no account is tracked the
same way in memory, so a locked account and an invented name cannot be told apart. An admin can lift
a lock. Root on the control socket is slowed, never locked: whoever could lock root out there is
root already.

**In the code:** `internal/auth/verbs.go` (`waiting`, `failed`), `store/users.go`
(`RecordFailure`).

## Sessions end

**Decided:** a login lasts 12 hours at most, enforced by the daemon, and the panel asks for it
again after 30 minutes with no key from its person (its own five-second reads do not count). A
secret shown on screen (a two-factor secret, recovery codes, a new token) leaves the screen with the
sign-out.

**In the code:** `internal/auth/users.go` (`SessionMax`), `internal/ui/auth.go` (`idleAfter`,
`signOut`).

## API tokens

**Decided:** a user makes tokens for scripts, each with a name, a role no higher than its own
(viewer unless asked), and a lifetime of 90 days by default and a year at most, never without an
end. A token is `apt_<id>_<secret>`, the secret 43 base62 characters (more than 256 random bits);
only its SHA-256 is stored, and it is shown once.

- At every use its role is capped by its owner's role then: a demoted owner's tokens fall with it,
  a disabled or removed owner's stop.
- A token never manages users, tokens or passphrases, so a leaked one cannot make a lasting one.
- An owner told to change its passphrase keeps its tokens: that rule is the passphrase login's, and
  a script cannot answer it.
- Over HTTPS a token is checked at every call ([The HTTPS API](api.md#the-core-decides)): a good
  one writes nothing, and failures are audited twenty times a minute at most.
- A token's id is never locked after failures: the id is the visible part, and locking it would let
  anyone stop every token. Failures are audited, and a burst raises an alarm.
- The CLI reads it only from a file that is the caller's and mode 0600:
  `autopanel --call --token-file <file> <verb> [json]`. Never from the command line or the
  environment, which leak into process listings and logs.
- Each call names `token <name> of <user>` on the audit log.

**In the code:** `internal/auth/verbs.go` (the `auth.token.*` verbs), `app/login.go`
(`tokenLogin`), `app/main.go` (`--token-file`).
