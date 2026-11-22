package mail

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	corefw "github.com/yongjohnlee80/autopanel/core/firewall"
	"github.com/yongjohnlee80/autopanel/core/gate"
	"github.com/yongjohnlee80/autopanel/core/mail/provider"
	"github.com/yongjohnlee80/autopanel/core/services"
	"github.com/yongjohnlee80/autopanel/internal/module"
)

// State is the store's record of mail: that it exists, and how far it got.
type State struct {
	Host         string
	Bootstrapped int64 // Unix seconds; 0 while the mail server is not set up
	CreatedAt    int64
}

// Store is mail's part of the store. Each write leaves its audit entry.
type Store interface {
	State(ctx context.Context) (State, bool, error)
	Create(ctx context.Context, host, firstDomain string) error
	// Forget drops a setup Stalwart never took up (bootstrapped 0), with its
	// domains: what a v0.2.6 setup left when its review was quit. ErrSetUp
	// once Stalwart has taken it.
	Forget(ctx context.Context) error
	// Drop drops mail's record, its domains, records and DKIM rows, whatever
	// its state: mail.remove's last step.
	Drop(ctx context.Context) error
	SetBootstrapped(ctx context.Context, at int64) error
	Domains(ctx context.Context) ([]string, error)
	AddDomain(ctx context.Context, name string) error
	RemoveDomain(ctx context.Context, name string) error

	// The DNS records AutoPanel published, by owner (a domain, or the mail
	// host), and each DKIM key's place in its rotation.
	Owned(ctx context.Context, owner string) ([]Owned, error)
	PutOwned(ctx context.Context, owner string, o Owned) error
	DeleteOwned(ctx context.Context, owner, name, typ string) error
	DKIM(ctx context.Context, domain string) ([]DKIMRow, error)
	PutDKIM(ctx context.Context, domain string, r DKIMRow) error
	DeleteDKIM(ctx context.Context, domain, selector string) error
}

// Vault keeps mail's keys and settings, sealed under the master key. Get
// answers ErrLocked while the vault is locked, and ErrNoSecret for a name it
// does not hold.
type Vault interface {
	Put(ctx context.Context, name string, value []byte) error
	Get(ctx context.Context, name string) ([]byte, error)
	Delete(ctx context.Context, name string) error
}

// Registry is the gate's registry of the administrator's domains.
type Registry interface {
	All(ctx context.Context) ([]gate.Domain, error)
}

// Stacks is what mail asks of the services module about the stack it owns.
type Stacks interface {
	EnsureUser(ctx context.Context, name string) error
	Up(ctx context.Context, name string) (state string, since int64, err error)
	Restart(ctx context.Context, name string) error
	// CheckDraft reviews a definition held in memory; Add registers and
	// applies the stack written since, given the review's sha256.
	CheckDraft(ctx context.Context, name string, compose []byte) (services.Review, error)
	Add(ctx context.Context, name, accept string) error
	// Check reviews the registered stack's definition as it is written: a
	// set-up that failed after its stack was added is resumed from it.
	Check(ctx context.Context, name string) (services.Review, error)
	// RemoveOwned removes the stack, for mail.remove.
	RemoveOwned(ctx context.Context, name string, purge bool) error
	// Apply applies the registered stack's definition as it is written, given
	// its review's sha256: a repair's change to it.
	Apply(ctx context.Context, name, accept string) error
}

// Firewall is the core's firewall as mail, an owner of rules, uses it: the
// gate's mail ports are mail's.
//
// Decision: docs/decisions/firewall.md#mails-ports
type Firewall interface {
	Review(ctx context.Context, owner string, wants []corefw.Want) ([]corefw.PortState, error)
	Open(ctx context.Context, owner string, wants []corefw.Want) error
	Close(ctx context.Context, owner string, wants []corefw.Want) error
}

// SetFirewall gives mail the firewall. It is set once, before the verbs are
// served.
func (m *Module) SetFirewall(f Firewall) { m.firewall = f }

// SetProxyProbe gives mail what the gate's probe found: the ports whose
// server no longer waits for the header naming the client, and when the gate
// last looked (0: never). It is set once, before the verbs are served.
func (m *Module) SetProxyProbe(fn func() (ports []string, at int64)) { m.proxyProbe = fn }

// wants are the firewall openings of public mail ports: all of them for nil.
func wants(ports []int) ([]corefw.Want, error) {
	if ports == nil {
		for _, p := range Ports {
			ports = append(ports, p.Public)
		}
	}
	var out []corefw.Want
	for _, n := range ports {
		ok := false
		for _, p := range Ports {
			ok = ok || p.Public == n
		}
		if !ok {
			return nil, ErrNotMailPort
		}
		out = append(out, corefw.Want{Proto: "tcp", From: n, To: n})
	}
	return out, nil
}

// Host is the machine side of mail (host/mail).
type Host interface {
	// CPU is the host's processor: its architecture (GOARCH's names) and its
	// /proc/cpuinfo flags, for the product to judge.
	CPU() (arch string, flags map[string]bool, err error)
	// WriteDefinition writes the mail stack's compose.yaml into the stacks'
	// directory.
	WriteDefinition(ctx context.Context, compose []byte) error
	// RemoveDefinition takes the mail stack's folder out of the stacks'
	// directory: the undo of WriteDefinition when a setup fails.
	RemoveDefinition(ctx context.Context) error
	// StackUID is the mail stack user's id.
	StackUID(ctx context.Context) (int, error)
	// Journal is what the mail stack printed since, line by line, from its
	// user's journal.
	Journal(ctx context.Context, since time.Time) ([]string, error)
	// Forwarder is the source the mail server sees forwarded connections
	// arrive from, as a prefix: the mail stack network's subnet, from Podman.
	// Forwarder is the subnet connections reach the mail server from, read
	// from the stack's network, which must hold container alone.
	Forwarder(ctx context.Context, container string) (string, error)
	// InstallLoopback writes and loads the loopback rule, ordered before the
	// stack user's systemd; EnsureLoopback checks it and loads it again if the
	// kernel lost it, reporting whether it had to.
	InstallLoopback(ctx context.Context, stackUID int) error
	// RemoveLoopback takes the rule out of the kernel and off the host: the
	// undo of InstallLoopback when a setup fails.
	RemoveLoopback(ctx context.Context, stackUID int) error
	EnsureLoopback(ctx context.Context, stackUID int) (reloaded bool, err error)
	// PublicIPv4 is the host's one global IPv4 address, for the mail host's A
	// record; "" when it has none or several.
	PublicIPv4(ctx context.Context) (string, error)
	// ReverseNames are the names an address resolves back to, as the world
	// sees it: none is an empty answer, not an error.
	ReverseNames(ctx context.Context, addr string) ([]string, error)
	// SMTPOut tries a connection out to port 25 of a mail server on the
	// internet: nil when one greets, an error when none can be reached.
	SMTPOut(ctx context.Context) error
	// ResolveTXT asks public resolvers for a name's TXT records.
	ResolveTXT(ctx context.Context, name string) ([]string, error)
}

// Sealed names: every key and setting of mail is in the vault. The mail
// server's own (its API key, its administrator) are under sealedServer, by the
// names its product gives them.
const (
	sealedConfig = "mail/config"
	sealedServer = "mail/"
	sealedKey    = sealedServer + provider.SealedAPIKey
)

// Config is mail's settings, sealed as mail/config.
type Config struct {
	Host         string `json:"host"`
	FirstDomain  string `json:"first_domain"`
	QuotaDefault int64  `json:"quota_default"` // bytes
	DMARC        string `json:"dmarc"`         // the first policy: quarantine
}

// defaultQuota is an account's quota when none is given.
const defaultQuota = 5 << 30

var (
	ErrNotSetUp          = errors.New("mail: mail is not set up")
	ErrSetUp             = errors.New("mail: mail is set up already")
	ErrNotReady          = errors.New("mail: the mail server is not set up yet")
	ErrBadHost           = errors.New("mail: the mail host is not a host name")
	ErrNotRegistered     = errors.New("mail: the domain is not in the registry")
	ErrCPU               = errors.New("mail: this processor cannot run the mail server")
	ErrLocked            = errors.New("mail: the vault is locked")
	ErrNoSecret          = errors.New("mail: no such sealed value")
	ErrDomainExists      = errors.New("mail: the domain receives mail already")
	ErrNoDomain          = errors.New("mail: the domain does not receive mail")
	ErrDomainHasAccounts = errors.New("mail: the domain has accounts")
	ErrNotMailPort       = errors.New("mail: a port to open is not one of mail's")
	ErrNotOurs           = errors.New("mail: the mail stack's definition is not AutoPanel's")
	ErrHasAccounts       = errors.New("mail: mail still has accounts")
	ErrBadAddress        = errors.New("mail: not a mail address of a mail domain")
	ErrNoAccount         = errors.New("mail: no such account")
	ErrAccountExists     = errors.New("mail: the account exists")
	ErrAddressTaken      = errors.New("mail: the address is an account's, or another account's alias")
	ErrTooManyAliases    = errors.New("mail: an account has at most 20 aliases")
	ErrServer            = errors.New("mail: the mail server refused")
	ErrAdminAccount      = errors.New("mail: that is the mail server's administrator")
	ErrNoRecord          = errors.New("mail: no record of that name and type is held by another")
	ErrNoPending         = errors.New("mail: no setup is waiting to be applied")
	ErrChanged           = errors.New("mail: the setup changed since it was reviewed")
	ErrWeakSecret        = errors.New("mail: the mail server made a weak app password")
	ErrExpired           = errors.New("mail: the app password expired before it was kept")
	ErrNoAppPassword     = errors.New("mail: no such app password")
	ErrBadDescription    = errors.New("mail: an app password's device name is 1 to 64 characters")
)

// Streams switches the gate's forwarding of mail's ports on or off.
type Streams func(on bool)

// Module is mail.*, and the loop that keeps mail running: the loopback rule
// held, Stalwart set up once its stack runs, the gate's streams on once it is.
type Module struct {
	store      Store
	vault      Vault
	registry   Registry
	stacks     Stacks
	host       Host
	firewall   Firewall                 // nil: this core drives no firewall
	proxyProbe func() ([]string, int64) // nil: no gate to ask
	product    provider.Product         // the mail server: its stack, its first start, its API
	streams    Streams
	log        *slog.Logger
	now        func() time.Time
	base       string // Stalwart's management API: ManageURL()
	dns        DNS    // nil: records are shown, never published
	certs      Certs  // nil: no certificate is handed over
	sync       syncState
	hostName   atomic.Value // string: the mail host, for IsHost

	mu       sync.Mutex
	progress Progress
	setupMu  sync.Mutex // one bootstrap at a time

	// pending is a setup answered and reviewed but not applied: held here
	// alone, so a setup left at its review leaves nothing behind (no row, no
	// file, no rule). pendMu orders mail.setup and mail.setup.apply.
	pendMu  sync.Mutex
	pending *pendingSetup
	// setupOpen is true while mail.setup or mail.setup.apply runs, or a
	// setup waits to be applied: the guard then admits the stack mail with
	// AutoPanel's own definition before mail is recorded. Read without
	// pendMu, since the guard is called from inside both verbs.
	setupOpen atomic.Bool
	// repairOpen is true while a repair reviews or applies the definition
	// with the recovery administrator.
	repairOpen atomic.Bool
	repairs    repairState
	audit      Auditor // nil: the steps of a repair are not audited
}

// pendingSetup is mail.setup's answers, until mail.setup.apply.
type pendingSetup struct {
	host, domain string
	accept       string // the review's sha256
}

// Progress is where mail's setting up is, for mail.status.
type Progress struct {
	Step     string `json:"step"`  // "", "waiting for the stack", "setting up", "ready"
	Error    string `json:"error"` // the last failure, with its step
	At       int64  `json:"at"`    // when Step or Error last changed, Unix seconds
	Loopback string `json:"loopback"`
}

// NewModule is the mail verbs and loop.
func NewModule(store Store, vault Vault, registry Registry, stacks Stacks, host Host, product provider.Product, streams Streams, log *slog.Logger) *Module {
	return &Module{store: store, vault: vault, registry: registry, stacks: stacks, host: host, product: product, streams: streams, log: log, now: time.Now,
		base: ManageURL(), sync: syncState{kick: make(chan struct{}, 1)}}
}

// SetDNS names the DNS provider records are published with. Set once, before
// Run.
func (m *Module) SetDNS(d DNS) { m.dns = d }

// SetCerts names AutoPanel's certificate manager. Set once, before Run.
func (m *Module) SetCerts(c Certs) { m.certs = c }

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

// IsHost reports whether name is the mail host: the certificate manager admits
// it, though no route names it.
func (m *Module) IsHost(name string) bool {
	h, _ := m.hostName.Load().(string)
	return h != "" && h == name
}

// HostName is the mail host, or "" before mail is set up.
func (m *Module) HostName() string {
	h, _ := m.hostName.Load().(string)
	return h
}

func (m *Module) Name() string { return "mail" }

func (m *Module) Errors() []module.PublicError {
	return []module.PublicError{
		{Err: ErrNotSetUp, Code: -32130, Name: "mail.not_set_up", Message: "mail is not set up: Mail → Set up mail"},
		{Err: ErrSetUp, Code: -32131, Name: "mail.set_up", Message: "mail is set up already"},
		{Err: ErrNoPending, Code: -32148, Name: "mail.no_pending", Message: "no setup is waiting to be applied: Mail → Set up mail first"},
		{Err: ErrChanged, Code: -32149, Name: "mail.changed", Message: "the setup changed since it was reviewed: set mail up again"},
		{Err: ErrNotReady, Code: -32132, Name: "mail.not_ready", Message: "the mail server is not set up yet: apply the mail stack, and wait for mail.status to say ready"},
		{Err: ErrBadHost, Code: -32133, Name: "mail.bad_host", Message: "the mail host is a host name with a dot: mail.example.com"},
		{Err: ErrNotRegistered, Code: -32134, Name: "mail.not_registered", Message: "the domain is not in the registry: add it under Domains first"},
		{Err: ErrCPU, Code: -32135, Name: "mail.cpu", Message: "this processor cannot run the mail server"},
		{Err: ErrLocked, Code: -32136, Name: "mail.locked", Message: "the vault is locked: log in as root first"},
		{Err: ErrDomainExists, Code: -32137, Name: "mail.domain_exists", Message: "the domain receives mail already"},
		{Err: ErrNoDomain, Code: -32138, Name: "mail.no_domain", Message: "the domain does not receive mail"},
		{Err: ErrDomainHasAccounts, Code: -32139, Name: "mail.domain_has_accounts", Message: "the domain has accounts, or aliases of accounts: remove them first"},
		{Err: ErrNotMailPort, Code: -32215, Name: "mail.not_mail_port", Message: "a port to open is not one of mail's (25, 465, 587, 993)"},
		{Err: ErrNotOurs, Code: -32216, Name: "mail.not_ours", Message: "the mail stack's definition is not AutoPanel's: Mail cannot go on from it"},
		{Err: ErrHasAccounts, Code: -32217, Name: "mail.has_accounts", Message: "mail still has accounts: remove them first"},
		{Err: ErrBadAddress, Code: -32140, Name: "mail.bad_address", Message: "an address is a local part (letters, digits, . _ + -) and a domain that receives mail"},
		{Err: ErrNoAccount, Code: -32141, Name: "mail.no_account", Message: "no such account"},
		{Err: ErrAccountExists, Code: -32142, Name: "mail.account_exists", Message: "that account exists"},
		{Err: ErrAddressTaken, Code: -32218, Name: "mail.address_taken", Message: "the address is an account's, or another account's alias"},
		{Err: ErrTooManyAliases, Code: -32219, Name: "mail.too_many_aliases", Message: "an account has at most 20 aliases"},
		{Err: ErrServer, Code: -32144, Name: "mail.refused", Message: "the mail server refused the change"},
		{Err: ErrNoRecord, Code: -32146, Name: "mail.no_record", Message: "no needed record of that name and type is held by one AutoPanel did not write"},
		{Err: ErrNoDNS, Code: -32147, Name: "mail.no_dns", Message: "no DNS token: set one (certs.cloudflare.set) for AutoPanel to publish records"},
		{Err: ErrWeakSecret, Code: -32175, Name: "mail.weak_secret", Message: "the mail server made an app password weaker than 128 bits; it is not handed out and stops signing in within ten minutes, and none is handed out until the server is fixed"},
		{Err: ErrExpired, Code: -32176, Name: "mail.expired", Message: "the app password expired before it was kept, and was destroyed: add another"},
		{Err: ErrNoAppPassword, Code: -32177, Name: "mail.no_app_password", Message: "the account has no such app password"},
		{Err: ErrBadDescription, Code: -32178, Name: "mail.bad_description", Message: "an app password's device name is 1 to 64 characters, with no control characters"},
		{Err: ErrAdminAccount, Code: -32145, Name: "mail.admin_account", Message: "that address is the mail server's administrator, which AutoPanel manages it with; it is not a mailbox"},
		{Err: ErrUnreachable, Code: -32221, Name: "mail.unreachable", Message: "the mail server does not answer; a repair would not help: see the stack's state and the host checks"},
		{Err: ErrNoRepair, Code: -32222, Name: "mail.no_repair", Message: "this mail server cannot be repaired by AutoPanel"},
		{Err: ErrRepairFails, Code: -32223, Name: "mail.repair_failed", Message: "the repair did not finish; the recovery administrator, if one was given, was taken away again"},
	}
}

func change(verb, param, doc string) module.Contract {
	return module.Contract{Verb: verb, Since: 6, Param: param, Mutates: true, Privileged: true, Doc: doc}
}

// adminChange is a change that administers the host (it writes a stack, or
// runs a recovery): the admin's and the operator's, never the mail role's.
func adminChange(verb, param, doc string) module.Contract {
	c := change(verb, param, doc)
	c.Area = "mail.admin"
	return c
}

func (m *Module) Verbs() []module.Verb {
	return []module.Verb{
		module.Handle(module.Contract{Verb: "mail.status", Discloses: module.Plain, Since: 6, Result: "{set_up, host, bootstrapped, stack, step, error, at, loopback, domains, ports: [{key, verdict, why, needs, by, managed, commands}]}",
			Doc: "Whether mail is set up, how far the mail server's setting up got, the mail stack's state, the loopback rule's, and the mail domains."}, m.status),
		module.Handle(adminChange("mail.setup", "{host, domain}",
			"Answers the review of the mail stack (the mail server, pinned) for this host and first domain, and holds the answers until mail.setup.apply. It writes nothing: a setup left here leaves no trace, and may be asked again."), m.setup),
		module.Handle(adminChange("mail.setup.apply", "{accept, open?: [port]}",
			"Applies the setup mail.setup reviewed, as one transaction: the stack's user, the loopback rule, its definition, the stack added and started, the ports chosen opened in the firewall, then the record of the host and first domain. A step that fails undoes the ones before it; the stack's own apply, once begun, is finished by asking again. Refused unless accept is the review's sha256."), m.apply),
		module.Handle(adminChange("mail.ports.open", "{ports: [port]}",
			"Opens mail's public ports in the firewall, as mail's: for a host where they were not opened at set-up. Closes nothing."), m.portsOpen),
		module.Handle(adminChange("mail.remove", "{purge?}",
			"Removes mail: its ports closed (each through the lockout guard), its stack (with purge, its mailboxes too), the loopback rule, the definition, the DNS records AutoPanel published, and its record. Refused while it has accounts. A step that fails says which; asking again finishes."), m.remove),
		module.Handle(module.Contract{Verb: "mail.domain.list", Discloses: module.Plain, Since: 6, Result: "[{name}]", Doc: "The domains that receive mail."}, m.domainList),
		module.Handle(change("mail.domain.add", "{name}", "Has a registry domain receive mail."), m.domainAdd),
		module.Handle(change("mail.domain.remove", "{name}", "Stops a domain receiving mail; refused while it has accounts."), m.domainRemove),
		module.Handle(module.Contract{Verb: "mail.account.list", Discloses: module.Plain, Since: 6, Param: "{domain?}", Result: "[{address, quota, used, aliases, disabled}]",
			Doc: "The mail accounts, of one domain or of all."}, m.accountList),
		module.Handle(change("mail.account.add", "{address, quota?}", "Makes a mail account. Its own password is generated and told to no one: mail apps sign in with its app passwords."), m.accountAdd),
		module.Handle(change("mail.account.lock", "{address}", "Replaces an account's own password, typed under an older AutoPanel, with one no one knows: from then on only its app passwords sign in."), m.accountLock),
		module.Handle(module.Contract{Verb: "mail.apppassword.list", Discloses: module.Plain, Since: 6, Param: "{address}", Result: "[{id, description, created_at, pending, expires_at}]",
			Doc: "An account's app passwords, never their secrets. A pending one stops at expires_at unless kept."}, m.appPasswordList),
		module.Handle(change("mail.apppassword.add", "{address, description}",
			"Makes an app password for a device, and answers its secret, once, with the settings a mail app needs. It is pending: it stops working after ten minutes unless mail.apppassword.keep keeps it."), m.appPasswordAdd),
		module.Handle(change("mail.apppassword.keep", "{address, id}", "Keeps a pending app password, once its device signs in: it works until revoked. One already expired is destroyed instead."), m.appPasswordKeep),
		module.Handle(change("mail.apppassword.revoke", "{address, id}", "Revokes an app password: its device stops signing in at once."), m.appPasswordRevoke),
		module.Handle(change("mail.account.quota", "{address, quota}", "Sets an account's quota, in bytes."), m.accountQuota),
		module.Handle(func() module.Contract {
			c := change("mail.account.set", "{address, disabled?, aliases?: [address]}", "Disables an account or enables it again (a disabled account signs nothing in and keeps its mail), or replaces its aliases: addresses of mail's domains that deliver to it.")
			c.Since = 11
			return c
		}(), m.accountSet),
		module.Handle(change("mail.account.remove", "{address}", "Deletes a mail account and its mail."), m.accountRemove),
		module.Handle(module.Contract{Verb: "mail.records", Discloses: module.Plain, Since: 6, Param: "{domain}", Result: "{at, records: [{name, type, value, found, state, why, error?}], dkim: [{selector, step, since}]}",
			Doc: "The records a mail domain (or the mail host) needs, and each one's state as the last pass found it: ok, publishing, different (a record AutoPanel did not write holds its place), manual (no DNS token), failed."}, m.records),
		module.Handle(change("mail.records.takeover", "{domain, name, type}",
			"Replaces the records AutoPanel did not write that hold a needed record's place, after the panel showed them: an SPF record is merged, any other is deleted. The next pass publishes the record."), m.recordsTakeover),
		module.Handle(module.Contract{Verb: "mail.repair.check", Area: "mail.admin", Discloses: module.Plain, Since: 11, Result: "{case, says, detail?, review?, plan}",
			Doc: "Tells why AutoPanel cannot manage the mail server, by trying, and changes nothing: ok, unreachable, not_set_up, recovery_leftover, key_lost or admin_lost; with what mail.repair would do, and for admin_lost the review of the mail stack with the recovery administrator."}, m.repairCheck),
		module.Handle(func() module.Contract {
			c := adminChange("mail.repair", "{accept?}", "Repairs AutoPanel's access to the mail server, as mail.repair.check says: a new API key made by the administrator; or, with accept (the review's sha256), the recovery administrator for one start to give the administrator a new secret, then a new key, then the recovery administrator taken away. Nothing of mail's data is touched.")
			c.Since = 11
			return c
		}(), m.repair),
		module.Handle(change("mail.sync", "", "Starts the DNS, DKIM and certificate pass now, in the background, and answers the last one's result: mail.records and mail.status show the new one when it ends."), m.syncNow),
	}
}

// --- the guard: the stack mail owns -------------------------------------------

// Owns: the stack named mail is AutoPanel's.
func (m *Module) Owns(name string) bool { return name == Stack }

// Review refuses a mail stack that was not set up from Mail, and warns of one
// whose definition is no longer the one AutoPanel wrote. Mail is recorded as
// set up only once its stack is added (setting mail up is one transaction),
// so while a setup is open the stack is admitted with AutoPanel's own
// definition, and with no other.
func (m *Module) Review(ctx context.Context, name string, compose []byte) []services.Finding {
	if name != Stack {
		return nil
	}
	_, recorded, err := m.store.State(ctx)
	ours := m.setupOpen.Load() && string(compose) == string(m.compose())
	if err != nil || (!recorded && !ours) {
		return []services.Finding{{ID: "reserved-name", Severity: services.Refused,
			Detail: "the stack mail is AutoPanel's: set it up from Mail → Set up mail"}}
	}
	// Stalwart trusts PROXY headers from its stack's network: a second service
	// there could forge one, past the gate and the loopback rule. Webmail and
	// the like are stacks of their own.
	if st, _ := services.Parse(compose, nil); len(st.Services) != 1 {
		return []services.Finding{{ID: "mail-one-service", Severity: services.Refused,
			Detail: "the mail stack runs the mail server alone: it trusts its network, so any other service belongs in a stack of its own"}}
	}
	if m.isRecovery(compose) {
		return []services.Finding{{ID: "mail-recovery", Severity: services.Warning,
			Detail: "the mail server's recovery administrator, for one start: Mail → Repair access takes it away again"}}
	}
	if string(compose) != string(m.compose()) {
		return []services.Finding{{ID: "not-autopanels", Severity: services.Warning,
			Detail: "the mail stack's definition is not the one AutoPanel wrote; Mail may not manage it"}}
	}
	return nil
}

// Sealed: the mail stack may reference one sealed value, the recovery
// administrator a repair gives it for one start.
func (m *Module) Sealed(name string) []string {
	if name != Stack {
		return nil
	}
	return []string{recoveryKey}
}

// Reserved: the loopback ports the mail stack publishes are its alone.
func (m *Module) Reserved() []services.Claim {
	out := make([]services.Claim, 0, len(Ports)+1)
	for _, p := range append(LoopbackPorts(), ManagePort) {
		out = append(out, services.Claim{Stack: Stack, PortUse: services.PortUse{Proto: "tcp", From: p, To: p}})
	}
	return out
}

// Mask hides any secret in the mail stack's log lines: the mail server's
// product knows which.
func (m *Module) Mask(name string, lines []string) []string {
	if name != Stack {
		return lines
	}
	return m.product.Mask(lines)
}

// --- status and setup ---------------------------------------------------------

// Status is mail.status's answer.
type Status struct {
	SetUp        bool     `json:"set_up"`
	Host         string   `json:"host"`
	Bootstrapped int64    `json:"bootstrapped"`
	Stack        string   `json:"stack"`
	Domains      []string `json:"domains"`
	Certificate  string   `json:"certificate"` // the mail host's, as Stalwart serves it
	// Ports are mail's public ports, each with the firewall's verdict, who
	// allowed it, and the commands when AutoPanel will not open it.
	Ports      []corefw.PortState `json:"ports"`
	SyncedAt   int64              `json:"synced_at"` // the last DNS and certificate pass
	SyncErrors []string           `json:"sync_errors"`
	Progress
}

func (m *Module) status(ctx context.Context, _ struct{}) (Status, error) {
	st, ok, err := m.store.State(ctx)
	if err != nil {
		return Status{}, err
	}
	m.mu.Lock()
	p := m.progress
	m.mu.Unlock()
	if !ok {
		return Status{Domains: []string{}, Progress: p}, nil
	}
	out := Status{SetUp: true, Host: st.Host, Bootstrapped: st.Bootstrapped, Progress: p}
	if out.Stack, _, err = m.stacks.Up(ctx, Stack); err != nil {
		out.Stack = "absent"
	}
	if out.Domains, err = m.store.Domains(ctx); err != nil {
		return Status{}, err
	}
	out.Ports = []corefw.PortState{}
	if m.firewall != nil {
		all, _ := wants(nil)
		if ports, err := m.firewall.Review(ctx, corefw.OwnerMail, all); err == nil {
			out.Ports = ports
		}
	}
	last := m.lastSync()
	out.Certificate, out.SyncedAt, out.SyncErrors = last.Certificate, last.At, last.Errors
	if out.SyncErrors == nil {
		out.SyncErrors = []string{}
	}
	return out, nil
}

// SetupAsk is mail.setup's param.
type SetupAsk struct {
	Host   string `json:"host"`
	Domain string `json:"domain"`
}

// Setup is mail.setup's answer: the review of the mail stack, to show before
// mail.setup.apply.
type Setup struct {
	Stack  string          `json:"stack"`
	SHA256 string          `json:"sha256"` // the review's: what mail.setup.apply must be given
	Review services.Review `json:"review"`
	// Ports are mail's four public ports, each with the firewall's verdict and
	// whether it needs a rule: the ones to tick are those that need one.
	Ports []corefw.PortState `json:"ports"`
}

// Accept is mail.setup.apply's param.
type Accept struct {
	Accept string `json:"accept"`
	Open   []int  `json:"open,omitempty"` // public ports to open in the firewall, of the review's
}

// Ports is mail.ports.open's param.
type PortsAsk struct {
	Ports []int `json:"ports"`
}

// RemoveAsk is mail.remove's param.
type RemoveAsk struct {
	Purge bool `json:"purge,omitempty"` // also the stack's data: its mailboxes
}

// setup checks the answers and reviews the mail stack from memory. It writes
// nothing (Decision: docs/decisions/mail.md#setting-mail-up-is-one-transaction):
// the answers wait in memory for mail.setup.apply, and asking again replaces
// them.
func (m *Module) setup(ctx context.Context, p SetupAsk) (Setup, error) {
	m.pendMu.Lock()
	defer m.pendMu.Unlock()
	m.setupOpen.Store(true)
	defer func() { m.setupOpen.Store(m.pending != nil) }()
	st, recorded, err := m.store.State(ctx)
	if err != nil {
		return Setup{}, err
	}
	if recorded && !m.untaken(ctx, st) {
		return Setup{}, ErrSetUp
	}
	host, err := gate.CanonicalHost(p.Host)
	if err != nil || !strings.Contains(host, ".") {
		return Setup{}, ErrBadHost
	}
	domain, err := m.registered(ctx, p.Domain)
	if err != nil {
		return Setup{}, err
	}
	if arch, flags, err := m.host.CPU(); err != nil {
		return Setup{}, err
	} else if err := m.product.CPU(arch, flags); err != nil {
		return Setup{}, with(ErrCPU, err.Error())
	}
	if _, err := m.vault.Get(ctx, sealedConfig); errors.Is(err, ErrLocked) { // the apply seals the settings
		return Setup{}, err
	}
	if recorded { // what a v0.2.6 setup left at its review: half a setup, dropped
		if err := m.store.Forget(ctx); err != nil {
			return Setup{}, err
		}
		if err := m.vault.Delete(ctx, sealedConfig); err != nil && !errors.Is(err, ErrNoSecret) {
			return Setup{}, err
		}
	}
	// A set-up that failed after its stack was added left the stack
	// registered and mail not recorded: it is reviewed from the definition
	// written, and the apply goes on from the steps done.
	var rev services.Review
	if _, _, upErr := m.stacks.Up(ctx, Stack); errors.Is(upErr, services.ErrNotFound) {
		rev, err = m.stacks.CheckDraft(ctx, Stack, m.compose())
	} else if rev, err = m.stacks.Check(ctx, Stack); err == nil && refused(rev.Findings) {
		return Setup{}, ErrNotOurs
	}
	if err != nil {
		return Setup{}, err
	}
	out := Setup{Stack: Stack, SHA256: rev.SHA256, Review: rev, Ports: []corefw.PortState{}}
	if m.firewall != nil {
		all, _ := wants(nil)
		if out.Ports, err = m.firewall.Review(ctx, corefw.OwnerMail, all); err != nil {
			return Setup{}, err
		}
	}
	m.pending = &pendingSetup{host: host, domain: domain, accept: rev.SHA256}
	return out, nil
}

// refused reports whether a review refuses the stack.
func refused(fs []services.Finding) bool {
	for _, f := range fs {
		if f.Severity == services.Refused {
			return true
		}
	}
	return false
}

// apply makes the setup setup reviewed, as one transaction. Every write is
// here, in an order that lets each be undone: the stack's user (the services
// module's, made by any add of the stack), the loopback rule (before the
// stack can run), the definition, the stack added and started, and last the
// record and the sealed settings, which make mail set up. A step that fails
// undoes the writes before it. The stack's own apply keeps its own journal:
// once the stack is registered it is not undone here, and asking again
// finishes it.
func (m *Module) apply(ctx context.Context, p Accept) (Setup, error) {
	m.pendMu.Lock()
	defer m.pendMu.Unlock()
	m.setupOpen.Store(true)
	defer func() { m.setupOpen.Store(m.pending != nil) }()
	pend := m.pending
	if pend == nil {
		return Setup{}, ErrNoPending
	}
	if p.Accept != pend.accept {
		return Setup{}, ErrChanged
	}
	var open []corefw.Want
	if p.Open != nil {
		var err error
		if open, err = wants(p.Open); err != nil {
			return Setup{}, err
		}
	}
	if _, recorded, err := m.store.State(ctx); err != nil {
		return Setup{}, err
	} else if recorded {
		return Setup{}, ErrSetUp
	}
	if _, err := m.vault.Get(ctx, sealedConfig); errors.Is(err, ErrLocked) {
		return Setup{}, err
	}
	registered := func() bool {
		_, _, err := m.stacks.Up(ctx, Stack)
		return !errors.Is(err, services.ErrNotFound)
	}
	var undo []func(context.Context) error
	fail := func(err error) (Setup, error) {
		if !registered() { // the stack's own journal holds what it made, once it is
			bg := context.WithoutCancel(ctx)
			for i := len(undo) - 1; i >= 0; i-- {
				if uerr := undo[i](bg); uerr != nil {
					m.log.Warn("mail: undoing a setup that failed", "err", uerr)
				}
			}
		}
		return Setup{}, err
	}

	if err := m.stacks.EnsureUser(ctx, Stack); err != nil {
		return fail(err)
	}
	uid, err := m.host.StackUID(ctx)
	if err != nil {
		return fail(err)
	}
	if err := m.host.InstallLoopback(ctx, uid); err != nil {
		return fail(fmt.Errorf("mail: the loopback rule: %w", err))
	}
	undo = append(undo, func(ctx context.Context) error { return m.host.RemoveLoopback(ctx, uid) })
	if err := m.host.WriteDefinition(ctx, m.compose()); err != nil {
		return fail(err)
	}
	undo = append(undo, m.host.RemoveDefinition)
	if err := m.stacks.Add(ctx, Stack, pend.accept); err != nil && !errors.Is(err, services.ErrDuplicate) {
		return fail(err)
	}
	// Mail's ports, after its stack and before the record that makes mail set
	// up. A failure here leaves the stack registered: asking again finishes.
	if len(open) > 0 && m.firewall != nil {
		if err := m.firewall.Open(ctx, corefw.OwnerMail, open); err != nil {
			return fail(err)
		}
	}
	cfg, _ := json.Marshal(Config{Host: pend.host, FirstDomain: pend.domain, QuotaDefault: defaultQuota, DMARC: "quarantine"})
	if err := m.vault.Put(ctx, sealedConfig, cfg); err != nil {
		return fail(err)
	}
	if err := m.store.Create(ctx, pend.host, pend.domain); err != nil {
		_ = m.vault.Delete(context.WithoutCancel(ctx), sealedConfig)
		return fail(err)
	}
	m.pending = nil
	m.hostName.Store(pend.host)
	m.note("waiting for the stack", "")
	return Setup{Stack: Stack, SHA256: pend.accept}, nil
}

// untaken says whether a setup was left before its stack was ever added (its
// review closed, the panel quit): Stalwart never ran, nothing was published,
// so mail.setup may run again, with the same answers or new ones.
func (m *Module) untaken(ctx context.Context, st State) bool {
	if st.Bootstrapped != 0 {
		return false
	}
	_, _, err := m.stacks.Up(ctx, Stack)
	return errors.Is(err, services.ErrNotFound)
}

// registered is name as the registry holds it, by its exact name.
func (m *Module) registered(ctx context.Context, name string) (string, error) {
	name, err := gate.CanonicalHost(name)
	if err != nil {
		return "", ErrNotRegistered
	}
	all, err := m.registry.All(ctx)
	if err != nil {
		return "", err
	}
	for _, d := range all {
		if d.Name == name {
			return name, nil
		}
	}
	return "", ErrNotRegistered
}

func (m *Module) note(step, failure string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if step != "" {
		m.progress.Step = step
	}
	m.progress.Error = failure
	m.progress.At = m.now().Unix()
}

// --- the loop -----------------------------------------------------------------

// tick is how often the loop looks at mail. A variable so a test need not wait.
var tick = 20 * time.Second

// loopbackEvery is how often the loopback rule is checked after the start.
var loopbackEvery = time.Hour

// Run keeps mail running until ctx ends. Its first act is the loopback rule:
// a rule that failed to load at boot leaves the mail ports open to every
// local process, so it is checked before anything else of mail's.
func (m *Module) Run(ctx context.Context) error {
	lastLoopback, lastSync, kicked := time.Time{}, time.Time{}, false
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		st, ok, err := m.store.State(ctx)
		if ok {
			m.hostName.Store(st.Host)
		}
		switch {
		case err != nil:
			m.log.Warn("mail: reading its state", "err", err)
		case !ok:
			m.streams(false)
		default:
			if time.Since(lastLoopback) >= loopbackEvery {
				m.holdLoopback(ctx)
				lastLoopback = time.Now()
			}
			if st.Bootstrapped == 0 {
				m.streams(false)
				m.tryBootstrap(ctx, st)
			} else {
				m.note("ready", m.progressError("ready"))
				m.streams(true)
				if (time.Since(lastSync) >= syncEvery || kicked) && !m.repairs.running.Load() {
					if _, err := m.vault.Get(ctx, sealedKey); err == nil { // the pass needs the vault open
						m.syncAll(ctx, st)
						lastSync = time.Now()
					}
				}
			}
		}
		kicked = false
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		case <-m.sync.kick:
			kicked = true
		}
	}
}

// progressError keeps the error only while the step is still step.
func (m *Module) progressError(step string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.progress.Step == step {
		return m.progress.Error
	}
	return ""
}

func (m *Module) holdLoopback(ctx context.Context) {
	uid, err := m.host.StackUID(ctx)
	if err != nil {
		m.setLoopback("unknown: " + err.Error())
		return
	}
	reloaded, err := m.host.EnsureLoopback(ctx, uid)
	switch {
	case err != nil:
		m.log.Error("mail: the loopback rule cannot be loaded; the mail ports are open to local processes", "err", err)
		m.setLoopback("failed: " + err.Error())
	case reloaded:
		m.log.Warn("mail: the loopback rule was missing or changed, and was loaded again")
		m.setLoopback("reloaded at " + m.now().UTC().Format(time.RFC3339))
	default:
		m.setLoopback("ok")
	}
}

func (m *Module) setLoopback(s string) {
	m.mu.Lock()
	m.progress.Loopback = s
	m.mu.Unlock()
}

// tryBootstrap sets Stalwart up once its stack runs. It is safe to run again
// after any failure: each step checks what the one before left.
func (m *Module) tryBootstrap(ctx context.Context, st State) {
	if !m.setupMu.TryLock() {
		return
	}
	defer m.setupMu.Unlock()
	state, since, err := m.stacks.Up(ctx, Stack)
	if err != nil || since == 0 {
		m.note("waiting for the stack", "")
		_ = state
		return
	}
	m.note("setting up", "")
	if err := m.bootstrap(ctx, st, time.Unix(since, 0)); err != nil {
		m.log.Warn("mail: setting the mail server up", "err", err)
		m.note("setting up", err.Error())
	}
}

// restartWait restarts the mail stack and waits until it has been up since
// after the restart.
func (m *Module) restartWait(ctx context.Context) (time.Time, error) {
	before := m.now().Unix()
	if err := m.stacks.Restart(ctx, Stack); err != nil {
		return time.Time{}, err
	}
	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		if _, since, err := m.stacks.Up(ctx, Stack); err == nil && since >= before {
			time.Sleep(3 * time.Second) // its listeners open a moment after the process starts
			return time.Unix(since, 0), nil
		}
		select {
		case <-ctx.Done():
			return time.Time{}, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return time.Time{}, errors.New("mail: the stack did not come back after a restart")
}

// bootstrap has the product take the freshly started server to one AutoPanel
// manages (its steps are the product's, resumable through the sealed values
// it keeps); then the sealed API key must sign in, and only then is mail
// marked set up.
func (m *Module) bootstrap(ctx context.Context, st State, upSince time.Time) error {
	cfgRaw, err := m.vault.Get(ctx, sealedConfig)
	if err != nil {
		return fmt.Errorf("reading mail's settings: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(cfgRaw, &cfg); err != nil {
		return fmt.Errorf("mail's settings do not parse: %w", err)
	}
	env := &bootEnv{m: m, set: provider.Settings{Host: cfg.Host, FirstDomain: cfg.FirstDomain}, since: upSince}
	if err := m.product.Bootstrap(ctx, env); err != nil {
		return err
	}
	if _, err := m.client().Domains(ctx); err != nil {
		return fmt.Errorf("the API key does not sign in: %w", err)
	}
	if err := m.store.SetBootstrapped(ctx, m.now().Unix()); err != nil {
		return err
	}
	m.log.Info("mail: the mail server is set up", "server", m.product.Name(), "host", st.Host)
	m.note("ready", "")
	return nil
}

// client is the mail server's API as the core uses it: with the sealed API
// key.
func (m *Module) client() provider.Server {
	return m.product.Client(m.base, func(ctx context.Context) (string, error) {
		k, err := m.vault.Get(ctx, sealedKey)
		return string(k), err
	})
}

// ready is the client of a set-up mail, or why there is none.
func (m *Module) ready(ctx context.Context) (provider.Server, error) {
	st, ok, err := m.store.State(ctx)
	switch {
	case err != nil:
		return nil, err
	case !ok:
		return nil, ErrNotSetUp
	case st.Bootstrapped == 0:
		return nil, ErrNotReady
	}
	return m.client(), nil
}

// serverErr turns the mail server's refusal into the declared error, its
// reason the detail.
func serverErr(err error) error {
	var r *provider.Refusal
	switch {
	case err == nil:
		return nil
	case errors.As(err, &r):
		return with(ErrServer, r.Why)
	case errors.Is(err, provider.ErrOverLimit):
		return with(ErrServer, err.Error())
	}
	return err
}

// detailed is a declared error that names what it is about.
type detailed struct {
	err    error
	detail string
}

func (e *detailed) Error() string        { return e.err.Error() + ": " + e.detail }
func (e *detailed) Unwrap() error        { return e.err }
func (e *detailed) PublicDetail() string { return e.detail }

func with(err error, detail string) error {
	if len(detail) > 200 {
		detail = detail[:200]
	}
	return &detailed{err: err, detail: detail}
}

// --- domains ------------------------------------------------------------------

// DomainView is one mail domain.
type DomainView struct {
	Name string `json:"name"`
}

// Name is a param that names one thing.
type Name struct {
	Name string `json:"name"`
}

func (m *Module) domainList(ctx context.Context, _ struct{}) ([]DomainView, error) {
	names, err := m.store.Domains(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]DomainView, 0, len(names))
	for _, n := range names {
		out = append(out, DomainView{Name: n})
	}
	return out, nil
}

func (m *Module) domainAdd(ctx context.Context, p Name) (DomainView, error) {
	c, err := m.ready(ctx)
	if err != nil {
		return DomainView{}, err
	}
	name, err := m.registered(ctx, p.Name)
	if err != nil {
		return DomainView{}, err
	}
	have, err := m.store.Domains(ctx)
	if err != nil {
		return DomainView{}, err
	}
	if slices.Contains(have, name) {
		return DomainView{}, ErrDomainExists
	}
	theirs, err := c.Domains(ctx)
	if err != nil {
		return DomainView{}, err
	}
	if !slices.ContainsFunc(theirs, func(d provider.Domain) bool { return d.Name == name }) {
		if _, err := c.AddDomain(ctx, name); err != nil {
			return DomainView{}, serverErr(err)
		}
	}
	if err := m.store.AddDomain(ctx, name); err != nil {
		return DomainView{}, err
	}
	m.kickSync()
	return DomainView{Name: name}, nil
}

func (m *Module) domainRemove(ctx context.Context, p Name) (struct{}, error) {
	c, err := m.ready(ctx)
	if err != nil {
		return struct{}{}, err
	}
	name, _ := gate.CanonicalHost(p.Name)
	have, err := m.store.Domains(ctx)
	if err != nil {
		return struct{}{}, err
	}
	if !slices.Contains(have, name) {
		return struct{}{}, ErrNoDomain
	}
	theirs, err := c.Domains(ctx)
	if err != nil {
		return struct{}{}, err
	}
	accounts, err := c.Accounts(ctx)
	if err != nil {
		return struct{}{}, err
	}
	for _, d := range theirs {
		if d.Name != name {
			continue
		}
		for _, a := range accounts {
			if a.DomainID == d.ID {
				return struct{}{}, ErrDomainHasAccounts
			}
			// An alias of another domain's account in this one holds it too.
			for _, al := range a.Aliases {
				if al.DomainID == d.ID {
					return struct{}{}, ErrDomainHasAccounts
				}
			}
		}
		if err := c.RemoveDomain(ctx, d.ID); err != nil {
			return struct{}{}, serverErr(err)
		}
	}
	if err := m.store.RemoveDomain(ctx, name); err != nil {
		return struct{}{}, err
	}
	// Its records go with it: only the ones AutoPanel published.
	if _, err := m.keep(ctx, name, nil); err != nil && !errors.Is(err, ErrNoDNS) {
		m.log.Warn("mail: removing a domain's records", "domain", name, "err", err)
	}
	if rows, err := m.store.DKIM(ctx, name); err == nil {
		for _, r := range rows {
			_ = m.store.DeleteDKIM(ctx, name, r.Selector)
		}
	}
	m.kickSync()
	return struct{}{}, nil
}

// Uses reports whether a registry domain receives mail, for the gate's check
// before it removes one.
func (m *Module) Uses(ctx context.Context, name string) (string, bool) {
	have, err := m.store.Domains(ctx)
	if err != nil || !slices.Contains(have, name) {
		return "", false
	}
	return "it receives mail", true
}

// --- accounts -----------------------------------------------------------------

// AccountView is one mail account.
type AccountView struct {
	Address  string   `json:"address"`
	Quota    int64    `json:"quota"`
	Used     int64    `json:"used"`
	Aliases  []string `json:"aliases"`
	Disabled bool     `json:"disabled"`
}

// DomainAsk is mail.account.list's param.
type DomainAsk struct {
	Domain string `json:"domain"`
}

// AccountAsk names an account, and what to set.
type AccountAsk struct {
	Address string `json:"address"`
	Quota   int64  `json:"quota"`
}

// AccountSet is mail.account.set's param: what to change of an account.
// What is left out is not changed.
type AccountSet struct {
	Address  string    `json:"address"`
	Disabled *bool     `json:"disabled,omitempty"`
	Aliases  *[]string `json:"aliases,omitempty"` // every alias it is to have; [] for none
}

// MaxAliases is how many aliases an account may have.
const MaxAliases = 20

var localPart = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9._+-]{0,62}[a-z0-9])?$`)

// address splits a mail address of a mail domain, validated.
func (m *Module) address(ctx context.Context, addr string) (local, domain string, err error) {
	addr = strings.ToLower(strings.TrimSpace(addr))
	local, domain, ok := strings.Cut(addr, "@")
	if !ok || !localPart.MatchString(local) || strings.Contains(local, "..") {
		return "", "", ErrBadAddress
	}
	have, err := m.store.Domains(ctx)
	if err != nil {
		return "", "", err
	}
	if !slices.Contains(have, domain) {
		return "", "", ErrBadAddress
	}
	return local, domain, nil
}

// domainIDs maps the mail server's domain ids to names.
func domainIDs(ds []provider.Domain) map[string]string {
	out := make(map[string]string, len(ds))
	for _, d := range ds {
		out[d.ID] = d.Name
	}
	return out
}

func (m *Module) accountList(ctx context.Context, p DomainAsk) ([]AccountView, error) {
	c, err := m.ready(ctx)
	if err != nil {
		return nil, err
	}
	ds, err := c.Domains(ctx)
	if err != nil {
		return nil, err
	}
	names := domainIDs(ds)
	accounts, err := c.Accounts(ctx)
	if err != nil {
		return nil, err
	}
	out := []AccountView{}
	for _, a := range accounts {
		if a.Admin { // Stalwart's administrator is AutoPanel's means of managing it, not a mailbox
			continue
		}
		if p.Domain != "" && names[a.DomainID] != strings.ToLower(p.Domain) {
			continue
		}
		v := AccountView{Address: a.Address, Quota: a.Quota, Used: a.Used, Aliases: []string{}, Disabled: a.Disabled}
		for _, al := range a.Aliases {
			v.Aliases = append(v.Aliases, al.Local+"@"+names[al.DomainID])
		}
		out = append(out, v)
	}
	return out, nil
}

// find is the account at an address, with Stalwart's id for its domain.
func (m *Module) find(ctx context.Context, c provider.Server, local, domain string) (provider.Account, string, error) {
	ds, err := c.Domains(ctx)
	if err != nil {
		return provider.Account{}, "", err
	}
	domainID := ""
	for _, d := range ds {
		if d.Name == domain {
			domainID = d.ID
		}
	}
	if domainID == "" {
		return provider.Account{}, "", ErrBadAddress
	}
	accounts, err := c.Accounts(ctx)
	if err != nil {
		return provider.Account{}, "", err
	}
	for _, a := range accounts {
		if a.DomainID == domainID && a.Local == local {
			if a.Admin { // never changed or removed through Mail: AutoPanel would lose its way in
				return provider.Account{}, domainID, ErrAdminAccount
			}
			return a, domainID, nil
		}
	}
	return provider.Account{}, domainID, ErrNoAccount
}

func (m *Module) accountAdd(ctx context.Context, p AccountAsk) (AccountView, error) {
	c, err := m.ready(ctx)
	if err != nil {
		return AccountView{}, err
	}
	local, domain, err := m.address(ctx, p.Address)
	if err != nil {
		return AccountView{}, err
	}
	quota := p.Quota
	if quota <= 0 {
		quota = defaultQuota
	}
	_, domainID, err := m.find(ctx, c, local, domain)
	switch {
	case err == nil:
		return AccountView{}, ErrAccountExists
	case !errors.Is(err, ErrNoAccount):
		return AccountView{}, err
	}
	if owner, err := aliasOwner(ctx, c, local, domainID); err != nil {
		return AccountView{}, err
	} else if owner != "" {
		return AccountView{}, ErrAddressTaken
	}
	if _, err := c.AddAccount(ctx, provider.NewAccount{Local: local, DomainID: domainID, Quota: quota, AppPasswords: AppPasswordLimit}); err != nil {
		return AccountView{}, serverErr(err)
	}
	return AccountView{Address: local + "@" + domain, Quota: quota, Aliases: []string{}}, nil
}

func (m *Module) accountQuota(ctx context.Context, p AccountAsk) (struct{}, error) {
	c, err := m.ready(ctx)
	if err != nil {
		return struct{}{}, err
	}
	local, domain, err := m.address(ctx, p.Address)
	if err != nil {
		return struct{}{}, err
	}
	if p.Quota <= 0 {
		return struct{}{}, module.ErrInvalidParams
	}
	a, _, err := m.find(ctx, c, local, domain)
	if err != nil {
		return struct{}{}, err
	}
	return struct{}{}, serverErr(c.SetQuota(ctx, a.ID, p.Quota))
}

// aliasOwner is the id of the account that has local@domainID as an alias,
// or "".
func aliasOwner(ctx context.Context, c provider.Server, local, domainID string) (string, error) {
	accounts, err := c.Accounts(ctx)
	if err != nil {
		return "", err
	}
	for _, a := range accounts {
		for _, al := range a.Aliases {
			if al.Local == local && al.DomainID == domainID {
				return a.ID, nil
			}
		}
	}
	return "", nil
}

// accountSet disables or enables an account, or replaces its aliases. An
// alias is an address of a domain that receives mail, and is no account's
// own address and no other account's alias. Aliases are checked before
// anything is changed: a change that is refused changes nothing.
func (m *Module) accountSet(ctx context.Context, p AccountSet) (AccountView, error) {
	c, err := m.ready(ctx)
	if err != nil {
		return AccountView{}, err
	}
	local, domain, err := m.address(ctx, p.Address)
	if err != nil {
		return AccountView{}, err
	}
	if p.Disabled == nil && p.Aliases == nil {
		return AccountView{}, module.ErrInvalidParams
	}
	a, _, err := m.find(ctx, c, local, domain)
	if err != nil {
		return AccountView{}, err
	}
	var want []provider.Alias
	if p.Aliases != nil {
		if len(*p.Aliases) > MaxAliases {
			return AccountView{}, ErrTooManyAliases
		}
		ds, err := c.Domains(ctx)
		if err != nil {
			return AccountView{}, err
		}
		ids := map[string]string{}
		for _, d := range ds {
			ids[d.Name] = d.ID
		}
		accounts, err := c.Accounts(ctx)
		if err != nil {
			return AccountView{}, err
		}
		seen := map[provider.Alias]bool{}
		for _, addr := range *p.Aliases {
			l, dom, err := m.address(ctx, addr)
			if err != nil {
				return AccountView{}, err
			}
			id, ok := ids[dom]
			if !ok {
				return AccountView{}, ErrBadAddress
			}
			al := provider.Alias{Local: l, DomainID: id}
			if seen[al] {
				continue
			}
			seen[al] = true
			for _, o := range accounts {
				if o.Local == l && o.DomainID == id {
					return AccountView{}, ErrAddressTaken // an account's own address, this one's included
				}
				if o.ID != a.ID && slices.Contains(o.Aliases, al) {
					return AccountView{}, ErrAddressTaken
				}
			}
			want = append(want, al)
		}
	}
	if p.Aliases != nil {
		if err := c.SetAliases(ctx, a.ID, want); err != nil {
			return AccountView{}, serverErr(err)
		}
	}
	if p.Disabled != nil && *p.Disabled != a.Disabled {
		if err := c.SetDisabled(ctx, a.ID, *p.Disabled); err != nil {
			return AccountView{}, serverErr(err)
		}
	}
	views, err := m.accountList(ctx, DomainAsk{Domain: domain})
	if err != nil {
		return AccountView{}, err
	}
	for _, v := range views {
		if v.Address == local+"@"+domain {
			return v, nil
		}
	}
	return AccountView{}, ErrNoAccount
}

func (m *Module) accountRemove(ctx context.Context, p AccountAsk) (struct{}, error) {
	c, err := m.ready(ctx)
	if err != nil {
		return struct{}{}, err
	}
	local, domain, err := m.address(ctx, p.Address)
	if err != nil {
		return struct{}{}, err
	}
	a, _, err := m.find(ctx, c, local, domain)
	if err != nil {
		return struct{}{}, err
	}
	return struct{}{}, serverErr(c.RemoveAccount(ctx, a.ID))
}

// --- records ------------------------------------------------------------------

// RecordsAnswer is mail.records' answer.
type RecordsAnswer struct {
	At      int64        `json:"at"`
	Records []RecordView `json:"records"`
	DKIM    []DKIMRow    `json:"dkim"`
}

func (m *Module) records(ctx context.Context, p DomainAsk) (RecordsAnswer, error) {
	st, ok, err := m.store.State(ctx)
	if err != nil {
		return RecordsAnswer{}, err
	}
	if !ok {
		return RecordsAnswer{}, ErrNotSetUp
	}
	owner := strings.ToLower(strings.TrimSuffix(p.Domain, "."))
	if owner != st.Host {
		have, err := m.store.Domains(ctx)
		if err != nil {
			return RecordsAnswer{}, err
		}
		if !slices.Contains(have, owner) {
			return RecordsAnswer{}, ErrNoDomain
		}
	}
	last := m.lastSync()
	out := RecordsAnswer{At: last.At, Records: last.Records[owner], DKIM: last.DKIM[owner]}
	if out.Records == nil {
		out.Records = []RecordView{}
	}
	if out.DKIM == nil {
		out.DKIM = []DKIMRow{}
	}
	return out, nil
}

// TakeoverAsk names the record to take over.
type TakeoverAsk struct {
	Domain string `json:"domain"`
	Name   string `json:"name"`
	Type   string `json:"type"`
}

func (m *Module) recordsTakeover(ctx context.Context, p TakeoverAsk) (struct{}, error) {
	st, ok, err := m.store.State(ctx)
	if err != nil {
		return struct{}{}, err
	}
	if !ok {
		return struct{}{}, ErrNotSetUp
	}
	owner := strings.ToLower(p.Domain)
	for _, v := range m.lastSync().Records[owner] {
		if v.Name == strings.ToLower(p.Name) && v.Type == strings.ToUpper(p.Type) && v.State == "different" {
			if err := m.takeover(ctx, owner, st.Host, v.Record); err != nil {
				return struct{}{}, with(ErrServer, err.Error())
			}
			m.kickSync()
			return struct{}{}, nil
		}
	}
	return struct{}{}, ErrNoRecord
}

func (m *Module) syncNow(ctx context.Context, _ struct{}) (Sync, error) {
	st, ok, err := m.store.State(ctx)
	switch {
	case err != nil:
		return Sync{}, err
	case !ok:
		return Sync{}, ErrNotSetUp
	case st.Bootstrapped == 0:
		return Sync{}, ErrNotReady
	}
	if _, err := m.vault.Get(ctx, sealedKey); err != nil {
		return Sync{}, err
	}
	m.kickSync()
	return m.lastSync(), nil
}

// portsOpen opens mail's public ports as mail's, for a host where they were
// not opened at set-up: unticked then, a firewall turned on since, or mail set
// up before the firewall work.
//
// Decision: docs/decisions/firewall.md#mails-ports
func (m *Module) portsOpen(ctx context.Context, p PortsAsk) (struct{}, error) {
	if _, ok, err := m.store.State(ctx); err != nil {
		return struct{}{}, err
	} else if !ok {
		return struct{}{}, ErrNotSetUp
	}
	open, err := wants(p.Ports)
	if err != nil || len(p.Ports) == 0 {
		if err == nil {
			err = ErrNotMailPort
		}
		return struct{}{}, err
	}
	if m.firewall == nil {
		return struct{}{}, ErrNotSetUp
	}
	return struct{}{}, m.firewall.Open(ctx, corefw.OwnerMail, open)
}

// remove takes mail down, each step one that asking again finishes: the
// accounts checked while the server still runs (once its stack is gone the
// check was passed), the gate's mail streams off, mail's firewall rules closed
// through the lockout guard, the stack, the loopback rule, the definition,
// the DNS records AutoPanel published for each domain and the mail host, the
// settings, and last the record that says mail is set up.
//
// Decision: docs/decisions/mail.md#removing-mail
func (m *Module) remove(ctx context.Context, p RemoveAsk) (struct{}, error) {
	m.pendMu.Lock()
	defer m.pendMu.Unlock()
	st, ok, err := m.store.State(ctx)
	switch {
	case err != nil:
		return struct{}{}, err
	case !ok:
		return struct{}{}, ErrNotSetUp
	}
	_, _, upErr := m.stacks.Up(ctx, Stack)
	present := !errors.Is(upErr, services.ErrNotFound)
	if present && st.Bootstrapped != 0 {
		accounts, err := m.client().Accounts(ctx)
		if err != nil {
			return struct{}{}, serverErr(err)
		}
		if len(accounts) > 0 {
			return struct{}{}, ErrHasAccounts
		}
	}
	m.streams(false)
	if m.firewall != nil {
		if err := m.firewall.Close(ctx, corefw.OwnerMail, nil); err != nil {
			return struct{}{}, err
		}
	}
	uid, uidErr := m.host.StackUID(ctx) // before the stack's user goes
	if present {
		if err := m.stacks.RemoveOwned(ctx, Stack, p.Purge); err != nil {
			return struct{}{}, err
		}
	}
	if uidErr == nil {
		if err := m.host.RemoveLoopback(ctx, uid); err != nil {
			return struct{}{}, err
		}
	}
	if err := m.host.RemoveDefinition(ctx); err != nil {
		return struct{}{}, err
	}
	domains, err := m.store.Domains(ctx)
	if err != nil {
		return struct{}{}, err
	}
	for _, owner := range append(domains, st.Host) {
		if _, err := m.keep(ctx, owner, nil); err != nil && !errors.Is(err, ErrNoDNS) {
			return struct{}{}, err // a record left published would be a stranger's later
		}
	}
	for _, name := range []string{sealedConfig, sealedKey} {
		if name == sealedKey && !p.Purge {
			continue // the server's data stays, and so does the key that opens it
		}
		if err := m.vault.Delete(ctx, name); err != nil && !errors.Is(err, ErrNoSecret) {
			return struct{}{}, err
		}
	}
	if err := m.store.Drop(ctx); err != nil {
		return struct{}{}, err
	}
	m.hostName.Store("")
	// What the last pass saw was this setup's: a later one starts with nothing.
	m.setLoopback("")
	m.sync.mu.Lock()
	m.sync.last, m.sync.port25At = Sync{}, time.Time{}
	m.sync.mu.Unlock()
	m.note("", "")
	return struct{}{}, nil
}
