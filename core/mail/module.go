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

	"github.com/yongjohnlee80/autopanel/core/gate"
	"github.com/yongjohnlee80/autopanel/core/services"
	"github.com/yongjohnlee80/autopanel/internal/module"
)

// State is the store's record of mail: that it exists, and how far it got.
type State struct {
	Host         string
	Bootstrapped int64 // Unix seconds; 0 while Stalwart is not set up
	CreatedAt    int64
}

// Store is mail's part of the store. Each write leaves its audit entry.
type Store interface {
	State(ctx context.Context) (State, bool, error)
	Create(ctx context.Context, host, firstDomain string) error
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
}

// Host is the machine side of mail (host/mail).
type Host interface {
	// CPU is nil when the host's processor runs Stalwart (x86-64-v2 or arm64).
	CPU() error
	// WriteDefinition writes the mail stack's compose.yaml into the stacks'
	// directory.
	WriteDefinition(ctx context.Context, compose []byte) error
	// StackUID is the mail stack user's id.
	StackUID(ctx context.Context) (int, error)
	// FirstPassword is the one-time password Stalwart printed at its start at
	// or after since, from the stack's journal.
	FirstPassword(ctx context.Context, since time.Time) (string, error)
	// Forwarder is the source Stalwart sees forwarded connections arrive
	// from, as a prefix: the mail stack network's subnet, read from Podman.
	Forwarder(ctx context.Context) (string, error)
	// InstallLoopback writes and loads the loopback rule, ordered before the
	// stack user's systemd; EnsureLoopback checks it and loads it again if the
	// kernel lost it, reporting whether it had to.
	InstallLoopback(ctx context.Context, stackUID int) error
	EnsureLoopback(ctx context.Context, stackUID int) (reloaded bool, err error)
	// PublicIPv4 is the host's one global IPv4 address, for the mail host's A
	// record; "" when it has none or several.
	PublicIPv4(ctx context.Context) (string, error)
	// ResolveTXT asks public resolvers for a name's TXT records.
	ResolveTXT(ctx context.Context, name string) ([]string, error)
}

// Sealed names: every key and setting of mail is in the vault.
const (
	sealedConfig = "mail/config"
	sealedAdmin  = "mail/admin"
	sealedKey    = "mail/apikey"
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
	ErrNotReady          = errors.New("mail: Stalwart is not set up yet")
	ErrBadHost           = errors.New("mail: the mail host is not a host name")
	ErrNotRegistered     = errors.New("mail: the domain is not in the registry")
	ErrCPU               = errors.New("mail: this processor cannot run Stalwart")
	ErrLocked            = errors.New("mail: the vault is locked")
	ErrNoSecret          = errors.New("mail: no such sealed value")
	ErrDomainExists      = errors.New("mail: the domain receives mail already")
	ErrNoDomain          = errors.New("mail: the domain does not receive mail")
	ErrDomainHasAccounts = errors.New("mail: the domain has accounts")
	ErrBadAddress        = errors.New("mail: not a mail address of a mail domain")
	ErrNoAccount         = errors.New("mail: no such account")
	ErrAccountExists     = errors.New("mail: the account exists")
	ErrWeakPassword      = errors.New("mail: the password is too short")
	ErrStalwart          = errors.New("mail: Stalwart refused")
	ErrAdminAccount      = errors.New("mail: that is Stalwart's administrator")
	ErrNoRecord          = errors.New("mail: no record of that name and type is held by another")
)

// Streams switches the gate's forwarding of mail's ports on or off.
type Streams func(on bool)

// Module is mail.*, and the loop that keeps mail running: the loopback rule
// held, Stalwart set up once its stack runs, the gate's streams on once it is.
type Module struct {
	store    Store
	vault    Vault
	registry Registry
	stacks   Stacks
	host     Host
	streams  Streams
	log      *slog.Logger
	now      func() time.Time
	base     string // Stalwart's management API: ManageURL()
	dns      DNS    // nil: records are shown, never published
	certs    Certs  // nil: no certificate is handed over
	sync     syncState
	hostName atomic.Value // string: the mail host, for IsHost

	mu       sync.Mutex
	progress Progress
	setupMu  sync.Mutex // one bootstrap at a time
}

// Progress is where mail's setting up is, for mail.status.
type Progress struct {
	Step     string `json:"step"`  // "", "waiting for the stack", "setting up", "ready"
	Error    string `json:"error"` // the last failure, with its step
	At       int64  `json:"at"`    // when Step or Error last changed, Unix seconds
	Loopback string `json:"loopback"`
}

// NewModule is the mail verbs and loop.
func NewModule(store Store, vault Vault, registry Registry, stacks Stacks, host Host, streams Streams, log *slog.Logger) *Module {
	return &Module{store: store, vault: vault, registry: registry, stacks: stacks, host: host, streams: streams, log: log, now: time.Now,
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

func (m *Module) Name() string { return "mail" }

func (m *Module) Errors() []module.PublicError {
	return []module.PublicError{
		{Err: ErrNotSetUp, Code: -32130, Name: "mail.not_set_up", Message: "mail is not set up: Mail → Set up mail"},
		{Err: ErrSetUp, Code: -32131, Name: "mail.set_up", Message: "mail is set up already"},
		{Err: ErrNotReady, Code: -32132, Name: "mail.not_ready", Message: "Stalwart is not set up yet: apply the mail stack, and wait for mail.status to say ready"},
		{Err: ErrBadHost, Code: -32133, Name: "mail.bad_host", Message: "the mail host is a host name with a dot: mail.example.com"},
		{Err: ErrNotRegistered, Code: -32134, Name: "mail.not_registered", Message: "the domain is not in the registry: add it under Domains first"},
		{Err: ErrCPU, Code: -32135, Name: "mail.cpu", Message: "this processor cannot run Stalwart, which needs x86-64-v2 (SSE4.2, POPCNT) or arm64"},
		{Err: ErrLocked, Code: -32136, Name: "mail.locked", Message: "the vault is locked: log in as root first"},
		{Err: ErrDomainExists, Code: -32137, Name: "mail.domain_exists", Message: "the domain receives mail already"},
		{Err: ErrNoDomain, Code: -32138, Name: "mail.no_domain", Message: "the domain does not receive mail"},
		{Err: ErrDomainHasAccounts, Code: -32139, Name: "mail.domain_has_accounts", Message: "the domain has accounts: remove them first"},
		{Err: ErrBadAddress, Code: -32140, Name: "mail.bad_address", Message: "an address is a local part (letters, digits, . _ + -) and a domain that receives mail"},
		{Err: ErrNoAccount, Code: -32141, Name: "mail.no_account", Message: "no such account"},
		{Err: ErrAccountExists, Code: -32142, Name: "mail.account_exists", Message: "that account exists"},
		{Err: ErrWeakPassword, Code: -32143, Name: "mail.weak_password", Message: "a password is 12 characters at least, 256 at most, with no control characters"},
		{Err: ErrStalwart, Code: -32144, Name: "mail.refused", Message: "Stalwart refused the change"},
		{Err: ErrNoRecord, Code: -32146, Name: "mail.no_record", Message: "no needed record of that name and type is held by one AutoPanel did not write"},
		{Err: ErrNoDNS, Code: -32147, Name: "mail.no_dns", Message: "no DNS token: set one (certs.cloudflare.set) for AutoPanel to publish records"},
		{Err: ErrAdminAccount, Code: -32145, Name: "mail.admin_account", Message: "that address is Stalwart's administrator, which AutoPanel manages Stalwart with; it is not a mailbox"},
	}
}

func change(verb, param, doc string) module.Contract {
	return module.Contract{Verb: verb, Since: 6, Param: param, Mutates: true, Privileged: true, Doc: doc}
}

func (m *Module) Verbs() []module.Verb {
	return []module.Verb{
		module.Handle(module.Contract{Verb: "mail.status", Since: 6, Result: "{set_up, host, bootstrapped, stack, step, error, at, loopback, domains}",
			Doc: "Whether mail is set up, how far Stalwart's setting up got, the mail stack's state, the loopback rule's, and the mail domains."}, m.status),
		module.Handle(change("mail.setup", "{host, domain}",
			"Sets mail up: writes the mail stack's definition (Stalwart, pinned), makes its user and the loopback rule, and records the host and first domain. The stack is then reviewed and applied as any stack; Stalwart is set up once it runs."), m.setup),
		module.Handle(module.Contract{Verb: "mail.domain.list", Since: 6, Result: "[{name}]", Doc: "The domains that receive mail."}, m.domainList),
		module.Handle(change("mail.domain.add", "{name}", "Has a registry domain receive mail."), m.domainAdd),
		module.Handle(change("mail.domain.remove", "{name}", "Stops a domain receiving mail; refused while it has accounts."), m.domainRemove),
		module.Handle(module.Contract{Verb: "mail.account.list", Since: 6, Param: "{domain?}", Result: "[{address, quota, used, aliases}]",
			Doc: "The mail accounts, of one domain or of all."}, m.accountList),
		module.Handle(change("mail.account.add", "{address, password, quota?}", "Makes a mail account. The password goes to Stalwart and nowhere else."), m.accountAdd),
		module.Handle(change("mail.account.password", "{address, password}", "Sets an account's password."), m.accountPassword),
		module.Handle(change("mail.account.quota", "{address, quota}", "Sets an account's quota, in bytes."), m.accountQuota),
		module.Handle(change("mail.account.remove", "{address}", "Deletes a mail account and its mail."), m.accountRemove),
		module.Handle(module.Contract{Verb: "mail.records", Since: 6, Param: "{domain}", Result: "{at, records: [{name, type, value, found, state, why, error?}], dkim: [{selector, step, since}]}",
			Doc: "The records a mail domain (or the mail host) needs, and each one's state as the last pass found it: ok, publishing, different (a record AutoPanel did not write holds its place), manual (no DNS token), failed."}, m.records),
		module.Handle(change("mail.records.takeover", "{domain, name, type}",
			"Replaces the records AutoPanel did not write that hold a needed record's place, after the panel showed them: an SPF record is merged, any other is deleted. The next pass publishes the record."), m.recordsTakeover),
		module.Handle(change("mail.sync", "", "Starts the DNS, DKIM and certificate pass now, in the background, and answers the last one's result: mail.records and mail.status show the new one when it ends."), m.syncNow),
	}
}

// --- the guard: the stack mail owns -------------------------------------------

// Owns: the stack named mail is AutoPanel's.
func (m *Module) Owns(name string) bool { return name == Stack }

// Review refuses a mail stack that was not set up from Mail, and warns of one
// whose definition is no longer the one AutoPanel wrote.
func (m *Module) Review(ctx context.Context, name string, compose []byte) []services.Finding {
	if name != Stack {
		return nil
	}
	if _, ok, err := m.store.State(ctx); err != nil || !ok {
		return []services.Finding{{ID: "reserved-name", Severity: services.Refused,
			Detail: "the stack mail is AutoPanel's: set it up from Mail → Set up mail"}}
	}
	// Stalwart trusts PROXY headers from its stack's network: a second service
	// there could forge one, past the gate and the loopback rule. Webmail and
	// the like are stacks of their own.
	if st, _ := services.Parse(compose, nil); len(st.Services) != 1 {
		return []services.Finding{{ID: "mail-one-service", Severity: services.Refused,
			Detail: "the mail stack runs Stalwart alone: it trusts its network, so any other service belongs in a stack of its own"}}
	}
	if string(compose) != string(Compose()) {
		return []services.Finding{{ID: "not-autopanels", Severity: services.Warning,
			Detail: "the mail stack's definition is not the one AutoPanel wrote; Mail may not manage it"}}
	}
	return nil
}

// Reserved: the loopback ports the mail stack publishes are its alone.
func (m *Module) Reserved() []services.Claim {
	out := make([]services.Claim, 0, len(Ports)+1)
	for _, p := range append(LoopbackPorts(), ManagePort) {
		out = append(out, services.Claim{Stack: Stack, PortUse: services.PortUse{Proto: "tcp", From: p, To: p}})
	}
	return out
}

// passwordLine is Stalwart's first-start banner line that holds its one-time
// password.
var passwordLine = regexp.MustCompile(`(?i)(password:\s*)\S+`)

// Mask hides the one-time password in the mail stack's log lines.
func (m *Module) Mask(name string, lines []string) []string {
	if name != Stack {
		return lines
	}
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = passwordLine.ReplaceAllString(l, "${1}[hidden]")
	}
	return out
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
	SyncedAt     int64    `json:"synced_at"`   // the last DNS and certificate pass
	SyncErrors   []string `json:"sync_errors"`
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

// Setup is mail.setup's answer: the stack to review and apply next.
type Setup struct {
	Stack  string `json:"stack"`
	SHA256 string `json:"sha256"` // of the compose file written
}

func (m *Module) setup(ctx context.Context, p SetupAsk) (Setup, error) {
	if _, ok, err := m.store.State(ctx); err != nil {
		return Setup{}, err
	} else if ok {
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
	if err := m.host.CPU(); err != nil {
		return Setup{}, fmt.Errorf("%w: %v", ErrCPU, err)
	}
	cfg, _ := json.Marshal(Config{Host: host, FirstDomain: domain, QuotaDefault: defaultQuota, DMARC: "quarantine"})
	if err := m.vault.Put(ctx, sealedConfig, cfg); err != nil {
		return Setup{}, err
	}
	// The user first, so the loopback rule can be ordered before its systemd,
	// and loaded before the stack ever runs.
	if err := m.stacks.EnsureUser(ctx, Stack); err != nil {
		return Setup{}, err
	}
	uid, err := m.host.StackUID(ctx)
	if err != nil {
		return Setup{}, err
	}
	if err := m.host.InstallLoopback(ctx, uid); err != nil {
		return Setup{}, fmt.Errorf("mail: the loopback rule: %w", err)
	}
	if err := m.host.WriteDefinition(ctx, Compose()); err != nil {
		return Setup{}, err
	}
	if err := m.store.Create(ctx, host, domain); err != nil {
		return Setup{}, err
	}
	m.note("waiting for the stack", "")
	return Setup{Stack: Stack, SHA256: ComposeSHA256()}, nil
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
				if time.Since(lastSync) >= syncEvery || kicked {
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
		m.log.Warn("mail: setting Stalwart up", "err", err)
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

// bootstrap: the one-time password Stalwart printed sets it up, which answers
// with the permanent administrator (sealed at once); a restart ends the
// one-time password; the administrator moves the listeners to the ports and
// the trust the gate needs and makes AutoPanel's API key (sealed); a restart
// applies the listeners. Only then is mail marked set up.
func (m *Module) bootstrap(ctx context.Context, st State, upSince time.Time) error {
	cfgRaw, err := m.vault.Get(ctx, sealedConfig)
	if err != nil {
		return fmt.Errorf("reading mail's settings: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(cfgRaw, &cfg); err != nil {
		return fmt.Errorf("mail's settings do not parse: %w", err)
	}
	var admin Admin
	if raw, err := m.vault.Get(ctx, sealedAdmin); err == nil {
		_ = json.Unmarshal(raw, &admin) // set up already, by an earlier try
	} else if !errors.Is(err, ErrNoSecret) {
		return err
	}
	if admin.Secret == "" {
		once, err := m.host.FirstPassword(ctx, upSince)
		if err != nil {
			return fmt.Errorf("the one-time password: %w", err)
		}
		c := NewClient(m.base, Basic("admin", once))
		admin, err = c.SetUp(ctx, Bootstrap{Hostname: cfg.Host, Domain: cfg.FirstDomain})
		if err != nil {
			return fmt.Errorf("setting Stalwart up: %w", err)
		}
		raw, _ := json.Marshal(admin)
		if err := m.vault.Put(ctx, sealedAdmin, raw); err != nil {
			return fmt.Errorf("sealing the administrator: %w", err)
		}
		if upSince, err = m.restartWait(ctx); err != nil {
			return err
		}
	}
	c := NewClient(m.base, Basic(admin.Username, admin.Secret))
	if _, err := c.Domains(ctx); err != nil {
		return fmt.Errorf("signing in as the administrator: %w", err)
	}
	forwarder, err := m.host.Forwarder(ctx)
	if err != nil {
		return fmt.Errorf("the forwarder's address: %w", err)
	}
	if err := c.ConfigureListeners(ctx, Listeners, forwarder); err != nil {
		return fmt.Errorf("the listeners: %w", err)
	}
	if _, err := m.vault.Get(ctx, sealedKey); errors.Is(err, ErrNoSecret) {
		_, key, err := c.CreateAPIKey(ctx, "autopanel core")
		if err != nil {
			return fmt.Errorf("the API key: %w", err)
		}
		if err := m.vault.Put(ctx, sealedKey, []byte(key)); err != nil {
			return fmt.Errorf("sealing the API key: %w", err)
		}
	} else if err != nil {
		return err
	}
	if _, err := m.restartWait(ctx); err != nil {
		return err
	}
	if _, err := m.client().Domains(ctx); err != nil {
		return fmt.Errorf("the API key does not sign in: %w", err)
	}
	if err := m.store.SetBootstrapped(ctx, m.now().Unix()); err != nil {
		return err
	}
	m.log.Info("mail: Stalwart is set up", "host", st.Host)
	m.note("ready", "")
	return nil
}

// client is Stalwart's API as the core uses it: with the sealed API key.
func (m *Module) client() *Client {
	return NewClient(m.base, Bearer(func(ctx context.Context) (string, error) {
		k, err := m.vault.Get(ctx, sealedKey)
		return string(k), err
	}))
}

// ready is the client of a set-up mail, or why there is none.
func (m *Module) ready(ctx context.Context) (*Client, error) {
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

// stalwartErr turns Stalwart's refusal into the declared error, its reason
// the detail.
func stalwartErr(err error) error {
	var se *SetError
	var me *MethodError
	switch {
	case errors.As(err, &se):
		return with(ErrStalwart, strings.TrimSpace(se.Type+": "+se.Description))
	case errors.As(err, &me):
		return with(ErrStalwart, strings.TrimSpace(me.Type+": "+me.Description))
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
	if !slices.ContainsFunc(theirs, func(d Domain) bool { return d.Name == name }) {
		if _, err := c.AddDomain(ctx, name); err != nil {
			return DomainView{}, stalwartErr(err)
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
		}
		if err := c.RemoveDomain(ctx, d.ID); err != nil {
			return struct{}{}, stalwartErr(err)
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
	Address string   `json:"address"`
	Quota   int64    `json:"quota"`
	Used    int64    `json:"used"`
	Aliases []string `json:"aliases"`
}

// DomainAsk is mail.account.list's param.
type DomainAsk struct {
	Domain string `json:"domain"`
}

// AccountAsk names an account, and what to set.
type AccountAsk struct {
	Address  string `json:"address"`
	Password string `json:"password"`
	Quota    int64  `json:"quota"`
}

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

func validPassword(p string) error {
	if n := len([]rune(p)); n < 12 || n > 256 {
		return ErrWeakPassword
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return ErrWeakPassword
		}
	}
	return nil
}

// domainIDs maps Stalwart's domain ids to names.
func domainIDs(ds []Domain) map[string]string {
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
		v := AccountView{Address: a.Address, Quota: a.Quota, Used: a.Used, Aliases: []string{}}
		for _, al := range a.Aliases {
			v.Aliases = append(v.Aliases, al.Name+"@"+names[al.DomainID])
		}
		out = append(out, v)
	}
	return out, nil
}

// find is the account at an address, with Stalwart's id for its domain.
func (m *Module) find(ctx context.Context, c *Client, local, domain string) (Account, string, error) {
	ds, err := c.Domains(ctx)
	if err != nil {
		return Account{}, "", err
	}
	domainID := ""
	for _, d := range ds {
		if d.Name == domain {
			domainID = d.ID
		}
	}
	if domainID == "" {
		return Account{}, "", ErrBadAddress
	}
	accounts, err := c.Accounts(ctx)
	if err != nil {
		return Account{}, "", err
	}
	for _, a := range accounts {
		if a.DomainID == domainID && a.Name == local {
			if a.Admin { // never changed or removed through Mail: AutoPanel would lose its way in
				return Account{}, domainID, ErrAdminAccount
			}
			return a, domainID, nil
		}
	}
	return Account{}, domainID, ErrNoAccount
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
	if err := validPassword(p.Password); err != nil {
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
	if _, err := c.AddAccount(ctx, NewAccount{Name: local, DomainID: domainID, Password: p.Password, Quota: quota}); err != nil {
		return AccountView{}, stalwartErr(err)
	}
	return AccountView{Address: local + "@" + domain, Quota: quota, Aliases: []string{}}, nil
}

func (m *Module) accountPassword(ctx context.Context, p AccountAsk) (struct{}, error) {
	c, err := m.ready(ctx)
	if err != nil {
		return struct{}{}, err
	}
	local, domain, err := m.address(ctx, p.Address)
	if err != nil {
		return struct{}{}, err
	}
	if err := validPassword(p.Password); err != nil {
		return struct{}{}, err
	}
	a, _, err := m.find(ctx, c, local, domain)
	if err != nil {
		return struct{}{}, err
	}
	return struct{}{}, stalwartErr(c.SetPassword(ctx, a.ID, p.Password))
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
	return struct{}{}, stalwartErr(c.SetQuota(ctx, a.ID, p.Quota))
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
	return struct{}{}, stalwartErr(c.RemoveAccount(ctx, a.ID))
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
				return struct{}{}, with(ErrStalwart, err.Error())
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
