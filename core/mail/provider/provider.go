// Package provider is the boundary between mail's rules (core/mail) and the
// mail server that carries them out. core/mail talks to a server only
// through Server and Product, in these neutral terms; a server's own
// protocol, deployment and quirks live in its SDK package (sdk/stalwart),
// which implements both. Moving AutoPanel to another mail server is a new SDK
// package that passes provider/conformance, and no change to core/mail.
//
// Nothing here imports core/mail or any SDK, so both can import it.
//
// Decision: docs/decisions/mail.md#mails-rules-name-no-mail-server
package provider

import (
	"context"
	"errors"
	"time"
)

// Server is a running mail server as AutoPanel manages it. Ids are the
// server's own, opaque to the caller. Every method is safe to call again
// after a failure.
type Server interface {
	// Domains are the domains the server receives mail for.
	Domains(ctx context.Context) ([]Domain, error)
	// AddDomain makes a domain that signs nothing and publishes nothing by
	// itself: AutoPanel keeps its records and its DKIM keys.
	AddDomain(ctx context.Context, name string) (Domain, error)
	RemoveDomain(ctx context.Context, id string) error
	// Records are what the server needs in a domain's zone (and the mail
	// host's): MX, SPF, DMARC, SRV, TLS reporting, and a TXT record for each
	// of the domain's DKIM keys, pending ones included. AutoPanel decides which
	// it publishes.
	Records(ctx context.Context, domainID string) ([]Record, error)

	// Accounts are the user accounts, the server's administrator marked.
	Accounts(ctx context.Context) ([]Account, error)
	// AddAccount makes an account with a password nobody knows: at least 256
	// random bits, made by the provider, stored as its server stores a
	// password, and kept nowhere else. Mail apps sign in with app passwords.
	AddAccount(ctx context.Context, a NewAccount) (string, error)
	// LockPassword replaces an account's password with one nobody knows, as
	// AddAccount makes, and nothing else: its app passwords and any second
	// factor stay.
	LockPassword(ctx context.Context, accountID string) error
	// SetQuota sets an account's disk quota, and nothing else.
	SetQuota(ctx context.Context, accountID string, bytes int64) error
	// SetDisabled disables an account or enables it again, and nothing else:
	// a disabled account signs nothing in, by any password or app password,
	// and keeps its mail, its app passwords and its aliases for when it is
	// enabled.
	SetDisabled(ctx context.Context, accountID string, disabled bool) error
	// SetAliases replaces an account's aliases with these, and nothing else.
	// Each is an address of a domain the server receives mail for, delivered
	// to the account.
	SetAliases(ctx context.Context, accountID string, aliases []Alias) error
	RemoveAccount(ctx context.Context, accountID string) error

	// AppPasswords are an account's app passwords, never their secrets.
	AppPasswords(ctx context.Context, accountID string) ([]AppPassword, error)
	// AddAppPassword makes an app password for a device, signing in until
	// expires, and answers its secret: the server generates it, and gives it
	// this once. The provider neither keeps nor logs the secret. The account
	// may hold at least room app passwords: a provider raises a lower limit.
	AddAppPassword(ctx context.Context, accountID, device string, expires time.Time, room int) (AppPassword, string, error)
	// KeepAppPassword clears an app password's expiry. A server may bring an
	// expired one back this way: the caller never keeps one that expired.
	KeepAppPassword(ctx context.Context, accountID, id string) error
	RevokeAppPassword(ctx context.Context, accountID, id string) error

	// DKIMKeys are every DKIM key the server holds.
	DKIMKeys(ctx context.Context) ([]DKIMKey, error)
	// AddDKIMKey gives the server a private key (PEM, PKCS #8) for a
	// domain's selector, pending: it signs nothing until made active. The
	// key's public half, in the TXT record Records answers for it, is the
	// base64 of its DER.
	AddDKIMKey(ctx context.Context, domainID, selector string, alg DKIMAlg, privatePEM string) (string, error)
	SetDKIMStage(ctx context.Context, id string, s DKIMStage) error
	RemoveDKIMKey(ctx context.Context, id string) error

	// Certificates are the TLS certificates the server holds.
	Certificates(ctx context.Context) ([]Certificate, error)
	// ServeCertificate hands the server a certificate (replacing id, or new
	// when id is ""), and has it served. It answers whether the server must
	// restart before it serves it.
	ServeCertificate(ctx context.Context, id, chainPEM, keyPEM string) (restart bool, err error)
}

// Product is a mail server as AutoPanel runs it: its stack definition, what
// it needs of the host, its first start, and the client to manage it with.
type Product interface {
	// Name is the server's name, for status and messages: "Stalwart".
	Name() string
	// Service is the name of the stack's one service: its container is the
	// stack's name, a hyphen, and this.
	Service() string
	// Compose is the mail stack's definition, its image pinned by digest:
	// each of mail's ports published on its loopback port, and the
	// management API on its own.
	Compose(s Stack) []byte
	// CPU is nil when a processor of arch with these /proc/cpuinfo flags runs
	// the server.
	CPU(arch string, flags map[string]bool) error
	// FirstCredential is the one-time credential a first start prints, if
	// line is the one holding it.
	FirstCredential(line string) (string, bool)
	// Mask is the server's log lines with any secret in them hidden.
	Mask(lines []string) []string
	// Bootstrap takes a freshly started server to one AutoPanel manages:
	// through env it reads the first start's credential, restarts the stack,
	// and seals what it must keep, the API key (SealedAPIKey) above all. It is
	// safe to run again after any failure: each step checks what the one
	// before left in env's sealed values.
	Bootstrap(ctx context.Context, env Env) error
	// Client is the server's API at base, signing in with the sealed API key.
	// apiKey is called for every request and its answer is never kept: the
	// key is sealed, and a vault locked later must stop the client.
	Client(base string, apiKey func(ctx context.Context) (string, error)) Server
}

// SealedAPIKey is the sealed value Bootstrap must leave: the key Client signs
// in with.
const SealedAPIKey = "apikey"

// Env is what a Bootstrap may use of AutoPanel.
type Env interface {
	// Base is the management API's URL.
	Base() string
	// Settings are the setup's answers.
	Settings() Settings
	// FirstCredential is the one-time credential the stack's current start
	// printed (read from its journal through Product.FirstCredential).
	FirstCredential(ctx context.Context) (string, error)
	// Restart restarts the stack and waits until it is up again.
	Restart(ctx context.Context) error
	// Forwarder is the address prefix forwarded connections arrive from: the
	// one to trust for PROXY headers.
	Forwarder(ctx context.Context) (string, error)
	// Sealed reads a sealed value of the server's; ErrNoSecret when none.
	Sealed(ctx context.Context, name string) ([]byte, error)
	// Seal keeps a value sealed under AutoPanel's master key.
	Seal(ctx context.Context, name string, value []byte) error
}

// Settings are a setup's answers.
type Settings struct {
	Host        string // the mail host: mail.example.com
	FirstDomain string
}

// Stack is what a product's definition is written for: the stack's name
// (its network's and its containers' prefix), mail's ports, and the loopback
// port of the management API.
type Stack struct {
	Name   string
	Ports  []PortMap
	Manage int
}

// PortMap is one of mail's ports: its name (smtp, submissions, submission,
// imaps) and the loopback port the gate forwards it to.
type PortMap struct {
	Name     string
	Loopback int
}

// Domain is a mail domain.
type Domain struct {
	ID   string
	Name string
}

// Record is a DNS record. Value is the record's value as it is published: for
// MX and SRV the priority is inside it; there is no TTL, which is AutoPanel's
// to set.
type Record struct {
	Type  string `json:"type"`  // MX, TXT, CNAME, SRV, TLSA, A, AAAA
	Name  string `json:"name"`  // "example.com", "ap202611e._domainkey.example.com"
	Value string `json:"value"` // as it is published
}

// Account is a user account.
type Account struct {
	ID       string
	Local    string // the address's local part
	DomainID string
	Address  string
	Quota    int64   // bytes; 0 for none
	Used     int64   // bytes; -1 when the server does not account for it
	Aliases  []Alias // the enabled ones
	Admin    bool    // the server's administrator, AutoPanel's way in: not a mailbox
	Disabled bool    // it signs nothing in: no app password, no password
}

// Alias is another address of an account's.
type Alias struct {
	Local    string
	DomainID string
}

// NewAccount is an account to make.
type NewAccount struct {
	Local        string
	DomainID     string
	Quota        int64 // bytes
	AppPasswords int   // room for at least this many app passwords
}

// AppPassword is one of an account's app passwords, without its secret.
type AppPassword struct {
	ID        string
	Device    string
	CreatedAt time.Time
	ExpiresAt *time.Time // nil: it never expires
}

// DKIMAlg is a DKIM key's algorithm.
type DKIMAlg string

const (
	Ed25519 DKIMAlg = "ed25519"
	RSA     DKIMAlg = "rsa"
)

// DKIMStage is where a key is in its life.
type DKIMStage string

const (
	Pending  DKIMStage = "pending"  // held, not signing; its record may be published
	Active   DKIMStage = "active"   // signs
	Retiring DKIMStage = "retiring" // no longer signs; its record stays published
	Retired  DKIMStage = "retired"
)

// DKIMKey is a DKIM key the server holds.
type DKIMKey struct {
	ID       string
	DomainID string
	Selector string
	Alg      DKIMAlg
	Stage    DKIMStage
}

// Certificate is a TLS certificate the server holds.
type Certificate struct {
	ID       string
	SANs     map[string]bool
	NotAfter time.Time
}

// The errors a Server answers with, besides its transport's. An SDK maps its
// server's refusals onto them, keeping the server's words as the detail.
var (
	// ErrRefused is a change the server refused: Refusal says why.
	ErrRefused = errors.New("the mail server refused")
	// ErrOverLimit is an app password beyond what the account may hold.
	ErrOverLimit = errors.New("the account holds as many app passwords as it may")
	// ErrUnauthorized is a credential the server refused.
	ErrUnauthorized = errors.New("the mail server refused AutoPanel's credential")
	// ErrNoSecret is a sealed value that is not there (Env.Sealed).
	ErrNoSecret = errors.New("no such sealed value")
)

// Refusal is ErrRefused with the server's words.
type Refusal struct {
	Why string
}

func (r *Refusal) Error() string { return ErrRefused.Error() + ": " + r.Why }
func (r *Refusal) Unwrap() error { return ErrRefused }
