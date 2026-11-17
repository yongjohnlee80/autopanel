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
	// AddAccount makes an account whose password is given as a hash
	// (argon2id, PHC form): the server never holds the password.
	AddAccount(ctx context.Context, a NewAccount) (string, error)
	// SetPasswordHash replaces an account's password, and nothing else: its
	// app passwords and any second factor stay.
	SetPasswordHash(ctx context.Context, accountID, hash string) error
	// SetQuota sets an account's disk quota, and nothing else.
	SetQuota(ctx context.Context, accountID string, bytes int64) error
	RemoveAccount(ctx context.Context, accountID string) error

	// AppPasswords are an account's app passwords, never their secrets.
	AppPasswords(ctx context.Context, accountID string) ([]AppPassword, error)
	// AddAppPassword makes an app password for a device, signing in until
	// expires, and answers its secret: the server generates it, and gives it
	// this once. The account may hold at least room app passwords.
	AddAppPassword(ctx context.Context, accountID, device string, expires time.Time, room int) (AppPassword, string, error)
	// KeepAppPassword clears an app password's expiry. A server may bring an
	// expired one back this way: the caller never keeps one that expired.
	KeepAppPassword(ctx context.Context, accountID, id string) error
	RevokeAppPassword(ctx context.Context, accountID, id string) error

	// DKIMKeys are every DKIM key the server holds.
	DKIMKeys(ctx context.Context) ([]DKIMKey, error)
	// AddDKIMKey gives the server a private key (PEM, PKCS #8) for a
	// domain's selector, pending: it signs nothing until made active.
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
	// Compose is the mail stack's definition, its image pinned by digest:
	// each of mail's ports published on its loopback port, and the
	// management API on manage.
	Compose(ports []PortMap, manage int) []byte
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

// Record is a DNS record.
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
	Quota    int64 // bytes; 0 for none
	Used     int64
	Aliases  []Alias // the enabled ones
	Admin    bool    // the server's administrator, AutoPanel's way in: not a mailbox
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
	PasswordHash string // argon2id, PHC form
	Quota        int64  // bytes
	AppPasswords int    // room for at least this many app passwords
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
