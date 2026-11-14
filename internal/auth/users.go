package auth

import (
	"context"
	"errors"
	"regexp"
	"time"

	"github.com/yongjohnlee80/autopanel/internal/keyslot"
)

// Role is what a user may do (policy.go).
type Role string

const (
	RoleAdmin    Role = "admin"    // everything; holds a copy of the master key
	RoleOperator Role = "operator" // runs the server: stacks, routes, mail; not users, not the host's administration
	RoleMail     Role = "mail"     // mailboxes and their records, and its own account
	RoleViewer   Role = "viewer"   // reads what is not sensitive, and its own account
)

// Roles are the roles, from the most to the least.
var Roles = []Role{RoleAdmin, RoleOperator, RoleMail, RoleViewer}

// Valid reports whether r is a role.
func (r Role) Valid() bool {
	for _, x := range Roles {
		if r == x {
			return true
		}
	}
	return false
}

// User is a panel user, as the store keeps it.
type User struct {
	ID           int64
	Name         string
	Role         Role
	Root         bool   // the user --init made: never removed, never demoted, never locked on the console
	Verifier     string // an argon2id PHC string; "" for an admin (its login is its passphrase slot)
	MustChange   bool
	DisabledAt   int64
	LockedUntil  int64
	FailCount    int
	LastLoginAt  int64
	TOTP         bool
	TOTPLastStep int64
	CreatedAt    int64
}

// Token is an API token, as the store keeps it: its secret only as a hash.
type Token struct {
	ID         int64
	UserID     int64
	Owner      string
	Name       string
	Hash       []byte
	Role       Role
	CreatedAt  int64
	ExpiresAt  int64
	LastUsedAt int64
	RevokedAt  int64
}

// Store is the users', their factors' and the tokens' part of the store. Each
// change writes its audit entry in the same transaction (R2); the last admin
// is guarded inside it (R3).
type Store interface {
	PassphraseSlot(ctx context.Context, name string) (keyslot.PassphraseSlot, error)
	User(ctx context.Context, name string) (User, error)
	UserByID(ctx context.Context, id int64) (User, error)
	Users(ctx context.Context) ([]User, error)

	// AddUser makes a user: an admin with a passphrase slot, any other role with a verifier.
	AddUser(ctx context.Context, name string, role Role, slot *keyslot.PassphraseSlot, verifier string, mustChange bool) (User, error)
	// SetLogin replaces how a user logs in: its role, and its slot or its
	// verifier (the other is dropped), and must_change.
	SetLogin(ctx context.Context, id int64, role Role, slot *keyslot.PassphraseSlot, verifier string, mustChange bool) error
	SetDisabled(ctx context.Context, id int64, disabled bool) error
	RemoveUser(ctx context.Context, id int64) error

	// RecordFailure counts a failed login and, at lockAfter in a row, locks the
	// user until lockUntil; it answers the count.
	RecordFailure(ctx context.Context, id int64, lockAfter int, lockUntil int64) (int, error)
	RecordLogin(ctx context.Context, id int64) error
	ClearLock(ctx context.Context, id int64) error

	// SetTOTP enrols (or drops) the second factor, replacing the recovery codes.
	SetTOTP(ctx context.Context, id int64, enrolled bool, recovery [][]byte) error
	// SpendStep records step as the last accepted one, and reports whether it
	// was newer than the last (a code is accepted once, N2).
	SpendStep(ctx context.Context, id, step int64) (bool, error)
	// SpendRecovery deletes a recovery code by its hash, and reports whether
	// there was one to delete.
	SpendRecovery(ctx context.Context, id int64, hash []byte) (bool, error)

	AddToken(ctx context.Context, t Token) (int64, error)
	Token(ctx context.Context, id int64) (Token, error)
	Tokens(ctx context.Context, userID int64) ([]Token, error) // 0: every user's
	RevokeToken(ctx context.Context, id int64) error
	TouchToken(ctx context.Context, id, at int64) error
}

// Secrets keeps sealed values under the master key (the store's secret
// table): a user's TOTP seed.
type Secrets interface {
	PutSecret(ctx context.Context, v *keyslot.Vault, name string, value []byte) error
	Secret(ctx context.Context, v *keyslot.Vault, name string) ([]byte, error)
	DeleteSecret(ctx context.Context, name string) error
}

var (
	ErrNoUser      = errors.New("auth: no such user")
	ErrNoToken     = errors.New("auth: no such token")
	ErrUserExists  = errors.New("auth: a user of that name exists")
	ErrLastAdmin   = errors.New("auth: that would leave no admin")
	ErrRootUser    = errors.New("auth: root is never removed or demoted")
	ErrBadName     = errors.New("auth: a user's name is a lower-case letter, then letters, digits, . _ -, 32 at most")
	ErrBadRole     = errors.New("auth: no such role")
	ErrWeak        = errors.New("auth: that passphrase is too easy to guess")
	ErrForbidden   = errors.New("auth: your role may not do that")
	ErrMustChange  = errors.New("auth: change your passphrase first")
	ErrVaultLocked = errors.New("auth: the vault is locked; an admin must log in first")
	ErrBadCode     = errors.New("auth: that code is not right")
	ErrNoTOTP      = errors.New("auth: two-factor is not enrolled")
	ErrTOTPAlready = errors.New("auth: two-factor is enrolled already")
	ErrNotOwn      = errors.New("auth: that is another user's")
	ErrBadTokenAsk = errors.New("auth: a token's role is no higher than its owner's, and it lasts a year at most")
	ErrExpired     = errors.New("auth: the session has expired; log in again")
)

var nameRE = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,31}$`)

// ValidName reports whether a new user's name is one AutoPanel takes.
func ValidName(name string) bool { return nameRE.MatchString(name) }

// The login's limits.
const (
	LockAfter = 10               // failures in a row that lock an account
	LockFor   = 15 * time.Minute // for this long
	// SessionMax is the longest a console login lasts (D6). The 30 minutes
	// idle are the TUI's to count: only it knows a person's keys from its own
	// five-second reads.
	SessionMax = 12 * time.Hour
)
