// Package tunnel is the tunnel agents AutoPanel knows: machines with no open
// port that dial the gate and hold a tunnel open. This package is who they
// are, and how one becomes known; the tunnel itself is internal/tunnel, and
// the gate holds it.
//
// An agent is a key pair made on its own machine. The administrator adds an
// agent by name and is given a token, once; the agent sends the token with
// its public key, and from then on is known by that key alone. Which services
// an agent reaches is its own file's to say, never anything kept here.
//
// Decision: docs/decisions/forwards.md#tunnels
package tunnel

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/yongjohnlee80/autopanel/internal/module"
)

// The limits.
const (
	MaxAgents = 16
	// TokenLife is how long an enrolment token is good for.
	TokenLife = 10 * time.Minute
	// tokenPrefix starts every enrolment token, so one found in a log or a
	// paste is known for what it is.
	tokenPrefix = "ape_"
)

// Agent is one agent as stored.
type Agent struct {
	ID           int64
	Name         string
	Key          string // the SHA-256 of its public key, in hex; "" until it enrols
	EnrolledFrom string
	EnrolledAt   int64
	TokenID      string // while it has not enrolled
	TokenHash    string
	TokenExpires int64
	CreatedAt    int64
}

var (
	ErrNotFound  = errors.New("tunnel: no such agent")
	ErrDuplicate = errors.New("tunnel: an agent has that name")
	ErrBadName   = errors.New("tunnel: not a name")
	ErrTooMany   = errors.New("tunnel: no room for another agent")
	// ErrBadToken is every way an enrolment can fail: the caller is a
	// stranger until it succeeds, and learns nothing of why.
	ErrBadToken = errors.New("tunnel: the enrolment was refused")
	ErrBadKey   = errors.New("tunnel: not a public key's digest")
)

// Store keeps the agents. Each change writes its audit entry in the same
// transaction.
type Store interface {
	All(ctx context.Context) ([]Agent, error)
	Add(ctx context.Context, a Agent) (Agent, error)
	// Enrol gives the agent waiting with that token its key, once: the token
	// is spent in the same statement. No such token, a wrong hash, a token
	// past now, or a key another agent holds is ErrBadToken.
	Enrol(ctx context.Context, tokenID, tokenHash, key, from string, now int64) (Agent, error)
	Remove(ctx context.Context, id int64) (Agent, error)
}

// Status is what the gate says of an agent's tunnel.
type Status struct {
	Connected bool     `json:"connected"`
	Since     int64    `json:"since,omitempty"`   // Unix seconds
	From      string   `json:"from,omitempty"`    // the address it dialled from
	Streams   int      `json:"streams"`           // open now
	Targets   []string `json:"targets,omitempty"` // the names its file lists; never their addresses
}

// Module is gate.tunnel.agent.*.
type Module struct {
	store  Store
	now    func() time.Time
	reload func(ctx context.Context) error // the gate is told
	status func() map[string]Status        // by agent name; nil: nothing known
	mu     sync.Mutex                      // one change at a time
}

// NewModule returns the agents' verbs. reload sends the gate the keys; status
// is what the gate last reported.
func NewModule(store Store, reload func(ctx context.Context) error, status func() map[string]Status) *Module {
	return &Module{store: store, now: time.Now, reload: reload, status: status}
}

// SetReload names how the gate is told. Set once, before the verbs are served.
func (m *Module) SetReload(reload func(ctx context.Context) error) { m.reload = reload }

func (m *Module) Name() string { return "tunnel" }

func (m *Module) Errors() []module.PublicError {
	return []module.PublicError{
		{Err: ErrNotFound, Code: -32270, Name: "gate.tunnel.not_found", Message: "no such agent"},
		{Err: ErrDuplicate, Code: -32271, Name: "gate.tunnel.duplicate", Message: "an agent has that name"},
		{Err: ErrBadName, Code: -32272, Name: "gate.tunnel.bad_name", Message: "a name is 1 to 32 lower-case letters, digits and hyphens, starting with a letter"},
		{Err: ErrTooMany, Code: -32273, Name: "gate.tunnel.too_many", Message: "no room for another agent"},
		{Err: ErrBadToken, Code: -32274, Name: "gate.tunnel.bad_token", Message: "the enrolment was refused"},
		{Err: ErrBadKey, Code: -32275, Name: "gate.tunnel.bad_key", Message: "not a public key's digest"},
	}
}

// View is an agent as the panel sees it. A token is never in it.
type View struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	// State is "waiting" (it has a token and has not enrolled), "expired"
	// (its token ran out: remove it and add it again) or "enrolled".
	State        string `json:"state"`
	Fingerprint  string `json:"fingerprint,omitempty"` // of its key, as the agent prints it
	EnrolledFrom string `json:"enrolled_from,omitempty"`
	EnrolledAt   int64  `json:"enrolled_at,omitempty"`
	TokenExpires int64  `json:"token_expires,omitempty"`
	Status
}

// Fingerprint is a key's digest as people compare it: the form the agent
// prints when it enrols.
func Fingerprint(keyHex string) string {
	raw, err := hex.DecodeString(keyHex)
	if err != nil || len(raw) != sha256.Size {
		return ""
	}
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(raw)
}

func (m *Module) view(a Agent, st map[string]Status) View {
	v := View{ID: a.ID, Name: a.Name, EnrolledFrom: a.EnrolledFrom, EnrolledAt: a.EnrolledAt}
	switch {
	case a.Key != "":
		v.State, v.Fingerprint, v.Status = "enrolled", Fingerprint(a.Key), st[a.Name]
	case a.TokenExpires > m.now().Unix():
		v.State, v.TokenExpires = "waiting", a.TokenExpires
	default:
		v.State = "expired"
	}
	return v
}

// Name is gate.tunnel.agent.add's param.
type Name struct {
	Name string `json:"name"`
}

// Added is gate.tunnel.agent.add's answer: the agent, and its token, shown
// this once.
type Added struct {
	Agent   View   `json:"agent"`
	Token   string `json:"token"`
	Expires int64  `json:"expires"`
}

// Ref names an agent.
type Ref struct {
	ID int64 `json:"id"`
}

func (m *Module) Verbs() []module.Verb {
	return []module.Verb{
		module.Handle(module.Contract{Verb: "gate.tunnel.agent.list", Area: "gate", Discloses: module.Plain, Since: 10,
			Result: "[{id, name, state, fingerprint?, enrolled_from?, enrolled_at?, token_expires?, connected, since?, from?, streams, targets?}]",
			Doc:    "Every tunnel agent, by name: whether it has enrolled, its key's fingerprint and the address it enrolled from, and its tunnel as the gate last reported it."}, m.list),
		module.Handle(module.Contract{Verb: "gate.tunnel.agent.add", Area: "gate", Mutates: true, Privileged: true, Since: 10,
			Param: "{name}", Result: "{agent, token, expires}",
			Doc: "Adds an agent and answers its enrolment token, once: good for ten minutes and for one use. Whoever uses it first becomes the agent, so compare the fingerprint the agent prints with the one listed before routing anything to it."}, m.add),
		module.Handle(module.Contract{Verb: "gate.tunnel.agent.remove", Area: "gate", Mutates: true, Privileged: true, Since: 10, Param: "{id}", Result: "the agent",
			Doc: "Removes an agent: its key is forgotten, its tunnel is closed at once and none is accepted from it again."}, m.remove),
	}
}

func validName(n string) bool {
	if len(n) < 1 || len(n) > 32 || n[0] < 'a' || n[0] > 'z' {
		return false
	}
	for _, c := range n {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

func (m *Module) list(ctx context.Context, _ struct{}) ([]View, error) {
	all, err := m.store.All(ctx)
	if err != nil {
		return nil, err
	}
	var st map[string]Status
	if m.status != nil {
		st = m.status()
	}
	out := make([]View, 0, len(all))
	for _, a := range all {
		out = append(out, m.view(a, st))
	}
	return out, nil
}

func random(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

func hashOf(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

func (m *Module) add(ctx context.Context, p Name) (Added, error) {
	if !validName(p.Name) {
		return Added{}, ErrBadName
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	all, err := m.store.All(ctx)
	if err != nil {
		return Added{}, err
	}
	if len(all) >= MaxAgents {
		return Added{}, ErrTooMany
	}
	id, err := random(8)
	if err != nil {
		return Added{}, err
	}
	secret, err := random(32)
	if err != nil {
		return Added{}, err
	}
	tid, sec := hex.EncodeToString(id), base64.RawURLEncoding.EncodeToString(secret)
	now := m.now()
	a, err := m.store.Add(ctx, Agent{Name: p.Name, TokenID: tid, TokenHash: hashOf(sec), TokenExpires: now.Add(TokenLife).Unix(), CreatedAt: now.Unix()})
	if err != nil {
		return Added{}, err
	}
	// Nothing reaches the gate yet: an agent with no key has no tunnel.
	return Added{Agent: m.view(a, nil), Token: tokenPrefix + tid + "_" + sec, Expires: a.TokenExpires}, nil
}

func (m *Module) remove(ctx context.Context, ref Ref) (View, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, err := m.store.Remove(ctx, ref.ID)
	if err != nil {
		return View{}, err
	}
	return m.view(a, nil), m.reload(ctx) // after the commit only: the gate drops its tunnel
}

// parseToken splits an enrolment token into its id and its secret.
func parseToken(s string) (id, secret string, ok bool) {
	rest, found := strings.CutPrefix(s, tokenPrefix)
	if !found || len(s) > 128 {
		return "", "", false
	}
	id, secret, found = strings.Cut(rest, "_")
	if !found || len(id) != 16 || len(secret) != 43 {
		return "", "", false
	}
	return id, secret, true
}

// validKey reports whether k is a SHA-256 in lower-case hex.
func validKey(k string) bool {
	if len(k) != 2*sha256.Size {
		return false
	}
	for _, c := range k {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// Enrol makes the agent waiting with token the holder of key: the SHA-256 of
// the public key the caller proved it holds, in hex. from is the address it
// came from, kept for the administrator to compare. It answers the agent's
// name. Every failure is ErrBadToken.
//
// The gate calls it, for a stranger: the gate limits how often by address,
// and nothing is written for a failure, so a stranger can fill no log.
func (m *Module) Enrol(ctx context.Context, token, key, from string) (string, error) {
	id, secret, ok := parseToken(token)
	if !ok || !validKey(key) {
		return "", ErrBadToken
	}
	if len(from) > 64 {
		from = from[:64]
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	a, err := m.store.Enrol(ctx, id, hashOf(secret), key, from, m.now().Unix())
	if err != nil {
		if errors.Is(err, ErrBadToken) {
			return "", ErrBadToken
		}
		return "", err
	}
	return a.Name, m.reload(ctx)
}

// Key is an enrolled agent as the gate needs it: its name and its key.
type Key struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

// Keys is every enrolled agent's key, by name: what the gate admits a tunnel
// by. They are not secrets.
func (m *Module) Keys(ctx context.Context) ([]Key, error) {
	all, err := m.store.All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Key, 0, len(all))
	for _, a := range all {
		if a.Key != "" {
			out = append(out, Key{Name: a.Name, Key: a.Key})
		}
	}
	return out, nil
}

// Enrolled reports whether an enrolled agent has that name: what a route or a
// forward that names one is checked against.
func (m *Module) Enrolled(ctx context.Context, name string) (bool, error) {
	keys, err := m.Keys(ctx)
	if err != nil {
		return false, err
	}
	for _, k := range keys {
		if k.Name == name {
			return true, nil
		}
	}
	return false, nil
}
