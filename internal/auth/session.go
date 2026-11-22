package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"time"
)

// BROWSER SESSIONS — a person signed in from a browser. The session lives in
// the store, found by the hash of a random id; the browser holds the id in a
// cookie its scripts cannot read. A second token, which a page must send
// with every change, is computed from a key in the store and the cookie's
// value, so it is the same in every tab and is never stored: someone who
// reads the store has neither the cookie nor the token.
//
// Decision: docs/decisions/auth.md#browser-sessions

// The hosts a session may be made on. A session belongs to the one it was
// made on and is refused on the other.
const (
	HostApp   = "app"   // mail and drive
	HostAdmin = "admin" // the admin application
)

// A session's limits, by host.
type SessionLimits struct {
	Life time.Duration // from its making, whatever happens
	Idle time.Duration // without a call
}

var (
	appLimits   = SessionLimits{Life: 12 * time.Hour, Idle: 30 * time.Minute}
	adminLimits = SessionLimits{Life: 8 * time.Hour, Idle: 15 * time.Minute}
)

const (
	// MaxSessions is how many a user may hold; the oldest goes for one more.
	MaxSessions = 10
	// seenEvery is how often a session's last call is written: not at every
	// call, so an application that polls does not write at every poll.
	seenEvery = time.Minute
	// maxAgent is how much of a browser's name is kept.
	maxAgent = 120
)

// ErrNoSession is every way a cookie is not a session: unknown, ended, past
// its life, idle too long, made on the other host, or its user disabled.
var ErrNoSession = errors.New("auth: no such session")

// Session is a browser's login, as the store keeps it.
type Session struct {
	IDHash    [32]byte // SHA-256 of the cookie's value; the value itself is never stored
	CSRFKey   [32]byte // random; the second token is HMAC-SHA256(CSRFKey, the cookie's value)
	UserID    int64
	Host      string // HostApp or HostAdmin
	CreatedAt int64  // Unix seconds
	SeenAt    int64
	Client    string // the address at login, for the list a user sees
	Agent     string // the browser's name at login, cut short
}

// SessionStore keeps the sessions.
type SessionStore interface {
	// PutSession inserts s, having removed every session past the limits
	// given and, when the user then holds max, that user's oldest.
	PutSession(ctx context.Context, s Session, max int, expired func(Session) bool) error
	Session(ctx context.Context, idHash [32]byte) (Session, error) // ErrNoSession
	TouchSession(ctx context.Context, idHash [32]byte, seenAt int64) error
	EndSession(ctx context.Context, idHash [32]byte) error // no error when there is none
	// EndUserSessions ends every session of the user but the one named, and
	// answers how many.
	EndUserSessions(ctx context.Context, userID int64, except *[32]byte) (int, error)
	UserSessions(ctx context.Context, userID int64) ([]Session, error) // newest first
}

// Sessions makes, finds and ends browser sessions.
type Sessions struct {
	store SessionStore
	now   func() time.Time
	rand  func([]byte) error
}

// NewSessions returns the sessions over store.
func NewSessions(store SessionStore) *Sessions {
	return &Sessions{store: store, now: time.Now, rand: func(b []byte) error { _, err := rand.Read(b); return err }}
}

func limitsOf(host string) (SessionLimits, bool) {
	switch host {
	case HostApp:
		return appLimits, true
	case HostAdmin:
		return adminLimits, true
	}
	return SessionLimits{}, false
}

// expired reports whether s is past its life or idle too long at now.
func expired(s Session, now time.Time) bool {
	l, ok := limitsOf(s.Host)
	if !ok {
		return true
	}
	t := now.Unix()
	return t >= s.CreatedAt+int64(l.Life/time.Second) || t >= s.SeenAt+int64(l.Idle/time.Second)
}

func hashID(cookie string) [32]byte { return sha256.Sum256([]byte(cookie)) }

// csrfToken is the second token of the session whose cookie is given.
func csrfToken(key [32]byte, cookie string) string {
	m := hmac.New(sha256.New, key[:])
	m.Write([]byte(cookie))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// Opened is a new session: what goes to the browser, once.
type Opened struct {
	Cookie    string // the session id, for the cookie; never in a body or a URL
	CSRF      string // the second token, for the page's memory
	ExpiresAt int64  // when its life ends, Unix seconds
	ShortID   string // its name in the audit log and the user's list
}

// New makes a session for userID on host. A session id that came with the
// login request is ended first, whoever's it was: nothing set before a login
// survives it. The id and the key are new random bytes; the user's oldest
// session goes when this is one too many.
func (ss *Sessions) New(ctx context.Context, userID int64, host, client, agent, presented string) (Opened, error) {
	l, ok := limitsOf(host)
	if !ok {
		return Opened{}, ErrNoSession
	}
	if presented != "" {
		if err := ss.store.EndSession(ctx, hashID(presented)); err != nil {
			return Opened{}, err
		}
	}
	var id, key [32]byte
	if err := ss.rand(id[:]); err != nil {
		return Opened{}, err
	}
	if err := ss.rand(key[:]); err != nil {
		return Opened{}, err
	}
	cookie := base64.RawURLEncoding.EncodeToString(id[:])
	now := ss.now()
	if len(agent) > maxAgent {
		agent = agent[:maxAgent]
	}
	s := Session{IDHash: hashID(cookie), CSRFKey: key, UserID: userID, Host: host, CreatedAt: now.Unix(), SeenAt: now.Unix(), Client: client, Agent: agent}
	if err := ss.store.PutSession(ctx, s, MaxSessions, func(o Session) bool { return expired(o, now) }); err != nil {
		return Opened{}, err
	}
	return Opened{Cookie: cookie, CSRF: csrfToken(key, cookie), ExpiresAt: s.CreatedAt + int64(l.Life/time.Second), ShortID: viewID(s.IDHash)}, nil
}

// Resolve finds the live session a cookie names on host: not ended, not past
// its life, not idle too long, and made on this host. It writes the time of
// this call at most once a minute. Whether the session's user may still act
// is the caller's to check, from the store, at every call.
func (ss *Sessions) Resolve(ctx context.Context, cookie, host string) (Session, error) {
	if cookie == "" {
		return Session{}, ErrNoSession
	}
	s, err := ss.store.Session(ctx, hashID(cookie))
	if err != nil {
		return Session{}, err
	}
	now := ss.now()
	if s.Host != host {
		return Session{}, ErrNoSession
	}
	if expired(s, now) {
		_ = ss.store.EndSession(ctx, s.IDHash)
		return Session{}, ErrNoSession
	}
	if now.Unix()-s.SeenAt >= int64(seenEvery/time.Second) {
		if err := ss.store.TouchSession(ctx, s.IDHash, now.Unix()); err != nil {
			return Session{}, err
		}
		s.SeenAt = now.Unix()
	}
	return s, nil
}

// CSRF reports whether token is the second token of session s, whose cookie
// is given. It takes the same time whatever is wrong.
func (ss *Sessions) CSRF(s Session, cookie, token string) bool {
	want := csrfToken(s.CSRFKey, cookie)
	return token != "" && subtle.ConstantTimeCompare([]byte(want), []byte(token)) == 1
}

// ExpiresAt is when s's life ends, Unix seconds, whatever its idle limit.
func (ss *Sessions) ExpiresAt(s Session) int64 {
	l, _ := limitsOf(s.Host)
	return s.CreatedAt + int64(l.Life/time.Second)
}

// ShortID is a session's name in the audit log and in a user's list: the
// first bytes of its id's hash, never the id.
func ShortID(s Session) string { return viewID(s.IDHash) }

// Token is the second token of a live session again: for a page that was
// reloaded, or a second tab. Nothing is written.
func (ss *Sessions) Token(s Session, cookie string) string { return csrfToken(s.CSRFKey, cookie) }

// End ends the session a cookie names: signing out.
func (ss *Sessions) End(ctx context.Context, cookie string) error {
	if cookie == "" {
		return nil
	}
	return ss.store.EndSession(ctx, hashID(cookie))
}

// EndAll ends every session of a user: the user was disabled or removed, its
// role changed, or its second factor was removed.
func (ss *Sessions) EndAll(ctx context.Context, userID int64) (int, error) {
	return ss.store.EndUserSessions(ctx, userID, nil)
}

// EndOthers ends every session of a user but the one whose cookie is given:
// the passphrase was changed from that one.
func (ss *Sessions) EndOthers(ctx context.Context, userID int64, keepCookie string) (int, error) {
	if keepCookie == "" {
		return ss.store.EndUserSessions(ctx, userID, nil)
	}
	h := hashID(keepCookie)
	return ss.store.EndUserSessions(ctx, userID, &h)
}

// List is a user's live sessions, newest first.
func (ss *Sessions) List(ctx context.Context, userID int64) ([]Session, error) {
	all, err := ss.store.UserSessions(ctx, userID)
	if err != nil {
		return nil, err
	}
	now := ss.now()
	out := all[:0]
	for _, s := range all {
		if !expired(s, now) {
			out = append(out, s)
		}
	}
	return out, nil
}
