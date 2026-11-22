package auth

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
)

// WHAT A PERSON DOES FOR THEMSELVES — change the passphrase, start or drop the
// second factor, make or revoke tokens, list and end their browser sessions.
// From a browser these are session verbs; on the console they are what they
// were. What makes or changes a credential asks for the passphrase again and
// checks it, on both: a script flaw or an unattended tab must not be able to
// mint a year-long token and carry it away, which is what the unreadable
// cookie is there to prevent.
//
// Decision: docs/decisions/auth.md#browser-sessions

// ErrNoSuchSession is auth.session.end naming no session of the caller's.
var ErrNoSuchSession = errors.New("auth: no such session")

// SessionCall is the browser session a call came by.
type SessionCall struct {
	Host   string // HostApp or HostAdmin
	Cookie string // the session's id, as the browser sent it
}

type sessionKey struct{}

// WithSession marks ctx as a call by a browser session.
func WithSession(ctx context.Context, s SessionCall) context.Context {
	return context.WithValue(ctx, sessionKey{}, s)
}

// SessionOf is the browser session a call came by; false for the console and
// for a token.
func SessionOf(ctx context.Context) (SessionCall, bool) {
	s, ok := ctx.Value(sessionKey{}).(SessionCall)
	return s, ok
}

// onAppHost reports a call by a session of the app host: there a person acts
// on their own account only, whatever their role. Managing others is the
// admin host's (docs/decisions/auth.md#browser-sessions).
func onAppHost(ctx context.Context) bool {
	s, ok := SessionOf(ctx)
	return ok && s.Host == HostApp
}

// SetSessions gives the module the browser sessions, which it ends when a
// user is disabled, changes role, has its passphrase reset or changed, or
// loses its second factor.
func (m *Module) SetSessions(ss *Sessions) { m.sessions = ss }

// endSessions ends every browser session of a user. A failure is logged in
// the audit and does not undo the change that called for it: the session's
// next call reads the user again from the store.
func (m *Module) endSessions(ctx context.Context, u User, why string) {
	if m.sessions == nil {
		return
	}
	n, err := m.sessions.EndAll(ctx, u.ID)
	m.noteEnded(ctx, u, n, err, why)
}

func (m *Module) noteEnded(ctx context.Context, u User, n int, err error, why string) {
	switch {
	case err != nil:
		m.audited(ctx, "auth.session.end", "user "+u.Name, "failed after "+why+": "+err.Error())
	case n > 0:
		m.audited(ctx, "auth.session.end", "user "+u.Name, why)
	}
}

// PassAsk carries the caller's passphrase, asked again.
type PassAsk struct {
	Passphrase string `json:"passphrase"`
}

// confirm checks the caller's passphrase, asked again before a credential is
// made or changed. It opens nothing: an admin's key is cleared inside the
// check. From a browser a wrong one counts as a failed browser login, so a
// session cannot be used to guess at the passphrase faster than the login
// allows.
func (m *Module) confirm(ctx context.Context, u User, pass string) error {
	_, browser := SessionOf(ctx)
	if browser && m.browserWaiting(u.Name) {
		return ErrThrottled
	}
	right, err := m.passphraseIsRight(ctx, u, pass)
	if err != nil {
		return err
	}
	if !right {
		if browser {
			m.browserFailed(u.Name)
		}
		m.audited(ctx, "auth.confirm", "user "+u.Name, "failed")
		return ErrBadLogin
	}
	return nil
}

// SessionView is one of a user's browser sessions as auth.session.list shows
// it: never its id or its key.
type SessionView struct {
	ID        string `json:"id"` // the first bytes of the id's hash, in hex: enough to name it
	Host      string `json:"host"`
	CreatedAt int64  `json:"created_at"`
	SeenAt    int64  `json:"seen_at"`
	Client    string `json:"client"`
	Agent     string `json:"agent"`
	Current   bool   `json:"current"` // the session this call came by
}

// SessionAsk names one of the caller's sessions.
type SessionAsk struct {
	ID string `json:"id"`
}

func viewID(h [32]byte) string { return hex.EncodeToString(h[:8]) }

func (m *Module) sessionList(ctx context.Context, _ struct{}) ([]SessionView, error) {
	u, t, err := m.caller(ctx)
	if err != nil {
		return nil, err
	}
	if t != nil {
		return nil, ErrForbidden
	}
	out := []SessionView{}
	if m.sessions == nil {
		return out, nil
	}
	all, err := m.sessions.List(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	var cur [32]byte
	sc, browser := SessionOf(ctx)
	if browser {
		cur = hashID(sc.Cookie)
	}
	for _, s := range all {
		out = append(out, SessionView{ID: viewID(s.IDHash), Host: s.Host, CreatedAt: s.CreatedAt, SeenAt: s.SeenAt,
			Client: s.Client, Agent: s.Agent, Current: browser && s.IDHash == cur})
	}
	return out, nil
}

func (m *Module) sessionEnd(ctx context.Context, p SessionAsk) (struct{}, error) {
	u, t, err := m.caller(ctx)
	if err != nil {
		return struct{}{}, err
	}
	if t != nil {
		return struct{}{}, ErrForbidden
	}
	id := strings.ToLower(strings.TrimSpace(p.ID))
	if m.sessions == nil || len(id) != 16 {
		return struct{}{}, ErrNoSuchSession
	}
	all, err := m.sessions.store.UserSessions(ctx, u.ID)
	if err != nil {
		return struct{}{}, err
	}
	for _, s := range all {
		if viewID(s.IDHash) == id {
			return struct{}{}, m.sessions.store.EndSession(ctx, s.IDHash)
		}
	}
	return struct{}{}, ErrNoSuchSession
}
