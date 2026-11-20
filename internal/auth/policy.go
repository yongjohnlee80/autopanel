package auth

import "github.com/yongjohnlee80/autopanel/internal/module"

// WHO MAY CALL WHAT — each role is a table of areas, each area a level of
// access, and a verb is allowed by its contract alone: its area, whether it
// mutates, and whether its answer is sensitive. No verb has a code path of
// its own here.
//
// Decision: docs/decisions/auth.md#roles

type access uint8

const (
	none    access = iota
	read           // verbs that neither mutate nor are Sensitive
	readAny        // every verb that does not mutate, Sensitive ones too
	all            // every verb
	own            // the caller's own account (auth.* own verbs, checked again by each verb)
)

var policy = map[Role]map[string]access{
	RoleAdmin:    {"sys": all, "sys.admin": all, "gate": all, "certs": all, "services": all, "mail": all, "mail.admin": all, "auth": all, "site": all, "site.admin": all},
	RoleOperator: {"sys": all, "sys.admin": none, "gate": all, "certs": read, "services": all, "mail": all, "mail.admin": all, "auth": own, "site": all, "site.admin": none},
	RoleMail:     {"sys": read, "sys.admin": none, "gate": read, "certs": none, "services": none, "mail": all, "mail.admin": none, "auth": own, "site": none, "site.admin": none},
	RoleViewer:   {"sys": read, "sys.admin": none, "gate": read, "certs": read, "services": read, "mail": read, "mail.admin": none, "auth": own, "site": none, "site.admin": none},
}

// ownVerbs are the auth verbs every role may call on its own account.
var ownVerbs = map[string]bool{
	"auth.whoami": true, "auth.passphrase.change": true,
	"auth.totp.begin": true, "auth.totp.confirm": true, "auth.totp.disable": true,
	"auth.token.list": true, "auth.token.create": true, "auth.token.revoke": true,
}

// everyone are the verbs any logged-in role may call: its own preferences.
var everyone = map[string]bool{"sys.prefs.get": true, "sys.prefs.set": true}

// Allows reports whether role may call the verb c describes. An unknown area
// or role allows nothing.
func Allows(role Role, c module.Contract) bool {
	if everyone[c.Verb] {
		return true
	}
	switch policy[role][c.AreaOf()] {
	case all:
		return true
	case readAny:
		return !c.Mutates
	case read:
		return !c.Mutates && c.Discloses == module.Plain
	case own:
		return ownVerbs[c.Verb]
	}
	return false
}

// rank orders the roles for a token's cap: a token's role is one its owner's
// role could hold.
func (r Role) holds(t Role) bool {
	switch r {
	case RoleAdmin:
		return true
	case RoleOperator:
		return t != RoleAdmin
	default:
		return t == r || t == RoleViewer
	}
}

// Effective is a token's role at use: its own, while its owner's current role
// could still make it; else its owner's, so a demoted owner's tokens fall with
// it.
func Effective(owner, token Role) Role {
	if owner.holds(token) {
		return token
	}
	return owner
}
