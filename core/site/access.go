package site

import "slices"

// WHO MAY DO WHAT — one table, read by every verb and by the serving of every
// held file. A person is known only by a session the core has just found
// valid for an enabled user; a passphrase is known only by a grant the core
// issued. An administrator may read, list and see the source of every
// document, so that content can be scrutinized (Johno, 2026-11-21); each such
// read that only the role allows is audited (ByAdminOnly). Changing a
// document stays its owner's.

// Reader is whoever asks.
type Reader struct {
	// User is the enabled user of a current session or token, or nil. The
	// caller has validated it against the store for this call.
	User *User
	// Granted reports whether the reader holds a grant that covers doc as it
	// is now (its site, its ID or its collection, the protection's
	// generation, not expired). nil: no grant.
	Granted func(doc Doc) bool
}

// User is what the table needs of a user.
type User struct {
	ID    int64
	Admin bool // the admin role
}

// What may be asked of a document.
const (
	ActRead     = "read"     // the built page and its resources
	ActSource   = "source"   // what was published: the Markdown, the files as sent
	ActList     = "list"     // to be named in a list the reader asks for
	ActChange   = "change"   // content, level, share list, collection
	ActProtect  = "protect"  // set or clear a protected document's passphrase
	ActRemove   = "remove"   //
	ActExists   = "exists"   // to learn its slug, owner, level and size
	ActTransfer = "transfer" // give it another owner
)

// ByAdminOnly reports whether who may do act to doc only because they are
// an administrator: the reads the audit log records.
func ByAdminOnly(who Reader, act string, doc Doc) bool {
	if who.User == nil || !who.User.Admin || !May(who, act, doc) {
		return false
	}
	plain := *who.User
	plain.Admin = false
	who.User = &plain
	return !May(who, act, doc)
}

// MayRead reports whether who may read doc's page and resources.
func MayRead(who Reader, doc Doc) bool { return May(who, ActRead, doc) }

// May reports whether who may do act to doc. Anything it does not know is
// refused.
func May(who Reader, act string, doc Doc) bool {
	u := who.User
	if u != nil && u.Admin && ValidLevel(doc.Visibility) {
		switch act {
		case ActRead, ActList, ActExists, ActSource:
			return true
		}
	}
	owner := u != nil && u.ID == doc.Owner
	admin := u != nil && u.Admin
	shared := u != nil && doc.Visibility == Private && slices.Contains(doc.Share, u.ID)
	switch act {
	case ActRead:
		switch doc.Visibility {
		case Public:
			return true
		case Protected:
			// Its owner set the passphrase: they need none to reach their own
			// node (and what they keep under it) through the verbs.
			return owner || (who.Granted != nil && who.Granted(doc))
		case Internal:
			return u != nil
		case Private:
			return owner || shared
		}
	case ActList:
		switch doc.Visibility {
		case Public:
			return true
		case Protected: // unlisted: only its owner sees it in a list
			return owner
		case Internal:
			return u != nil
		case Private:
			return owner || shared
		}
	case ActExists:
		switch doc.Visibility {
		case Public:
			return true
		case Protected:
			return owner || admin
		case Internal:
			return u != nil
		case Private:
			return owner || shared || admin
		}
	case ActSource, ActChange:
		return owner
	case ActProtect:
		return doc.Visibility == Protected && (owner || admin)
	case ActRemove:
		return owner || admin
	case ActTransfer:
		return false // nobody: a transfer to oneself would be a way to read
	}
	return false
}

// MayAt reports whether who may do act to the last node of chain (the node
// and every folder above it, the root first): act on the node, and read every
// folder above it. A node is no more open than the most closed folder it is
// in; a passphrase's grant for a folder opens what it holds that is public.
func MayAt(who Reader, act string, chain []Doc) bool {
	if len(chain) == 0 {
		return false
	}
	for _, f := range chain[:len(chain)-1] {
		if !f.IsRoot() && !May(who, ActRead, f) {
			return false
		}
	}
	return May(who, act, chain[len(chain)-1])
}

// ByAdminOnlyAt is ByAdminOnly over a chain: the role alone allowed it.
func ByAdminOnlyAt(who Reader, act string, chain []Doc) bool {
	if who.User == nil || !who.User.Admin || !MayAt(who, act, chain) {
		return false
	}
	plain := *who.User
	plain.Admin = false
	who.User = &plain
	return !MayAt(who, act, chain)
}

// MayPutIn reports whether who may put a folder or a document into the
// folder at the end of chain: the root is any publisher's; another folder
// is its owner's and an administrator's.
func MayPutIn(who Reader, chain []Doc) bool {
	if len(chain) == 0 || who.User == nil {
		return false
	}
	f := chain[len(chain)-1]
	if !f.IsFolder() {
		return false
	}
	if f.IsRoot() {
		return true
	}
	return (who.User.ID == f.Owner || who.User.Admin) && MayAt(who, ActRead, chain)
}

// PublicAt reports whether the last node of chain is public in effect: it
// and every folder above it.
func PublicAt(chain []Doc) bool {
	for _, d := range chain {
		if d.Visibility != Public {
			return false
		}
	}
	return len(chain) > 0
}
