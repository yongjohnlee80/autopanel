package site

import "slices"

// WHO MAY DO WHAT — one table, read by every verb and by the serving of every
// held file. A person is known only by a session the core has just found
// valid for an enabled user; a passphrase is known only by a grant the core
// issued. An administrator has no branch for reading: a private document is
// its owner's and its share list's, as its level says.

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

// MayRead reports whether who may read doc's page and resources.
func MayRead(who Reader, doc Doc) bool { return May(who, ActRead, doc) }

// May reports whether who may do act to doc. Anything it does not know is
// refused.
func May(who Reader, act string, doc Doc) bool {
	u := who.User
	owner := u != nil && u.ID == doc.Owner
	admin := u != nil && u.Admin
	shared := u != nil && doc.Visibility == Private && slices.Contains(doc.Share, u.ID)
	switch act {
	case ActRead:
		switch doc.Visibility {
		case Public:
			return true
		case Protected:
			return who.Granted != nil && who.Granted(doc)
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
