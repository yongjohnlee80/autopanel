package site

import "testing"

// TestWhoMayDoWhat: every principal against every action and level, as the
// decision's table has it. The table below is written out, not computed, so
// a change to the rule is a change someone reads here.
func TestWhoMayDoWhat(t *testing.T) {
	const ownerID, sharedID, otherID, adminID = 7, 8, 9, 1
	doc := func(level string) Doc {
		d := Doc{ID: 3, Site: 1, Slug: "x", Format: Markdown, Owner: ownerID, Visibility: level}
		if level == Private {
			d.Share = []int64{sharedID}
		}
		return d
	}
	readers := map[string]Reader{
		"anonymous":       {},
		"a grant":         {Granted: func(Doc) bool { return true }},
		"a stale grant":   {Granted: func(Doc) bool { return false }},
		"the owner":       {User: &User{ID: ownerID}},
		"a shared member": {User: &User{ID: sharedID}},
		"another member":  {User: &User{ID: otherID}},
		"an admin":        {User: &User{ID: adminID, Admin: true}},
		"an admin owner":  {User: &User{ID: ownerID, Admin: true}},
	}
	// who may, by action and level; everyone not named may not.
	want := map[string]map[string][]string{
		ActRead: {
			Public:    {"anonymous", "a grant", "a stale grant", "the owner", "a shared member", "another member", "an admin", "an admin owner"},
			Protected: {"a grant"},
			Internal:  {"the owner", "a shared member", "another member", "an admin", "an admin owner"},
			Private:   {"the owner", "a shared member", "an admin owner"},
		},
		ActList: {
			Public:    {"anonymous", "a grant", "a stale grant", "the owner", "a shared member", "another member", "an admin", "an admin owner"},
			Protected: {"the owner", "an admin owner"},
			Internal:  {"the owner", "a shared member", "another member", "an admin", "an admin owner"},
			Private:   {"the owner", "a shared member", "an admin owner"},
		},
		ActExists: {
			Public:    {"anonymous", "a grant", "a stale grant", "the owner", "a shared member", "another member", "an admin", "an admin owner"},
			Protected: {"the owner", "an admin", "an admin owner"},
			Internal:  {"the owner", "a shared member", "another member", "an admin", "an admin owner"},
			Private:   {"the owner", "a shared member", "an admin", "an admin owner"},
		},
		ActSource:   {Public: {"the owner", "an admin owner"}, Protected: {"the owner", "an admin owner"}, Internal: {"the owner", "an admin owner"}, Private: {"the owner", "an admin owner"}},
		ActChange:   {Public: {"the owner", "an admin owner"}, Protected: {"the owner", "an admin owner"}, Internal: {"the owner", "an admin owner"}, Private: {"the owner", "an admin owner"}},
		ActProtect:  {Protected: {"the owner", "an admin", "an admin owner"}},
		ActRemove:   {Public: {"the owner", "an admin", "an admin owner"}, Protected: {"the owner", "an admin", "an admin owner"}, Internal: {"the owner", "an admin", "an admin owner"}, Private: {"the owner", "an admin", "an admin owner"}},
		ActTransfer: {},
		"unknown":   {},
	}
	for act, byLevel := range want {
		for _, level := range []string{Public, Protected, Internal, Private} {
			allowed := map[string]bool{}
			for _, name := range byLevel[level] {
				allowed[name] = true
			}
			for name, who := range readers {
				if got := May(who, act, doc(level)); got != allowed[name] {
					t.Errorf("%s may %s a %s document: %v; want %v", name, act, level, got, allowed[name])
				}
			}
		}
	}
	// The two things the table must never give: an admin who is not the owner
	// reads no private document, and nobody transfers one.
	if MayRead(readers["an admin"], doc(Private)) {
		t.Error("an administrator read a private document that is not theirs")
	}
	// A grant does not open a document that is no longer protected.
	for _, level := range []string{Internal, Private} {
		if MayRead(readers["a grant"], doc(level)) {
			t.Errorf("a grant opened a %s document", level)
		}
	}
	// A document with no valid level is nobody's to read.
	if MayRead(readers["the owner"], doc("")) || MayRead(Reader{}, doc("everyone")) {
		t.Error("a document with an unknown level was read")
	}
}
