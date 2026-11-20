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
			Protected: {"a grant", "an admin", "an admin owner"},
			Internal:  {"the owner", "a shared member", "another member", "an admin", "an admin owner"},
			Private:   {"the owner", "a shared member", "an admin", "an admin owner"},
		},
		ActList: {
			Public:    {"anonymous", "a grant", "a stale grant", "the owner", "a shared member", "another member", "an admin", "an admin owner"},
			Protected: {"the owner", "an admin", "an admin owner"},
			Internal:  {"the owner", "a shared member", "another member", "an admin", "an admin owner"},
			Private:   {"the owner", "a shared member", "an admin", "an admin owner"},
		},
		ActExists: {
			Public:    {"anonymous", "a grant", "a stale grant", "the owner", "a shared member", "another member", "an admin", "an admin owner"},
			Protected: {"the owner", "an admin", "an admin owner"},
			Internal:  {"the owner", "a shared member", "another member", "an admin", "an admin owner"},
			Private:   {"the owner", "a shared member", "an admin", "an admin owner"},
		},
		ActSource:   {Public: {"the owner", "an admin", "an admin owner"}, Protected: {"the owner", "an admin", "an admin owner"}, Internal: {"the owner", "an admin", "an admin owner"}, Private: {"the owner", "an admin", "an admin owner"}},
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
	// An administrator answers for what the site holds, so reads everything
	// (Johno, 2026-11-21: "for legal purposes"), changes nothing of another's,
	// and each read only the role allows is one the audit log records.
	for _, level := range []string{Public, Protected, Internal, Private} {
		if !MayRead(readers["an admin"], doc(level)) || May(readers["an admin"], ActChange, doc(level)) {
			t.Errorf("an administrator and a %s document", level)
		}
	}
	for level, want := range map[string]bool{Public: false, Protected: true, Internal: false, Private: true} {
		if got := ByAdminOnly(readers["an admin"], ActRead, doc(level)); got != want {
			t.Errorf("reading a %s document by the role alone: %v", level, got)
		}
		// An owner's read of their own source is never the role's (their page,
		// when protected, needs a grant like anyone's).
		if ByAdminOnly(readers["an admin owner"], ActSource, doc(level)) || ByAdminOnly(readers["the owner"], ActSource, doc(level)) {
			t.Errorf("an owner's read of their %s document's source is not the role's", level)
		}
	}
	if got := ByAdminOnly(readers["an admin"], ActSource, doc(Public)); !got {
		t.Error("an administrator's read of another's source is the role's")
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
