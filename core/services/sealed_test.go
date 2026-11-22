package services

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// TestASealedReferenceIsReadExactly: the whole value of a variable, in a
// mapping, with the pinned grammar; anything else that could be read as one
// is refused.
func TestASealedReferenceIsReadExactly(t *testing.T) {
	ok := "services:\n  a:\n    image: x@sha256:" + strings.Repeat("a", 64) + "\n    environment:\n      R: \"${sealed:stack/a/recovery}\"\n"
	st, fs := Parse([]byte(ok), nil)
	if refused(fs) || len(st.Services) != 1 || st.Services[0].Environment[0] != (EnvVar{Key: "R", Sealed: "stack/a/recovery"}) {
		t.Fatalf("a reference: %+v %+v", st.Services, fs)
	}
	for name, value := range map[string]string{
		"a default":         "${sealed:-x}",
		"an error":          "${sealed:?x}",
		"bare":              "$sealed",
		"braced bare":       "${sealed}",
		"in a longer value": "a${sealed:stack/a/recovery}",
		"upper case":        "${sealed:stack/a/Recovery}",
		"a dot":             "${sealed:stack/a/../x}",
	} {
		bad := strings.Replace(ok, "${sealed:stack/a/recovery}", value, 1)
		if _, fs := Parse([]byte(bad), map[string]string{"sealed": "x"}); !refused(fs) {
			t.Errorf("%s (%s): not refused", name, value)
		}
	}
	cmd := "services:\n  a:\n    image: x@sha256:" + strings.Repeat("a", 64) + "\n    command: [\"${sealed:stack/a/recovery}\"]\n"
	if _, fs := Parse([]byte(cmd), nil); !refused(fs) {
		t.Fatal("a reference in a command")
	}
	list := "services:\n  a:\n    image: x@sha256:" + strings.Repeat("a", 64) + "\n    environment: [\"R=${sealed:stack/a/recovery}\"]\n"
	if _, fs := Parse([]byte(list), nil); !refused(fs) {
		t.Fatal("a reference in the list form")
	}
	if _, fs := Parse([]byte(strings.Replace(ok, "${sealed:stack/a/recovery}", "$sealedish", 1)), map[string]string{"sealedish": "v"}); refused(fs) {
		t.Fatal("a variable whose name starts with sealed is refused")
	}
}

// TestOnlyItsOwnersKeysMayBeReferenced: stack/<this stack>/<a key its owner
// made>, shown by name; a stack nobody owns may reference none.
func TestOnlyItsOwnersKeysMayBeReferenced(t *testing.T) {
	m := &Module{}
	st := func(ref string) Stack {
		return Stack{Services: []Spec{{Name: "a", Environment: []EnvVar{{Key: "R", Sealed: ref}}}}}
	}
	if fs := m.sealedFindings("site", st("stack/site/recovery")); len(fs) != 1 || fs[0].ID != "sealed-not-allowed" {
		t.Fatalf("no owner: %+v", fs)
	}
	m.guard = ownedBy{name: "site", sealed: []string{"recovery"}}
	fs := m.sealedFindings("site", st("stack/site/recovery"))
	if len(fs) != 1 || fs[0].ID != "sealed-reference" || fs[0].Severity != Warning || fs[0].Detail != "R ← stack/site/recovery" {
		t.Fatalf("its owner's key: %+v", fs)
	}
	for _, ref := range []string{"stack/other/recovery", "stack/site/apikey", "mail/apikey", "stack/site/", "stack/site/recovery/x", "cloudflare_api_token"} {
		if fs := m.sealedFindings("site", st(ref)); len(fs) != 1 || fs[0].Severity != Refused {
			t.Errorf("%s: %+v", ref, fs)
		}
	}
}

// TestTheApplyReadsTheValueIntoTheGeneratedFile: the value is read from the
// vault at the apply, reaches the container through its 0400 file, and is
// in no unit, review or record; a missing one stops the apply first.
func TestTheApplyReadsTheValueIntoTheGeneratedFile(t *testing.T) {
	f := setup(t)
	f.h.defs["site"]["compose.yaml"] = strings.Replace(site, `environment: {TOKEN: "${TOKEN}"}`, `environment: {TOKEN: "${TOKEN}", R: "${sealed:stack/site/recovery}"}`, 1)
	f.m.SetGuard(ownedBy{name: "site", sealed: []string{"recovery"}})
	vault := map[string]string{}
	f.m.SetSealed(func(_ context.Context, name string) ([]byte, error) {
		v, ok := vault[name]
		if !ok {
			return nil, errors.New("no such sealed value")
		}
		return []byte(v), nil
	})
	r, err := f.m.check(context.Background(), Ref{Name: "site"})
	if err != nil || refused(r.Findings) {
		t.Fatalf("the review: %+v, %v", r.Findings, err)
	}
	if _, err := f.m.add(context.Background(), Accept{Name: "site", Accept: r.SHA256}); !errors.Is(err, ErrSealed) || len(f.s.all) != 0 {
		t.Fatalf("an apply with no value in the vault: %v; rows %d", err, len(f.s.all))
	}
	vault["stack/site/recovery"] = "recovery:s3cret"
	if _, err := f.m.add(context.Background(), Accept{Name: "site", Accept: r.SHA256}); err != nil {
		t.Fatal(err)
	}
	env := f.h.folder["site"][Generated+"/web.env"]
	if !strings.Contains(env, "R=recovery:s3cret\n") || !strings.Contains(env, "TOKEN=t0ken\n") {
		t.Fatalf("the generated file: %q", env)
	}
	for p, u := range f.h.units["site"] {
		if strings.Contains(u, "s3cret") {
			t.Fatalf("the value is in %s", p)
		}
	}
	for _, x := range f.s.all {
		if strings.Contains(strings.Join(toText(x), ""), "s3cret") {
			t.Fatal("the value is on record")
		}
	}
	// a changed value is a changed file: web restarts
	vault["stack/site/recovery"] = "recovery:another"
	f.h.calls("")
	if _, err := f.apply("site"); err != nil {
		t.Fatal(err)
	}
	if got := f.h.calls("restart"); len(got) != 1 || !strings.Contains(got[0], "site-web.service") {
		t.Fatalf("after the value changed, restarted %v", got)
	}
	// without the reference the file holds it no more
	f.h.defs["site"]["compose.yaml"] = site
	if _, err := f.apply("site"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(f.h.folder["site"][Generated+"/web.env"], "recovery:") {
		t.Fatal("the value outlived its reference")
	}
	// a value no line can hold
	f.h.defs["site"]["compose.yaml"] = strings.Replace(site, `environment: {TOKEN: "${TOKEN}"}`, `environment: {R: "${sealed:stack/site/recovery}"}`, 1)
	vault["stack/site/recovery"] = "two\nlines"
	if _, err := f.apply("site"); !errors.Is(err, ErrSealed) {
		t.Fatalf("a value with a line break: %v", err)
	}
}

// toText is a record as text, for a search.
func toText(s Service) []string {
	var out []string
	for _, u := range s.Applied.Units {
		out = append(out, u.Body, u.EnvSHA)
	}
	return out
}
