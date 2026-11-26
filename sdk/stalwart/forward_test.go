package stalwart

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/yongjohnlee80/autopanel/core/mail/provider"
)

// TestTheForwardScriptIsReadBackAsItWasWritten: every list of one to five
// addresses, with a copy kept or not, is read back as it was written; a
// script with one byte changed is not AutoPanel's.
func TestTheForwardScriptIsReadBackAsItWasWritten(t *testing.T) {
	all := []string{"a@example.org", "b.c+d@mail.example.com", "E=f@example.net", "g-h@x.example.org", "i@example.co.uk"}
	for n := 1; n <= len(all); n++ {
		for _, keep := range []bool{true, false} {
			f := provider.Forward{To: all[:n], Keep: keep}
			script := generateForward(f)
			got, ok := parseForward(script)
			if !ok || !slices.Equal(got.To, f.To) || got.Keep != keep {
				t.Fatalf("%d addresses, keep %v: read back %+v, %v\n%s", n, keep, got, ok, script)
			}
			if strings.Count(script, "redirect :copy") != n || strings.Contains(script, "discard;") == keep {
				t.Fatalf("the script:\n%s", script)
			}
			for i := range script {
				changed := script[:i] + string(script[i]^1) + script[i+1:]
				// A changed byte either makes it no script of AutoPanel's, or
				// (inside an address) another plain address: never a quote,
				// a backslash or a space that could end the string.
				if g, ok := parseForward(changed); ok {
					if generateForward(g) != changed || len(g.To) != n {
						t.Fatalf("a script changed at byte %d was read as AutoPanel's:\n%s", i, changed)
					}
					for _, to := range g.To {
						if strings.ContainsAny(to, "\"\\ \n") {
							t.Fatalf("a script changed at byte %d holds the address %q", i, to)
						}
					}
				}
			}
		}
	}
	for what, script := range map[string]string{
		"nothing":                   "",
		"another script":            "require [\"fileinto\"];\nfileinto \"Junk\";\n",
		"the marker alone":          forwardMarker,
		"no address":                forwardMarker + forwardRequire + forwardIf + forwardEnd,
		"a command after the end":   generateForward(provider.Forward{To: all[:1], Keep: true}) + "redirect \"x@evil.example\";\n",
		"a command inside":          forwardMarker + forwardRequire + forwardIf + forwardLine + all[0] + forwardLineEnd + "    redirect \"x@evil.example\";\n" + forwardEnd,
		"no last newline":           strings.TrimSuffix(generateForward(provider.Forward{To: all[:1], Keep: true}), "\n"),
		"discard before a redirect": forwardMarker + forwardRequire + forwardIf + forwardDiscard + forwardLine + all[0] + forwardLineEnd + forwardEnd,
	} {
		if f, ok := parseForward(script); ok {
			t.Errorf("%s was read as AutoPanel's: %+v", what, f)
		}
	}
}

// sieveStalwart is Stalwart's JMAP for Sieve, for one account: its scripts,
// their blobs, and the interpreter's limits.
type sieveStalwart struct {
	t       *testing.T
	scripts map[string]*sieveScript
	blobs   map[string]string
	seq     int
	limits  map[string]any // x:SieveUserInterpreter's singleton; nil: none answered
	failGet bool           // the limits cannot be read
}

func newSieveStalwart(t *testing.T) *sieveStalwart {
	return &sieveStalwart{t: t, scripts: map[string]*sieveScript{}, blobs: map[string]string{}}
}

func (f *sieveStalwart) add(name, text string, active bool) {
	f.seq++
	id, blob := fmt.Sprintf("s%d", f.seq), fmt.Sprintf("b%d", f.seq)
	f.blobs[blob] = text
	f.scripts[id] = &sieveScript{ID: id, Name: name, BlobID: blob, IsActive: active}
}

func (f *sieveStalwart) active() (name, text string) {
	for _, s := range f.scripts {
		if s.IsActive {
			return s.Name, f.blobs[s.BlobID]
		}
	}
	return "", ""
}

func (f *sieveStalwart) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/jmap/upload/acc/":
		raw, _ := io.ReadAll(r.Body)
		f.seq++
		blob := fmt.Sprintf("b%d", f.seq)
		f.blobs[blob] = string(raw)
		_ = json.NewEncoder(w).Encode(map[string]any{"blobId": blob})
		return
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/jmap/download/acc/"):
		blob := strings.Split(strings.TrimPrefix(r.URL.Path, "/jmap/download/acc/"), "/")[0]
		text, ok := f.blobs[blob]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, text)
		return
	case r.Method != http.MethodPost || r.URL.Path != "/jmap/":
		http.NotFound(w, r)
		return
	}
	var req struct {
		MethodCalls [][]json.RawMessage `json:"methodCalls"`
	}
	raw, _ := io.ReadAll(r.Body)
	if err := json.Unmarshal(raw, &req); err != nil || len(req.MethodCalls) != 1 {
		f.t.Fatalf("a request that is no single method call: %s", raw)
	}
	var method string
	var args map[string]any
	_ = json.Unmarshal(req.MethodCalls[0][0], &method)
	_ = json.Unmarshal(req.MethodCalls[0][1], &args)
	answer := func(name string, out any) {
		_ = json.NewEncoder(w).Encode(map[string]any{"methodResponses": []any{[]any{name, out, "c"}}})
	}
	switch method {
	case "x:SieveUserInterpreter/get":
		if f.failGet {
			answer("error", map[string]any{"type": "serverFail", "description": "no"})
			return
		}
		list := []any{}
		if f.limits != nil {
			list = append(list, f.limits)
		}
		answer(method, map[string]any{"list": list})
	case "SieveScript/get":
		if args["accountId"] != "acc" {
			f.t.Fatalf("SieveScript/get for %v", args["accountId"])
		}
		list := []*sieveScript{}
		for _, s := range f.scripts {
			list = append(list, s)
		}
		answer(method, map[string]any{"list": list})
	case "SieveScript/set":
		out := map[string]any{}
		if create, ok := args["create"].(map[string]any); ok {
			for key, v := range create {
				c := v.(map[string]any)
				f.seq++
				id := fmt.Sprintf("s%d", f.seq)
				f.scripts[id] = &sieveScript{ID: id, Name: c["name"].(string), BlobID: c["blobId"].(string)}
				out["created"] = map[string]any{key: map[string]any{"id": id}}
				if args["onSuccessActivateScript"] == "#"+key {
					args["onSuccessActivateScript"] = id
				}
			}
		}
		if update, ok := args["update"].(map[string]any); ok {
			for id, v := range update {
				s, ok := f.scripts[id]
				if !ok {
					out["notUpdated"] = map[string]any{id: map[string]any{"type": "notFound"}}
					continue
				}
				s.BlobID = v.(map[string]any)["blobId"].(string)
				out["updated"] = map[string]any{id: nil}
			}
		}
		if destroy, ok := args["destroy"].([]any); ok {
			for _, v := range destroy {
				id := v.(string)
				if s, ok := f.scripts[id]; ok && s.IsActive {
					out["notDestroyed"] = map[string]any{id: map[string]any{"type": "scriptIsActive"}}
					continue
				}
				delete(f.scripts, id)
				out["destroyed"] = []string{id}
			}
		}
		if id, ok := args["onSuccessActivateScript"].(string); ok && out["notUpdated"] == nil {
			for _, s := range f.scripts {
				s.IsActive = s.ID == id
			}
		}
		if args["onSuccessDeactivateScript"] == true {
			for _, s := range f.scripts {
				s.IsActive = false
			}
		}
		answer(method, out)
	default:
		answer("error", map[string]any{"type": "unknownMethod", "description": method})
	}
}

// TestForwardingIsOneScriptOfAutoPanelsOwn drives the provider's side
// against Stalwart's Sieve methods: set, read back, replace in place, turn
// off; never more addresses than the server runs redirects for; and never a
// change beside a script the owner wrote or changed.
func TestForwardingIsOneScriptOfAutoPanelsOwn(t *testing.T) {
	ctx := context.Background()
	f := newSieveStalwart(t)
	s := newServer(t, f)
	st, err := s.Forward(ctx, "acc")
	if err != nil || len(st.To) != 0 || st.Other || st.Max != 1 {
		t.Fatalf("an account with no script, a server with its defaults: %+v, %v", st, err)
	}
	if err := s.SetForward(ctx, "acc", provider.Forward{}); err != nil || len(f.scripts) != 0 {
		t.Fatalf("turning off what was never on: %v", err)
	}
	one := provider.Forward{To: []string{"me@example.org"}, Keep: true}
	if err := s.SetForward(ctx, "acc", one); err != nil {
		t.Fatal(err)
	}
	if name, text := f.active(); name != forwardScript || text != generateForward(one) || len(f.scripts) != 1 {
		t.Fatalf("the active script: %q\n%s", name, text)
	}
	if st, err := s.Forward(ctx, "acc"); err != nil || !slices.Equal(st.To, one.To) || !st.Keep || st.Other {
		t.Fatalf("read back: %+v, %v", st, err)
	}
	// Replaced in place: still one script, still active.
	away := provider.Forward{To: []string{"other@example.org"}}
	if err := s.SetForward(ctx, "acc", away); err != nil {
		t.Fatal(err)
	}
	if name, text := f.active(); name != forwardScript || text != generateForward(away) || len(f.scripts) != 1 {
		t.Fatalf("after replacing it: %q, %d scripts\n%s", name, len(f.scripts), text)
	}
	// The server runs one redirect: two addresses are refused, and nothing changes.
	two := provider.Forward{To: []string{"a@example.org", "b@example.org"}, Keep: true}
	if err := s.SetForward(ctx, "acc", two); !errors.Is(err, provider.ErrTooManyForwards) {
		t.Fatalf("two addresses on a server that runs one redirect: %v", err)
	}
	if _, text := f.active(); text != generateForward(away) {
		t.Fatal("a refused change changed the script")
	}
	// Raised by its administrator: the lesser of the two limits, never more
	// than AutoPanel's own five.
	for _, tc := range []struct {
		redirects, out, want int
	}{{5, 5, 5}, {3, 2, 2}, {2, 9, 2}, {50, 50, provider.MaxForwards}, {0, 3, 0}} {
		f.limits = map[string]any{"id": "singleton", "maxRedirects": tc.redirects, "maxOutMessages": tc.out}
		if st, err := s.Forward(ctx, "acc"); err != nil || st.Max != tc.want {
			t.Errorf("maxRedirects %d, maxOutMessages %d: Max %d, %v; want %d", tc.redirects, tc.out, st.Max, err, tc.want)
		}
	}
	f.limits = map[string]any{"id": "singleton", "maxRedirects": 5, "maxOutMessages": 5}
	if err := s.SetForward(ctx, "acc", two); err != nil {
		t.Fatalf("two addresses once the server runs five: %v", err)
	}
	for _, bad := range []string{"a\"; discard; redirect \"x@evil.example", "a b@example.org", "a\\@example.org", "nobody", "a@b@example.org", "a\n@example.org"} {
		if err := s.SetForward(ctx, "acc", provider.Forward{To: []string{bad}, Keep: true}); !errors.As(err, new(*provider.Refusal)) {
			t.Errorf("the address %q was written into a script: %v", bad, err)
		}
	}
	// When the limits cannot be read nothing is set: never a guess.
	f.failGet = true
	if err := s.SetForward(ctx, "acc", one); err == nil {
		t.Fatal("forwarding was set without knowing how many redirects the server runs")
	}
	if _, err := s.Forward(ctx, "acc"); err == nil {
		t.Fatal("forwarding was read without the server's limits")
	}
	f.failGet = false
	// Off: deactivated, then destroyed.
	if err := s.SetForward(ctx, "acc", provider.Forward{}); err != nil || len(f.scripts) != 0 {
		t.Fatalf("turning it off: %v, %d scripts left", err, len(f.scripts))
	}

	// A script of the owner's own is the active one: nothing is read as
	// AutoPanel's, and nothing is changed, set or turned off.
	f.add("vacation", "require [\"vacation\"];\nvacation \"away\";\n", true)
	if st, err := s.Forward(ctx, "acc"); err != nil || !st.Other || len(st.To) != 0 {
		t.Fatalf("beside the owner's script: %+v, %v", st, err)
	}
	var refusal *provider.Refusal
	for _, change := range []provider.Forward{one, {}} {
		if err := s.SetForward(ctx, "acc", change); !errors.As(err, &refusal) {
			t.Fatalf("a change beside the owner's script: %v", err)
		}
	}
	if name, _ := f.active(); name != "vacation" || len(f.scripts) != 1 {
		t.Fatalf("the owner's script was touched: %q, %d scripts", name, len(f.scripts))
	}
	// A script of AutoPanel's name that someone changed by hand is not
	// replaced either, active or not.
	g := newSieveStalwart(t)
	s = newServer(t, g)
	for _, active := range []bool{true, false} {
		g.scripts = map[string]*sieveScript{}
		g.add(forwardScript, generateForward(one)+"keep;\n", active)
		if st, err := s.Forward(ctx, "acc"); err != nil || !st.Other || len(st.To) != 0 {
			t.Fatalf("a changed script (active %v): %+v, %v", active, st, err)
		}
		if err := s.SetForward(ctx, "acc", away); !errors.As(err, &refusal) {
			t.Fatalf("a changed script (active %v) was replaced: %v", active, err)
		}
	}
	// AutoPanel's own script, left inactive (someone deactivated it): not
	// forwarding, and AutoPanel's to set again.
	g.scripts = map[string]*sieveScript{}
	g.add(forwardScript, generateForward(one), false)
	if st, err := s.Forward(ctx, "acc"); err != nil || st.Other || len(st.To) != 0 {
		t.Fatalf("AutoPanel's script, inactive: %+v, %v", st, err)
	}
	if err := s.SetForward(ctx, "acc", away); err != nil {
		t.Fatal(err)
	}
	if name, text := g.active(); name != forwardScript || text != generateForward(away) || len(g.scripts) != 1 {
		t.Fatalf("set again: %q, %d scripts", name, len(g.scripts))
	}
}
