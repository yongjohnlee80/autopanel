package stalwart

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yongjohnlee80/golib/auth/password"

	"github.com/yongjohnlee80/autopanel/core/mail/provider"
	"github.com/yongjohnlee80/autopanel/core/services"
)

// keysStalwart plays what a repair asks of Stalwart, as the pinned v1.1.0
// answered on a copy of the test VM's server (the repair record's claims):
// API keys per account, listed with their secrets unless properties say
// otherwise; accounts with a role; a recovery administrator who is no
// account; 401 for any credential it does not take.
type keysStalwart struct {
	mu       sync.Mutex
	admins   map[string]string // address → the password's hash (or plain, as bootstrapped)
	recovery string            // name:secret, while the server runs with it
	keys     map[string]apiKey // id → key
	next     int
	asked    []map[string]any // each x:ApiKey/get's arguments
}

type apiKey struct{ description, secret string }

func (s *keysStalwart) who(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if k, ok := strings.CutPrefix(h, "Bearer "); ok {
		for _, v := range s.keys {
			if v.secret == k {
				return "admin", true
			}
		}
		return "", false
	}
	user, pass, ok := r.BasicAuth()
	if !ok {
		return "", false
	}
	if s.recovery != "" && user+":"+pass == s.recovery {
		return "recovery", true
	}
	stored, ok := s.admins[user]
	if !ok {
		return "", false
	}
	if stored == pass || password.Verify(stored, pass) == nil {
		return "admin", true
	}
	return "", false
}

func (s *keysStalwart) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	who, ok := s.who(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var req struct {
		MethodCalls [][3]json.RawMessage `json:"methodCalls"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	var method string
	var args map[string]any
	_ = json.Unmarshal(req.MethodCalls[0][0], &method)
	_ = json.Unmarshal(req.MethodCalls[0][1], &args)
	answer := func(v any) {
		_ = json.NewEncoder(w).Encode(map[string]any{"methodResponses": []any{[]any{method, v, "c"}}})
	}
	switch method {
	case "x:Domain/get":
		answer(map[string]any{"list": []any{}})
	case "x:Account/get":
		if ids, _ := args["ids"].([]any); len(ids) == 1 { // SetSecret's read of the credentials
			answer(map[string]any{"list": []any{map[string]any{"credentials": map[string]any{"0": map[string]any{"@type": "Password"}, "1": map[string]any{"@type": "AppPassword"}}}}})
			return
		}
		var list []any
		for addr := range s.admins {
			list = append(list, map[string]any{"id": "id-" + addr, "name": strings.Split(addr, "@")[0], "emailAddress": addr, "@type": "User", "roles": map[string]any{"@type": "Admin"}})
		}
		list = append(list, map[string]any{"id": "id-ann", "name": "ann", "emailAddress": "ann@example.net", "@type": "User", "roles": map[string]any{"@type": "User"}})
		answer(map[string]any{"list": list})
	case "x:Account/set":
		for id, patch := range args["update"].(map[string]any) {
			addr := strings.TrimPrefix(id, "id-")
			s.admins[addr] = patch.(map[string]any)["credentials/0/secret"].(string)
		}
		answer(map[string]any{"updated": map[string]any{}})
	case "x:ApiKey/get":
		if who == "recovery" {
			answer(map[string]any{"list": []any{}})
			return
		}
		s.asked = append(s.asked, args)
		var list []any
		for id, k := range s.keys {
			item := map[string]any{"id": id, "description": k.description, "secret": k.secret}
			if p, ok := args["properties"].([]any); ok && len(p) == 1 {
				item = map[string]any{"id": id, "description": k.description}
			}
			list = append(list, item)
		}
		answer(map[string]any{"list": list})
	case "x:ApiKey/set":
		if who == "recovery" {
			answer(map[string]any{"notCreated": map[string]any{"k": map[string]any{"type": "notFound"}}})
			return
		}
		out := map[string]any{}
		if c, ok := args["create"].(map[string]any); ok {
			s.next++
			id := "k" + string(rune('0'+s.next))
			s.keys[id] = apiKey{description: c["k"].(map[string]any)["description"].(string), secret: "secret-" + id}
			out["created"] = map[string]any{"k": map[string]any{"id": id, "secret": "secret-" + id}}
		}
		if d, ok := args["destroy"].([]any); ok {
			for _, id := range d {
				delete(s.keys, id.(string))
			}
			out["destroyed"] = d
		}
		answer(out)
	default:
		http.Error(w, "unknown "+method, http.StatusBadRequest)
	}
}

func newKeysStalwart(t *testing.T) (*keysStalwart, *fakeEnv) {
	s := &keysStalwart{admins: map[string]string{"admin@example.net": "first"}, keys: map[string]apiKey{
		"k0": {description: "autopanel core", secret: "the-bootstrap-key"},
		"kA": {description: "autopanel core 2026-11-01T10:00Z", secret: "an-older-repair"},
		"kB": {description: "autopanel corehelper", secret: "someone-elses"},
		"kC": {description: "monitoring", secret: "monitoring-key"},
	}}
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	raw, _ := json.Marshal(Admin{Username: "admin@example.net", Secret: "first"})
	return s, &fakeEnv{base: srv.URL, sealed: map[string][]byte{sealedAdmin: raw}}
}

// TestANewKeyReplacesAutoPanelsOnly: sealed, signing in, then the older
// keys named exactly "autopanel core" or "autopanel core …" destroyed, and
// no key's secret ever asked for.
func TestANewKeyReplacesAutoPanelsOnly(t *testing.T) {
	s, env := newKeysStalwart(t)
	ctx := context.Background()
	if err := (Product{}).AdminSignsIn(ctx, env); err != nil {
		t.Fatal(err)
	}
	kr, err := Product{}.NewAPIKey(ctx, env, time.Date(2026, 11, 22, 9, 30, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if kr.Destroyed != 2 || strings.Join(kr.Kept, ",") == "" || len(kr.Kept) != 2 {
		t.Fatalf("the repair: %+v", kr)
	}
	var left []string
	for _, k := range s.keys {
		left = append(left, k.description)
	}
	got := strings.Join(sortedCopy(left), ",")
	if got != "autopanel core 2026-11-22T09:30Z,autopanel corehelper,monitoring" {
		t.Fatalf("the keys left: %s", got)
	}
	if string(env.sealed[provider.SealedAPIKey]) == "" || !strings.HasPrefix(string(env.sealed[provider.SealedAPIKey]), "secret-") {
		t.Fatalf("the sealed key: %q", env.sealed[provider.SealedAPIKey])
	}
	for _, a := range s.asked {
		if p, _ := a["properties"].([]any); len(p) != 1 || p[0] != "description" {
			t.Fatalf("the keys were listed with %v: their secrets with them", a["properties"])
		}
	}
	s.admins["admin@example.net"] = "changed by hand"
	if err := (Product{}).AdminSignsIn(ctx, env); !errors.Is(err, provider.ErrUnauthorized) {
		t.Fatalf("a changed administrator: %v", err)
	}
	delete(env.sealed, sealedAdmin)
	if err := (Product{}).AdminSignsIn(ctx, env); !errors.Is(err, provider.ErrNoSecret) {
		t.Fatalf("no sealed administrator: %v", err)
	}
}

func sortedCopy(in []string) []string {
	out := append([]string{}, in...)
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

// TestTheRecoveryAdministratorResetsTheAdministrator: it finds the one
// administrator by role, gives it a new secret (a hash), and the sealed
// administrator signs in with it; it cannot make a key.
func TestTheRecoveryAdministratorResetsTheAdministrator(t *testing.T) {
	s, env := newKeysStalwart(t)
	ctx := context.Background()
	s.admins["admin@example.net"] = "lost"
	rec, err := (Product{}).RecoveryCredential()
	if err != nil || !strings.HasPrefix(string(rec), recoveryName+":") || len(rec) < len(recoveryName)+40 {
		t.Fatalf("the recovery credential: %v", err)
	}
	if err := (Product{}).ResetAdmin(ctx, env, rec); !errors.Is(err, provider.ErrUnauthorized) {
		t.Fatalf("before the server runs with it: %v", err)
	}
	s.recovery = string(rec)
	if err := (Product{}).RecoverySignsIn(ctx, env.base, rec); err != nil {
		t.Fatal(err)
	}
	if err := (Product{}).ResetAdmin(ctx, env, rec); err != nil {
		t.Fatal(err)
	}
	var a Admin
	_ = json.Unmarshal(env.sealed[sealedAdmin], &a)
	if a.Username != "admin@example.net" || a.Secret == "" || s.admins["admin@example.net"] == a.Secret || !strings.HasPrefix(s.admins["admin@example.net"], "$argon2id$") {
		t.Fatalf("the administrator: %+v, stored %q", a, s.admins["admin@example.net"])
	}
	if err := (Product{}).AdminSignsIn(ctx, env); err != nil {
		t.Fatalf("the administrator with its new secret: %v", err)
	}
	s.admins["second@example.net"] = "x"
	if err := (Product{}).ResetAdmin(ctx, env, rec); err == nil || !strings.Contains(err.Error(), "2 administrator") {
		t.Fatalf("two administrators: %v", err)
	}
	s.recovery = ""
	if err := (Product{}).RecoverySignsIn(ctx, env.base, rec); !errors.Is(err, provider.ErrUnauthorized) {
		t.Fatalf("after the restart without it: %v", err)
	}
}

// TestTheRecoveryDefinition: the variable by its sealed reference, a value
// the services review takes as one, and nothing else changed.
func TestTheRecoveryDefinition(t *testing.T) {
	st := provider.Stack{Name: "mail", Ports: []provider.PortMap{{Name: "smtp", Loopback: 10025}}, Manage: 18480}
	plain := string(Product{}.Compose(st))
	st.Recovery = "${sealed:stack/mail/recovery}"
	with := string(Product{}.Compose(st))
	if strings.Replace(with, "    environment:\n      STALWART_RECOVERY_ADMIN: \"${sealed:stack/mail/recovery}\"\n", "", 1) != plain {
		t.Fatalf("the recovery definition:\n%s", with)
	}
	parsed, fs := services.Parse([]byte(with), nil)
	if len(parsed.Services) != 1 || len(parsed.Services[0].Environment) != 1 || parsed.Services[0].Environment[0].Sealed != "stack/mail/recovery" {
		t.Fatalf("parsed: %+v %+v", parsed.Services, fs)
	}
	for _, f := range fs {
		if f.Severity == services.Refused {
			t.Fatalf("refused: %+v", f)
		}
	}
	for d, want := range map[string]bool{"autopanel core": true, "autopanel core 2026-11-21": true, "autopanel corehelper": false, "autopanel": false, " autopanel core": false} {
		if ourKey(d) != want {
			t.Errorf("ourKey(%q) = %v", d, !want)
		}
	}
}

// TestRepairAgainstStalwart repairs a real, throwaway Stalwart on the test VM
// (the record's tests 2 and 3): AUTOPANEL_TEST_STALWART_REPAIR names a
// rootless Podman container this test may remove and make again, with two
// volumes of the same name and -etc, -data; AUTOPANEL_TEST_STALWART is its
// management URL. Never a server that matters: the test destroys it.
func TestRepairAgainstStalwart(t *testing.T) {
	name, url := os.Getenv("AUTOPANEL_TEST_STALWART_REPAIR"), os.Getenv("AUTOPANEL_TEST_STALWART")
	if name == "" || url == "" {
		t.Skip("needs a throwaway Stalwart: AUTOPANEL_TEST_STALWART_REPAIR and AUTOPANEL_TEST_STALWART")
	}
	port := url[strings.LastIndex(url, ":")+1:]
	run := func(recovery string, fresh bool) {
		t.Helper()
		_ = exec.Command("podman", "rm", "-f", name).Run()
		if fresh {
			_ = exec.Command("podman", "volume", "rm", "-f", name+"-etc", name+"-data").Run()
		}
		args := []string{"run", "-d", "--name", name, "-p", "127.0.0.1:" + port + ":8080",
			"-v", name + "-etc:/etc/stalwart", "-v", name + "-data:/var/lib/stalwart"}
		if recovery != "" {
			args = append(args, "-e", recoveryVariable+"="+recovery)
		}
		if out, err := exec.Command("podman", append(args, Image)...).CombinedOutput(); err != nil {
			t.Fatalf("podman run: %v: %s", err, out)
		}
		for range 60 {
			if resp, err := http.Get(url + "/"); err == nil {
				resp.Body.Close()
				time.Sleep(2 * time.Second)
				return
			}
			time.Sleep(time.Second)
		}
		t.Fatal("Stalwart did not start")
	}
	t.Cleanup(func() {
		_ = exec.Command("podman", "rm", "-f", name).Run()
		_ = exec.Command("podman", "volume", "rm", "-f", name+"-etc", name+"-data").Run()
	})
	run("", true)
	env := &podmanEnv{t: t, name: name, base: url, sealed: map[string][]byte{}}
	ctx := context.Background()
	if err := (Product{}).Bootstrap(ctx, env); err != nil {
		t.Fatal(err)
	}
	oldKey := string(env.sealed[provider.SealedAPIKey])
	keyClient := func(k string) *Client {
		return NewClient(url, Bearer(func(context.Context) (string, error) { return k, nil }))
	}
	a, err := sealedAdminOf(ctx, env)
	if err != nil {
		t.Fatal(err)
	}
	admin := NewClient(url, Basic(a.Username, a.Secret))
	for _, d := range []string{"autopanel core 2026-01-01T00:00Z", "monitoring", "autopanel corehelper"} {
		if _, _, err := admin.CreateAPIKey(ctx, d); err != nil {
			t.Fatal(err)
		}
	}

	// key_lost: the administrator makes a new key; AutoPanel's older ones go.
	kr, err := (Product{}).NewAPIKey(ctx, env, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if kr.Destroyed != 2 || len(kr.Kept) != 2 {
		t.Fatalf("a new key: %+v", kr)
	}
	if _, err := keyClient(oldKey).Domains(ctx); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("the bootstrap's key after the repair: %v", err)
	}
	if _, err := keyClient(string(env.sealed[provider.SealedAPIKey])).Domains(ctx); err != nil {
		t.Fatalf("the new key: %v", err)
	}

	// admin_lost: the administrator's secret changed behind AutoPanel's back.
	accounts, err := admin.Accounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var adminID string
	for _, acc := range accounts {
		if acc.Admin {
			adminID = acc.ID
		}
	}
	unknown, _ := lockedSecret()
	if err := admin.SetSecret(ctx, adminID, unknown); err != nil {
		t.Fatal(err)
	}
	if err := (Product{}).AdminSignsIn(ctx, env); !errors.Is(err, provider.ErrUnauthorized) {
		t.Fatalf("a lost administrator: %v", err)
	}
	rec, err := (Product{}).RecoveryCredential()
	if err != nil {
		t.Fatal(err)
	}
	run(string(rec), false)
	if err := (Product{}).RecoverySignsIn(ctx, url, rec); err != nil {
		t.Fatalf("the recovery administrator: %v", err)
	}
	if err := (Product{}).ResetAdmin(ctx, env, rec); err != nil {
		t.Fatal(err)
	}
	if _, err := (Product{}).NewAPIKey(ctx, env, time.Now()); err != nil {
		t.Fatal(err)
	}
	run("", false)
	if err := (Product{}).RecoverySignsIn(ctx, url, rec); !errors.Is(err, provider.ErrUnauthorized) {
		t.Fatalf("the recovery administrator after a start without it: %v", err)
	}
	if err := (Product{}).AdminSignsIn(ctx, env); err != nil {
		t.Fatalf("the administrator after the repair: %v", err)
	}
	if _, err := keyClient(string(env.sealed[provider.SealedAPIKey])).Domains(ctx); err != nil {
		t.Fatalf("the key after the repair: %v", err)
	}
	if accs, err := admin.Accounts(ctx); err == nil {
		t.Fatalf("the administrator's lost secret still signs in (%d accounts)", len(accs))
	}
}
