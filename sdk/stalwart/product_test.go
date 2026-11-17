package stalwart

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/yongjohnlee80/autopanel/core/mail/provider"
	"github.com/yongjohnlee80/autopanel/core/services"
)

// mailPorts are mail's ports as core/mail gives them.
var mailPorts = []provider.PortMap{{Name: "smtp", Loopback: 10025}, {Name: "submissions", Loopback: 10465},
	{Name: "submission", Loopback: 10587}, {Name: "imaps", Loopback: 10993}}

func TestTheComposeIsAcceptedAndPinned(t *testing.T) {
	st, findings := services.Parse(Product{}.Compose(mailPorts, 18480), nil)
	for _, f := range findings {
		if f.Severity == services.Refused {
			t.Errorf("the mail definition is refused: %+v", f)
		}
	}
	if len(st.Services) != 1 || !strings.Contains(st.Services[0].Image, "@sha256:") {
		t.Fatalf("one service, pinned by digest: %+v", st.Services)
	}
	s := st.Services[0]
	if !s.ReadOnly || !s.HasUser || s.MemLimit == 0 || !slices.Equal(s.CapAdd, []string{"NET_BIND_SERVICE"}) {
		t.Fatalf("read-only, its own user, a memory limit and one capability: %+v", s)
	}
	for _, p := range s.Ports {
		if p.Public() {
			t.Errorf("a mail port published beyond loopback: %+v", p)
		}
	}
}

func TestTheDefinitionMapsMailsPortsToStalwarts(t *testing.T) {
	def := string(Product{}.Compose(mailPorts, 18480))
	for _, p := range []string{"127.0.0.1:10025:2525", "127.0.0.1:10465:4465", "127.0.0.1:10587:5587", "127.0.0.1:10993:9993", "127.0.0.1:18480:8080"} {
		if !strings.Contains(def, p) {
			t.Errorf("no %s in %s", p, def)
		}
	}
}

func TestTheCPU(t *testing.T) {
	all := map[string]bool{}
	for _, f := range x86v2 {
		all[f] = true
	}
	if err := (Product{}).CPU("amd64", all); err != nil {
		t.Fatal(err)
	}
	delete(all, "sse4_2")
	if err := (Product{}).CPU("amd64", all); err == nil || !strings.Contains(err.Error(), "sse4_2") {
		t.Fatalf("kvm64's flags: %v", err)
	}
	if err := (Product{}).CPU("arm64", nil); err != nil {
		t.Fatalf("arm64: %v", err)
	}
}

func TestTheBannerAndItsMask(t *testing.T) {
	p := Product{}
	if c, ok := p.FirstCredential("   password: Zx9-secret"); !ok || c != "Zx9-secret" {
		t.Fatalf("the banner's line: %q %v", c, ok)
	}
	if _, ok := p.FirstCredential("   username: admin"); ok {
		t.Fatal("a line with no password")
	}
	masked := p.Mask([]string{"   username: admin", "   password: Zx9-secret", "an ordinary line"})
	if masked[1] != "   password: [hidden]" || masked[0] != "   username: admin" || masked[2] != "an ordinary line" {
		t.Fatalf("masked: %q", masked)
	}
}

// --- the bootstrap against a fake Stalwart ------------------------------------------

// stalwart is a fake of Stalwart's management API through a bootstrap: it
// answers the one-time password before set-up and the administrator and the
// key after, and records what it was told.
type fakeBootstrap struct {
	mu        sync.Mutex
	setUp     bool
	restarted func() bool
	listeners map[string]any
	keys      int
	domains   []string
}

func (s *fakeBootstrap) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var req struct {
		MethodCalls [][]json.RawMessage `json:"methodCalls"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	var method string
	var args map[string]any
	_ = json.Unmarshal(req.MethodCalls[0][0], &method)
	_ = json.Unmarshal(req.MethodCalls[0][1], &args)
	user, pass, basic := r.BasicAuth()
	bearer := r.Header.Get("Authorization") == "Bearer the-key"
	answer := func(v any) {
		_ = json.NewEncoder(w).Encode(map[string]any{"methodResponses": []any{[]any{method, v, "c"}}})
	}
	switch {
	case !s.setUp:
		if !basic || user != "admin" || pass != "once-printed" || method != "x:Bootstrap/set" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		s.setUp = true
		answer(map[string]any{"updated": map[string]any{"singleton": map[string]any{"username": "admin@example.net", "secret": "permanent"}}})
	case basic && user == "admin" && pass == "once-printed" && s.restarted():
		w.WriteHeader(http.StatusUnauthorized) // the printed password ends with the restart
	case !(basic && user == "admin@example.net" && pass == "permanent") && !bearer:
		w.WriteHeader(http.StatusUnauthorized)
	case method == "x:Domain/get":
		answer(map[string]any{"list": []any{map[string]any{"id": "b", "name": "example.net"}}})
	case method == "x:NetworkListener/get":
		answer(map[string]any{"list": []any{map[string]any{"id": "l1", "name": "smtp", "bind": map[string]bool{"[::]:25": true}, "protocol": "smtp"}}})
	case method == "x:NetworkListener/set":
		s.listeners = args
		answer(map[string]any{})
	case method == "x:ApiKey/set":
		s.keys++
		answer(map[string]any{"created": map[string]any{"k": map[string]any{"id": "k1", "secret": "the-key"}}})
	default:
		w.WriteHeader(http.StatusBadRequest)
	}
}

// fakeEnv is what core/mail gives a bootstrap: here, a journal holding the
// banner, a restart that ends the printed password, a forwarder, and a vault.
type fakeEnv struct {
	base     string
	restarts int
	sealed   map[string][]byte
	printed  bool
}

func (e *fakeEnv) Base() string { return e.base }
func (e *fakeEnv) Settings() provider.Settings {
	return provider.Settings{Host: "mail.example.net", FirstDomain: "example.net"}
}
func (e *fakeEnv) FirstCredential(context.Context) (string, error) {
	if !e.printed {
		return "", errors.New("nothing printed")
	}
	return "once-printed", nil
}
func (e *fakeEnv) Restart(context.Context) error             { e.restarts++; return nil }
func (e *fakeEnv) Forwarder(context.Context) (string, error) { return "10.89.0.0/24", nil }
func (e *fakeEnv) Sealed(_ context.Context, n string) ([]byte, error) {
	v, ok := e.sealed[n]
	if !ok {
		return nil, provider.ErrNoSecret
	}
	return v, nil
}
func (e *fakeEnv) Seal(_ context.Context, n string, v []byte) error { e.sealed[n] = v; return nil }

func TestBootstrap(t *testing.T) {
	env := &fakeEnv{sealed: map[string][]byte{}, printed: true}
	fake := &fakeBootstrap{restarted: func() bool { return env.restarts > 0 }}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	env.base = srv.URL
	if err := (Product{}).Bootstrap(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	if !fake.setUp || env.restarts != 2 || fake.keys != 1 {
		t.Fatalf("set up %v, restarts %d, keys %d; want set up, restarted twice, one key", fake.setUp, env.restarts, fake.keys)
	}
	if string(env.sealed[provider.SealedAPIKey]) != "the-key" {
		t.Fatal("the API key is not sealed")
	}
	var admin Admin
	if err := json.Unmarshal(env.sealed[sealedAdmin], &admin); err != nil || admin.Secret != "permanent" {
		t.Fatalf("the administrator is not sealed: %+v %v", admin, err)
	}
	smtp := fake.listeners["update"].(map[string]any)["l1"].(map[string]any)
	if _, ok := smtp["overrideProxyTrustedNetworks"].(map[string]any)["10.89.0.0/24"]; !ok {
		t.Fatalf("the forwarder is not trusted: %v", smtp)
	}
}

// TestABootstrapCarriesOnAfterAFailure: a bootstrap that sealed the
// administrator and then failed carries on with it: the printed password is
// gone after the restart, and is not needed.
func TestABootstrapCarriesOnAfterAFailure(t *testing.T) {
	env := &fakeEnv{sealed: map[string][]byte{}}
	fake := &fakeBootstrap{setUp: true, restarted: func() bool { return true }}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	env.base = srv.URL
	env.sealed[sealedAdmin], _ = json.Marshal(Admin{Username: "admin@example.net", Secret: "permanent"})
	if err := (Product{}).Bootstrap(context.Background(), env); err != nil || fake.keys != 1 {
		t.Fatalf("carried on: %v, keys %d", err, fake.keys)
	}
}
