package stalwart

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yongjohnlee80/autopanel/core/mail/provider"
	"github.com/yongjohnlee80/autopanel/core/mail/provider/conformance"
)

// Stalwart's quirks, handled by the server adapter, against fakes that behave
// as the pinned v1.1.0 did on a VM; and the conformance suite against a real
// Stalwart, when one is given.

// accountsStalwart plays Stalwart's accounts and app passwords as the pinned
// v1.1.0 behaved on a VM (ADR claims C1 to C9, the KB note of 2026-11-17):
// an account's app passwords are entries of its credentials map beside its
// password, so replacing the map deletes them; an app password whose expiry
// is cleared works again even after it expired; the limit is 5 unless set,
// expired ones counting; a read gives every secret as ****.
type accountsStalwart struct {
	t   *testing.T
	mu  sync.Mutex
	now func() time.Time
	gen func(n int) string // an app password's secret

	accounts      map[string]*fakeAccount
	nextID        int
	passwordFirst bool // where the password's entry sits in the credentials map
	calls         []string
}

type fakeAccount struct {
	id, name, domainID string
	secret             string // the password's secret as sent: a hash, from AutoPanel
	quotas             map[string]int64
	apps               []*fakeApp
}

type fakeApp struct {
	id, description, secret string
	created                 time.Time
	expires                 *time.Time
}

func newAccountsStalwart(t *testing.T, now func() time.Time) *accountsStalwart {
	return &accountsStalwart{t: t, now: now, accounts: map[string]*fakeAccount{}, passwordFirst: true,
		gen: stalwartLike}
}

// stalwartLike is a secret of Stalwart's form, app_ and 36 of [a-z0-9],
// different for each n.
func stalwartLike(n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	sum := sha256.Sum256([]byte(strconv.Itoa(n)))
	out := []byte("app_")
	for i := range 36 {
		out = append(out, alphabet[int(sum[i%32]+byte(i*7))%36])
	}
	return string(out)
}

func (f *accountsStalwart) id() string {
	f.nextID++
	return "i" + strconv.Itoa(f.nextID)
}

func (f *accountsStalwart) credentials(a *fakeAccount) map[string]any {
	var list []map[string]any
	for _, p := range a.apps {
		list = append(list, map[string]any{"@type": "AppPassword", "credentialId": p.id, "description": p.description, "secret": "****"})
	}
	pw := map[string]any{"@type": "Password", "credentialId": "pw", "secret": "****"}
	if f.passwordFirst {
		list = append([]map[string]any{pw}, list...)
	} else {
		list = append(list, pw)
	}
	out := map[string]any{}
	for i, c := range list {
		out[strconv.Itoa(i)] = c
	}
	return out
}

func (f *accountsStalwart) limit(a *fakeAccount) int64 {
	if n, ok := a.quotas["maxAppPasswords"]; ok {
		return n
	}
	return 5
}

func (f *accountsStalwart) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var req struct {
		MethodCalls [][]json.RawMessage `json:"methodCalls"`
	}
	body, _ := io.ReadAll(r.Body)
	if err := json.Unmarshal(body, &req); err != nil || len(req.MethodCalls) != 1 {
		f.t.Errorf("not one JMAP call: %s", body)
		return
	}
	var method string
	var args map[string]any
	_ = json.Unmarshal(req.MethodCalls[0][0], &method)
	_ = json.Unmarshal(req.MethodCalls[0][1], &args)
	f.calls = append(f.calls, method)
	answer := func(name string, v any) {
		_ = json.NewEncoder(w).Encode(map[string]any{"methodResponses": []any{[]any{name, v, "c"}}})
	}
	account := func() *fakeAccount {
		id, _ := args["accountId"].(string)
		return f.accounts[id]
	}
	switch method {
	case "x:Domain/get":
		answer(method, map[string]any{"list": []any{map[string]any{"id": "dn", "name": "example.net"}}})
	case "x:Account/get":
		var list []any
		for _, a := range f.accounts {
			list = append(list, map[string]any{"@type": "User", "id": a.id, "name": a.name, "domainId": a.domainID,
				"emailAddress": a.name + "@example.net", "quotas": a.quotas, "credentials": f.credentials(a), "roles": map[string]any{"@type": "User"}})
		}
		answer(method, map[string]any{"list": list})
	case "x:Account/set":
		out := map[string]any{"created": map[string]any{}, "updated": map[string]any{}, "notUpdated": map[string]any{}}
		if c, ok := args["create"].(map[string]any); ok {
			for k, raw := range c {
				o := raw.(map[string]any)
				cr := o["credentials"].(map[string]any)["0"].(map[string]any)
				q := map[string]int64{}
				for qk, qv := range o["quotas"].(map[string]any) {
					q[qk] = int64(qv.(float64))
				}
				a := &fakeAccount{id: f.id(), name: o["name"].(string), domainID: o["domainId"].(string), secret: cr["secret"].(string), quotas: q}
				f.accounts[a.id] = a
				out["created"].(map[string]any)[k] = map[string]any{"id": a.id}
			}
		}
		if u, ok := args["update"].(map[string]any); ok {
			for id, raw := range u {
				a := f.accounts[id]
				for path, v := range raw.(map[string]any) {
					switch {
					case path == "credentials": // the whole map: what was not sent is gone
						a.apps, a.secret = nil, v.(map[string]any)["0"].(map[string]any)["secret"].(string)
					case strings.HasPrefix(path, "credentials/") && strings.HasSuffix(path, "/secret"):
						key := strings.TrimSuffix(strings.TrimPrefix(path, "credentials/"), "/secret")
						if f.credentials(a)[key].(map[string]any)["@type"] != "Password" {
							out["notUpdated"].(map[string]any)[id] = map[string]any{"type": "invalidPatch", "description": "not the password"}
							continue
						}
						a.secret = v.(string)
					case strings.HasPrefix(path, "quotas/"):
						a.quotas[strings.TrimPrefix(path, "quotas/")] = int64(v.(float64))
					case path == "quotas":
						a.quotas = map[string]int64{}
						for qk, qv := range v.(map[string]any) {
							a.quotas[qk] = int64(qv.(float64))
						}
					default:
						f.t.Errorf("an account patch this fake does not know: %s", path)
					}
				}
				out["updated"].(map[string]any)[id] = nil
			}
		}
		answer(method, out)
	case "x:AppPassword/get":
		a := account()
		if a == nil {
			answer("error", map[string]any{"type": "forbidden", "description": "Account not found."})
			return
		}
		var list []any
		for _, p := range a.apps {
			var exp any
			if p.expires != nil {
				exp = p.expires.UTC().Format(time.RFC3339)
			}
			list = append(list, map[string]any{"id": p.id, "description": p.description, "createdAt": p.created.UTC().Format(time.RFC3339),
				"expiresAt": exp, "secret": "****", "permissions": map[string]any{"@type": "Inherit"}, "allowedIps": map[string]any{}})
		}
		answer(method, map[string]any{"accountId": a.id, "list": list})
	case "x:AppPassword/set":
		a := account()
		out := map[string]any{"created": map[string]any{}, "updated": map[string]any{}, "destroyed": []string{}, "notCreated": map[string]any{}}
		if c, ok := args["create"].(map[string]any); ok {
			for k, raw := range c {
				if int64(len(a.apps)) >= f.limit(a) {
					out["notCreated"].(map[string]any)[k] = map[string]any{"type": "overQuota", "description": "You have exceeded your quota of " + strconv.FormatInt(f.limit(a), 10) + " app passwords."}
					continue
				}
				o := raw.(map[string]any)
				p := &fakeApp{id: f.id(), description: o["description"].(string), secret: f.gen(f.nextID), created: f.now()}
				if s, ok := o["expiresAt"].(string); ok {
					e, _ := time.Parse(time.RFC3339, s)
					p.expires = &e
				}
				a.apps = append(a.apps, p)
				out["created"].(map[string]any)[k] = map[string]any{"id": p.id, "secret": p.secret}
			}
		}
		if u, ok := args["update"].(map[string]any); ok {
			for id, raw := range u {
				for _, p := range a.apps {
					if p.id == id {
						if v, ok := raw.(map[string]any)["expiresAt"]; ok && v == nil {
							p.expires = nil // revives an expired one, as Stalwart does
						}
					}
				}
				out["updated"].(map[string]any)[id] = nil
			}
		}
		if d, ok := args["destroy"].([]any); ok {
			for _, id := range d {
				for i, p := range a.apps {
					if p.id == id {
						a.apps = append(a.apps[:i], a.apps[i+1:]...)
						out["destroyed"] = append(out["destroyed"].([]string), p.id)
						break
					}
				}
			}
		}
		answer(method, out)
	default:
		f.t.Errorf("a method this fake does not play: %s", method)
	}
}

// signsIn is what an IMAP sign-in with secret would answer.
func (f *accountsStalwart) signsIn(address, secret string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, a := range f.accounts {
		if a.name+"@example.net" != address {
			continue
		}
		for _, p := range a.apps {
			if p.secret == secret && (p.expires == nil || p.expires.After(f.now())) {
				return true
			}
		}
	}
	return false
}

func (f *accountsStalwart) only(address string) *fakeAccount {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, a := range f.accounts {
		if a.name+"@example.net" == address {
			return a
		}
	}
	return nil
}

// dkimStalwart is a fake of Stalwart's DKIM, domain and certificate objects.
type dkimStalwart struct {
	mu    sync.Mutex
	keys  map[string]map[string]any // by id
	next  int
	certs map[string]map[string]any
}

func (s *dkimStalwart) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
	answer := func(v any) {
		_ = json.NewEncoder(w).Encode(map[string]any{"methodResponses": []any{[]any{method, v, "c"}}})
	}
	set := func(store map[string]map[string]any) map[string]any {
		out := map[string]any{"created": map[string]any{}, "updated": map[string]any{}, "destroyed": []string{}}
		if c, ok := args["create"].(map[string]any); ok {
			for k, v := range c {
				s.next++
				id := fmt.Sprintf("x%d", s.next)
				obj := v.(map[string]any)
				obj["id"] = id
				store[id] = obj
				out["created"].(map[string]any)[k] = map[string]any{"id": id}
			}
		}
		if u, ok := args["update"].(map[string]any); ok {
			for id, v := range u {
				for k, val := range v.(map[string]any) {
					store[id][k] = val
				}
				out["updated"].(map[string]any)[id] = nil
			}
		}
		if d, ok := args["destroy"].([]any); ok {
			for _, id := range d {
				delete(store, id.(string))
			}
		}
		return out
	}
	switch method {
	case "x:DkimSignature/get":
		var list []any
		for _, k := range s.keys {
			list = append(list, k)
		}
		answer(map[string]any{"list": list})
	case "x:DkimSignature/set":
		answer(set(s.keys))
	case "x:Certificate/get":
		var list []any
		for _, c := range s.certs {
			list = append(list, c)
		}
		answer(map[string]any{"list": list})
	case "x:Certificate/set":
		out := set(s.certs)
		for _, c := range s.certs { // what Stalwart derives from the PEM
			if v, ok := c["certificate"].(map[string]any); ok {
				leaf := parsePEMLeaf(v["value"].(string))
				c["subjectAlternativeNames"] = map[string]bool{leaf.DNSNames[0]: true}
				c["notValidAfter"] = leaf.NotAfter.UTC().Format(time.RFC3339)
			}
		}
		answer(out)
	case "x:Action/set":
		answer(map[string]any{"created": map[string]any{"a": map[string]any{"id": "a"}}})
	default:
		w.WriteHeader(http.StatusBadRequest)
	}
}

func (s *dkimStalwart) stages() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]string{}
	for _, k := range s.keys {
		out[k["selector"].(string)] = k["stage"].(string)
	}
	return out
}

// newServer is the adapter over a fake, with the key it signs in with.
func newServer(t *testing.T, h http.Handler) server {
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return server{c: NewClient(srv.URL, Bearer(func(context.Context) (string, error) { return "k", nil }))}
}

const aHash = "$argon2id$v=19$m=8192,t=1,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g"

// TestAnAccountIsMadeWithItsRoom: the limit asked goes into the account's
// quotas beside the disk quota.
func TestAnAccountIsMadeWithItsRoom(t *testing.T) {
	fake := newAccountsStalwart(t, time.Now)
	s := newServer(t, fake)
	if _, err := s.AddAccount(context.Background(), provider.NewAccount{Local: "ana", DomainID: "dn", PasswordHash: aHash, Quota: 1 << 30, AppPasswords: 20}); err != nil {
		t.Fatal(err)
	}
	a := fake.only("ana@example.net")
	if a.secret != aHash || a.quotas["maxAppPasswords"] != 20 || a.quotas["maxDiskQuota"] != 1<<30 {
		t.Fatalf("made: %+v", a)
	}
}

// TestAnOlderAccountGetsRoom: an account made with Stalwart's default of 5 is
// raised to the room asked when its app passwords are made.
func TestAnOlderAccountGetsRoom(t *testing.T) {
	fake := newAccountsStalwart(t, time.Now)
	s := newServer(t, fake)
	fake.accounts["old"] = &fakeAccount{id: "old", name: "old", domainID: "dn", secret: "typed", quotas: map[string]int64{"maxDiskQuota": 1}}
	for i := range 6 {
		if _, _, err := s.AddAppPassword(context.Background(), "old", "device "+strconv.Itoa(i), time.Now().Add(time.Hour), 20); err != nil {
			t.Fatalf("app password %d: %v", i+1, err)
		}
	}
	if fake.only("old@example.net").quotas["maxAppPasswords"] != 20 {
		t.Fatal("the limit was not raised")
	}
}

// TestOverTheLimitIsErrOverLimit: Stalwart's overQuota is the provider's.
func TestOverTheLimitIsErrOverLimit(t *testing.T) {
	fake := newAccountsStalwart(t, time.Now)
	s := newServer(t, fake)
	fake.accounts["a"] = &fakeAccount{id: "a", name: "a", domainID: "dn", quotas: map[string]int64{"maxAppPasswords": 1}}
	if _, _, err := s.AddAppPassword(context.Background(), "a", "one", time.Now().Add(time.Hour), 1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.AddAppPassword(context.Background(), "a", "two", time.Now().Add(time.Hour), 1); !errors.Is(err, provider.ErrOverLimit) {
		t.Fatalf("over the limit: %v", err)
	}
}

// TestANewPasswordKeepsTheAppPasswords: the password's own entry is patched,
// wherever it sits in the credentials map; the app passwords stay.
func TestANewPasswordKeepsTheAppPasswords(t *testing.T) {
	fake := newAccountsStalwart(t, time.Now)
	s := newServer(t, fake)
	fake.accounts["old"] = &fakeAccount{id: "old", name: "old", domainID: "dn", secret: "typed-password", quotas: map[string]int64{}}
	_, secret, err := s.AddAppPassword(context.Background(), "old", "phone", time.Now().Add(time.Hour), 20)
	if err != nil {
		t.Fatal(err)
	}
	fake.passwordFirst = false // the password's entry is not "0"
	if err := s.SetPasswordHash(context.Background(), "old", aHash); err != nil {
		t.Fatal(err)
	}
	if a := fake.only("old@example.net"); a.secret != aHash || len(a.apps) != 1 || !fake.signsIn("old@example.net", secret) {
		t.Fatalf("after a new password: app passwords %d", len(a.apps))
	}
}

// TestAQuotaKeepsTheLimit: the disk quota is a patch, not the quotas map
// (which would put the limit back to 5).
func TestAQuotaKeepsTheLimit(t *testing.T) {
	fake := newAccountsStalwart(t, time.Now)
	s := newServer(t, fake)
	fake.accounts["a"] = &fakeAccount{id: "a", name: "a", domainID: "dn", quotas: map[string]int64{"maxDiskQuota": 1, "maxAppPasswords": 20}}
	if err := s.SetQuota(context.Background(), "a", 2<<30); err != nil {
		t.Fatal(err)
	}
	if q := fake.only("a@example.net").quotas; q["maxDiskQuota"] != 2<<30 || q["maxAppPasswords"] != 20 {
		t.Fatalf("quotas: %v", q)
	}
}

// TestDKIMKindsAndCertificates: algorithms map to Stalwart's kinds; a new
// certificate needs a restart, a renewal is served at once.
func TestDKIMKindsAndCertificates(t *testing.T) {
	fake := &dkimStalwart{keys: map[string]map[string]any{}, certs: map[string]map[string]any{}}
	s := newServer(t, fake)
	ctx := context.Background()
	id, err := s.AddDKIMKey(ctx, "dn", "ap202611e", provider.Ed25519, "PEM")
	if err != nil {
		t.Fatal(err)
	}
	if fake.keys[id]["@type"] != "Dkim1Ed25519Sha256" {
		t.Fatalf("the kind sent: %v", fake.keys[id])
	}
	ks, _ := s.DKIMKeys(ctx)
	if len(ks) != 1 || ks[0].Alg != provider.Ed25519 {
		t.Fatalf("keys: %+v", ks)
	}
	chain, key := selfSignedPEM(t, "mail.example.net")
	restart, err := s.ServeCertificate(ctx, "", chain, key)
	if err != nil || !restart {
		t.Fatalf("a new certificate: restart %v, %v; want a restart", restart, err)
	}
	cs, _ := s.Certificates(ctx)
	if restart, err := s.ServeCertificate(ctx, cs[0].ID, chain, key); err != nil || restart {
		t.Fatalf("a renewal: restart %v, %v", restart, err)
	}
}

// TestStalwartConforms runs the conformance suite against a real Stalwart,
// on a throwaway machine: AUTOPANEL_TEST_STALWART names its management URL,
// AUTOPANEL_TEST_STALWART_KEY a file holding an API key, and
// AUTOPANEL_TEST_STALWART_IMAP its IMAPS address (host:port), for sign-ins.
// It adds and removes a domain and accounts of its own, and touches nothing
// else.
func TestStalwartConforms(t *testing.T) {
	url, keyFile := os.Getenv("AUTOPANEL_TEST_STALWART"), os.Getenv("AUTOPANEL_TEST_STALWART_KEY")
	if url == "" || keyFile == "" {
		t.Skip("needs a throwaway Stalwart: AUTOPANEL_TEST_STALWART and AUTOPANEL_TEST_STALWART_KEY")
	}
	raw, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	key := strings.TrimSpace(string(raw))
	tg := conformance.Target{Server: Product{}.Client(url, func(context.Context) (string, error) { return key, nil }),
		Domain: "autopanel-conformance.example.net"}
	if addr := os.Getenv("AUTOPANEL_TEST_STALWART_IMAP"); addr != "" {
		tg.SignIn = func(user, secret string) bool { return imapSignIn(t, addr, user, secret) }
	}
	conformance.Run(t, tg)
}

// imapSignIn is a LOGIN over IMAPS, the certificate not checked (a throwaway
// Stalwart serves its own).
func imapSignIn(t *testing.T, addr, user, secret string) bool {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // a throwaway server's own certificate
	if err != nil {
		t.Fatalf("IMAPS %s: %v", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	r := bufio.NewReader(conn)
	if _, err := r.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(conn, "a1 LOGIN %q %q\r\n", user, secret)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(line, "a1 ") {
			return strings.HasPrefix(line, "a1 OK")
		}
	}
}

func selfSignedPEM(t *testing.T, host string) (string, string) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: host},
		DNSNames: []string{host}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(30 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalPKCS8PrivateKey(k)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}))
}

func parsePEMLeaf(p string) *x509.Certificate {
	b, _ := pem.Decode([]byte(p))
	if b == nil {
		return nil
	}
	c, _ := x509.ParseCertificate(b.Bytes)
	return c
}

// TestBootstrapAgainstStalwart sets a freshly started Stalwart up, on a
// throwaway machine: AUTOPANEL_TEST_STALWART_FRESH names its rootless Podman
// container, never set up, and AUTOPANEL_TEST_STALWART its management URL.
// Restarts and the first start's banner are the container's own; the
// sealed values stay in memory. The key it seals must then sign in.
func TestBootstrapAgainstStalwart(t *testing.T) {
	name, url := os.Getenv("AUTOPANEL_TEST_STALWART_FRESH"), os.Getenv("AUTOPANEL_TEST_STALWART")
	if name == "" || url == "" {
		t.Skip("needs a fresh throwaway Stalwart: AUTOPANEL_TEST_STALWART_FRESH and AUTOPANEL_TEST_STALWART")
	}
	env := &podmanEnv{t: t, name: name, base: url, sealed: map[string][]byte{}}
	ctx := context.Background()
	if err := (Product{}).Bootstrap(ctx, env); err != nil {
		t.Fatal(err)
	}
	if env.restarts != 2 {
		t.Fatalf("restarts: %d", env.restarts)
	}
	s := Product{}.Client(url, func(context.Context) (string, error) { return string(env.sealed[provider.SealedAPIKey]), nil })
	if _, err := s.Domains(ctx); err != nil {
		t.Fatalf("the sealed key does not sign in: %v", err)
	}
	// Once more, as after a failure: nothing is made twice.
	if err := (Product{}).Bootstrap(ctx, env); err != nil {
		t.Fatalf("again: %v", err)
	}
}

// podmanEnv is a bootstrap's environment over a Podman container.
type podmanEnv struct {
	t        *testing.T
	name     string
	base     string
	restarts int
	sealed   map[string][]byte
}

func (e *podmanEnv) Base() string { return e.base }
func (e *podmanEnv) Settings() provider.Settings {
	return provider.Settings{Host: "mail.example.net", FirstDomain: "example.net"}
}
func (e *podmanEnv) FirstCredential(context.Context) (string, error) {
	out, err := exec.Command("podman", "logs", e.name).CombinedOutput()
	if err != nil {
		return "", err
	}
	found := ""
	for _, l := range strings.Split(string(out), "\n") {
		if c, ok := (Product{}).FirstCredential(l); ok {
			found = c
		}
	}
	if found == "" {
		return "", errors.New("no banner")
	}
	return found, nil
}
func (e *podmanEnv) Restart(context.Context) error {
	e.restarts++
	if out, err := exec.Command("podman", "restart", e.name).CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, out)
	}
	for range 60 { // its management port answers a moment after the start
		if resp, err := http.Get(e.base + "/"); err == nil {
			resp.Body.Close()
			time.Sleep(2 * time.Second)
			return nil
		}
		time.Sleep(time.Second)
	}
	return errors.New("not back after a restart")
}
func (e *podmanEnv) Forwarder(context.Context) (string, error) { return "10.0.2.100/32", nil }
func (e *podmanEnv) Sealed(_ context.Context, n string) ([]byte, error) {
	v, ok := e.sealed[n]
	if !ok {
		return nil, provider.ErrNoSecret
	}
	return v, nil
}
func (e *podmanEnv) Seal(_ context.Context, n string, v []byte) error { e.sealed[n] = v; return nil }
