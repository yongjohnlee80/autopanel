package mail

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

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

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// readyMail is a mail module that is set up and bootstrapped, talking to a
// fake Stalwart's accounts.
func readyMail(t *testing.T) (*Module, *accountsStalwart, *clock) {
	t.Helper()
	m, st, v, _, _, _ := newTestModule(t)
	st.state = &State{Host: "mail.example.net", CreatedAt: 1, Bootstrapped: 1}
	st.domains = []string{"example.net"}
	v.m[sealedKey] = []byte("k")
	clk := &clock{t: time.Date(2026, 11, 17, 9, 0, 0, 0, time.UTC)}
	m.now = clk.now
	fake := newAccountsStalwart(t, clk.now)
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	m.base = srv.URL
	return m, fake, clk
}

func TestStrongSecret(t *testing.T) {
	for _, c := range []struct {
		s    string
		want bool
	}{
		{stalwartLike(1), true}, // Stalwart's: 36 of [a-z0-9], about 186 bits
		{stalwartLike(2), true},
		{"app_qwertyuiopasdfghjklzxcvb", false}, // 24 lowercase letters: 113 bits
		{"app_qWeRtY1u2I3oPaSdF4g5H6jK", true},  // 24 of 62: 143 bits
		{stalwartLike(3)[4:] + "abcd", false},   // no app_
		{"app_", false},
		{stalwartLike(4)[:20] + " " + stalwartLike(4)[20:], false}, // a space
		{"app_" + strings.Repeat("a1b2c3", 10), false},             // six characters, repeated
		{"app_" + strings.Repeat("é1", 20), false},                 // not ASCII
	} {
		if got := strongSecret(c.s); got != c.want {
			t.Errorf("strongSecret(%q) = %v; want %v", c.s, got, c.want)
		}
	}
}

// TestAnAccountIsMadeWithNoKnownPassword: mail.account.add takes no password;
// Stalwart is given an argon2id hash of one no one is told, and room for 20
// app passwords.
func TestAnAccountIsMadeWithNoKnownPassword(t *testing.T) {
	m, fake, _ := readyMail(t)
	ctx := context.Background()
	if _, err := m.accountAdd(ctx, AccountAsk{Address: "ana@example.net"}); err != nil {
		t.Fatal(err)
	}
	a := fake.only("ana@example.net")
	if a == nil || !strings.HasPrefix(a.secret, "$argon2id$v=19$m=8192,t=1,p=1$") {
		t.Fatalf("the secret Stalwart was given: %+v", a)
	}
	if a.quotas["maxAppPasswords"] != AppPasswordLimit || a.quotas["maxDiskQuota"] != defaultQuota {
		t.Fatalf("quotas: %v", a.quotas)
	}
	if _, err := m.accountAdd(ctx, AccountAsk{Address: "ben@example.net"}); err != nil {
		t.Fatal(err)
	}
	if b := fake.only("ben@example.net"); b.secret == a.secret {
		t.Fatal("two accounts were given the same secret")
	}
}

// TestAnAppPasswordIsPendingUntilKept: it signs in from the start, stops at
// ten minutes unless kept, and once kept works on.
func TestAnAppPasswordIsPendingUntilKept(t *testing.T) {
	m, fake, clk := readyMail(t)
	ctx := context.Background()
	if _, err := m.accountAdd(ctx, AccountAsk{Address: "ana@example.net"}); err != nil {
		t.Fatal(err)
	}
	n, err := m.appPasswordAdd(ctx, AppPasswordAsk{Address: "ana@example.net", Description: "  Ana's phone "})
	if err != nil {
		t.Fatal(err)
	}
	if n.User != "ana@example.net" || n.Host != "mail.example.net" || n.IMAP != 993 || n.SMTP != 465 || n.Submission != 587 {
		t.Fatalf("the settings: %+v", n)
	}
	if n.ExpiresAt != clk.now().Add(pendingFor).Unix() || !fake.signsIn("ana@example.net", n.Secret) {
		t.Fatalf("a new app password is not pending for ten minutes: %+v", n)
	}
	list, err := m.appPasswordList(ctx, AppPasswordAsk{Address: "ana@example.net"})
	if err != nil || len(list) != 1 || !list[0].Pending || list[0].Description != "Ana's phone" {
		t.Fatalf("the list: %+v, %v", list, err)
	}
	clk.add(3 * time.Minute)
	if _, err := m.appPasswordKeep(ctx, AppPasswordAsk{Address: "ana@example.net", ID: n.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.appPasswordKeep(ctx, AppPasswordAsk{Address: "ana@example.net", ID: n.ID}); err != nil {
		t.Fatalf("keeping twice: %v", err)
	}
	clk.add(time.Hour)
	if !fake.signsIn("ana@example.net", n.Secret) {
		t.Fatal("a kept app password stopped")
	}
	list, _ = m.appPasswordList(ctx, AppPasswordAsk{Address: "ana@example.net"})
	if len(list) != 1 || list[0].Pending || list[0].ExpiresAt != 0 {
		t.Fatalf("kept, the list: %+v", list)
	}
}

// TestAnExpiredAppPasswordIsNeverRevived: Stalwart brings an expired app
// password back when its expiry is cleared, so keep destroys it instead.
func TestAnExpiredAppPasswordIsNeverRevived(t *testing.T) {
	m, fake, clk := readyMail(t)
	ctx := context.Background()
	_, _ = m.accountAdd(ctx, AccountAsk{Address: "ana@example.net"})
	n, err := m.appPasswordAdd(ctx, AppPasswordAsk{Address: "ana@example.net", Description: "laptop"})
	if err != nil {
		t.Fatal(err)
	}
	clk.add(pendingFor - keepMargin/2) // inside the margin: as good as gone
	if _, err := m.appPasswordKeep(ctx, AppPasswordAsk{Address: "ana@example.net", ID: n.ID}); !errors.Is(err, ErrExpired) {
		t.Fatalf("keeping one about to expire: %v; want ErrExpired", err)
	}
	clk.add(time.Hour)
	if fake.signsIn("ana@example.net", n.Secret) || len(fake.only("ana@example.net").apps) != 0 {
		t.Fatal("an app password kept too late was revived, or left")
	}
	if _, err := m.appPasswordKeep(ctx, AppPasswordAsk{Address: "ana@example.net", ID: n.ID}); !errors.Is(err, ErrNoAppPassword) {
		t.Fatalf("keeping a destroyed one: %v", err)
	}
}

func TestRevokingAnAppPassword(t *testing.T) {
	m, fake, _ := readyMail(t)
	ctx := context.Background()
	_, _ = m.accountAdd(ctx, AccountAsk{Address: "ana@example.net"})
	_, _ = m.accountAdd(ctx, AccountAsk{Address: "ben@example.net"})
	phone, _ := m.appPasswordAdd(ctx, AppPasswordAsk{Address: "ana@example.net", Description: "phone"})
	laptop, _ := m.appPasswordAdd(ctx, AppPasswordAsk{Address: "ana@example.net", Description: "laptop"})
	if _, err := m.appPasswordRevoke(ctx, AppPasswordAsk{Address: "ben@example.net", ID: phone.ID}); !errors.Is(err, ErrNoAppPassword) {
		t.Fatalf("revoking another account's app password: %v", err)
	}
	if _, err := m.appPasswordRevoke(ctx, AppPasswordAsk{Address: "ana@example.net", ID: phone.ID}); err != nil {
		t.Fatal(err)
	}
	if fake.signsIn("ana@example.net", phone.Secret) || !fake.signsIn("ana@example.net", laptop.Secret) {
		t.Fatal("revoking one app password touched the wrong one")
	}
}

// TestAWeakSecretIsNeverHandedOut: a Stalwart whose generator weakened stops
// the feature; the weak app password is destroyed.
func TestAWeakSecretIsNeverHandedOut(t *testing.T) {
	m, fake, _ := readyMail(t)
	ctx := context.Background()
	_, _ = m.accountAdd(ctx, AccountAsk{Address: "ana@example.net"})
	fake.gen = func(int) string { return "app_abcdef" }
	if n, err := m.appPasswordAdd(ctx, AppPasswordAsk{Address: "ana@example.net", Description: "phone"}); !errors.Is(err, ErrWeakSecret) || n.Secret != "" {
		t.Fatalf("a weak secret: %+v, %v", n, err)
	}
	if len(fake.only("ana@example.net").apps) != 0 {
		t.Fatal("the weak app password was left")
	}
}

func TestADeviceNameIsChecked(t *testing.T) {
	m, _, _ := readyMail(t)
	ctx := context.Background()
	_, _ = m.accountAdd(ctx, AccountAsk{Address: "ana@example.net"})
	for _, d := range []string{"", "   ", strings.Repeat("x", 65), "tab\there"} {
		if _, err := m.appPasswordAdd(ctx, AppPasswordAsk{Address: "ana@example.net", Description: d}); !errors.Is(err, ErrBadDescription) {
			t.Errorf("device %q: %v", d, err)
		}
	}
}

// TestAnOlderAccountGetsRoomForAppPasswords: an account made before this has
// Stalwart's limit of 5; its first app password raises it to 20.
func TestAnOlderAccountGetsRoomForAppPasswords(t *testing.T) {
	m, fake, _ := readyMail(t)
	ctx := context.Background()
	fake.accounts["old"] = &fakeAccount{id: "old", name: "old", domainID: "dn", secret: "typed", quotas: map[string]int64{"maxDiskQuota": 1}}
	for i := range 6 {
		if _, err := m.appPasswordAdd(ctx, AppPasswordAsk{Address: "old@example.net", Description: "device " + strconv.Itoa(i)}); err != nil {
			t.Fatalf("app password %d: %v", i+1, err)
		}
	}
	if fake.only("old@example.net").quotas["maxAppPasswords"] != AppPasswordLimit {
		t.Fatal("the limit was not raised")
	}
}

// TestLockingKeepsTheAppPasswords: Lock password patches the password's own
// entry, wherever it sits in the credentials map; the app passwords stay.
func TestLockingKeepsTheAppPasswords(t *testing.T) {
	m, fake, _ := readyMail(t)
	ctx := context.Background()
	fake.accounts["old"] = &fakeAccount{id: "old", name: "old", domainID: "dn", secret: "typed-password", quotas: map[string]int64{}}
	phone, err := m.appPasswordAdd(ctx, AppPasswordAsk{Address: "old@example.net", Description: "phone"})
	if err != nil {
		t.Fatal(err)
	}
	fake.passwordFirst = false // the password's entry is not "0"
	if _, err := m.accountLock(ctx, AccountAsk{Address: "old@example.net"}); err != nil {
		t.Fatal(err)
	}
	a := fake.only("old@example.net")
	if !strings.HasPrefix(a.secret, "$argon2id$") || len(a.apps) != 1 || !fake.signsIn("old@example.net", phone.Secret) {
		t.Fatalf("after Lock password: secret %q, app passwords %d", a.secret[:min(10, len(a.secret))], len(a.apps))
	}
}

// TestSettingAQuotaKeepsTheAppPasswordLimit: the quota is a patch, not the
// quotas map (which would put the limit back to Stalwart's 5).
func TestSettingAQuotaKeepsTheAppPasswordLimit(t *testing.T) {
	m, fake, _ := readyMail(t)
	ctx := context.Background()
	_, _ = m.accountAdd(ctx, AccountAsk{Address: "ana@example.net"})
	if _, err := m.accountQuota(ctx, AccountAsk{Address: "ana@example.net", Quota: 2 << 30}); err != nil {
		t.Fatal(err)
	}
	q := fake.only("ana@example.net").quotas
	if q["maxDiskQuota"] != 2<<30 || q["maxAppPasswords"] != AppPasswordLimit {
		t.Fatalf("quotas: %v", q)
	}
}

// TestTheHourlyPassDestroysExpiredAppPasswords: shown and never kept, they
// are destroyed, and stop counting toward the limit; kept ones stay.
func TestTheHourlyPassDestroysExpiredAppPasswords(t *testing.T) {
	m, fake, clk := readyMail(t)
	ctx := context.Background()
	_, _ = m.accountAdd(ctx, AccountAsk{Address: "ana@example.net"})
	kept, _ := m.appPasswordAdd(ctx, AppPasswordAsk{Address: "ana@example.net", Description: "kept"})
	_, _ = m.appPasswordKeep(ctx, AppPasswordAsk{Address: "ana@example.net", ID: kept.ID})
	_, _ = m.appPasswordAdd(ctx, AppPasswordAsk{Address: "ana@example.net", Description: "left"})
	if list, _ := m.appPasswordList(ctx, AppPasswordAsk{Address: "ana@example.net"}); len(list) != 2 {
		t.Fatalf("before: %+v", list)
	}
	clk.add(pendingFor + time.Second)
	if list, _ := m.appPasswordList(ctx, AppPasswordAsk{Address: "ana@example.net"}); len(list) != 1 || list[0].ID != kept.ID {
		t.Fatalf("an expired one is listed: %+v", list)
	}
	if err := m.sweepAppPasswords(ctx, m.client()); err != nil {
		t.Fatal(err)
	}
	if apps := fake.only("ana@example.net").apps; len(apps) != 1 || apps[0].id != kept.ID {
		t.Fatalf("after the pass: %d app passwords", len(apps))
	}
}

// TestNoSecretLeavesTheVerbs: the list never carries a secret; only add's
// answer does.
func TestNoSecretLeavesTheVerbs(t *testing.T) {
	m, _, _ := readyMail(t)
	ctx := context.Background()
	_, _ = m.accountAdd(ctx, AccountAsk{Address: "ana@example.net"})
	n, _ := m.appPasswordAdd(ctx, AppPasswordAsk{Address: "ana@example.net", Description: "phone"})
	list, _ := m.appPasswordList(ctx, AppPasswordAsk{Address: "ana@example.net"})
	raw, _ := json.Marshal(list)
	if strings.Contains(string(raw), n.Secret) || strings.Contains(string(raw), "secret") {
		t.Fatalf("the list carries a secret: %s", raw)
	}
	accounts, _ := m.accountList(ctx, DomainAsk{})
	raw, _ = json.Marshal(accounts)
	if strings.Contains(string(raw), "argon2") {
		t.Fatalf("the account list carries a hash: %s", raw)
	}
}
