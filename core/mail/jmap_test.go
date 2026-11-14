package mail

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// fakeStalwart answers one JMAP method call with what answer gives, and keeps
// the last request's method and arguments.
type fakeStalwart struct {
	t      *testing.T
	method string
	args   map[string]any
	auth   string
	answer func(method string, args map[string]any) (string, any)
}

func (f *fakeStalwart) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.auth = r.Header.Get("Authorization")
	if r.URL.Path != "/jmap/" || r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if f.auth == "Bearer wrong" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var req struct {
		Using       []string            `json:"using"`
		MethodCalls [][]json.RawMessage `json:"methodCalls"`
	}
	body, _ := io.ReadAll(r.Body)
	if err := json.Unmarshal(body, &req); err != nil || len(req.MethodCalls) != 1 {
		f.t.Fatalf("a request that is no single method call: %s", body)
	}
	_ = json.Unmarshal(req.MethodCalls[0][0], &f.method)
	_ = json.Unmarshal(req.MethodCalls[0][1], &f.args)
	name, out := f.answer(f.method, f.args)
	_ = json.NewEncoder(w).Encode(map[string]any{"methodResponses": []any{[]any{name, out, "c"}}, "sessionState": "x"})
}

func newFake(t *testing.T, answer func(string, map[string]any) (string, any)) (*fakeStalwart, *Client) {
	f := &fakeStalwart{t: t, answer: answer}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, NewClient(srv.URL, Bearer(func(context.Context) (string, error) { return "k", nil }))
}

func TestSetUpAnswersTheAdministrator(t *testing.T) {
	f, c := newFake(t, func(m string, _ map[string]any) (string, any) {
		return m, map[string]any{"updated": map[string]any{"singleton": map[string]any{"username": "admin@example.net", "secret": "s3"}}}
	})
	admin, err := c.SetUp(context.Background(), Bootstrap{Hostname: "mail.example.net", Domain: "example.net"})
	if err != nil || admin.Username != "admin@example.net" || admin.Secret != "s3" {
		t.Fatalf("SetUp = %+v, %v", admin, err)
	}
	upd := f.args["update"].(map[string]any)["singleton"].(map[string]any)
	if f.method != "x:Bootstrap/set" || upd["requestTlsCertificate"] != false || upd["generateDkimKeys"] != false || upd["defaultHostname"] != "mail.example.net" {
		t.Fatalf("the bootstrap sent: %s %v", f.method, upd)
	}
	if f.auth != "Bearer k" {
		t.Fatalf("auth = %q", f.auth)
	}
}

func TestARefusalIsASetError(t *testing.T) {
	_, c := newFake(t, func(m string, _ map[string]any) (string, any) {
		return m, map[string]any{"notUpdated": map[string]any{"singleton": map[string]any{"type": "invalidProperties", "description": "Invalid server hostname", "properties": []string{"defaultHostname"}}}}
	})
	_, err := c.SetUp(context.Background(), Bootstrap{Hostname: "mail.example", Domain: "example"})
	var se *SetError
	if !errors.As(err, &se) || se.Type != "invalidProperties" || !strings.Contains(err.Error(), "defaultHostname") {
		t.Fatalf("err = %v", err)
	}
}

func TestAMethodErrorAndAnUnauthorized(t *testing.T) {
	_, c := newFake(t, func(string, map[string]any) (string, any) {
		return "error", map[string]any{"type": "forbidden", "description": "The server is in bootstrap mode."}
	})
	var me *MethodError
	if _, err := c.Domains(context.Background()); !errors.As(err, &me) || me.Type != "forbidden" {
		t.Fatalf("err = %v", err)
	}
	c.auth = Bearer(func(context.Context) (string, error) { return "wrong", nil })
	if _, err := c.Domains(context.Background()); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("a refused key: %v", err)
	}
}

func TestConfigureListeners(t *testing.T) {
	var sent map[string]any
	_, c := newFake(t, func(m string, args map[string]any) (string, any) {
		if m == "x:NetworkListener/get" {
			return m, map[string]any{"list": []any{
				map[string]any{"id": "l1", "name": "smtp", "bind": map[string]bool{"[::]:25": true}, "protocol": "smtp"},
				map[string]any{"id": "l2", "name": "pop3s", "bind": map[string]bool{"[::]:995": true}, "protocol": "pop3"},
				map[string]any{"id": "l3", "name": "http", "bind": map[string]bool{"[::]:8080": true}, "protocol": "http"},
			}}
		}
		sent = args
		return m, map[string]any{}
	})
	if err := c.ConfigureListeners(context.Background(), Listeners, "10.0.2.100/32"); err != nil {
		t.Fatal(err)
	}
	upd := sent["update"].(map[string]any)
	smtp := upd["l1"].(map[string]any)
	if _, ok := smtp["bind"].(map[string]any)["[::]:2525"]; !ok {
		t.Fatalf("smtp not moved to 2525: %v", smtp)
	}
	if _, ok := smtp["overrideProxyTrustedNetworks"].(map[string]any)["10.0.2.100/32"]; !ok {
		t.Fatalf("smtp does not trust the forwarder: %v", smtp)
	}
	if http := upd["l3"].(map[string]any); len(http["overrideProxyTrustedNetworks"].(map[string]any)) != 0 {
		t.Fatalf("the management listener must trust no PROXY header: %v", http)
	}
	if d := sent["destroy"].([]any); len(d) != 1 || d[0] != "l2" {
		t.Fatalf("destroy = %v; want pop3s alone", d)
	}
	created := sent["create"].(map[string]any)
	for _, name := range []string{"submissions", "submission", "imaps"} {
		if _, ok := created[name]; !ok {
			t.Errorf("%s not created: %v", name, created)
		}
	}
	if sub := created["submission"].(map[string]any); sub["implicitTls"] != false || sub["useTls"] != true {
		t.Errorf("submission is STARTTLS: %v", sub)
	}
}

func TestAddDomainIsManualThroughout(t *testing.T) {
	f, c := newFake(t, func(m string, _ map[string]any) (string, any) {
		return m, map[string]any{"created": map[string]any{"d": map[string]any{"id": "b"}}}
	})
	d, err := c.AddDomain(context.Background(), "example.net")
	if err != nil || d.ID != "b" || d.Name != "example.net" {
		t.Fatalf("AddDomain = %+v, %v", d, err)
	}
	made := f.args["create"].(map[string]any)["d"].(map[string]any)
	for _, k := range []string{"dkimManagement", "dnsManagement", "certificateManagement"} {
		if made[k].(map[string]any)["@type"] != "Manual" {
			t.Errorf("%s = %v; want Manual", k, made[k])
		}
	}
}

// TestAgainstStalwart runs the client against a real Stalwart, on a throwaway
// machine: AUTOPANEL_TEST_STALWART names its management URL and
// AUTOPANEL_TEST_STALWART_KEY a file holding an API key. It adds and removes a
// domain and an account of its own, and touches nothing else.
func TestAgainstStalwart(t *testing.T) {
	url, keyFile := os.Getenv("AUTOPANEL_TEST_STALWART"), os.Getenv("AUTOPANEL_TEST_STALWART_KEY")
	if url == "" || keyFile == "" {
		t.Skip("needs a throwaway Stalwart: AUTOPANEL_TEST_STALWART and AUTOPANEL_TEST_STALWART_KEY")
	}
	raw, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	key := strings.TrimSpace(string(raw))
	ctx := context.Background()
	c := NewClient(url, Bearer(func(context.Context) (string, error) { return key, nil }))

	d, err := c.AddDomain(ctx, "autopanel-test.example.net")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.RemoveDomain(context.Background(), d.ID) })
	zone, err := c.ZoneFile(ctx, d.ID)
	if err != nil || !strings.Contains(zone, "IN MX") || strings.Contains(zone, "_domainkey") {
		t.Fatalf("a new manual domain's zone: %v\n%s", err, zone)
	}
	id, err := c.AddAccount(ctx, NewAccount{Name: "probe", DomainID: d.ID, Password: "a-long-test-password-1", Quota: 1 << 30})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.RemoveAccount(context.Background(), id) })
	if err := c.SetPassword(ctx, id, "a-long-test-password-2"); err != nil {
		t.Fatal(err)
	}
	if err := c.SetQuota(ctx, id, 2<<30); err != nil {
		t.Fatal(err)
	}
	accounts, err := c.Accounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var found *Account
	for i := range accounts {
		if accounts[i].ID == id {
			found = &accounts[i]
		}
	}
	if found == nil || found.Address != "probe@autopanel-test.example.net" || found.Quota != 2<<30 {
		t.Fatalf("the account as listed: %+v", found)
	}
	if err := c.RemoveAccount(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := c.RemoveDomain(ctx, d.ID); err != nil {
		t.Fatal(err)
	}
}

func TestAccountsMarksTheAdministrator(t *testing.T) {
	_, c := newFake(t, func(m string, _ map[string]any) (string, any) {
		return m, map[string]any{"list": []any{
			map[string]any{"@type": "User", "id": "a", "name": "admin", "domainId": "b", "emailAddress": "admin@example.net", "roles": map[string]any{"@type": "Admin"}},
			map[string]any{"@type": "User", "id": "c", "name": "ana", "domainId": "b", "emailAddress": "ana@example.net", "roles": map[string]any{"@type": "User"},
				"quotas": map[string]any{"maxDiskQuota": 1024}, "usedDiskQuota": 10,
				"aliases": map[string]any{"0": map[string]any{"name": "a", "domainId": "b", "enable": true}, "1": map[string]any{"name": "off", "domainId": "b", "enable": false}}},
			map[string]any{"@type": "Group", "id": "g", "name": "team", "domainId": "b"},
		}}
	})
	got, err := c.Accounts(context.Background())
	if err != nil || len(got) != 2 {
		t.Fatalf("Accounts = %+v, %v; want the two users, no group", got, err)
	}
	if !got[0].Admin || got[1].Admin {
		t.Fatalf("admin flags: %+v", got)
	}
	if got[1].Quota != 1024 || got[1].Used != 10 || len(got[1].Aliases) != 1 || got[1].Aliases[0].Name != "a" {
		t.Fatalf("ana: %+v", got[1])
	}
}
