package stalwart

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// THE JMAP CLIENT — the few of Stalwart's management objects AutoPanel uses,
// over net/http and encoding/json, against its management port on loopback.
// Stalwart v1 is managed through JMAP: its objects are `x:` methods under the
// urn:stalwart:jmap capability, at /jmap/.
//
// Decision: docs/decisions/mail.md#mails-rules-name-no-mail-server

// usingCaps is every request's capability list.
var usingCaps = []string{"urn:ietf:params:jmap:core", "urn:stalwart:jmap"}

// callTimeout bounds one request.
const callTimeout = 15 * time.Second

// maxAnswer bounds what one answer may be.
const maxAnswer = 4 << 20

// Client calls Stalwart's management API.
type Client struct {
	base string                                    // "http://127.0.0.1:18480"
	auth func(ctx context.Context) (string, error) // the Authorization header's value
	http *http.Client
}

// NewClient is a client of the API at base, signing in with what auth gives.
func NewClient(base string, auth func(ctx context.Context) (string, error)) *Client {
	return &Client{base: strings.TrimRight(base, "/"), auth: auth, http: &http.Client{Timeout: callTimeout}}
}

// Basic is auth for a user name and password.
func Basic(user, password string) func(context.Context) (string, error) {
	return func(context.Context) (string, error) {
		req, _ := http.NewRequest(http.MethodGet, "/", nil)
		req.SetBasicAuth(user, password)
		return req.Header.Get("Authorization"), nil
	}
}

// Bearer is auth for an API key that key reads.
func Bearer(key func(ctx context.Context) (string, error)) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		k, err := key(ctx)
		if err != nil {
			return "", err
		}
		return "Bearer " + k, nil
	}
}

// ErrUnauthorized is a credential Stalwart refused.
var ErrUnauthorized = errors.New("mail: Stalwart refused the credential")

// MethodError is a JMAP method's own error: ["error", {type, description}].
type MethodError struct {
	Method, Type, Description string
}

func (e *MethodError) Error() string {
	return fmt.Sprintf("mail: %s: %s: %s", e.Method, e.Type, e.Description)
}

// SetError is one object Stalwart would not create, update or destroy.
type SetError struct {
	Method      string   `json:"-"`
	Type        string   `json:"type"`
	Description string   `json:"description"`
	Properties  []string `json:"properties"`
}

func (e *SetError) Error() string {
	msg := fmt.Sprintf("mail: %s refused: %s", e.Method, e.Type)
	if e.Description != "" {
		msg += ": " + e.Description
	}
	if len(e.Properties) > 0 {
		msg += " (" + strings.Join(e.Properties, ", ") + ")"
	}
	return msg
}

// call sends one request of one method and decodes its answer's arguments
// into out.
func (c *Client) call(ctx context.Context, method string, args any, out any) error {
	body, err := json.Marshal(map[string]any{"using": usingCaps, "methodCalls": []any{[]any{method, args, "c"}}})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/jmap/", bytes.NewReader(body))
	if err != nil {
		return err
	}
	auth, err := c.auth(ctx)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer))
	if err != nil {
		return err
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return ErrUnauthorized
	case resp.StatusCode != http.StatusOK:
		return fmt.Errorf("mail: %s: Stalwart answered %d", method, resp.StatusCode)
	}
	var env struct {
		MethodResponses [][3]json.RawMessage `json:"methodResponses"`
	}
	if err := json.Unmarshal(raw, &env); err != nil || len(env.MethodResponses) != 1 {
		return fmt.Errorf("mail: %s: an answer that is no JMAP response", method)
	}
	var name string
	_ = json.Unmarshal(env.MethodResponses[0][0], &name)
	if name == "error" {
		var e struct{ Type, Description string }
		_ = json.Unmarshal(env.MethodResponses[0][1], &e)
		return &MethodError{Method: method, Type: e.Type, Description: e.Description}
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(env.MethodResponses[0][1], out)
}

// setAnswer is a /set method's answer.
type setAnswer struct {
	Created      map[string]json.RawMessage `json:"created"`
	Updated      map[string]json.RawMessage `json:"updated"`
	Destroyed    []string                   `json:"destroyed"`
	NotCreated   map[string]*SetError       `json:"notCreated"`
	NotUpdated   map[string]*SetError       `json:"notUpdated"`
	NotDestroyed map[string]*SetError       `json:"notDestroyed"`
}

// refused is the first object a /set refused, or nil.
func (a setAnswer) refused(method string) error {
	for _, m := range []map[string]*SetError{a.NotCreated, a.NotUpdated, a.NotDestroyed} {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			e := m[k]
			e.Method = method
			return e
		}
	}
	return nil
}

func (c *Client) set(ctx context.Context, object string, args map[string]any) (setAnswer, error) {
	var a setAnswer
	method := "x:" + object + "/set"
	if err := c.call(ctx, method, args, &a); err != nil {
		return a, err
	}
	return a, a.refused(method)
}

// --- the bootstrap ----------------------------------------------------------

// Bootstrap is what a fresh Stalwart is set up with: the only object it takes
// before it is.
type Bootstrap struct {
	Hostname string `json:"defaultHostname"`
	Domain   string `json:"defaultDomain"`
	// RequestTLSCertificate is off: the certificate is AutoPanel's.
	RequestTLSCertificate bool `json:"requestTlsCertificate"`
	// GenerateDKIMKeys is off: the first key goes through AutoPanel's rotation.
	GenerateDKIMKeys bool `json:"generateDkimKeys"`
}

// Admin is a Stalwart administrator's credential.
type Admin struct {
	Username string `json:"username"`
	Secret   string `json:"secret"`
}

// SetUp sets a fresh Stalwart up. It answers with the permanent
// administrator, which it gives only here. Stalwart does not restart by
// itself: the next start is its first as set up.
func (c *Client) SetUp(ctx context.Context, b Bootstrap) (Admin, error) {
	a, err := c.set(ctx, "Bootstrap", map[string]any{"update": map[string]any{"singleton": b}})
	if err != nil {
		return Admin{}, err
	}
	var admin Admin
	if raw, ok := a.Updated["singleton"]; ok {
		_ = json.Unmarshal(raw, &admin)
	}
	if admin.Username == "" || admin.Secret == "" {
		return Admin{}, errors.New("mail: Stalwart was set up but named no administrator")
	}
	return admin, nil
}

// --- listeners ---------------------------------------------------------------

// Listener is one of Stalwart's network listeners.
type Listener struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	Bind     map[string]bool `json:"bind"`
	Protocol string          `json:"protocol"`
}

// Listen is a listener as AutoPanel wants it.
type Listen struct {
	Name, Protocol string
	Port           int
	ImplicitTLS    bool
	Trusted        bool // reads a PROXY header from the forwarder
}

// Listeners are the listeners mail runs with, inside its container: high
// ports, so Stalwart binds nothing below 1024; the PROXY header read on the
// four the gate forwards; the management listener as Stalwart made it.
var Listeners = []Listen{
	{Name: "smtp", Protocol: "smtp", Port: 2525, Trusted: true},
	{Name: "submissions", Protocol: "smtp", Port: 4465, ImplicitTLS: true, Trusted: true},
	{Name: "submission", Protocol: "smtp", Port: 5587, Trusted: true},
	{Name: "imaps", Protocol: "imap", Port: 9993, ImplicitTLS: true, Trusted: true},
	{Name: "http", Protocol: "http", Port: 8080},
}

// ConfigureListeners makes Stalwart's listeners exactly want: each moved to
// its port and trusting the forwarder's address for PROXY headers, the
// missing ones made, and every other one (POP3, ManageSieve, Stalwart's own
// HTTPS) destroyed. They apply at Stalwart's next start.
func (c *Client) ConfigureListeners(ctx context.Context, want []Listen, forwarder string) error {
	var got struct {
		List []Listener `json:"list"`
	}
	if err := c.call(ctx, "x:NetworkListener/get", map[string]any{"ids": nil, "properties": []string{"name", "bind", "protocol"}}, &got); err != nil {
		return err
	}
	byName := map[string]Listen{}
	for _, l := range want {
		byName[l.Name] = l
	}
	trust := func(l Listen) map[string]bool {
		if !l.Trusted {
			return map[string]bool{}
		}
		return map[string]bool{forwarder: true}
	}
	update, create := map[string]any{}, map[string]any{}
	var destroy []string
	seen := map[string]bool{}
	for _, l := range got.List {
		w, ok := byName[l.Name]
		if !ok || seen[l.Name] {
			destroy = append(destroy, l.ID)
			continue
		}
		seen[l.Name] = true
		update[l.ID] = map[string]any{"bind": map[string]bool{fmt.Sprintf("[::]:%d", w.Port): true}, "overrideProxyTrustedNetworks": trust(w)}
	}
	for _, w := range want {
		if seen[w.Name] {
			continue
		}
		create[w.Name] = map[string]any{"name": w.Name, "protocol": w.Protocol, "bind": map[string]bool{fmt.Sprintf("[::]:%d", w.Port): true},
			"useTls": w.Protocol != "http", "implicitTls": w.ImplicitTLS, "overrideProxyTrustedNetworks": trust(w)}
	}
	args := map[string]any{}
	if len(update) > 0 {
		args["update"] = update
	}
	if len(create) > 0 {
		args["create"] = create
	}
	if len(destroy) > 0 {
		args["destroy"] = destroy
	}
	if len(args) == 0 {
		return nil
	}
	_, err := c.set(ctx, "NetworkListener", args)
	return err
}

// --- API keys ----------------------------------------------------------------

// CreateAPIKey makes an API key of the administrator's, and answers its
// secret, once.
func (c *Client) CreateAPIKey(ctx context.Context, description string) (id, secret string, err error) {
	a, err := c.set(ctx, "ApiKey", map[string]any{"create": map[string]any{"k": map[string]any{"description": description}}})
	if err != nil {
		return "", "", err
	}
	var k struct{ ID, Secret string }
	if raw, ok := a.Created["k"]; ok {
		_ = json.Unmarshal(raw, &k)
	}
	if k.Secret == "" {
		return "", "", errors.New("mail: Stalwart made an API key but answered no secret")
	}
	return k.ID, k.Secret, nil
}

// --- domains -----------------------------------------------------------------

// Domain is one of Stalwart's mail domains.
type Domain struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Domains are Stalwart's domains, by name.
func (c *Client) Domains(ctx context.Context) ([]Domain, error) {
	var got struct {
		List []Domain `json:"list"`
	}
	if err := c.call(ctx, "x:Domain/get", map[string]any{"ids": nil, "properties": []string{"name"}}, &got); err != nil {
		return nil, err
	}
	sort.Slice(got.List, func(i, j int) bool { return got.List[i].Name < got.List[j].Name })
	return got.List, nil
}

// AddDomain makes a domain with DKIM, DNS and certificates all manual:
// AutoPanel publishes its records and runs its keys, and nothing signs until
// its first key's record resolves.
func (c *Client) AddDomain(ctx context.Context, name string) (Domain, error) {
	manual := map[string]string{"@type": "Manual"}
	a, err := c.set(ctx, "Domain", map[string]any{"create": map[string]any{"d": map[string]any{
		"name": name, "dkimManagement": manual, "dnsManagement": manual, "certificateManagement": manual}}})
	if err != nil {
		return Domain{}, err
	}
	var d Domain
	if raw, ok := a.Created["d"]; ok {
		_ = json.Unmarshal(raw, &d)
	}
	d.Name = name
	return d, nil
}

// RemoveDomain destroys a domain.
func (c *Client) RemoveDomain(ctx context.Context, id string) error {
	_, err := c.set(ctx, "Domain", map[string]any{"destroy": []string{id}})
	return err
}

// ZoneFile is the zone file Stalwart writes for a domain: every record it
// would have published, in master-file form.
func (c *Client) ZoneFile(ctx context.Context, id string) (string, error) {
	var got struct {
		List []struct {
			DNSZoneFile string `json:"dnsZoneFile"`
		} `json:"list"`
	}
	if err := c.call(ctx, "x:Domain/get", map[string]any{"ids": []string{id}, "properties": []string{"dnsZoneFile"}}, &got); err != nil {
		return "", err
	}
	if len(got.List) != 1 {
		return "", fmt.Errorf("mail: Stalwart has no domain %q", id)
	}
	return got.List[0].DNSZoneFile, nil
}

// --- accounts ----------------------------------------------------------------

// Account is one of Stalwart's user accounts.
type Account struct {
	ID       string  `json:"id"`
	Name     string  `json:"name"`     // the local part
	DomainID string  `json:"domainId"` // its domain
	Address  string  `json:"emailAddress"`
	Quota    int64   `json:"-"` // bytes; 0 for none
	Used     int64   `json:"usedDiskQuota"`
	Aliases  []Alias `json:"-"` // the enabled ones
	Admin    bool    `json:"-"` // Stalwart's administrator: the one the bootstrap made
	Disabled bool    `json:"-"` // its permissions take away authenticate: it signs nothing in
	// AppPasswordLimit is quotas' maxAppPasswords; 0 when unset (Stalwart's
	// default of 5 applies).
	AppPasswordLimit int64 `json:"-"`
}

// Alias is an extra address of an account's.
type Alias struct {
	Name     string // the local part
	DomainID string
}

// Accounts are every user account.
func (c *Client) Accounts(ctx context.Context) ([]Account, error) {
	var got struct {
		List []struct {
			Account
			Type   string           `json:"@type"`
			Quotas map[string]int64 `json:"quotas"`
			Roles  struct {
				Type string `json:"@type"`
			} `json:"roles"`
			Aliases map[string]struct {
				Name     string `json:"name"`
				DomainID string `json:"domainId"`
				Enable   bool   `json:"enable"`
			} `json:"aliases"`
			Permissions permissions `json:"permissions"`
		} `json:"list"`
	}
	if err := c.call(ctx, "x:Account/get", map[string]any{"ids": nil}, &got); err != nil {
		return nil, err
	}
	out := make([]Account, 0, len(got.List))
	for _, a := range got.List {
		if a.Type != "" && a.Type != "User" {
			continue
		}
		acc := a.Account
		acc.Quota = a.Quotas["maxDiskQuota"]
		acc.AppPasswordLimit = a.Quotas["maxAppPasswords"]
		acc.Admin = a.Roles.Type == "Admin"
		acc.Disabled = a.Permissions.Disabled[permAuthenticate]
		for _, al := range a.Aliases {
			if al.Enable {
				acc.Aliases = append(acc.Aliases, Alias{Name: al.Name, DomainID: al.DomainID})
			}
		}
		sort.Slice(acc.Aliases, func(i, j int) bool { return acc.Aliases[i].Name < acc.Aliases[j].Name })
		out = append(out, acc)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Address < out[j].Address })
	return out, nil
}

// NewAccount is an account to make.
type NewAccount struct {
	Name     string // the local part, validated
	DomainID string
	Secret   string // the password's hash: Stalwart verifies it and never holds the password
	Quota    int64  // bytes
	// AppPasswords is the account's limit of app passwords; 0 leaves
	// Stalwart's default of 5. One expired but not destroyed counts.
	AppPasswords int64
}

// AddAccount makes a user account with a password's hash, a disk quota and
// its limit of app passwords.
func (c *Client) AddAccount(ctx context.Context, n NewAccount) (string, error) {
	quotas := map[string]int64{"maxDiskQuota": n.Quota}
	if n.AppPasswords > 0 {
		quotas["maxAppPasswords"] = n.AppPasswords
	}
	a, err := c.set(ctx, "Account", map[string]any{"create": map[string]any{"a": map[string]any{
		"@type": "User", "name": n.Name, "domainId": n.DomainID,
		"credentials": map[string]any{"0": map[string]any{"@type": "Password", "secret": n.Secret}},
		"quotas":      quotas}}})
	if err != nil {
		return "", err
	}
	var made struct{ ID string }
	if raw, ok := a.Created["a"]; ok {
		_ = json.Unmarshal(raw, &made)
	}
	return made.ID, nil
}

// SetSecret replaces the account's password (its hash) and nothing else.
// The credentials map holds the account's app passwords beside its password:
// sending the map would delete every one of them, and two-factor with them.
// So the password's own entry is found by its type, and its secret patched.
func (c *Client) SetSecret(ctx context.Context, id, secret string) error {
	var got struct {
		List []struct {
			Credentials map[string]struct {
				Type string `json:"@type"`
			} `json:"credentials"`
		} `json:"list"`
	}
	if err := c.call(ctx, "x:Account/get", map[string]any{"ids": []string{id}, "properties": []string{"credentials"}}, &got); err != nil {
		return err
	}
	if len(got.List) != 1 {
		return fmt.Errorf("mail: Stalwart has no account %q", id)
	}
	key := ""
	for k, cr := range got.List[0].Credentials {
		if cr.Type == "Password" {
			if key != "" {
				return errors.New("mail: the account has two passwords")
			}
			key = k
		}
	}
	if key == "" {
		return errors.New("mail: the account has no password")
	}
	_, err := c.set(ctx, "Account", map[string]any{"update": map[string]any{id: map[string]any{"credentials/" + key + "/secret": secret}}})
	return err
}

// permAuthenticate is the permission every sign-in needs: taken away, the
// account signs nothing in, by password or app password, over any protocol.
// Stalwart v1 has no other way to disable an account.
const permAuthenticate = "authenticate"

// permissions is an account's own permissions: inherited from its roles, or
// merged with these.
type permissions struct {
	Type     string          `json:"@type"`
	Enabled  map[string]bool `json:"enabledPermissions"`
	Disabled map[string]bool `json:"disabledPermissions"`
}

// SetDisabled takes authenticate from the account's permissions, or gives it
// back. Any other permission the account's own list holds is kept; a list
// left empty goes back to inheriting.
func (c *Client) SetDisabled(ctx context.Context, id string, disabled bool) error {
	var got struct {
		List []struct {
			Permissions permissions `json:"permissions"`
		} `json:"list"`
	}
	if err := c.call(ctx, "x:Account/get", map[string]any{"ids": []string{id}, "properties": []string{"permissions"}}, &got); err != nil {
		return err
	}
	if len(got.List) != 1 {
		return fmt.Errorf("mail: Stalwart has no account %q", id)
	}
	p := got.List[0].Permissions
	if p.Enabled == nil {
		p.Enabled = map[string]bool{}
	}
	if p.Disabled == nil {
		p.Disabled = map[string]bool{}
	}
	if disabled {
		p.Disabled[permAuthenticate] = true
	} else {
		delete(p.Disabled, permAuthenticate)
	}
	var value any = map[string]any{"@type": "Merge", "enabledPermissions": p.Enabled, "disabledPermissions": p.Disabled}
	if len(p.Enabled) == 0 && len(p.Disabled) == 0 {
		value = map[string]any{"@type": "Inherit"}
	}
	_, err := c.set(ctx, "Account", map[string]any{"update": map[string]any{id: map[string]any{"permissions": value}}})
	return err
}

// SetAliases replaces the account's aliases: every one given, enabled, and
// no other.
func (c *Client) SetAliases(ctx context.Context, id string, aliases []Alias) error {
	m := make(map[string]any, len(aliases))
	for i, a := range aliases {
		m[strconv.Itoa(i)] = map[string]any{"name": a.Name, "domainId": a.DomainID, "enable": true}
	}
	_, err := c.set(ctx, "Account", map[string]any{"update": map[string]any{id: map[string]any{"aliases": m}}})
	return err
}

// SetQuota sets an account's disk quota, in bytes. A patch: its other quotas
// (the app passwords' limit) stay.
func (c *Client) SetQuota(ctx context.Context, id string, bytes int64) error {
	_, err := c.set(ctx, "Account", map[string]any{"update": map[string]any{id: map[string]any{"quotas/maxDiskQuota": bytes}}})
	return err
}

// SetAppPasswordLimit sets how many app passwords an account may have.
func (c *Client) SetAppPasswordLimit(ctx context.Context, id string, n int64) error {
	_, err := c.set(ctx, "Account", map[string]any{"update": map[string]any{id: map[string]any{"quotas/maxAppPasswords": n}}})
	return err
}

// --- app passwords -------------------------------------------------------------

// AppPassword is one of an account's app passwords. Its secret is Stalwart's
// alone: answered once, when it is made, and read back as ****.
type AppPassword struct {
	ID          string     `json:"id"`
	Description string     `json:"description"`
	CreatedAt   time.Time  `json:"createdAt"`
	ExpiresAt   *time.Time `json:"expiresAt"` // nil: it never expires
}

// AppPasswords are an account's app passwords, oldest first.
func (c *Client) AppPasswords(ctx context.Context, accountID string) ([]AppPassword, error) {
	var got struct {
		List []AppPassword `json:"list"`
	}
	if err := c.call(ctx, "x:AppPassword/get", map[string]any{"accountId": accountID, "ids": nil,
		"properties": []string{"description", "createdAt", "expiresAt"}}, &got); err != nil {
		return nil, err
	}
	sort.Slice(got.List, func(i, j int) bool {
		if !got.List[i].CreatedAt.Equal(got.List[j].CreatedAt) {
			return got.List[i].CreatedAt.Before(got.List[j].CreatedAt)
		}
		return got.List[i].ID < got.List[j].ID
	})
	return got.List, nil
}

// AddAppPassword makes an app password for an account, expiring at expires,
// and answers it with its secret: Stalwart generates the secret, and gives it
// this once.
func (c *Client) AddAppPassword(ctx context.Context, accountID, description string, expires time.Time) (AppPassword, string, error) {
	a, err := c.set(ctx, "AppPassword", map[string]any{"accountId": accountID, "create": map[string]any{"p": map[string]any{
		"description": description, "expiresAt": expires.UTC().Format(time.RFC3339)}}})
	if err != nil {
		return AppPassword{}, "", err
	}
	var made struct{ ID, Secret string }
	if raw, ok := a.Created["p"]; ok {
		_ = json.Unmarshal(raw, &made)
	}
	if made.ID == "" || made.Secret == "" {
		return AppPassword{}, "", errors.New("mail: Stalwart made an app password but answered no secret")
	}
	e := expires.UTC()
	return AppPassword{ID: made.ID, Description: description, ExpiresAt: &e}, made.Secret, nil
}

// KeepAppPassword clears an app password's expiry: it works until revoked.
// Stalwart revives an expired one this way too, so the caller checks first.
func (c *Client) KeepAppPassword(ctx context.Context, accountID, id string) error {
	_, err := c.set(ctx, "AppPassword", map[string]any{"accountId": accountID, "update": map[string]any{id: map[string]any{"expiresAt": nil}}})
	return err
}

// RevokeAppPassword destroys an app password.
func (c *Client) RevokeAppPassword(ctx context.Context, accountID, id string) error {
	_, err := c.set(ctx, "AppPassword", map[string]any{"accountId": accountID, "destroy": []string{id}})
	return err
}

// RemoveAccount destroys an account and its mail.
func (c *Client) RemoveAccount(ctx context.Context, id string) error {
	_, err := c.set(ctx, "Account", map[string]any{"destroy": []string{id}})
	return err
}

// --- actions -----------------------------------------------------------------

// ReloadTLS has Stalwart serve its certificates as they are now.
func (c *Client) ReloadTLS(ctx context.Context) error {
	_, err := c.set(ctx, "Action", map[string]any{"create": map[string]any{"a": map[string]any{"@type": "ReloadTlsCertificates"}}})
	return err
}

// --- DKIM keys ---------------------------------------------------------------

// DKIMKey is one of Stalwart's DKIM keys.
type DKIMKey struct {
	ID       string `json:"id"`
	Selector string `json:"selector"`
	DomainID string `json:"domainId"`
	Stage    string `json:"stage"`
	Kind     string `json:"@type"`
}

// DKIMKeys are every DKIM key Stalwart holds.
func (c *Client) DKIMKeys(ctx context.Context) ([]DKIMKey, error) {
	var got struct {
		List []DKIMKey `json:"list"`
	}
	err := c.call(ctx, "x:DkimSignature/get", map[string]any{"ids": nil, "properties": []string{"@type", "selector", "domainId", "stage"}}, &got)
	return got.List, err
}

// AddDKIM gives Stalwart a key AutoPanel made, not yet signing.
func (c *Client) AddDKIM(ctx context.Context, domainID, selector, kind, pemKey string) (string, error) {
	a, err := c.set(ctx, "DkimSignature", map[string]any{"create": map[string]any{"k": map[string]any{
		"@type": kind, "domainId": domainID, "selector": selector, "stage": "pending",
		"privateKey": map[string]any{"@type": "Text", "secret": pemKey}}}})
	if err != nil {
		return "", err
	}
	var made struct{ ID string }
	if raw, ok := a.Created["k"]; ok {
		_ = json.Unmarshal(raw, &made)
	}
	return made.ID, nil
}

// SetDKIMStage moves a key: "active" signs, "retiring" stops signing.
func (c *Client) SetDKIMStage(ctx context.Context, id, stage string) error {
	if id == "" {
		return errors.New("mail: Stalwart holds no key of that selector")
	}
	_, err := c.set(ctx, "DkimSignature", map[string]any{"update": map[string]any{id: map[string]any{"stage": stage}}})
	return err
}

// RemoveDKIM deletes a key.
func (c *Client) RemoveDKIM(ctx context.Context, id string) error {
	_, err := c.set(ctx, "DkimSignature", map[string]any{"destroy": []string{id}})
	return err
}

// --- certificates -------------------------------------------------------------

// Certificate is one of Stalwart's TLS certificates.
type Certificate struct {
	ID       string          `json:"id"`
	SANs     map[string]bool `json:"subjectAlternativeNames"`
	NotAfter time.Time       `json:"notValidAfter"`
}

// Certificates are Stalwart's certificates.
func (c *Client) Certificates(ctx context.Context) ([]Certificate, error) {
	var got struct {
		List []Certificate `json:"list"`
	}
	err := c.call(ctx, "x:Certificate/get", map[string]any{"ids": nil, "properties": []string{"subjectAlternativeNames", "notValidAfter"}}, &got)
	return got.List, err
}

// PutCertificate replaces certificate id with a chain and key (PEM), or makes
// one when id is empty, answering its id.
func (c *Client) PutCertificate(ctx context.Context, id, chainPEM, keyPEM string) (string, error) {
	obj := map[string]any{"certificate": map[string]any{"@type": "Text", "value": chainPEM},
		"privateKey": map[string]any{"@type": "Text", "secret": keyPEM}}
	if id != "" {
		_, err := c.set(ctx, "Certificate", map[string]any{"update": map[string]any{id: obj}})
		return id, err
	}
	a, err := c.set(ctx, "Certificate", map[string]any{"create": map[string]any{"c": obj}})
	if err != nil {
		return "", err
	}
	var made struct{ ID string }
	if raw, ok := a.Created["c"]; ok {
		_ = json.Unmarshal(raw, &made)
	}
	return made.ID, nil
}
