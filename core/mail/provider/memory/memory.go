// Package memory is a mail server in memory: provider.Server and
// provider.Product with no server behind them. core/mail's tests run on it,
// and it passes provider/conformance as any SDK must; that it can stand in for
// Stalwart is the proof that mail's rules need no particular server.
//
// It plays the worst a server may do where the contract allows it: an expired
// app password whose expiry is cleared works again, and a new certificate is
// served only after a restart.
package memory

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yongjohnlee80/autopanel/core/mail/provider"
)

// Server is a mail server in memory. Its zero value is not ready: use New.
type Server struct {
	mu sync.Mutex
	// Now is the server's clock: an app password's expiry is judged by it.
	Now func() time.Time
	// Secret makes the n-th app password's secret: app_ and 36 random
	// letters and digits unless a test says otherwise.
	Secret func(n int) string
	// Fail, when it answers an error for a method's name, makes that method
	// fail with it.
	Fail func(method string) error

	// Redirects is how many addresses the server sends one message on to;
	// 0 is a mail server's usual one.
	Redirects int

	seq      int
	domains  map[string]*provider.Domain
	accounts map[string]*account
	keys     map[string]*provider.DKIMKey
	certs    map[string]*provider.Certificate
	calls    []string
}

type account struct {
	provider.Account
	forward provider.Forward
	other   bool // a script of the owner's own is the active one
	hash    string
	limit   int
	apps    []*app
}

type app struct {
	provider.AppPassword
	secret string
}

// New is an empty server on the wall clock.
func New() *Server {
	return &Server{Now: time.Now, Secret: randomSecret, domains: map[string]*provider.Domain{},
		accounts: map[string]*account{}, keys: map[string]*provider.DKIMKey{}, certs: map[string]*provider.Certificate{}}
}

const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

func randomSecret(int) string {
	b := make([]byte, 36)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return "app_" + string(b)
}

var _ provider.Server = (*Server)(nil)

func (s *Server) enter(method string) error {
	s.calls = append(s.calls, method)
	if s.Fail != nil {
		return s.Fail(method)
	}
	return nil
}

func (s *Server) id() string {
	s.seq++
	return "m" + strconv.Itoa(s.seq)
}

func refuse(why string) error { return &provider.Refusal{Why: why} }

// Calls are the methods called, in order.
func (s *Server) Calls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.calls)
}

func (s *Server) Domains(context.Context) ([]provider.Domain, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.enter("Domains"); err != nil {
		return nil, err
	}
	var out []provider.Domain
	for _, d := range s.domains {
		out = append(out, *d)
	}
	slices.SortFunc(out, func(a, b provider.Domain) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

func (s *Server) AddDomain(_ context.Context, name string) (provider.Domain, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.enter("AddDomain"); err != nil {
		return provider.Domain{}, err
	}
	for _, d := range s.domains {
		if d.Name == name {
			return provider.Domain{}, refuse("the domain exists")
		}
	}
	d := &provider.Domain{ID: s.id(), Name: name}
	s.domains[d.ID] = d
	return *d, nil
}

func (s *Server) RemoveDomain(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.enter("RemoveDomain"); err != nil {
		return err
	}
	delete(s.domains, id)
	return nil
}

// Records are a domain's MX, SPF and DMARC, and a TXT record per DKIM key
// (its value names the selector: "v=DKIM1; k=<alg>; p=KEY<selector>").
func (s *Server) Records(_ context.Context, domainID string) ([]provider.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.enter("Records"); err != nil {
		return nil, err
	}
	d, ok := s.domains[domainID]
	if !ok {
		return nil, refuse("no such domain")
	}
	out := []provider.Record{
		{Type: "MX", Name: d.Name, Value: "10 mail." + d.Name},
		{Type: "TXT", Name: d.Name, Value: "v=spf1 mx -all"},
		{Type: "TXT", Name: "_dmarc." + d.Name, Value: "v=DMARC1; p=reject"},
	}
	for _, k := range s.keys {
		if k.DomainID == domainID {
			out = append(out, provider.Record{Type: "TXT", Name: k.Selector + "._domainkey." + d.Name,
				Value: "v=DKIM1; k=" + string(k.Alg) + "; p=KEY" + k.Selector})
		}
	}
	return out, nil
}

func (s *Server) Accounts(context.Context) ([]provider.Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.enter("Accounts"); err != nil {
		return nil, err
	}
	var out []provider.Account
	for _, a := range s.accounts {
		out = append(out, a.Account)
	}
	slices.SortFunc(out, func(a, b provider.Account) int { return strings.Compare(a.Address, b.Address) })
	return out, nil
}

func (s *Server) AddAccount(_ context.Context, n provider.NewAccount) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.enter("AddAccount"); err != nil {
		return "", err
	}
	d, ok := s.domains[n.DomainID]
	if !ok {
		return "", refuse("no such domain")
	}
	for _, a := range s.accounts {
		if a.Local == n.Local && a.DomainID == n.DomainID {
			return "", refuse("the account exists")
		}
	}
	a := &account{Account: provider.Account{ID: s.id(), Local: n.Local, DomainID: n.DomainID, Address: n.Local + "@" + d.Name, Quota: n.Quota},
		hash: unknownPassword(), limit: max(n.AppPasswords, 5)}
	s.accounts[a.ID] = a
	return a.ID, nil
}

// AddAdmin adds the server's administrator, as a bootstrap leaves it.
func (s *Server) AddAdmin(local, domainID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := &account{Account: provider.Account{ID: s.id(), Local: local, DomainID: domainID, Address: local + "@" + s.domains[domainID].Name, Admin: true}}
	s.accounts[a.ID] = a
	return a.ID
}

func (s *Server) account(id string) (*account, error) {
	a, ok := s.accounts[id]
	if !ok {
		return nil, refuse("no such account")
	}
	return a, nil
}

// unknownPassword stands for the hash of a password nobody knows: different
// every time, as a provider's must be.
func unknownPassword() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return "locked:" + hex.EncodeToString(b[:])
}

func (s *Server) LockPassword(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.enter("LockPassword"); err != nil {
		return err
	}
	a, err := s.account(id)
	if err != nil {
		return err
	}
	a.hash = unknownPassword()
	return nil
}

func (s *Server) SetQuota(_ context.Context, id string, bytes int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.enter("SetQuota"); err != nil {
		return err
	}
	a, err := s.account(id)
	if err != nil {
		return err
	}
	a.Quota = bytes
	return nil
}

func (s *Server) SetDisabled(_ context.Context, id string, disabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.enter("SetDisabled"); err != nil {
		return err
	}
	a, err := s.account(id)
	if err != nil {
		return err
	}
	a.Disabled = disabled
	return nil
}

// SetAliases replaces the account's aliases. As a real server would, it
// refuses one of a domain it does not hold, or an address another account
// holds as its own or as an alias.
func (s *Server) SetAliases(_ context.Context, id string, aliases []provider.Alias) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.enter("SetAliases"); err != nil {
		return err
	}
	a, err := s.account(id)
	if err != nil {
		return err
	}
	for _, al := range aliases {
		if _, ok := s.domains[al.DomainID]; !ok {
			return refuse("no such domain")
		}
		for _, o := range s.accounts {
			if o.Local == al.Local && o.DomainID == al.DomainID {
				return refuse("the address is an account's")
			}
			if o != a && slices.Contains(o.Aliases, al) {
				return refuse("the address is another account's alias")
			}
		}
	}
	a.Aliases = slices.Clone(aliases)
	return nil
}

// SetForward has the account's mail sent on to f.To. As a real server
// would, it leaves a script of the owner's own alone, and sends to no more
// addresses than it is set to.
func (s *Server) SetForward(_ context.Context, id string, f provider.Forward) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.enter("SetForward"); err != nil {
		return err
	}
	a, err := s.account(id)
	if err != nil {
		return err
	}
	if a.other {
		return refuse("a script AutoPanel did not write is the account's own")
	}
	if len(f.To) > s.redirects() {
		return provider.ErrTooManyForwards
	}
	if len(f.To) == 0 {
		a.forward = provider.Forward{}
		return nil
	}
	a.forward = provider.Forward{To: slices.Clone(f.To), Keep: f.Keep}
	return nil
}

func (s *Server) redirects() int {
	if s.Redirects <= 0 {
		return 1
	}
	return min(s.Redirects, provider.MaxForwards)
}

// Forward answers how the account forwards.
func (s *Server) Forward(_ context.Context, id string) (provider.ForwardState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.enter("Forward"); err != nil {
		return provider.ForwardState{}, err
	}
	a, err := s.account(id)
	if err != nil {
		return provider.ForwardState{}, err
	}
	st := provider.ForwardState{Max: s.redirects(), Other: a.other}
	if !a.other {
		st.Forward = provider.Forward{To: slices.Clone(a.forward.To), Keep: a.forward.Keep}
	}
	return st, nil
}

// OwnScript makes a script of the owner's own the account's active one, as
// someone does in the mail server itself; or removes it.
func (s *Server) OwnScript(id string, has bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a, ok := s.accounts[id]; ok {
		a.other = has
	}
}

func (s *Server) RemoveAccount(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.enter("RemoveAccount"); err != nil {
		return err
	}
	delete(s.accounts, id)
	return nil
}

func (s *Server) AppPasswords(_ context.Context, accountID string) ([]provider.AppPassword, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.enter("AppPasswords"); err != nil {
		return nil, err
	}
	a, err := s.account(accountID)
	if err != nil {
		return nil, err
	}
	out := make([]provider.AppPassword, 0, len(a.apps))
	for _, p := range a.apps {
		out = append(out, p.AppPassword)
	}
	return out, nil
}

func (s *Server) AddAppPassword(_ context.Context, accountID, device string, expires time.Time, room int) (provider.AppPassword, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.enter("AddAppPassword"); err != nil {
		return provider.AppPassword{}, "", err
	}
	a, err := s.account(accountID)
	if err != nil {
		return provider.AppPassword{}, "", err
	}
	a.limit = max(a.limit, room)
	if len(a.apps) >= a.limit { // an expired one still counts until destroyed
		return provider.AppPassword{}, "", provider.ErrOverLimit
	}
	e := expires.UTC()
	p := &app{AppPassword: provider.AppPassword{ID: s.id(), Device: device, CreatedAt: s.Now().UTC().Truncate(time.Second), ExpiresAt: &e},
		secret: s.Secret(s.seq)}
	a.apps = append(a.apps, p)
	return p.AppPassword, p.secret, nil
}

// KeepAppPassword clears the expiry, even of an expired one: it works again.
func (s *Server) KeepAppPassword(_ context.Context, accountID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.enter("KeepAppPassword"); err != nil {
		return err
	}
	a, err := s.account(accountID)
	if err != nil {
		return err
	}
	for _, p := range a.apps {
		if p.ID == id {
			p.ExpiresAt = nil
			return nil
		}
	}
	return refuse("no such app password")
}

func (s *Server) RevokeAppPassword(_ context.Context, accountID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.enter("RevokeAppPassword"); err != nil {
		return err
	}
	a, err := s.account(accountID)
	if err != nil {
		return err
	}
	n := len(a.apps)
	a.apps = slices.DeleteFunc(a.apps, func(p *app) bool { return p.ID == id })
	if len(a.apps) == n {
		return refuse("no such app password")
	}
	return nil
}

// SignIn is what a mail app's sign-in with user and secret would answer: an
// app password of the account at that address, not expired. The account's
// own password never signs a mail app in here, as AutoPanel's never do.
func (s *Server) SignIn(user, secret string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.accounts {
		if a.Address != user || a.Disabled {
			continue
		}
		for _, p := range a.apps {
			if p.secret == secret && (p.ExpiresAt == nil || p.ExpiresAt.After(s.Now())) {
				return true
			}
		}
	}
	return false
}

// PasswordHash stands for an account's password hash, for a test to see that
// it was made, and made anew.
func (s *Server) PasswordHash(address string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.accounts {
		if a.Address == address {
			return a.hash
		}
	}
	return ""
}

func (s *Server) DKIMKeys(context.Context) ([]provider.DKIMKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.enter("DKIMKeys"); err != nil {
		return nil, err
	}
	var out []provider.DKIMKey
	for _, k := range s.keys {
		out = append(out, *k)
	}
	slices.SortFunc(out, func(a, b provider.DKIMKey) int { return strings.Compare(a.Selector, b.Selector) })
	return out, nil
}

func (s *Server) AddDKIMKey(_ context.Context, domainID, selector string, alg provider.DKIMAlg, privatePEM string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.enter("AddDKIMKey"); err != nil {
		return "", err
	}
	if b, _ := pem.Decode([]byte(privatePEM)); b == nil {
		return "", refuse("the key is not PEM")
	} else if _, err := x509.ParsePKCS8PrivateKey(b.Bytes); err != nil {
		return "", refuse("the key is not PKCS #8: " + err.Error())
	}
	k := &provider.DKIMKey{ID: s.id(), DomainID: domainID, Selector: selector, Alg: alg, Stage: provider.Pending}
	s.keys[k.ID] = k
	return k.ID, nil
}

func (s *Server) SetDKIMStage(_ context.Context, id string, st provider.DKIMStage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.enter("SetDKIMStage"); err != nil {
		return err
	}
	k, ok := s.keys[id]
	if !ok {
		return refuse("no such key")
	}
	k.Stage = st
	return nil
}

func (s *Server) RemoveDKIMKey(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.enter("RemoveDKIMKey"); err != nil {
		return err
	}
	delete(s.keys, id)
	return nil
}

// Stages are the DKIM keys' stages, by selector.
func (s *Server) Stages() map[string]provider.DKIMStage {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]provider.DKIMStage{}
	for _, k := range s.keys {
		out[k.Selector] = k.Stage
	}
	return out
}

func (s *Server) Certificates(context.Context) ([]provider.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.enter("Certificates"); err != nil {
		return nil, err
	}
	var out []provider.Certificate
	for _, c := range s.certs {
		out = append(out, *c)
	}
	return out, nil
}

// ServeCertificate keeps the leaf's names and expiry; a new one needs a
// restart.
func (s *Server) ServeCertificate(_ context.Context, id, chainPEM, keyPEM string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.enter("ServeCertificate"); err != nil {
		return false, err
	}
	b, _ := pem.Decode([]byte(chainPEM))
	if b == nil {
		return false, refuse("the chain is not PEM")
	}
	leaf, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return false, refuse(err.Error())
	}
	if kb, _ := pem.Decode([]byte(keyPEM)); kb == nil {
		return false, refuse("the key is not PEM")
	}
	c := &provider.Certificate{ID: id, SANs: map[string]bool{}, NotAfter: leaf.NotAfter.UTC()}
	for _, n := range leaf.DNSNames {
		c.SANs[n] = true
	}
	if id == "" {
		c.ID = s.id()
	} else if _, ok := s.certs[id]; !ok {
		return false, refuse("no such certificate")
	}
	s.certs[c.ID] = c
	return id == "", nil
}

// Product is the server in memory as a product: a definition the stack review
// accepts, a first start whose credential is printed as "one-time: <it>", and
// a bootstrap that seals an API key. Its Client is Server, behind the key.
type Product struct {
	Server *Server
	// CPUError, when set, is what CPU answers.
	CPUError error
	// Key is the API key Bootstrap seals and Client requires.
	Key string
	// Bootstraps counts Bootstrap's runs.
	Bootstraps int

	// The repair's side (Repairer): the administrator the server takes, the
	// recovery administrator it started with (Start), how many
	// administrators it has, keys someone else made, and a failure a test
	// puts in a step's way.
	Admin      string
	Recovery   []byte
	Admins     int
	OtherKeys  []string
	RepairFail func(step string) error
	ours       int // the keys AutoPanel made that still exist
	keys       int
}

var _ provider.Product = (*Product)(nil)

// Image is the product's pinned image, which no registry holds.
const Image = "registry.invalid/mail@sha256:0000000000000000000000000000000000000000000000000000000000000001"

func (p *Product) Name() string { return "the memory server" }

func (p *Product) Service() string { return "mail" }

func (p *Product) Compose(st provider.Stack) []byte {
	ports, manage := st.Ports, st.Manage
	var b strings.Builder
	b.WriteString("services:\n  mail:\n    image: " + Image + "\n    user: \"2000:2000\"\n    ports:\n")
	for i, pm := range ports {
		fmt.Fprintf(&b, "      - \"127.0.0.1:%d:%d\"\n", pm.Loopback, 3000+i)
	}
	fmt.Fprintf(&b, "      - \"127.0.0.1:%d:8080\"\n    read_only: true\n    cap_drop:\n      - ALL\n    restart: unless-stopped\n", manage)
	if st.Recovery != "" {
		fmt.Fprintf(&b, "    environment:\n      RECOVERY: \"%s\"\n", st.Recovery)
	}
	return []byte(b.String())
}

func (p *Product) CPU(string, map[string]bool) error { return p.CPUError }

func (p *Product) FirstCredential(line string) (string, bool) {
	c, ok := strings.CutPrefix(strings.TrimSpace(line), "one-time: ")
	return c, ok && c != ""
}

func (p *Product) Mask(lines []string) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		if _, ok := p.FirstCredential(l); ok {
			l = "one-time: [hidden]"
		}
		out[i] = l
	}
	return out
}

// Bootstrap reads the first credential, seals the administrator and the API
// key, and restarts twice, as a real server's might; each step is skipped
// when the sealed value it leaves is there.
func (p *Product) Bootstrap(ctx context.Context, env provider.Env) error {
	p.Bootstraps++
	if had, err := env.Sealed(ctx, "admin"); errors.Is(err, provider.ErrNoSecret) {
		once, err := env.FirstCredential(ctx)
		if err != nil {
			return err
		}
		if err := env.Seal(ctx, "admin", []byte("admin:"+once)); err != nil {
			return err
		}
		p.Admin = "admin:" + once
		if err := env.Restart(ctx); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else if p.Admin == "" {
		p.Admin = string(had)
	}
	if _, err := env.Forwarder(ctx); err != nil {
		return err
	}
	if _, err := env.Sealed(ctx, provider.SealedAPIKey); errors.Is(err, provider.ErrNoSecret) {
		if err := env.Seal(ctx, provider.SealedAPIKey, []byte(p.Key)); err != nil {
			return err
		}
		p.ours = 1
	} else if err != nil {
		return err
	}
	return env.Restart(ctx)
}

func (p *Product) Client(_ string, apiKey func(context.Context) (string, error)) provider.Server {
	return keyed{s: p.Server, key: p.Key, apiKey: apiKey}
}

// keyed is the server behind the API key: a call with another key, or none,
// is refused.
type keyed struct {
	s      *Server
	key    string
	apiKey func(context.Context) (string, error)
}

func (k keyed) check(ctx context.Context) error {
	got, err := k.apiKey(ctx)
	if err != nil {
		return err
	}
	if got != k.key {
		return provider.ErrUnauthorized
	}
	return nil
}

func (k keyed) Domains(ctx context.Context) ([]provider.Domain, error) {
	if err := k.check(ctx); err != nil {
		return nil, err
	}
	return k.s.Domains(ctx)
}
func (k keyed) AddDomain(ctx context.Context, n string) (provider.Domain, error) {
	if err := k.check(ctx); err != nil {
		return provider.Domain{}, err
	}
	return k.s.AddDomain(ctx, n)
}
func (k keyed) RemoveDomain(ctx context.Context, id string) error {
	if err := k.check(ctx); err != nil {
		return err
	}
	return k.s.RemoveDomain(ctx, id)
}
func (k keyed) Records(ctx context.Context, id string) ([]provider.Record, error) {
	if err := k.check(ctx); err != nil {
		return nil, err
	}
	return k.s.Records(ctx, id)
}
func (k keyed) Accounts(ctx context.Context) ([]provider.Account, error) {
	if err := k.check(ctx); err != nil {
		return nil, err
	}
	return k.s.Accounts(ctx)
}
func (k keyed) AddAccount(ctx context.Context, a provider.NewAccount) (string, error) {
	if err := k.check(ctx); err != nil {
		return "", err
	}
	return k.s.AddAccount(ctx, a)
}
func (k keyed) LockPassword(ctx context.Context, id string) error {
	if err := k.check(ctx); err != nil {
		return err
	}
	return k.s.LockPassword(ctx, id)
}
func (k keyed) SetQuota(ctx context.Context, id string, b int64) error {
	if err := k.check(ctx); err != nil {
		return err
	}
	return k.s.SetQuota(ctx, id, b)
}
func (k keyed) SetDisabled(ctx context.Context, id string, d bool) error {
	if err := k.check(ctx); err != nil {
		return err
	}
	return k.s.SetDisabled(ctx, id, d)
}

func (k keyed) SetAliases(ctx context.Context, id string, as []provider.Alias) error {
	if err := k.check(ctx); err != nil {
		return err
	}
	return k.s.SetAliases(ctx, id, as)
}

func (k keyed) SetForward(ctx context.Context, id string, f provider.Forward) error {
	if err := k.check(ctx); err != nil {
		return err
	}
	return k.s.SetForward(ctx, id, f)
}

func (k keyed) Forward(ctx context.Context, id string) (provider.ForwardState, error) {
	if err := k.check(ctx); err != nil {
		return provider.ForwardState{}, err
	}
	return k.s.Forward(ctx, id)
}

func (k keyed) RemoveAccount(ctx context.Context, id string) error {
	if err := k.check(ctx); err != nil {
		return err
	}
	return k.s.RemoveAccount(ctx, id)
}
func (k keyed) AppPasswords(ctx context.Context, id string) ([]provider.AppPassword, error) {
	if err := k.check(ctx); err != nil {
		return nil, err
	}
	return k.s.AppPasswords(ctx, id)
}
func (k keyed) AddAppPassword(ctx context.Context, id, d string, e time.Time, room int) (provider.AppPassword, string, error) {
	if err := k.check(ctx); err != nil {
		return provider.AppPassword{}, "", err
	}
	return k.s.AddAppPassword(ctx, id, d, e, room)
}
func (k keyed) KeepAppPassword(ctx context.Context, a, id string) error {
	if err := k.check(ctx); err != nil {
		return err
	}
	return k.s.KeepAppPassword(ctx, a, id)
}
func (k keyed) RevokeAppPassword(ctx context.Context, a, id string) error {
	if err := k.check(ctx); err != nil {
		return err
	}
	return k.s.RevokeAppPassword(ctx, a, id)
}
func (k keyed) DKIMKeys(ctx context.Context) ([]provider.DKIMKey, error) {
	if err := k.check(ctx); err != nil {
		return nil, err
	}
	return k.s.DKIMKeys(ctx)
}
func (k keyed) AddDKIMKey(ctx context.Context, d, sel string, a provider.DKIMAlg, p string) (string, error) {
	if err := k.check(ctx); err != nil {
		return "", err
	}
	return k.s.AddDKIMKey(ctx, d, sel, a, p)
}
func (k keyed) SetDKIMStage(ctx context.Context, id string, st provider.DKIMStage) error {
	if err := k.check(ctx); err != nil {
		return err
	}
	return k.s.SetDKIMStage(ctx, id, st)
}
func (k keyed) RemoveDKIMKey(ctx context.Context, id string) error {
	if err := k.check(ctx); err != nil {
		return err
	}
	return k.s.RemoveDKIMKey(ctx, id)
}
func (k keyed) Certificates(ctx context.Context) ([]provider.Certificate, error) {
	if err := k.check(ctx); err != nil {
		return nil, err
	}
	return k.s.Certificates(ctx)
}
func (k keyed) ServeCertificate(ctx context.Context, id, c, key string) (bool, error) {
	if err := k.check(ctx); err != nil {
		return false, err
	}
	return k.s.ServeCertificate(ctx, id, c, key)
}

// --- repairing access ------------------------------------------------------------

var _ provider.Repairer = (*Product)(nil)

func (p *Product) fail(step string) error {
	if p.RepairFail != nil {
		return p.RepairFail(step)
	}
	return nil
}

// Start is the server started with a definition: with recovery, the value
// its sealed reference resolved to; nil for none.
func (p *Product) Start(recovery []byte) { p.Recovery = slices.Clone(recovery) }

func (p *Product) AdminSignsIn(ctx context.Context, env provider.Env) error {
	if err := p.fail("admin"); err != nil {
		return err
	}
	a, err := env.Sealed(ctx, "admin")
	if err != nil {
		return err
	}
	if string(a) != p.Admin {
		return provider.ErrUnauthorized
	}
	return nil
}

func (p *Product) NewAPIKey(ctx context.Context, env provider.Env, _ time.Time) (provider.KeyRepair, error) {
	if err := p.AdminSignsIn(ctx, env); err != nil {
		return provider.KeyRepair{}, err
	}
	if err := p.fail("key"); err != nil {
		return provider.KeyRepair{}, err
	}
	p.keys++
	key := fmt.Sprintf("repaired-key-%d", p.keys)
	if err := env.Seal(ctx, provider.SealedAPIKey, []byte(key)); err != nil {
		return provider.KeyRepair{}, err
	}
	p.Key = key
	out := provider.KeyRepair{Destroyed: p.ours, Kept: append([]string{}, p.OtherKeys...)}
	p.ours = 1
	return out, nil
}

func (p *Product) RecoveryCredential() ([]byte, error) {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return []byte(fmt.Sprintf("recovery:%x", b)), nil
}

func (p *Product) ResetAdmin(ctx context.Context, env provider.Env, recovery []byte) error {
	if p.Recovery == nil || string(p.Recovery) != string(recovery) {
		return provider.ErrUnauthorized
	}
	if err := p.fail("reset"); err != nil {
		return err
	}
	if n := p.Admins; n != 0 && n != 1 {
		return fmt.Errorf("the server has %d administrators", n)
	}
	p.keys++
	p.Admin = fmt.Sprintf("admin:reset-%d", p.keys)
	return env.Seal(ctx, "admin", []byte(p.Admin))
}

func (p *Product) RecoverySignsIn(_ context.Context, _ string, recovery []byte) error {
	if p.Recovery != nil && string(p.Recovery) == string(recovery) {
		return nil
	}
	return provider.ErrUnauthorized
}
