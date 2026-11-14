package ui

import (
	"context"
	"strings"
	"testing"

	"github.com/yongjohnlee80/golib/tui/decl/decltest"

	"github.com/yongjohnlee80/autopanel/core/mail"
	"github.com/yongjohnlee80/autopanel/core/services"
)

// fakeMail is the Mail menu's daemon, in memory.
type fakeMail struct {
	status    mail.Status
	records   map[string]mail.RecordsAnswer
	accounts  []mail.AccountView
	setups    []string // "host domain"
	asks      []string // "add-domain x", "takeover d TXT n", "sync"
	passwords []string // what reached the daemon, for the test to compare; never shown
}

func (f *fakeClient) MailStatus(context.Context) (mail.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mail.status, nil
}

func (f *fakeClient) MailSetup(_ context.Context, host, domain string) (mail.Setup, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mail.setups = append(f.mail.setups, host+" "+domain)
	if domain != "example.com" && domain != "example.net" {
		return mail.Setup{}, mail.ErrNotRegistered
	}
	f.mail.status = mail.Status{SetUp: true, Host: host, Domains: []string{domain}, Stack: "absent"}
	if f.reviews == nil {
		f.reviews = map[string]services.Review{}
	}
	f.reviews[mail.Stack] = warned(webSHA)
	return mail.Setup{Stack: mail.Stack, SHA256: "abc"}, nil
}

func (f *fakeClient) MailAddDomain(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mail.asks = append(f.mail.asks, "add-domain "+name)
	f.mail.status.Domains = append(f.mail.status.Domains, name)
	return nil
}

func (f *fakeClient) MailRemoveDomain(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mail.asks = append(f.mail.asks, "remove-domain "+name)
	return nil
}

func (f *fakeClient) MailRecords(_ context.Context, domain string) (mail.RecordsAnswer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mail.records[domain], nil
}

func (f *fakeClient) MailTakeover(_ context.Context, domain, name, typ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mail.asks = append(f.mail.asks, "takeover "+domain+" "+typ+" "+name)
	return nil
}

func (f *fakeClient) MailSync(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mail.asks = append(f.mail.asks, "sync")
	return nil
}

func (f *fakeClient) MailAccounts(context.Context, string) ([]mail.AccountView, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]mail.AccountView(nil), f.mail.accounts...), nil
}

func (f *fakeClient) MailAddAccount(_ context.Context, address, password string, _ int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mail.passwords = append(f.mail.passwords, password)
	f.mail.accounts = append(f.mail.accounts, mail.AccountView{Address: address, Quota: 5 << 30, Aliases: []string{}})
	return nil
}

func (f *fakeClient) MailSetPassword(_ context.Context, _, password string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mail.passwords = append(f.mail.passwords, password)
	return nil
}

func (f *fakeClient) MailRemoveAccount(_ context.Context, address string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mail.asks = append(f.mail.asks, "remove-account "+address)
	return nil
}

func (f *fakeClient) mailAsked() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.mail.asks...)
}

// withMail is a client whose mail is set up, with a domain whose zone holds
// another provider's MX.
func withMail() *fakeClient {
	f := newFakeClient()
	f.mail.status = mail.Status{SetUp: true, Host: "mail.example.com", Bootstrapped: 1, Stack: "applied",
		Domains: []string{"example.com"}, Certificate: "ok until 2027-02-12", Progress: mail.Progress{Step: "ready", Loopback: "ok"}}
	f.mail.records = map[string]mail.RecordsAnswer{"example.com": {At: 1, Records: []mail.RecordView{
		{Record: mail.Record{Name: "example.com", Type: "MX", Value: "10 mail.example.com"}, State: "different", Found: "10 mx.other.example", Why: "receives mail"},
		{Record: mail.Record{Name: "_dmarc.example.com", Type: "TXT", Value: "v=DMARC1; p=quarantine"}, State: "ok", Why: "says what to do with mail that fails (DMARC)"},
	}, DKIM: []mail.DKIMRow{{Selector: "ap202611e", Step: "published", Since: 1}}}}
	f.mail.accounts = []mail.AccountView{{Address: "ana@example.com", Quota: 5 << 30, Used: 3 << 20, Aliases: []string{}}}
	return f
}

// TestSettingMailUp: Mail › Set up mail asks the host, then the first domain
// (an unregistered one refused in the prompt), writes the mail stack, and
// opens its review.
func TestSettingMailUp(t *testing.T) {
	f := newFakeClient()
	h, s := startHost(t, f)
	s.WaitForText(t, "CA LE staging")
	run(t, h, h.mailSetup)
	s.WaitForText(t, "Set up mail: the mail host")
	s.WaitForText(t, "mail.example.com") // offered from the first registered domain
	s.Keys(t, enter)
	s.WaitForText(t, "Set up mail: the first domain")
	for range len("example.com") {
		s.Keys(t, backspace)
	}
	s.Keys(t, decltest.Type("example.org")...)
	s.Keys(t, enter)
	s.WaitForText(t, "example.org is not a registered domain")
	for range len("example.org") {
		s.Keys(t, backspace)
	}
	s.Keys(t, decltest.Type("example.com")...)
	s.Keys(t, enter)
	s.WaitForText(t, "Add stack mail: review") // the status bar's notice is under it
	s.WaitFor(t, "the mail stack's review", func(string) bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		return len(f.checks) > 0 && f.checks[len(f.checks)-1] == "mail"
	})
	f.mu.Lock()
	setups := strings.Join(f.mail.setups, ";")
	f.mu.Unlock()
	if setups != "mail.example.com example.org;mail.example.com example.com" {
		t.Fatalf("setups: %q", setups)
	}
}

// TestTheMailDomainsPanel: the domains, the selected one's records with their
// states, a foreign record's value, the DKIM keys; Take over asks first.
func TestTheMailDomainsPanel(t *testing.T) {
	f := withMail()
	h, s := startHost(t, f)
	s.WaitForText(t, "CA LE staging")
	run(t, h, h.openMailDomains)
	for _, part := range []string{"Mail domains", "example.com", "different", "MX", "_dmarc.example.com", "ap202611e"} {
		s.WaitForText(t, part)
	}
	s.WaitForText(t, "10 mx.other.example") // the first record's: what holds its place now
	run(t, h, func() error { return h.mailTakeover(0) })
	s.WaitForText(t, "Take a record over")
	s.Keys(t, decltest.Rune('y'))
	s.WaitFor(t, "the takeover", func(string) bool {
		a := f.mailAsked()
		return len(a) > 0 && a[len(a)-1] == "takeover example.com MX example.com"
	})
	run(t, h, func() error { return h.mailTakeover(1) }) // an ok record: nothing to take over
	s.WaitForText(t, "nothing to take over")
}

// TestAMailPasswordIsNeverShown: Accounts › Add asks the address, then the
// password in a dialog that shows nothing of it; a short one is refused there.
func TestAMailPasswordIsNeverShown(t *testing.T) {
	f := withMail()
	h, s := startHost(t, f)
	s.WaitForText(t, "CA LE staging")
	run(t, h, h.openMailAccounts)
	s.WaitForText(t, "ana@example.com")
	run(t, h, h.mailAddAccount)
	s.WaitForText(t, "New mail account")
	for range len("@example.com") { // the field starts with the first domain
		s.Keys(t, backspace)
	}
	s.Keys(t, decltest.Type("bo@example.com")...)
	s.Keys(t, enter)
	s.WaitForText(t, "Mail account password")
	s.Keys(t, decltest.Type("short")...)
	s.Keys(t, enter)
	s.WaitForText(t, "12 characters at least")
	for range len("short") {
		s.Keys(t, backspace)
	}
	const pw = "correct-horse-battery"
	s.Keys(t, decltest.Type(pw)...)
	if strings.Contains(s.String(), pw) || strings.Contains(s.String(), "correct-horse") {
		t.Fatal("the password is on the screen")
	}
	s.Keys(t, enter)
	s.WaitForText(t, "made")
	f.mu.Lock()
	got := f.mail.passwords
	f.mu.Unlock()
	if len(got) != 1 || got[0] != pw {
		t.Fatalf("what reached the daemon: %d passwords", len(got))
	}
	if strings.Contains(s.String(), pw) {
		t.Fatal("the password is on the screen after it was taken")
	}
}
