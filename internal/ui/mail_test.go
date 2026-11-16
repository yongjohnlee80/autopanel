package ui

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/yongjohnlee80/golib/tui/decl/decltest"

	"github.com/yongjohnlee80/autopanel/core/gate"
	"github.com/yongjohnlee80/autopanel/core/mail"
)

// fakeMail is the Mail menu's daemon, in memory.
type fakeMail struct {
	status   mail.Status
	records  map[string]mail.RecordsAnswer
	accounts []mail.AccountView
	setups   []string                          // "host domain"
	pending  string                            // the setup the daemon holds until it is applied: "host domain"
	asks     []string                          // "add-domain x", "takeover d TXT n", "sync"
	apps     map[string][]mail.AppPasswordView // by address
	appSeq   int
}

// appSecret is the secret the fake daemon answers for its n-th app password.
func appSecret(n int) string { return fmt.Sprintf("app_q7%034d", n) }

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
	// Set up mail writes nothing: the setup waits for MailSetupApply.
	f.mail.pending = host + " " + domain
	return mail.Setup{Stack: mail.Stack, SHA256: webSHA, Review: warned(webSHA)}, nil
}

func (f *fakeClient) MailSetupApply(_ context.Context, accept string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mail.asks = append(f.mail.asks, "apply "+accept)
	if f.mail.pending == "" {
		return mail.ErrNoPending
	}
	host, domain, _ := strings.Cut(f.mail.pending, " ")
	f.mail.status = mail.Status{SetUp: true, Host: host, Domains: []string{domain}, Stack: "applied"}
	f.mail.pending = ""
	return nil
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

func (f *fakeClient) MailAddAccount(_ context.Context, address string, _ int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mail.asks = append(f.mail.asks, "add-account "+address)
	f.mail.accounts = append(f.mail.accounts, mail.AccountView{Address: address, Quota: 5 << 30, Aliases: []string{}})
	return nil
}

func (f *fakeClient) MailLockAccount(_ context.Context, address string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mail.asks = append(f.mail.asks, "lock "+address)
	return nil
}

func (f *fakeClient) MailAppPasswords(_ context.Context, address string) ([]mail.AppPasswordView, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]mail.AppPasswordView(nil), f.mail.apps[address]...), nil
}

func (f *fakeClient) MailAddAppPassword(_ context.Context, address, device string) (mail.NewAppPassword, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mail.appSeq++
	id := fmt.Sprintf("p%d", f.mail.appSeq)
	if f.mail.apps == nil {
		f.mail.apps = map[string][]mail.AppPasswordView{}
	}
	exp := time.Date(2026, 11, 17, 9, 10, 0, 0, time.Local).Unix()
	f.mail.apps[address] = append(f.mail.apps[address], mail.AppPasswordView{ID: id, Description: device, CreatedAt: exp - 600, Pending: true, ExpiresAt: exp})
	f.mail.asks = append(f.mail.asks, "app-add "+address+" "+device)
	return mail.NewAppPassword{ID: id, Secret: appSecret(f.mail.appSeq), User: address, Host: "mail.example.com",
		IMAP: 993, SMTP: 465, Submission: 587, ExpiresAt: exp}, nil
}

func (f *fakeClient) MailKeepAppPassword(_ context.Context, address, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, p := range f.mail.apps[address] {
		if p.ID == id {
			f.mail.apps[address][i].Pending, f.mail.apps[address][i].ExpiresAt = false, 0
		}
	}
	f.mail.asks = append(f.mail.asks, "app-keep "+id)
	return nil
}

func (f *fakeClient) MailRevokeAppPassword(_ context.Context, address, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mail.apps[address] = slices.DeleteFunc(f.mail.apps[address], func(p mail.AppPasswordView) bool { return p.ID == id })
	f.mail.asks = append(f.mail.asks, "app-revoke "+id)
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
	}, DKIM: []mail.DKIMRow{{Selector: "ap202611e", Step: "published", Since: 1}}},
		"mail.example.com": {At: 1, Records: []mail.RecordView{
			{Record: mail.Record{Name: "mail.example.com", Type: "A", Value: "192.0.2.10"}, State: "manual", Why: "the mail host's address"},
		}}}
	f.mail.accounts = []mail.AccountView{{Address: "ana@example.com", Quota: 5 << 30, Used: 3 << 20, Aliases: []string{}}}
	return f
}

// TestSettingMailUp: Mail › Set up mail asks the host, then the first domain
// (an unregistered one refused in the prompt), and opens the mail stack's
// review, having written nothing. Left there, it can be asked again, with the
// answers offered; Add and start makes the whole setup in one call.
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
	s.WaitForText(t, "Add stack mail: review")
	if a := f.mailAsked(); len(a) != 0 || len(f.asked().applies) != 0 {
		t.Fatalf("something was applied before Add and start: %v %v", a, f.asked().applies)
	}

	// Left at its review: Set up mail is open again, with the answers offered.
	s.Keys(t, escape)
	s.WaitFor(t, "the review to close", func(screen string) bool { return !strings.Contains(screen, "Add stack mail: review") })
	if !onLoop(h, h.mailMaySetUp) {
		t.Fatal("Set up mail is closed after its review was left")
	}
	run(t, h, h.mailSetup)
	s.WaitForText(t, "Set up mail: the mail host")
	s.Keys(t, enter)
	s.WaitForText(t, "Set up mail: the first domain")
	s.Keys(t, enter)
	s.WaitForText(t, "Add stack mail: review")
	s.Keys(t, decltest.Rune('a'))
	s.WaitFor(t, "the setup applied", func(string) bool {
		a := f.mailAsked()
		return len(a) == 1 && a[0] == "apply "+webSHA
	})
	s.WaitForText(t, "mail is set up")
	if ap := f.asked().applies; len(ap) != 0 {
		t.Fatalf("the mail stack was added as any stack: %v", ap)
	}
	f.mu.Lock()
	setups := strings.Join(f.mail.setups, ";")
	f.mu.Unlock()
	if setups != "mail.example.com example.org;mail.example.com example.com;mail.example.com example.com" {
		t.Fatalf("setups: %q", setups)
	}
	s.WaitFor(t, "Set up mail to close", func(string) bool { return !onLoop(h, h.mailMaySetUp) })
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

	// The mail host's own records are the last row; it is no domain to remove.
	s.WaitForText(t, "mail.example.com (mail")
	run(t, h, func() error { return h.mailDomainMoved(1) })
	s.WaitForText(t, "192.0.2.10")
	run(t, h, func() error { return h.mailRemoveDomain(1) })
	s.WaitForText(t, "nothing to remove")
}

// TestAnAppPasswordIsShownOnceAndKeptOnDone: Accounts › Add asks the address
// alone (no password: the daemon makes one no one knows), then offers an app
// password for the first device. Its dialog shows the secret, its groups of
// four and a QR code; Done keeps it, and the secret leaves the screen. Another,
// left with Escape, is revoked.
func TestAnAppPasswordIsShownOnceAndKeptOnDone(t *testing.T) {
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
	s.WaitForText(t, "make one for its first device now?")
	waitMailAsked(t, s, f, "add-account bo@example.com")
	s.Keys(t, decltest.Type("y")...)
	s.WaitForText(t, "New app password")
	s.Keys(t, decltest.Type("Bo's phone")...)
	s.Keys(t, enter)
	secret := appSecret(1)
	s.WaitForText(t, secret)
	s.WaitForText(t, groupsOfFour(secret))
	s.WaitForText(t, "bo@example.com")
	s.WaitForText(t, "993")
	s.WaitForText(t, "▀") // the QR code
	s.WaitForText(t, "Shown once")
	s.Keys(t, decltest.Type("d")...)
	waitMailAsked(t, s, f, "app-keep p1")
	s.WaitForText(t, "the app password is kept")
	if strings.Contains(s.String(), secret) || strings.Contains(s.String(), "▀▀") {
		t.Fatal("the secret stayed on the screen after Done")
	}

	// A second, for the selected account, left with Escape: revoked at once.
	run(t, h, func() error { return h.mailAddAppPassword(1) })
	s.WaitForText(t, "New app password")
	s.Keys(t, decltest.Type("laptop")...)
	s.Keys(t, enter)
	s.WaitForText(t, appSecret(2))
	s.Keys(t, escape)
	waitMailAsked(t, s, f, "app-revoke p2")
	s.WaitFor(t, "the second secret to leave the screen", func(sc string) bool { return !strings.Contains(sc, appSecret(2)) })
}

func waitMailAsked(t *testing.T, s *decltest.Screen, f *fakeClient, want string) {
	t.Helper()
	s.WaitFor(t, want, func(string) bool { return slices.Contains(f.mailAsked(), want) })
}

func TestQRTextDrawsTheCodeForTheTheme(t *testing.T) {
	dark, err := qrText("app_abc", true)
	if err != nil {
		t.Fatal(err)
	}
	light, _ := qrText("app_abc", false)
	lines := strings.Split(dark, "\n")
	// Version 1 at level M is 21 modules, plus two of margin each side: 25
	// wide, 13 lines of two module rows.
	if len(lines) != 13 || len([]rune(lines[0])) != 25 {
		t.Fatalf("the code is %d lines of %d", len(lines), len([]rune(lines[0])))
	}
	// On a dark window the margin is drawn (it is light); on a light one, not.
	if lines[0] != strings.Repeat("█", 25) || strings.Split(light, "\n")[0] != strings.Repeat(" ", 25) {
		t.Fatalf("the margin: dark %q, light %q", lines[0], strings.Split(light, "\n")[0])
	}
}

func TestRelHostAndZone(t *testing.T) {
	for _, c := range []struct{ name, zone, want string }{
		{"example.com", "example.com", "@"},
		{"_dmarc.example.com", "example.com", "_dmarc"},
		{"ap202611e._domainkey.example.com", "example.com", "ap202611e._domainkey"},
		{"mail.example.com", "example.com", "mail"},
	} {
		if got := relHost(c.name, c.zone); got != c.want {
			t.Errorf("relHost(%s, %s) = %q, want %q", c.name, c.zone, got, c.want)
		}
	}
	if z := zoneOf("mail.lists.example.com", []string{"example.com"}, []gate.DomainView{{Name: "lists.example.com"}}); z != "lists.example.com" {
		t.Errorf("the longest domain a name is under: %s", z)
	}
	if z := zoneOf("mail.example.org", nil, nil); z != "example.org" {
		t.Errorf("under no known domain, the parent: %s", z)
	}
}

// TestTheDNSRecordsDialog: every record of every mail domain and of the mail
// host, each host as a DNS provider's form takes it, an MX split into its
// fields; with records to enter by hand, the intro says how.
func TestTheDNSRecordsDialog(t *testing.T) {
	f := withMail()
	h, s := startHost(t, f)
	s.WaitForText(t, "CA LE staging")
	run(t, h, h.openMailDomains)
	s.WaitForText(t, "example.com")
	run(t, h, h.openDNSRecords)
	for _, part := range []string{"Records to enter at your DNS provider", "Custom MX", "_dmarc", "192.0.2.10"} {
		s.WaitForText(t, part)
	}
	waitFact(t, s, "Host", "@") // the first: the MX, at the zone itself
	waitFact(t, s, "Priority", "10")
	waitFact(t, s, "Target", "mail.example.com")
	run(t, h, func() error { return h.dnsMoved(2) }) // the mail host's A
	waitFact(t, s, "Host", "mail")
	run(t, h, func() error { return h.dnsCopy(2) })
	s.WaitForText(t, "clipboard")
}
