package mail

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yongjohnlee80/autopanel/core/mail/provider/memory"
)

// The app passwords' rules, on the mail server in memory: what any server
// does is the conformance suite's; what Stalwart does, the SDK's tests.

// randomish is a secret of the usual form, app_ and 36 of [a-z0-9], different
// for each n.
func randomish(n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	sum := sha256.Sum256([]byte(strconv.Itoa(n)))
	out := []byte("app_")
	for i := range 36 {
		out = append(out, alphabet[int(sum[i%32]+byte(i*7))%36])
	}
	return string(out)
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

// readyMail is a mail module that is set up and bootstrapped, its server in
// memory holding the domain example.net, both on one clock.
func readyMail(t *testing.T) (*Module, *memory.Server, *clock) {
	t.Helper()
	m, st, v, _, _, _ := newTestModule(t)
	st.state = &State{Host: "mail.example.net", CreatedAt: 1, Bootstrapped: 1}
	st.domains = []string{"example.net"}
	v.m[sealedKey] = []byte(prod(m).Key)
	clk := &clock{t: time.Date(2026, 11, 17, 9, 0, 0, 0, time.UTC)}
	m.now = clk.now
	srv := mem(m)
	srv.Now = clk.now
	if _, err := srv.AddDomain(context.Background(), "example.net"); err != nil {
		t.Fatal(err)
	}
	return m, srv, clk
}

func appPasswordsOf(t *testing.T, m *Module, address string) []AppPasswordView {
	t.Helper()
	list, err := m.appPasswordList(context.Background(), AppPasswordAsk{Address: address})
	if err != nil {
		t.Fatal(err)
	}
	return list
}

func TestStrongSecret(t *testing.T) {
	for _, c := range []struct {
		s    string
		want bool
	}{
		{randomish(1), true}, // 36 of [a-z0-9], about 186 bits
		{randomish(2), true},
		{"app_qwertyuiopasdfghjklzxcvb", false}, // 24 lowercase letters: 113 bits
		{"app_qWeRtY1u2I3oPaSdF4g5H6jK", true},  // 24 of 62: 143 bits
		{randomish(3)[4:] + "abcd", false},      // no app_
		{"app_", false},
		{randomish(4)[:20] + " " + randomish(4)[20:], false}, // a space
		{"app_" + strings.Repeat("a1b2c3", 10), false},       // six characters, repeated
		{"app_" + strings.Repeat("é1", 20), false},           // not ASCII
	} {
		if got := strongSecret(c.s); got != c.want {
			t.Errorf("strongSecret(%q) = %v; want %v", c.s, got, c.want)
		}
	}
}

// TestAnAccountIsMadeWithNoKnownPassword: mail.account.add takes no password;
// the server is given an argon2id hash of one no one is told.
func TestAnAccountIsMadeWithNoKnownPassword(t *testing.T) {
	m, srv, _ := readyMail(t)
	ctx := context.Background()
	if _, err := m.accountAdd(ctx, AccountAsk{Address: "ana@example.net"}); err != nil {
		t.Fatal(err)
	}
	a := srv.PasswordHash("ana@example.net")
	if !strings.HasPrefix(a, "$argon2id$v=19$m=8192,t=1,p=1$") {
		t.Fatalf("the hash the server was given: %q", a)
	}
	if _, err := m.accountAdd(ctx, AccountAsk{Address: "ben@example.net"}); err != nil {
		t.Fatal(err)
	}
	if srv.PasswordHash("ben@example.net") == a {
		t.Fatal("two accounts were given the same password")
	}
}

// TestAnAppPasswordIsPendingUntilKept: it signs in from the start, stops at
// ten minutes unless kept, and once kept works on.
func TestAnAppPasswordIsPendingUntilKept(t *testing.T) {
	m, srv, clk := readyMail(t)
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
	if n.ExpiresAt != clk.now().Add(pendingFor).Unix() || !srv.SignIn("ana@example.net", n.Secret) {
		t.Fatalf("a new app password is not pending for ten minutes: %+v", n)
	}
	if list := appPasswordsOf(t, m, "ana@example.net"); len(list) != 1 || !list[0].Pending || list[0].Description != "Ana's phone" {
		t.Fatalf("the list: %+v", list)
	}
	clk.add(3 * time.Minute)
	if _, err := m.appPasswordKeep(ctx, AppPasswordAsk{Address: "ana@example.net", ID: n.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.appPasswordKeep(ctx, AppPasswordAsk{Address: "ana@example.net", ID: n.ID}); err != nil {
		t.Fatalf("keeping twice: %v", err)
	}
	clk.add(time.Hour)
	if !srv.SignIn("ana@example.net", n.Secret) {
		t.Fatal("a kept app password stopped")
	}
	if list := appPasswordsOf(t, m, "ana@example.net"); len(list) != 1 || list[0].Pending || list[0].ExpiresAt != 0 {
		t.Fatalf("kept, the list: %+v", list)
	}
}

// TestAnExpiryFromOutsideIsLeftAlone: an app password given a far expiry with
// the mail server's own tools is not one of AutoPanel's pending ones: the list
// doesn't call it pending, and keep doesn't make it permanent.
func TestAnExpiryFromOutsideIsLeftAlone(t *testing.T) {
	m, srv, clk := readyMail(t)
	ctx := context.Background()
	_, _ = m.accountAdd(ctx, AccountAsk{Address: "ana@example.net"})
	_, a, err := m.account(ctx, "ana@example.net")
	if err != nil {
		t.Fatal(err)
	}
	until := clk.now().Add(30 * 24 * time.Hour)
	made, secret, err := srv.AddAppPassword(ctx, a.ID, "a month's loan", until, AppPasswordLimit)
	if err != nil {
		t.Fatal(err)
	}
	list := appPasswordsOf(t, m, "ana@example.net")
	if len(list) != 1 || list[0].Pending || list[0].ExpiresAt != until.Unix() {
		t.Fatalf("the list: %+v; want it not pending, with its expiry", list)
	}
	if _, err := m.appPasswordKeep(ctx, AppPasswordAsk{Address: "ana@example.net", ID: made.ID}); err != nil {
		t.Fatal(err)
	}
	clk.add(31 * 24 * time.Hour)
	if srv.SignIn("ana@example.net", secret) {
		t.Fatal("keep made an app password with its own expiry permanent")
	}
}

// TestAnExpiredAppPasswordIsNeverRevived: a server may bring an expired app
// password back when its expiry is cleared (the one in memory does), so keep
// destroys it instead.
func TestAnExpiredAppPasswordIsNeverRevived(t *testing.T) {
	m, srv, clk := readyMail(t)
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
	if srv.SignIn("ana@example.net", n.Secret) {
		t.Fatal("an app password kept too late was revived")
	}
	if _, err := m.appPasswordKeep(ctx, AppPasswordAsk{Address: "ana@example.net", ID: n.ID}); !errors.Is(err, ErrNoAppPassword) {
		t.Fatalf("keeping a destroyed one: %v", err)
	}
}

func TestRevokingAnAppPassword(t *testing.T) {
	m, srv, _ := readyMail(t)
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
	if srv.SignIn("ana@example.net", phone.Secret) || !srv.SignIn("ana@example.net", laptop.Secret) {
		t.Fatal("revoking one app password touched the wrong one")
	}
}

// TestAWeakSecretIsNeverHandedOut: a server whose generator weakened stops
// the feature; the weak app password is destroyed.
func TestAWeakSecretIsNeverHandedOut(t *testing.T) {
	m, srv, _ := readyMail(t)
	ctx := context.Background()
	_, _ = m.accountAdd(ctx, AccountAsk{Address: "ana@example.net"})
	srv.Secret = func(int) string { return "app_abcdef" }
	if n, err := m.appPasswordAdd(ctx, AppPasswordAsk{Address: "ana@example.net", Description: "phone"}); !errors.Is(err, ErrWeakSecret) || n.Secret != "" {
		t.Fatalf("a weak secret: %+v, %v", n, err)
	}
	if list := appPasswordsOf(t, m, "ana@example.net"); len(list) != 0 {
		t.Fatalf("the weak app password was left: %+v", list)
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

// TestAnAccountHoldsTwentyAppPasswords: the module asks the server for room
// for AppPasswordLimit, and says so when the account is full.
func TestAnAccountHoldsTwentyAppPasswords(t *testing.T) {
	m, _, _ := readyMail(t)
	ctx := context.Background()
	_, _ = m.accountAdd(ctx, AccountAsk{Address: "ana@example.net"})
	for i := range AppPasswordLimit {
		if _, err := m.appPasswordAdd(ctx, AppPasswordAsk{Address: "ana@example.net", Description: "device " + strconv.Itoa(i)}); err != nil {
			t.Fatalf("app password %d: %v", i+1, err)
		}
	}
	if _, err := m.appPasswordAdd(ctx, AppPasswordAsk{Address: "ana@example.net", Description: "one more"}); !errors.Is(err, ErrServer) {
		t.Fatalf("the 21st: %v; want the server's refusal", err)
	}
}

// TestLockingKeepsTheAppPasswords: Lock password replaces the account's
// password with a hash of one no one knows; its app passwords sign in still.
func TestLockingKeepsTheAppPasswords(t *testing.T) {
	m, srv, _ := readyMail(t)
	ctx := context.Background()
	_, _ = m.accountAdd(ctx, AccountAsk{Address: "ana@example.net"})
	before := srv.PasswordHash("ana@example.net")
	phone, err := m.appPasswordAdd(ctx, AppPasswordAsk{Address: "ana@example.net", Description: "phone"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.accountLock(ctx, AccountAsk{Address: "ana@example.net"}); err != nil {
		t.Fatal(err)
	}
	after := srv.PasswordHash("ana@example.net")
	if after == before || !strings.HasPrefix(after, "$argon2id$") || !srv.SignIn("ana@example.net", phone.Secret) {
		t.Fatal("Lock password did not replace the password, or took the app passwords with it")
	}
}

// TestTheHourlyPassDestroysExpiredAppPasswords: shown and never kept, they
// are destroyed, and stop counting toward the limit; kept ones stay.
func TestTheHourlyPassDestroysExpiredAppPasswords(t *testing.T) {
	m, srv, clk := readyMail(t)
	ctx := context.Background()
	_, _ = m.accountAdd(ctx, AccountAsk{Address: "ana@example.net"})
	kept, _ := m.appPasswordAdd(ctx, AppPasswordAsk{Address: "ana@example.net", Description: "kept"})
	_, _ = m.appPasswordKeep(ctx, AppPasswordAsk{Address: "ana@example.net", ID: kept.ID})
	_, _ = m.appPasswordAdd(ctx, AppPasswordAsk{Address: "ana@example.net", Description: "left"})
	if list := appPasswordsOf(t, m, "ana@example.net"); len(list) != 2 {
		t.Fatalf("before: %+v", list)
	}
	clk.add(pendingFor + time.Second)
	if list := appPasswordsOf(t, m, "ana@example.net"); len(list) != 1 || list[0].ID != kept.ID {
		t.Fatalf("an expired one is listed: %+v", list)
	}
	if err := m.sweepAppPasswords(ctx, m.client()); err != nil {
		t.Fatal(err)
	}
	accounts, _ := srv.Accounts(ctx)
	held, _ := srv.AppPasswords(ctx, accounts[0].ID)
	if len(held) != 1 || held[0].ID != kept.ID {
		t.Fatalf("after the pass the server holds %d", len(held))
	}
}

// TestNoSecretLeavesTheVerbs: the list never carries a secret; only add's
// answer does.
func TestNoSecretLeavesTheVerbs(t *testing.T) {
	m, _, _ := readyMail(t)
	ctx := context.Background()
	_, _ = m.accountAdd(ctx, AccountAsk{Address: "ana@example.net"})
	n, _ := m.appPasswordAdd(ctx, AppPasswordAsk{Address: "ana@example.net", Description: "phone"})
	raw, _ := json.Marshal(appPasswordsOf(t, m, "ana@example.net"))
	if strings.Contains(string(raw), n.Secret) || strings.Contains(string(raw), "secret") {
		t.Fatalf("the list carries a secret: %s", raw)
	}
	accounts, _ := m.accountList(ctx, DomainAsk{})
	raw, _ = json.Marshal(accounts)
	if strings.Contains(string(raw), "argon2") {
		t.Fatalf("the account list carries a hash: %s", raw)
	}
}
