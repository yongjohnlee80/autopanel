package auth_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yongjohnlee80/golib/auth/totp"

	"github.com/yongjohnlee80/autopanel/internal/auth"
	"github.com/yongjohnlee80/autopanel/internal/keyslot"
)

func (f fixture) browser(user, pass, code string) (auth.User, error) {
	return f.m.BrowserLogin(context.Background(), auth.Login{User: user, Passphrase: pass, Code: code}, "203.0.113.9")
}

// TestABrowserLoginOpensNothing: an administrator's right passphrase from a
// browser answers who they are and leaves the vault locked; nothing that
// follows an unlock runs; every attempt is in the audit log before it is
// checked, as a browser's.
func TestABrowserLoginOpensNothing(t *testing.T) {
	f := newFixture(t)
	unlocks := 0
	m, err := auth.New(f.store, authtestSecrets(f), f.aud, f.vault, func(context.Context) { unlocks++ }, cheap)
	if err != nil {
		t.Fatal(err)
	}
	auth.SetClock(m, func() time.Time { return *f.clock })
	f.m = m
	u, err := f.browser("root", rootPass, "")
	if err != nil || u.Name != "root" || u.Role != auth.RoleAdmin {
		t.Fatalf("BrowserLogin = %+v, %v", u, err)
	}
	if f.vault.Unlocked() || unlocks != 0 {
		t.Fatalf("a browser login unlocked the vault (unlocked %v, ran what follows an unlock %d times)", f.vault.Unlocked(), unlocks)
	}
	if _, err := f.browser("root", "the wrong passphrase", ""); !errors.Is(err, auth.ErrBadLogin) {
		t.Fatalf("a wrong passphrase: %v", err)
	}
	f.aud.mu.Lock()
	log := strings.Join(f.aud.entries, "\n")
	f.aud.mu.Unlock()
	for _, want := range []string{"auth.login user root attempt", "auth.login user root ok", "auth.login user root failed: passphrase"} {
		if !strings.Contains(log, want) {
			t.Errorf("the audit log lacks %q:\n%s", want, log)
		}
	}
	if strings.Contains(log, rootPass) || strings.Contains(log, "the wrong passphrase") {
		t.Error("a passphrase is in the audit log")
	}
}

// TestABrowsersSecondFactorNeedsTheHostsVault: with a second factor, a
// browser login works only while the vault the host opened is open: the seed
// is never read with the key the passphrase could open. A code is used once.
func TestABrowsersSecondFactorNeedsTheHostsVault(t *testing.T) {
	f := newFixture(t)
	if _, err := f.login(t, "root", rootPass, ""); err != nil { // the console opens the vault, as the keyfile does at start
		t.Fatal(err)
	}
	var e auth.Enrol
	if err := f.call(t, "user:1", "auth.totp.begin", auth.PassAsk{Passphrase: rootPass}, &e); err != nil {
		t.Fatal(err)
	}
	seed, err := totp.Decode(strings.ReplaceAll(e.Secret, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.call(t, "user:1", "auth.totp.confirm", auth.CodeAsk{Code: totp.Code(seed, *f.clock)}, nil); err != nil {
		t.Fatal(err)
	}
	*f.clock = f.clock.Add(2 * time.Minute)
	if _, err := f.browser("root", rootPass, ""); !errors.Is(err, auth.ErrBadLogin) {
		t.Fatalf("the right passphrase without its code: %v", err)
	}
	*f.clock = f.clock.Add(2 * time.Minute)
	code := totp.Code(seed, *f.clock)
	if _, err := f.browser("root", rootPass, code); err != nil {
		t.Fatalf("passphrase and code with the vault open: %v", err)
	}
	*f.clock = f.clock.Add(time.Second)
	if _, err := f.browser("root", rootPass, code); !errors.Is(err, auth.ErrBadLogin) {
		t.Fatalf("the same code again: %v", err)
	}
	// A core whose vault no keyfile opened: the same passphrase and a fresh
	// code are the same failure, and the vault stays locked.
	locked := &keyslot.Vault{}
	m2, err := auth.New(f.store, authtestSecrets(f), f.aud, locked, nil, cheap)
	if err != nil {
		t.Fatal(err)
	}
	*f.clock = f.clock.Add(5 * time.Minute)
	auth.SetClock(m2, func() time.Time { return *f.clock })
	if _, err := m2.BrowserLogin(context.Background(), auth.Login{User: "root", Passphrase: rootPass, Code: totp.Code(seed, *f.clock)}, "203.0.113.9"); !errors.Is(err, auth.ErrBadLogin) {
		t.Fatalf("a browser login with the vault locked: %v; want the one failure", err)
	}
	if locked.Unlocked() {
		t.Fatal("a browser login opened the vault to read the seed")
	}
}

// TestBrowserFailuresAreCountedApart: ten bad browser logins lock a name for
// browsers, the first administrator included, and an unknown name alike; the
// console is not locked by them; the lock ends by itself.
func TestBrowserFailuresAreCountedApart(t *testing.T) {
	f := newFixture(t)
	for _, name := range []string{"root", "nobody"} {
		for i := 1; i <= auth.LockAfter; i++ {
			if _, err := f.browser(name, "wrong", ""); !errors.Is(err, auth.ErrBadLogin) {
				t.Fatalf("%s, failure %d: %v", name, i, err)
			}
			if i < auth.LockAfter {
				// In its wait the name answers throttled, whatever is sent.
				if _, err := f.browser(name, rootPass, ""); !errors.Is(err, auth.ErrThrottled) {
					t.Fatalf("%s, inside the wait after failure %d: %v", name, i, err)
				}
				*f.clock = f.clock.Add(auth.MaxWait + time.Second)
			}
		}
		*f.clock = f.clock.Add(auth.MaxWait + time.Second) // past any wait, inside the lock
		if _, err := f.browser(name, rootPass, ""); !errors.Is(err, auth.ErrThrottled) {
			t.Fatalf("%s after ten browser failures: %v; want locked for browsers", name, err)
		}
		if _, err := f.browser(strings.ToUpper(name), rootPass, ""); !errors.Is(err, auth.ErrThrottled) {
			t.Fatalf("%s in capitals after ten failures: %v", name, err)
		}
	}
	// The console is another count: the administrator signs in at the host.
	if _, err := f.login(t, "root", rootPass, ""); err != nil {
		t.Fatalf("the console after ten bad browser logins: %v; a browser must not lock the console", err)
	}
	*f.clock = f.clock.Add(auth.LockFor)
	if _, err := f.browser("root", rootPass, ""); err != nil {
		t.Fatalf("after the lock: %v", err)
	}
	// The console's own lock holds for a browser too (the first administrator
	// is never locked at the console, so another user shows it), and so do a
	// disabled user's refusal and the need to change a passphrase.
	const anaPass = "a fine long passphrase 1"
	if err := f.call(t, "user:1", "auth.user.add", auth.UserAsk{Name: "ana", Role: auth.RoleOperator, Passphrase: anaPass}, nil); err != nil {
		t.Fatal(err)
	}
	if u, err := f.browser("ana", anaPass, ""); err != nil || !u.MustChange || u.Role != auth.RoleOperator {
		t.Fatalf("a new user's first browser login: %+v, %v; want in, and told to change the passphrase", u, err)
	}
	for i := 0; i < auth.LockAfter; i++ {
		_, _ = f.login(t, "ana", "wrong", "")
		*f.clock = f.clock.Add(auth.MaxWait + time.Second)
	}
	if _, err := f.browser("ana", anaPass, ""); !errors.Is(err, auth.ErrThrottled) {
		t.Fatalf("a browser login of a name locked at the console: %v", err)
	}
	*f.clock = f.clock.Add(auth.LockFor)
	if err := f.call(t, "user:1", "auth.user.disable", auth.UserAsk{Name: "ana", Disabled: true}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := f.browser("ana", anaPass, ""); !errors.Is(err, auth.ErrBadLogin) {
		t.Fatalf("a disabled user's right passphrase from a browser: %v; want the one failure", err)
	}
}

// TestBrowserLoginsQueue: one is verified at a time, four may wait, and the
// sixth is refused at once; a disabled user and a user who must change their
// passphrase are told apart only after a right login.
func TestBrowserLoginsQueue(t *testing.T) {
	f := newFixture(t)
	release := auth.HoldDerive(f.m)
	var wg sync.WaitGroup
	results := make(chan error, 5)
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := f.browser("root", rootPass, "")
			results <- err
		}()
	}
	// The five are in: one at the passphrase check, four behind it.
	deadline := time.Now().Add(5 * time.Second)
	for auth.BrowserQueued(f.m) < 5 {
		if time.Now().After(deadline) {
			t.Fatalf("only %d of five browser logins got in", auth.BrowserQueued(f.m))
		}
		time.Sleep(5 * time.Millisecond)
	}
	_, sixth := f.browser("root", rootPass, "")
	if !errors.Is(sixth, auth.ErrBusy) {
		t.Fatalf("a sixth browser login with five inside: %v; want refused as busy", sixth)
	}
	select {
	case err := <-results:
		t.Fatalf("a login finished while the check was held: %v", err)
	default:
	}
	release()
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("a queued login: %v", err)
		}
	}
	// A caller who goes away while waiting leaves its place.
	release = auth.HoldDerive(f.m)
	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan struct{})
	go func() {
		_, _ = f.m.BrowserLogin(context.Background(), auth.Login{User: "root", Passphrase: rootPass}, "c")
		close(first)
	}()
	for auth.BrowserQueued(f.m) < 1 {
		time.Sleep(5 * time.Millisecond)
	}
	gone := make(chan error, 1)
	go func() {
		_, err := f.m.BrowserLogin(ctx, auth.Login{User: "root", Passphrase: rootPass}, "c")
		gone <- err
	}()
	for auth.BrowserQueued(f.m) < 2 {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if err := <-gone; !errors.Is(err, auth.ErrBusy) {
		t.Fatalf("a login whose caller went away: %v", err)
	}
	if n := auth.BrowserQueued(f.m); n != 1 {
		t.Fatalf("%d places held after the waiting caller left; want the first login's one", n)
	}
	release()
	<-first
}
