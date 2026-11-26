package site

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// PROTECTED NODES — a folder or a document read by whoever gives its
// passphrase. The core keeps an Argon2id verifier of the passphrase, and a
// record of each reader it let in (a grant): the reader's browser holds an
// opaque value, the store its hash. A grant opens the node it was given for,
// while that node is protected and its passphrase is the one that was given;
// a public node under a protected folder is opened by the folder's grant, by
// the chain's rule (MayAt). Decision: docs/decisions/site.md.

// The bounds of protection.
const (
	GrantFor         = 12 * time.Hour
	MaxGrantsASite   = 20000
	MaxGrantCookies  = 8             // grants one browser keeps: the cookie slots
	unlockWaiting    = 8             // unlocks that may wait for the one derivation
	unlockPerMinute  = 5             // attempts a minute from one address, or one /64
	unlockFailures   = 30            // failures an hour on one node before it slows
	unlockSlowEvery  = time.Minute   // then: one attempt a minute on that node
	unlockWindow     = time.Hour     //
	unlockAddresses  = 4096          // addresses whose attempts are remembered
	unlockNodes      = 4096          // nodes whose failures are remembered
	maxPassphrase    = 1024          // bytes
	minPassphrase    = 12            // characters, when no stricter rule is given
	unlockCookieSize = 32            // bytes of the form's cookie
	UnlockPath       = "/_unlock/"   // POST /_unlock/<node id>, on the site's host
	UnlockCookie     = "__Host-ap_u" // the form's cookie
	GrantCookie      = "__Host-ap_g" // + a slot, 0 to 7
)

var (
	ErrWeakPassphrase = errors.New("site: a passphrase is at least 12 characters, and none of the common ones")
	ErrNotProtected   = errors.New("site: only a protected folder or document has a passphrase")
)

// verifierParams are Argon2id's: the login's own (19 MiB, two passes). A
// test lowers them.
var verifierParams = struct {
	time, memKiB uint32
}{2, 19 * 1024}

// makeVerifier is an Argon2id verifier of pass, with a salt of its own.
func makeVerifier(pass string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	p := verifierParams
	sum := argon2.IDKey([]byte(pass), salt, p.time, p.memKiB, 1, 32)
	return fmt.Sprintf("argon2id$%d$%d$%s$%s", p.time, p.memKiB, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(sum)), nil
}

// checkVerifier reports whether pass is the passphrase of verifier. It
// derives once whatever the verifier's shape, so a refusal costs the same.
func checkVerifier(verifier, pass string) bool {
	parts := strings.Split(verifier, "$")
	t, m := uint64(verifierParams.time), uint64(verifierParams.memKiB)
	var salt, want []byte
	ok := len(parts) == 5 && parts[0] == "argon2id"
	if ok {
		var e1, e2, e3, e4 error
		t, e1 = strconv.ParseUint(parts[1], 10, 32)
		m, e2 = strconv.ParseUint(parts[2], 10, 32)
		salt, e3 = base64.RawStdEncoding.DecodeString(parts[3])
		want, e4 = base64.RawStdEncoding.DecodeString(parts[4])
		ok = e1 == nil && e2 == nil && e3 == nil && e4 == nil && t >= 1 && t <= 16 && m >= 8 && m <= 256*1024 && len(want) == 32
	}
	if !ok {
		t, m, salt, want = uint64(verifierParams.time), uint64(verifierParams.memKiB), make([]byte, 16), make([]byte, 32)
	}
	got := argon2.IDKey([]byte(pass), salt, uint32(t), uint32(m), 1, 32)
	return subtle.ConstantTimeCompare(got, want) == 1 && ok
}

// protection is the module's state for unlocks: the form's key, the one
// derivation at a time, and what it remembers of attempts.
type protection struct {
	key    [32]byte      // signs the unlock form's token; made at start, so a form does not outlive the core
	inside chan struct{} // the one derivation
	queue  chan struct{} // those inside and waiting

	mu       sync.Mutex
	attempts map[string][]time.Time // by address and by /64
	failures map[int64][]time.Time  // by node
	slowed   map[int64]time.Time    // a node's last attempt once it is slowed
}

func newProtection() *protection {
	p := &protection{inside: make(chan struct{}, 1), queue: make(chan struct{}, 1+unlockWaiting),
		attempts: map[string][]time.Time{}, failures: map[int64][]time.Time{}, slowed: map[int64]time.Time{}}
	if _, err := rand.Read(p.key[:]); err != nil {
		panic("site: no randomness for the unlock key: " + err.Error())
	}
	return p
}

// SetWeak gives the module the rule a passphrase must pass beside its length
// (the login's list of common ones). nil: the length alone.
func (m *Module) SetWeak(weak func(pass string) bool) { m.weak = weak }

// ProtectAsk names a protected node and its passphrase.
type ProtectAsk struct {
	Site       string `json:"site"`
	Path       string `json:"path"`
	Passphrase string `json:"passphrase,omitempty"`
}

// protectable is the protected node at a.Path that the caller may set a
// passphrase on: its owner's, or an administrator's.
func (m *Module) protectable(ctx context.Context, a ProtectAsk) (Doc, error) {
	who, _, err := m.reader(ctx)
	if err != nil {
		return Doc{}, err
	}
	s, err := m.siteOf(ctx, a.Site)
	if err != nil {
		return Doc{}, err
	}
	chain, err := m.node(ctx, who, s, a.Path)
	if err != nil {
		return Doc{}, err
	}
	d := chain[len(chain)-1]
	if d.Visibility != Protected {
		return Doc{}, ErrNotProtected
	}
	if !MayAt(who, ActProtect, chain) {
		return Doc{}, ErrNotYours
	}
	return d, nil
}

func (m *Module) protect(ctx context.Context, p ProtectAsk) (struct{}, error) {
	d, err := m.protectable(ctx, p)
	if err != nil {
		return struct{}{}, err
	}
	if len([]rune(p.Passphrase)) < minPassphrase || len(p.Passphrase) > maxPassphrase || (m.weak != nil && m.weak(p.Passphrase)) {
		return struct{}{}, ErrWeakPassphrase
	}
	// One derivation at a time here too, with the unlocks.
	if !m.prot.enter(ctx) {
		return struct{}{}, ErrBusy
	}
	v, err := makeVerifier(p.Passphrase)
	m.prot.leave()
	if err != nil {
		return struct{}{}, err
	}
	_, err = m.store.SetProtect(ctx, d.ID, v)
	return struct{}{}, err
}

func (m *Module) unprotect(ctx context.Context, p ProtectAsk) (struct{}, error) {
	d, err := m.protectable(ctx, p)
	if err != nil {
		return struct{}{}, err
	}
	return struct{}{}, m.store.ClearProtect(ctx, d.ID)
}

// ErrBusy: the one derivation is taken and its queue is full.
var ErrBusy = errors.New("site: too many passphrases are being checked; try again shortly")

func (p *protection) enter(ctx context.Context) bool {
	select {
	case p.queue <- struct{}{}:
	default:
		return false
	}
	select {
	case p.inside <- struct{}{}:
		return true
	case <-ctx.Done():
		<-p.queue
		return false
	}
}

func (p *protection) leave() {
	<-p.inside
	<-p.queue
}

// granted answers Reader.Granted for the grant cookies a request carried: a
// node is opened by a grant given for that node, at its protection's
// generation as it is now, while the node is protected.
func (m *Module) granted(ctx context.Context, site int64, cookies []string) func(Doc) bool {
	if len(cookies) == 0 {
		return nil
	}
	if len(cookies) > MaxGrantCookies {
		cookies = cookies[:MaxGrantCookies]
	}
	hashes := make([][32]byte, 0, len(cookies))
	for _, c := range cookies {
		hashes = append(hashes, sha256.Sum256([]byte(c)))
	}
	grants, err := m.store.GrantsOf(ctx, hashes, m.now().Unix())
	if err != nil || len(grants) == 0 {
		return nil
	}
	return func(d Doc) bool {
		if d.Visibility != Protected || d.Site != site {
			return false
		}
		for _, g := range grants {
			if g.Node != d.ID || g.Site != site {
				continue
			}
			if _, gen, err := m.store.ProtectOf(ctx, d.ID); err == nil && gen == g.Generation {
				return true
			}
		}
		return false
	}
}

// unlockToken binds the unlock form to the node, its protection as it is now
// and the browser the form was given to (its cookie): a form made for
// another node, another passphrase or another browser is refused.
func (p *protection) unlockToken(node, gen int64, cookie string) string {
	mac := hmac.New(sha256.New, p.key[:])
	fmt.Fprintf(mac, "unlock\x00%d\x00%d\x00%s", node, gen, cookie)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// lock is the first protected node of chain that who has no grant for: the
// one whose passphrase is asked for. ok is false when there is none.
func lock(who Reader, chain []Doc) (Doc, bool) {
	for _, d := range chain {
		if d.Visibility == Protected && !May(who, ActRead, d) {
			return d, true
		}
	}
	return Doc{}, false
}

// unlockForm is the page a protected address answers to a reader without its
// grant: the core's own, with nothing of the node but that it is protected.
// cookie is the form's cookie: the one the request carried, or a new one.
func (m *Module) unlockForm(ctx context.Context, s Site, d Doc, next, cookie string, failed bool) ReadAnswer {
	ans := ReadAnswer{Status: ReadUnlock, Protected: true}
	_, gen, err := m.store.ProtectOf(ctx, d.ID)
	if err != nil {
		return ReadAnswer{Status: ReadMissing, Protected: true} // no passphrase is set: nobody is let in
	}
	if !validUnlockCookie(cookie) {
		raw := make([]byte, unlockCookieSize)
		if _, err := rand.Read(raw); err != nil {
			return ReadAnswer{Status: ReadMissing, Protected: true}
		}
		cookie = base64.RawURLEncoding.EncodeToString(raw)
		ans.SetCookie = UnlockCookie + "=" + cookie + "; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=3600"
	}
	config, _ := StoredConfig(s)
	title := config.Title
	if title == "" {
		title = s.Host
	}
	note := ""
	if failed {
		note = `<p class="unlock-failed">That passphrase did not open it.</p>`
	}
	ans.Form = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">` +
		`<meta name="robots" content="noindex"><title>Protected · ` + html.EscapeString(title) + `</title><link rel="stylesheet" href="/look.css"></head>` +
		`<body class="unlock"><main><h1>This page is protected</h1>` + note +
		`<form method="post" action="` + UnlockPath + strconv.FormatInt(d.ID, 10) + `">` +
		`<label>Passphrase <input type="password" name="passphrase" autocomplete="off" required autofocus></label>` +
		`<input type="hidden" name="token" value="` + m.prot.unlockToken(d.ID, gen, cookie) + `">` +
		`<input type="hidden" name="next" value="` + html.EscapeString(next) + `">` +
		`<button type="submit">Open</button></form></main></body></html>`
	return ans
}

func validUnlockCookie(c string) bool {
	if len(c) != base64.RawURLEncoding.EncodedLen(unlockCookieSize) {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(c)
	return err == nil
}

// UnlockAsk is a reader's answer to the unlock form, as the serving process
// passes it on: what the form held, the form's cookie, where the request
// came from, and the grant cookies the browser already has, by slot.
type UnlockAsk struct {
	Host       string   `json:"host"`
	Node       int64    `json:"node"`
	Passphrase string   `json:"passphrase"`
	Token      string   `json:"token"`
	Next       string   `json:"next"`
	Cookie     string   `json:"cookie"`     // the form's cookie
	Origin     string   `json:"origin"`     // the request's Origin
	FetchSite  string   `json:"fetch_site"` // its Sec-Fetch-Site
	Client     string   `json:"client"`     // the reader's address, as the gate wrote it
	Slots      []string `json:"slots"`      // the grant cookies by slot, "" where there is none
}

// The answers to an unlock.
const (
	UnlockGranted = "granted" // set SetCookie, go to Location
	UnlockRefused = "refused" // show Form again
	UnlockBusy    = "busy"    // 503: too many are being checked, or this node is slowed; try shortly
	UnlockGone    = "missing" // nothing to unlock here
)

// UnlockAnswer is the core's answer to an unlock.
type UnlockAnswer struct {
	Status    string `json:"status"`
	SetCookie string `json:"set_cookie,omitempty"`
	Location  string `json:"location,omitempty"`
	Form      string `json:"form,omitempty"`
	Wait      int    `json:"wait,omitempty"` // seconds, with busy
}

// Unlock checks a passphrase given at the unlock form and answers a grant.
// What it checks, in order, each before the next costs anything: that the
// post came from the site's own page; that the form was this node's, for
// this browser; the limits by address; the attempt's audit entry; the
// node's own limit; and then, one at a time, the passphrase.
func (m *Module) Unlock(ctx context.Context, ask UnlockAsk) UnlockAnswer {
	gone := UnlockAnswer{Status: UnlockGone}
	s, err := m.store.SiteByHost(ctx, ask.Host)
	if err != nil || ask.Node <= 0 {
		return gone
	}
	// A post from another site's page is refused before anything is read.
	if ask.Origin != "https://"+s.Host || (ask.FetchSite != "" && ask.FetchSite != "same-origin") {
		return gone
	}
	d, err := m.store.DocByID(ctx, ask.Node)
	if err != nil || d.Site != s.ID || d.Visibility != Protected {
		return gone
	}
	verifier, gen, err := m.store.ProtectOf(ctx, d.ID)
	if err != nil {
		return gone
	}
	if !validUnlockCookie(ask.Cookie) || !hmac.Equal([]byte(ask.Token), []byte(m.prot.unlockToken(d.ID, gen, ask.Cookie))) {
		return gone
	}
	next := ask.Next
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.ContainsAny(next, "\\\r\n") || len(next) > MaxPath+MaxResourceName+8 {
		next = "/"
	}
	now := m.now()
	if !m.prot.admit(ask.Client, now) {
		return UnlockAnswer{Status: UnlockBusy, Wait: 60}
	}
	if wait := m.prot.slow(d.ID, now); wait > 0 {
		return UnlockAnswer{Status: UnlockBusy, Wait: wait}
	}
	if len(ask.Passphrase) == 0 || len(ask.Passphrase) > maxPassphrase {
		m.prot.failed(d.ID, now)
		return m.refused(ctx, s, d, next, ask.Cookie)
	}
	// Written down before the passphrase is tried, or it is not tried.
	if err := m.store.NoteUnlock(ctx, d, printableClient(ask.Client)); err != nil {
		return UnlockAnswer{Status: UnlockBusy, Wait: 5}
	}
	if !m.prot.enter(ctx) {
		return UnlockAnswer{Status: UnlockBusy, Wait: 2}
	}
	ok := checkVerifier(verifier, ask.Passphrase)
	m.prot.leave()
	if !ok {
		m.prot.failed(d.ID, now)
		return m.refused(ctx, s, d, next, ask.Cookie)
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return UnlockAnswer{Status: UnlockBusy, Wait: 5}
	}
	value := base64.RawURLEncoding.EncodeToString(raw)
	g := Grant{IDHash: sha256.Sum256([]byte(value)), Site: s.ID, Node: d.ID, Generation: gen, Issued: now.Unix(), Expires: now.Add(GrantFor).Unix()}
	if err := m.store.AddGrant(ctx, g, MaxGrantsASite, now.Unix()); err != nil {
		return UnlockAnswer{Status: UnlockBusy, Wait: 5}
	}
	slot := m.slotFor(ctx, ask.Slots, now)
	return UnlockAnswer{Status: UnlockGranted, Location: next,
		SetCookie: GrantCookie + strconv.Itoa(slot) + "=" + value + "; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=" + strconv.Itoa(int(GrantFor/time.Second))}
}

func (m *Module) refused(ctx context.Context, s Site, d Doc, next, cookie string) UnlockAnswer {
	form := m.unlockForm(ctx, s, d, next, cookie, true)
	if form.Status != ReadUnlock {
		return UnlockAnswer{Status: UnlockGone}
	}
	return UnlockAnswer{Status: UnlockRefused, Form: form.Form}
}

// slotFor is the cookie slot a new grant takes: the first the browser has
// free, or the one whose grant is gone or oldest.
func (m *Module) slotFor(ctx context.Context, slots []string, now time.Time) int {
	oldest, at := 0, int64(1<<62)
	for i := 0; i < MaxGrantCookies; i++ {
		if i >= len(slots) || slots[i] == "" {
			return i
		}
		gs, err := m.store.GrantsOf(ctx, [][32]byte{sha256.Sum256([]byte(slots[i]))}, now.Unix())
		if err != nil || len(gs) == 0 {
			return i // a cookie whose grant has ended
		}
		if gs[0].Issued < at {
			oldest, at = i, gs[0].Issued
		}
	}
	return oldest
}

func printableClient(c string) string {
	if a, err := netip.ParseAddr(strings.TrimSpace(c)); err == nil {
		return a.String()
	}
	return "an unknown address"
}

// admit counts an attempt from client against its address and its /64, and
// reports whether it is within unlockPerMinute for both. An address that
// cannot be read is one address.
func (p *protection) admit(client string, now time.Time) bool {
	keys := []string{"?"}
	if a, err := netip.ParseAddr(strings.TrimSpace(client)); err == nil {
		a = a.Unmap()
		keys = []string{a.String()}
		if a.Is6() {
			if pfx, err := a.Prefix(64); err == nil {
				keys = append(keys, pfx.String())
			}
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.attempts) > unlockAddresses {
		clear(p.attempts) // more addresses than are remembered: forget, and count again
	}
	ok := true
	for _, k := range keys {
		recent := within(p.attempts[k], now, time.Minute)
		if len(recent) >= unlockPerMinute {
			ok = false
		}
		p.attempts[k] = recent
	}
	if ok {
		for _, k := range keys {
			p.attempts[k] = append(p.attempts[k], now)
		}
	}
	return ok
}

// slow reports how long an attempt on node must still wait: 0 unless the
// node has had unlockFailures failures within the hour, after which one
// attempt a minute is let through. Readers who are in are not touched.
func (p *protection) slow(node int64, now time.Time) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.failures[node] = within(p.failures[node], now, unlockWindow)
	if len(p.failures[node]) < unlockFailures {
		delete(p.slowed, node)
		return 0
	}
	if last, ok := p.slowed[node]; ok && now.Sub(last) < unlockSlowEvery {
		return int((unlockSlowEvery-now.Sub(last))/time.Second) + 1
	}
	p.slowed[node] = now
	return 0
}

func (p *protection) failed(node int64, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.failures) > unlockNodes {
		clear(p.failures)
		clear(p.slowed)
	}
	fs := within(p.failures[node], now, unlockWindow)
	if len(fs) < unlockFailures {
		fs = append(fs, now)
	}
	p.failures[node] = fs
}

// within are the times of ts within d before now.
func within(ts []time.Time, now time.Time, d time.Duration) []time.Time {
	out := ts[:0]
	for _, t := range ts {
		if now.Sub(t) < d {
			out = append(out, t)
		}
	}
	return out
}
