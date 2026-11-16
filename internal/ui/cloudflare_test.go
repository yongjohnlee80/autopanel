package ui

import (
	"context"
	"strings"
	"testing"

	"github.com/yongjohnlee80/golib/tui/decl/decltest"

	"github.com/yongjohnlee80/autopanel/internal/cloudflare"
)

// goodToken is the token the fake Cloudflare accepts: 40 characters, as
// Cloudflare's are.
const goodToken = "cf-test-0123456789abcdefghijklmnopqrstuv"

// challenge is the certificate service's, as the daemon reports it: DNS
// through Cloudflare while a token is held. The caller holds f.mu.
func (f *fakeClient) challenge() string {
	if f.cf != "" {
		return "dns-01 (cloudflare)"
	}
	return "http-01"
}

// SetCloudflare plays the daemon: Cloudflare refuses any token but goodToken,
// and a refused one is not kept.
func (f *fakeClient) SetCloudflare(_ context.Context, token string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if token != goodToken {
		return cloudflare.ErrTokenRefused
	}
	f.cf = token
	return nil
}

func (f *fakeClient) ClearCloudflare(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cf = ""
	return nil
}

func (f *fakeClient) heldToken() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cf
}

// TestTheCloudflareToken: Certs › Cloudflare token… takes the token unseen; a
// short one and one Cloudflare refuses are said in the dialog and not kept; a
// good one is kept, and Remove Cloudflare token… opens once one is held.
func TestTheCloudflareToken(t *testing.T) {
	f := newFakeClient()
	h, s := startHost(t, f)
	s.WaitForText(t, "CA LE staging")
	if onLoop(h, h.cloudflareClearable) {
		t.Fatal("Remove Cloudflare token is open with no token held")
	}
	run(t, h, h.setCloudflare)
	s.WaitForText(t, "Cloudflare token")
	s.Keys(t, decltest.Type("short")...)
	s.Keys(t, enter)
	s.WaitForText(t, "too short for a Cloudflare token")
	for range len("short") {
		s.Keys(t, backspace)
	}
	const mistyped = "cf-test-0123456789abcdefghijklmnopqrstuX"
	s.Keys(t, decltest.Type(mistyped)...)
	s.Keys(t, enter)
	s.WaitForText(t, "Cloudflare refused this token")
	if f.heldToken() != "" {
		t.Fatal("a refused token was kept")
	}
	for range len(mistyped) {
		s.Keys(t, backspace)
	}
	s.Keys(t, decltest.Type(goodToken)...)
	if strings.Contains(s.String(), "0123456789abcdef") {
		t.Fatal("the token is on the screen")
	}
	s.Keys(t, enter)
	s.WaitForText(t, "certificates now come through DNS")
	if f.heldToken() != goodToken {
		t.Fatalf("the token kept: %d characters", len(f.heldToken()))
	}
	if strings.Contains(s.String(), "0123456789abcdef") {
		t.Fatal("the token is on the screen after it was kept")
	}
	s.WaitFor(t, "Remove Cloudflare token to open", func(string) bool { return onLoop(h, h.cloudflareClearable) })

	run(t, h, h.clearCloudflare)
	s.WaitForText(t, "Remove the Cloudflare token")
	s.Keys(t, decltest.Rune('y'))
	s.WaitForText(t, "certificates come through HTTP again")
	if f.heldToken() != "" {
		t.Fatal("the token is still held")
	}
}
