package auth

import "time"

// SetClock gives a test the module's clock.
func SetClock(m *Module, now func() time.Time) { m.now = now }

// SecretsOf is the module's secrets, for a second module over the same store.
func SecretsOf(m *Module) Secrets { return m.secrets }

// HoldDerive takes the one place a passphrase check runs in, so every login
// waits until the returned function is called.
func HoldDerive(m *Module) (release func()) {
	m.sem <- struct{}{}
	return func() { <-m.sem }
}

// BrowserQueued is how many browser logins are inside or waiting.
func BrowserQueued(m *Module) int { return len(m.browser.queue) }
