package auth

import "time"

// SetClock gives a test the module's clock.
func SetClock(m *Module, now func() time.Time) { m.now = now }

// SecretsOf is the module's secrets, for a second module over the same store.
func SecretsOf(m *Module) Secrets { return m.secrets }
