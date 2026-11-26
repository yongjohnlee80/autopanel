package site

import "time"

// CheapVerifiers makes a passphrase's verifier cost little, for tests.
func CheapVerifiers() { verifierParams.time, verifierParams.memKiB = 1, 8 }

// SetClock has the module read the time from now.
func SetClock(m *Module, now func() time.Time) { m.now = now }
