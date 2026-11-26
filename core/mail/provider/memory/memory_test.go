package memory_test

import (
	"sync"
	"testing"
	"time"

	"github.com/yongjohnlee80/autopanel/core/mail/provider/conformance"
	"github.com/yongjohnlee80/autopanel/core/mail/provider/memory"
)

// TestTheServerInMemoryConforms: the server core/mail's tests run on keeps
// the contract any SDK must.
func TestTheServerInMemoryConforms(t *testing.T) {
	var mu sync.Mutex
	now := time.Now()
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	s := memory.New()
	s.Now = clock
	conformance.Run(t, conformance.Target{Server: s, Domain: "conformance.example", SignIn: s.SignIn, Now: clock,
		Wait: func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() },
		OwnScript: func(_ *testing.T, id string) func() {
			s.OwnScript(id, true)
			return func() { s.OwnScript(id, false) }
		}})
}
