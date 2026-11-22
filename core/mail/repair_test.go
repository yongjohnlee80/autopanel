package mail

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yongjohnlee80/autopanel/core/mail/provider"
	"github.com/yongjohnlee80/autopanel/core/mail/provider/memory"
	"github.com/yongjohnlee80/autopanel/core/services"
)

type stepAudit struct {
	mu    sync.Mutex
	steps []string
}

func (a *stepAudit) Audit(_ context.Context, _, _, _, detail string) error {
	a.mu.Lock()
	a.steps = append(a.steps, detail)
	a.mu.Unlock()
	return nil
}

type repairFixture struct {
	m      *Module
	st     *fakeStore
	v      *fakeVault
	stacks *fakeStacks
	h      *fakeHost
	p      *memory.Product
	aud    *stepAudit
}

// newRepair is set-up mail whose server signs AutoPanel in, with the stack's
// definition written as AutoPanel writes it, and an apply that starts the
// server with the recovery administrator its definition references.
func newRepair(t *testing.T) *repairFixture {
	t.Helper()
	m, st, v, stacks, h, _ := newTestModule(t)
	f := &repairFixture{m: m, st: st, v: v, stacks: stacks, h: h, p: prod(m), aud: &stepAudit{}}
	m.SetAudit(f.aud)
	st.state = &State{Host: "mail.example.net", CreatedAt: 1, Bootstrapped: 1}
	cfg, _ := json.Marshal(Config{Host: "mail.example.net", FirstDomain: "example.net"})
	v.m[sealedConfig] = cfg
	v.m[sealedKey] = []byte(f.p.Key)
	v.m[sealedServer+"admin"] = []byte("admin:first")
	f.p.Admin = "admin:first"
	h.definition = m.compose()
	stacks.def = func() []byte { return h.definition }
	stacks.onApply = func(compose []byte) error {
		if strings.Contains(string(compose), "${sealed:stack/mail/recovery}") {
			f.p.Start(v.m[sealedRecovery])
		} else {
			f.p.Start(nil)
		}
		return nil
	}
	t.Cleanup(func() { restartTimeout, listenersOpen = 2*time.Minute, 3*time.Second })
	restartTimeout, listenersOpen = 5*time.Second, 0
	return f
}

func (f *repairFixture) check(t *testing.T) Diagnosis {
	t.Helper()
	d, err := f.m.repairCheck(context.Background(), struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// revoke is the API key revoked in the server's own UI.
func (f *repairFixture) revoke() { f.p.Key = "a key nobody has" }

// TestTheDiagnosis: each case told apart by trying, and nothing changed.
func TestTheDiagnosis(t *testing.T) {
	f := newRepair(t)
	if d := f.check(t); d.Case != CaseOK {
		t.Fatalf("a working key: %+v", d)
	}
	f.revoke()
	if d := f.check(t); d.Case != CaseKeyLost {
		t.Fatalf("a revoked key: %+v", d)
	}
	delete(f.v.m, sealedKey) // a vault restored from before the key
	if d := f.check(t); d.Case != CaseKeyLost {
		t.Fatalf("a key the vault lost: %+v", d)
	}
	f.p.Admin = "admin:changed by hand"
	d := f.check(t)
	if d.Case != CaseAdminLost || d.Review == nil || d.Review.SHA256 != "reviewed-recovery" || len(d.Plan) != 5 {
		t.Fatalf("the key and the administrator lost: %+v", d)
	}
	if string(f.h.definition) != string(f.m.compose()) || len(f.stacks.applies) != 0 {
		t.Fatal("the check changed the stack")
	}
	if _, ok := f.v.m[sealedRecovery]; ok {
		t.Fatal("the check sealed a recovery value")
	}
	f.p.RepairFail = func(string) error { return errors.New("connection refused") }
	if d := f.check(t); d.Case != CaseUnreachable || !strings.Contains(d.Detail, "connection refused") {
		t.Fatalf("a server that does not answer the administrator: %+v", d)
	}
	f.p.RepairFail = nil
	mem(f.m).Fail = func(method string) error {
		if method == "Domains" {
			return errors.New("connection refused")
		}
		return nil
	}
	f.p.Key = string(f.v.m[sealedKey])
	f.v.m[sealedKey] = []byte(f.p.Key)
	if d := f.check(t); d.Case != CaseUnreachable {
		t.Fatalf("a server that does not answer: %+v", d)
	}
	mem(f.m).Fail = nil
	f.v.m[sealedRecovery] = []byte("recovery:left")
	if d := f.check(t); d.Case != CaseLeftover {
		t.Fatalf("a recovery value left in the vault: %+v", d)
	}
	delete(f.v.m, sealedRecovery)
	f.h.definition = f.m.composeRecovery()
	if d := f.check(t); d.Case != CaseLeftover {
		t.Fatalf("a definition left with the reference: %+v", d)
	}
	f.h.definition = f.m.compose()
	f.st.state.Bootstrapped = 0
	if d := f.check(t); d.Case != CaseNotSetUp {
		t.Fatalf("a server never set up: %+v", d)
	}
	f.st.state.Bootstrapped = 1
	f.v.locked = true
	if _, err := f.m.repairCheck(context.Background(), struct{}{}); !errors.Is(err, ErrLocked) {
		t.Fatalf("a locked vault: %v", err)
	}
}

// TestALostKeyIsMadeAgain: by the administrator, sealed, signing in; no
// restart; nothing of mail's changed.
func TestALostKeyIsMadeAgain(t *testing.T) {
	f := newRepair(t)
	f.p.OtherKeys = []string{"made by hand"}
	if _, err := mem(f.m).AddDomain(context.Background(), "example.net"); err != nil {
		t.Fatal(err)
	}
	f.revoke()
	r, err := f.m.repair(context.Background(), RepairAsk{})
	if err != nil {
		t.Fatal(err)
	}
	if r.Case != CaseKeyLost || len(r.Kept) != 1 || r.Kept[0] != "made by hand" {
		t.Fatalf("the repair: %+v", r)
	}
	if _, err := f.m.client().Domains(context.Background()); err != nil {
		t.Fatalf("the new key does not sign in: %v", err)
	}
	if f.stacks.restarts != 0 || len(f.stacks.applies) != 0 {
		t.Fatal("a new key restarted the stack")
	}
	if ds, _ := mem(f.m).Domains(context.Background()); len(ds) != 1 {
		t.Fatal("the repair touched mail's domains")
	}
	if d := f.check(t); d.Case != CaseOK {
		t.Fatalf("after the repair: %+v", d)
	}
	if !strings.Contains(strings.Join(f.aud.steps, "\n"), "key_lost: a new API key, by the administrator") {
		t.Fatalf("the steps on record: %v", f.aud.steps)
	}
}

// TestALostAdministratorIsRecovered: only with the review accepted; the
// recovery administrator for one start, then gone, its value last.
func TestALostAdministratorIsRecovered(t *testing.T) {
	f := newRepair(t)
	f.revoke()
	f.p.Admin = "admin:changed by hand"
	ctx := context.Background()
	r, err := f.m.repair(ctx, RepairAsk{})
	if err != nil || !r.NeedsAccept || r.Diagnosis == nil || r.Diagnosis.Review == nil || len(f.stacks.applies) != 0 {
		t.Fatalf("without the acceptance: %+v, %v", r, err)
	}
	if r, err := f.m.repair(ctx, RepairAsk{Accept: "something else"}); err != nil || !r.NeedsAccept {
		t.Fatalf("another acceptance: %+v, %v", r, err)
	}
	r, err = f.m.repair(ctx, RepairAsk{Accept: "reviewed-recovery"})
	if err != nil || r.Case != CaseAdminLost {
		t.Fatalf("the repair: %+v, %v", r, err)
	}
	if strings.Join(f.stacks.applies, " ") != "reviewed-recovery reviewed-compose" {
		t.Fatalf("the applies: %v; want the recovery's, then AutoPanel's own", f.stacks.applies)
	}
	if string(f.h.definition) != string(f.m.compose()) || f.p.Recovery != nil {
		t.Fatal("the recovery administrator is still in place")
	}
	if _, ok := f.v.m[sealedRecovery]; ok {
		t.Fatal("the recovery value is still in the vault")
	}
	if string(f.v.m[sealedServer+"admin"]) != f.p.Admin || f.p.Admin == "admin:changed by hand" {
		t.Fatal("the administrator's new secret is not the sealed one")
	}
	if d := f.check(t); d.Case != CaseOK {
		t.Fatalf("after the repair: %+v", d)
	}
	steps := strings.Join(f.aud.steps, "\n")
	for _, s := range []string{"admin_lost: the recovery value sealed", "the administrator's new secret", "recovery: the recovery value deleted"} {
		if !strings.Contains(steps, s) {
			t.Errorf("no step %q on record: %s", s, steps)
		}
	}
	if strings.Contains(steps, "recovery:") && strings.Contains(steps, string(f.p.Recovery)) && f.p.Recovery != nil {
		t.Fatal("a secret is on record")
	}
}

// TestAFailedRecoveryLeavesNoRecoveryAdministrator: at each step it can fail,
// the recovery administrator is taken away again.
func TestAFailedRecoveryLeavesNoRecoveryAdministrator(t *testing.T) {
	for name, set := range map[string]func(f *repairFixture){
		"two administrators":    func(f *repairFixture) { f.p.Admins = 2 },
		"the reset refused":     func(f *repairFixture) { f.p.RepairFail = failAt("reset") },
		"the new key refused":   func(f *repairFixture) { f.p.RepairFail = failAt("key") },
		"the first apply fails": func(f *repairFixture) { f.stacks.applyErr = errors.New("podman: no") },
	} {
		t.Run(name, func(t *testing.T) {
			f := newRepair(t)
			f.revoke()
			f.p.Admin = "admin:changed by hand"
			set(f)
			if _, err := f.m.repair(context.Background(), RepairAsk{Accept: "reviewed-recovery"}); !errors.Is(err, ErrRepairFails) {
				t.Fatalf("the repair: %v", err)
			}
			if string(f.h.definition) != string(f.m.compose()) || f.p.Recovery != nil {
				t.Fatal("the recovery administrator is still in place")
			}
			if _, ok := f.v.m[sealedRecovery]; ok {
				t.Fatal("the recovery value is still in the vault")
			}
		})
	}
}

func failAt(step string) func(string) error {
	return func(s string) error {
		if s == step {
			return errors.New("refused at " + step)
		}
		return nil
	}
}

// TestALeftoverIsFinishedFirst: what a core that stopped half way left is
// taken away, then the case under it repaired.
func TestALeftoverIsFinishedFirst(t *testing.T) {
	f := newRepair(t)
	f.v.m[sealedRecovery] = []byte("recovery:left")
	f.h.definition = f.m.composeRecovery()
	f.p.Start([]byte("recovery:left"))
	f.revoke()
	r, err := f.m.repair(context.Background(), RepairAsk{})
	if err != nil || r.Case != CaseKeyLost || len(r.Done) != 2 {
		t.Fatalf("the repair: %+v, %v", r, err)
	}
	if _, ok := f.v.m[sealedRecovery]; ok || f.p.Recovery != nil || string(f.h.definition) != string(f.m.compose()) {
		t.Fatal("the leftover is still there")
	}
	// The value is deleted only once the recovery administrator no longer
	// signs in.
	f = newRepair(t)
	f.v.m[sealedRecovery] = []byte("recovery:left")
	f.stacks.onApply = func([]byte) error { f.p.Start([]byte("recovery:left")); return nil } // a server that keeps it
	if _, err := f.m.repair(context.Background(), RepairAsk{}); !errors.Is(err, ErrRepairFails) {
		t.Fatalf("a recovery administrator that outlives its removal: %v", err)
	}
	if _, ok := f.v.m[sealedRecovery]; !ok {
		t.Fatal("the value was deleted while the recovery administrator still signs in")
	}
}

// TestTwoRepairsAtOnce: the second waits for the first, and finds nothing to
// repair.
func TestTwoRepairsAtOnce(t *testing.T) {
	f := newRepair(t)
	f.revoke()
	var wg sync.WaitGroup
	cases := make(chan string, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := f.m.repair(context.Background(), RepairAsk{})
			if err != nil {
				t.Error(err)
			}
			cases <- r.Case
		}()
	}
	wg.Wait()
	close(cases)
	var got []string
	for c := range cases {
		got = append(got, c)
	}
	if !(len(got) == 2 && ((got[0] == CaseKeyLost && got[1] == CaseOK) || (got[0] == CaseOK && got[1] == CaseKeyLost))) {
		t.Fatalf("two repairs: %v", got)
	}
}

// TestTheRepairsHostChecks: mail-access while the key does not sign in,
// mail-recovery-active while a recovery value is left, none while a repair
// runs.
func TestTheRepairsHostChecks(t *testing.T) {
	f := newRepair(t)
	ctx := context.Background()
	f.m.noteAccess(provider.ErrUnauthorized)
	f.v.m[sealedRecovery] = []byte("x")
	ids := func() string {
		var out []string
		for _, x := range f.m.accessFindings(ctx) {
			out = append(out, x.ID)
		}
		return strings.Join(out, " ")
	}
	if got := ids(); got != "mail-access mail-recovery-active" {
		t.Fatalf("the checks: %q", got)
	}
	f.m.repairs.running.Store(true)
	if got := ids(); got != "" {
		t.Fatalf("during a repair: %q", got)
	}
	f.m.repairs.running.Store(false)
	f.m.noteAccess(nil)
	delete(f.v.m, sealedRecovery)
	if got := ids(); got != "" {
		t.Fatalf("all well: %q", got)
	}
}

// TestTheGuardKnowsTheRecovery: the mail stack may reference its recovery
// value, and no other; its definition with it is shown as the repair's.
func TestTheGuardKnowsTheRecovery(t *testing.T) {
	f := newRepair(t)
	if got := f.m.Sealed(Stack); len(got) != 1 || got[0] != "recovery" || f.m.Sealed("blog") != nil {
		t.Fatalf("sealed keys: %v", got)
	}
	if fs := f.m.Review(context.Background(), Stack, f.m.composeRecovery()); len(fs) != 1 || fs[0].ID != "mail-recovery" || fs[0].Severity != services.Warning {
		t.Fatalf("the recovery definition's review: %+v", fs)
	}
}
