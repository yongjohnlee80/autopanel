package mail

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/yongjohnlee80/autopanel/core/audit"
	"github.com/yongjohnlee80/autopanel/core/mail/provider"
	"github.com/yongjohnlee80/autopanel/core/services"
)

// REPAIRING ACCESS — when the API key AutoPanel signs in to the mail server
// with no longer signs in, or the vault no longer holds it. mail.repair.check
// tells which of the cases it is, by trying, and changes nothing;
// mail.repair repairs it with the least power that works:
//
//   - key_lost: the sealed administrator makes a new key; the older keys
//     AutoPanel made are destroyed once the new one signs in;
//   - admin_lost: the server's recovery administrator, given to the stack
//     for one start through a reviewed sealed reference, gives the
//     administrator a new secret; then a new key; then the reference is
//     removed, the stack restarted, and only then the recovery value
//     deleted. One acceptance covers the whole run, and the end runs on
//     success as on failure;
//   - not_set_up: the stack is restarted and the bootstrap runs again;
//   - recovery_leftover: what a core that stopped half way through
//     admin_lost left, finished first.
//
// Nothing of mail's data is touched. Every step is audited before it acts.
//
// Decision: docs/decisions/mail.md#repairing-access

// The cases a diagnosis tells apart.
const (
	CaseOK          = "ok"
	CaseUnreachable = "unreachable"
	CaseNotSetUp    = "not_set_up"
	CaseLeftover    = "recovery_leftover"
	CaseKeyLost     = "key_lost"
	CaseAdminLost   = "admin_lost"
)

// recoveryKey is the one key the mail stack's definition may reference
// sealed: stack/mail/recovery, the recovery administrator.
const recoveryKey = "recovery"

var sealedRecovery = "stack/" + Stack + "/" + recoveryKey

var (
	ErrUnreachable = errors.New("mail: the mail server does not answer; a repair would not help")
	ErrNoRepair    = errors.New("mail: this mail server cannot be repaired by AutoPanel")
	ErrRepairFails = errors.New("mail: the repair did not finish")
)

// Auditor records a step before it acts.
type Auditor interface {
	Audit(ctx context.Context, actor, action, subject, detail string) error
}

// SetAudit gives mail the audit log. Set once, before the verbs are served.
func (m *Module) SetAudit(a Auditor) { m.audit = a }

// repairState is what a repair in progress tells the rest of mail: the sync
// waits, and the stack's restarts raise no alert.
type repairState struct {
	running atomic.Bool
	// access is the last sync's word on the API key: "" while it signs in,
	// "unauthorized" once it does not.
	access atomic.Value
}

// Diagnosis is mail.repair.check's answer.
type Diagnosis struct {
	Case   string `json:"case"`
	Says   string `json:"says"`             // the case in a line, for people
	Detail string `json:"detail,omitempty"` // an unreachable server's error
	// Review is admin_lost's: the stack's definition with the recovery
	// administrator, to accept with mail.repair. Its sha256 covers the
	// whole run.
	Review *services.Review `json:"review,omitempty"`
	Plan   []string         `json:"plan"`
}

// RepairAsk is mail.repair's param.
type RepairAsk struct {
	Accept string `json:"accept,omitempty"` // admin_lost: the review's sha256
}

// Repaired is mail.repair's answer.
type Repaired struct {
	Case      string   `json:"case"`
	Done      []string `json:"done"`
	Destroyed int      `json:"destroyed"`      // older keys of AutoPanel's
	Kept      []string `json:"kept,omitempty"` // keys someone else made
	// NeedsAccept: admin_lost's run was not accepted; Diagnosis says what it
	// would do.
	NeedsAccept bool       `json:"needs_accept,omitempty"`
	Diagnosis   *Diagnosis `json:"diagnosis,omitempty"`
}

func (m *Module) repairer() (provider.Repairer, error) {
	r, ok := m.product.(provider.Repairer)
	if !ok {
		return nil, ErrNoRepair
	}
	return r, nil
}

// env is the product's way to AutoPanel for a repair: the bootstrap's.
func (m *Module) env(ctx context.Context) (*bootEnv, error) {
	cfg, err := m.config(ctx)
	if err != nil {
		return nil, err
	}
	return &bootEnv{m: m, set: provider.Settings{Host: cfg.Host, FirstDomain: cfg.FirstDomain}, since: m.now()}, nil
}

// lostKey reports whether err is the API key not signing in: refused by the
// server, or not in the vault at all.
func lostKey(err error) bool {
	return errors.Is(err, provider.ErrUnauthorized) || errors.Is(err, ErrNoSecret)
}

// recoveryLeft reports a recovery administrator left in place: its value in
// the vault, or the stack's written definition still referencing it.
func (m *Module) recoveryLeft(ctx context.Context) (bool, error) {
	if _, err := m.vault.Get(ctx, sealedRecovery); err == nil {
		return true, nil
	} else if !errors.Is(err, ErrNoSecret) {
		return false, err
	}
	r, err := m.stacks.Check(ctx, Stack)
	if err != nil {
		return false, err
	}
	for _, f := range r.Findings {
		if f.ID == "sealed-reference" || f.ID == "sealed-not-allowed" {
			return true, nil
		}
	}
	return false, nil
}

func (m *Module) diagnose(ctx context.Context) (Diagnosis, error) {
	rep, err := m.repairer()
	if err != nil {
		return Diagnosis{}, err
	}
	st, ok, err := m.store.State(ctx)
	switch {
	case err != nil:
		return Diagnosis{}, err
	case !ok:
		return Diagnosis{}, ErrNotSetUp
	}
	if _, err := m.vault.Get(ctx, sealedConfig); errors.Is(err, ErrLocked) {
		return Diagnosis{}, ErrLocked
	}
	if st.Bootstrapped == 0 {
		return Diagnosis{Case: CaseNotSetUp, Says: "the mail server was never set up: it will be restarted, and set up again",
			Plan: []string{"restart the mail stack", "set the mail server up"}}, nil
	}
	left, err := m.recoveryLeft(ctx)
	if err != nil {
		return Diagnosis{}, err
	}
	if left {
		return Diagnosis{Case: CaseLeftover, Says: "a repair stopped half way and left the recovery administrator: it will be removed first",
			Plan: []string{"apply the definition without the recovery administrator (a restart)", "delete the recovery value from the vault", "diagnose again"}}, nil
	}
	_, err = m.client().Domains(ctx)
	switch {
	case err == nil:
		return Diagnosis{Case: CaseOK, Says: "the API key signs in: nothing to repair", Plan: []string{}}, nil
	case !lostKey(err):
		return Diagnosis{Case: CaseUnreachable, Says: "the mail server does not answer: see the stack's state and the host checks", Detail: oneLine(err.Error()), Plan: []string{}}, nil
	}
	env, err := m.env(ctx)
	if err != nil {
		return Diagnosis{}, err
	}
	err = rep.AdminSignsIn(ctx, env)
	switch {
	case err == nil:
		return Diagnosis{Case: CaseKeyLost, Says: "the API key no longer signs in; the administrator does: a new key will be made",
			Plan: []string{"make a new API key with the administrator, and seal it", "destroy the older keys AutoPanel made"}}, nil
	case !lostKey(err) && !errors.Is(err, provider.ErrNoSecret):
		return Diagnosis{Case: CaseUnreachable, Says: "the mail server does not answer: see the stack's state and the host checks", Detail: oneLine(err.Error()), Plan: []string{}}, nil
	}
	review, err := m.recoveryReview(ctx)
	if err != nil {
		return Diagnosis{}, err
	}
	return Diagnosis{Case: CaseAdminLost, Says: "neither the API key nor the administrator signs in: the server's recovery administrator will set things right, for one start",
		Review: &review, Plan: []string{
			"add the recovery administrator to the mail stack, by its sealed name (" + sealedRecovery + "): a restart",
			"as the recovery administrator, give the server's administrator a new secret, and seal it",
			"make a new API key with the administrator, and seal it; destroy the older keys AutoPanel made",
			"remove the recovery administrator from the mail stack: a restart",
			"delete the recovery value from the vault",
		}}, nil
}

// composeRecovery is the mail stack's definition with the recovery
// administrator, by reference.
func (m *Module) composeRecovery() []byte {
	ports := make([]provider.PortMap, len(Ports))
	for i, p := range Ports {
		ports[i] = provider.PortMap{Name: p.Name, Loopback: p.Loopback}
	}
	return m.product.Compose(provider.Stack{Name: Stack, Ports: ports, Manage: ManagePort, Recovery: "${sealed:" + sealedRecovery + "}"})
}

// recoveryReview is the review of the definition with the recovery
// administrator, from memory: nothing is written until it is accepted.
func (m *Module) recoveryReview(ctx context.Context) (services.Review, error) {
	m.repairOpen.Store(true)
	defer m.repairOpen.Store(false)
	return m.stacks.CheckDraft(ctx, Stack, m.composeRecovery())
}

func (m *Module) step(ctx context.Context, what string) {
	if m.audit != nil {
		_ = m.audit.Audit(ctx, audit.Actor(ctx), "mail.repair", "step", what)
	}
}

func (m *Module) repairCheck(ctx context.Context, _ struct{}) (Diagnosis, error) {
	m.setupMu.Lock()
	defer m.setupMu.Unlock()
	return m.diagnose(ctx)
}

// repair is mail.repair. It holds the setup lock for its whole run: two
// repairs, or a repair and a bootstrap, never interleave on the sealed
// administrator, the key or the stack's definition.
func (m *Module) repair(ctx context.Context, p RepairAsk) (Repaired, error) {
	m.setupMu.Lock()
	defer m.setupMu.Unlock()
	m.repairs.running.Store(true)
	defer m.repairs.running.Store(false)
	rep, err := m.repairer()
	if err != nil {
		return Repaired{}, err
	}
	out := Repaired{Done: []string{}}
	for range 2 { // a leftover is finished, then the case under it repaired
		d, err := m.diagnose(ctx)
		if err != nil {
			return out, err
		}
		out.Case = d.Case
		switch d.Case {
		case CaseOK:
			if len(out.Done) == 0 {
				out.Done = append(out.Done, "nothing to repair: the API key signs in")
			}
			return out, nil
		case CaseUnreachable:
			return out, with(ErrUnreachable, d.Detail)
		case CaseNotSetUp:
			st, _, err := m.store.State(ctx)
			if err != nil {
				return out, err
			}
			m.step(ctx, "not_set_up: restart, then the bootstrap")
			since, err := m.restartWait(ctx)
			if err != nil {
				return out, err
			}
			if err := m.bootstrap(ctx, st, since); err != nil {
				return out, with(ErrRepairFails, err.Error())
			}
			out.Done = append(out.Done, "the mail server was set up again")
			return out, nil
		case CaseLeftover:
			m.step(ctx, "recovery_leftover: removing the recovery administrator")
			if err := m.endRecovery(ctx); err != nil {
				return out, with(ErrRepairFails, err.Error())
			}
			out.Done = append(out.Done, "the recovery administrator a stopped repair left was removed")
			continue
		case CaseKeyLost:
			kr, err := m.newKey(ctx, rep)
			if err != nil {
				return out, err
			}
			out.Destroyed, out.Kept = kr.Destroyed, kr.Kept
			out.Done = append(out.Done, "a new API key was made and sealed")
			return out, nil
		case CaseAdminLost:
			if d.Review == nil || p.Accept == "" || p.Accept != d.Review.SHA256 {
				out.NeedsAccept, out.Diagnosis = true, &d
				return out, nil
			}
			kr, err := m.recover(ctx, rep, p.Accept)
			if err != nil {
				return out, with(ErrRepairFails, err.Error())
			}
			out.Destroyed, out.Kept = kr.Destroyed, kr.Kept
			out.Done = append(out.Done, "the administrator was given a new secret", "a new API key was made and sealed", "the recovery administrator was removed")
			return out, nil
		}
	}
	return out, with(ErrRepairFails, "a leftover came back after it was removed")
}

// newKey is key_lost's repair.
func (m *Module) newKey(ctx context.Context, rep provider.Repairer) (provider.KeyRepair, error) {
	env, err := m.env(ctx)
	if err != nil {
		return provider.KeyRepair{}, err
	}
	m.step(ctx, "key_lost: a new API key, by the administrator")
	kr, err := rep.NewAPIKey(ctx, env, m.now())
	if err != nil {
		return kr, with(ErrRepairFails, err.Error())
	}
	if _, err := m.client().Domains(ctx); err != nil {
		return kr, with(ErrRepairFails, "the new API key does not sign in: "+err.Error())
	}
	m.step(ctx, fmt.Sprintf("key_lost: done; %d older keys of AutoPanel's destroyed, %d of others kept", kr.Destroyed, len(kr.Kept)))
	m.repairs.access.Store("")
	return kr, nil
}

// recover is admin_lost's repair, accepted as accept. Whatever happens after
// the recovery administrator is given to the stack, it is taken away again
// before this returns.
func (m *Module) recover(ctx context.Context, rep provider.Repairer, accept string) (kr provider.KeyRepair, err error) {
	value, err := rep.RecoveryCredential()
	if err != nil {
		return kr, err
	}
	defer clear(value)
	m.step(ctx, "admin_lost: the recovery value sealed as "+sealedRecovery)
	if err := m.vault.Put(ctx, sealedRecovery, value); err != nil {
		return kr, err
	}
	m.step(ctx, "admin_lost: the definition with the recovery administrator, applied")
	m.repairOpen.Store(true)
	defer m.repairOpen.Store(false)
	if err := m.host.WriteDefinition(ctx, m.composeRecovery()); err != nil {
		return kr, errors.Join(err, m.endRecovery(context.WithoutCancel(ctx)))
	}
	// From here the recovery administrator may be running: the end runs
	// whatever happens.
	defer func() {
		if eerr := m.endRecovery(context.WithoutCancel(ctx)); eerr != nil {
			err = errors.Join(err, fmt.Errorf("removing the recovery administrator: %w", eerr))
		}
	}()
	before := m.now().Unix()
	if err := m.stacks.Apply(ctx, Stack, accept); err != nil {
		return kr, err
	}
	if err := m.waitUp(ctx, before); err != nil {
		return kr, err
	}
	env, err := m.env(ctx)
	if err != nil {
		return kr, err
	}
	m.step(ctx, "admin_lost: the administrator's new secret, by the recovery administrator")
	if err := rep.ResetAdmin(ctx, env, value); err != nil {
		return kr, err
	}
	m.step(ctx, "admin_lost: a new API key, by the administrator")
	if kr, err = rep.NewAPIKey(ctx, env, m.now()); err != nil {
		return kr, err
	}
	m.repairs.access.Store("")
	return kr, nil
}

// endRecovery takes the recovery administrator away: the definition without
// it, reviewed and applied (a restart), then a check that it no longer signs
// in, and only then its value deleted from the vault. Run with the vault's
// value deleted first, a failed apply would leave a stack that cannot start.
func (m *Module) endRecovery(ctx context.Context) error {
	m.step(ctx, "recovery: the definition without the recovery administrator, applied")
	if err := m.host.WriteDefinition(ctx, m.compose()); err != nil {
		return err
	}
	r, err := m.stacks.Check(ctx, Stack)
	if err != nil {
		return err
	}
	before := m.now().Unix()
	if err := m.stacks.Apply(ctx, Stack, r.SHA256); err != nil {
		return err
	}
	if err := m.waitUp(ctx, before); err != nil {
		return err
	}
	if rep, rerr := m.repairer(); rerr == nil {
		if value, verr := m.vault.Get(ctx, sealedRecovery); verr == nil {
			serr := rep.RecoverySignsIn(ctx, m.base, value)
			clear(value)
			if serr == nil {
				return errors.New("the recovery administrator still signs in after the restart")
			}
			if !errors.Is(serr, provider.ErrUnauthorized) {
				return fmt.Errorf("checking that the recovery administrator is gone: %w", serr)
			}
		}
	}
	m.step(ctx, "recovery: the recovery value deleted from the vault")
	if err := m.vault.Delete(ctx, sealedRecovery); err != nil && !errors.Is(err, ErrNoSecret) {
		return err
	}
	return nil
}

// waitUp waits until the mail stack has been up since after before.
func (m *Module) waitUp(ctx context.Context, before int64) error {
	deadline := time.Now().Add(restartTimeout)
	for time.Now().Before(deadline) {
		if _, since, err := m.stacks.Up(ctx, Stack); err == nil && since >= before {
			sleep(ctx, listenersOpen)
			return nil
		}
		sleep(ctx, time.Second)
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return errors.New("mail: the stack did not come back after its apply")
}

// The waits around a restart: how long the stack may take, and how long
// its listeners open after the process starts. A test shortens them.
var (
	restartTimeout = 2 * time.Minute
	listenersOpen  = 3 * time.Second
)

func sleep(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

// accessFindings are the host checks of a repair: mail-access while the API
// key does not sign in, and mail-recovery-active while a recovery
// administrator is left in place.
func (m *Module) accessFindings(ctx context.Context) []Finding {
	if m.repairs.running.Load() {
		return nil
	}
	var out []Finding
	if a, _ := m.repairs.access.Load().(string); a != "" {
		out = append(out, Finding{ID: "mail-access", Alert: true, Detail: a})
	}
	if _, err := m.vault.Get(ctx, sealedRecovery); err == nil {
		out = append(out, Finding{ID: "mail-recovery-active", Alert: true, Detail: sealedRecovery})
	}
	return out
}

// noteAccess is what a sync learned of the API key.
func (m *Module) noteAccess(err error) {
	switch {
	case err == nil:
		m.repairs.access.Store("")
	case lostKey(err):
		m.repairs.access.Store("unauthorized")
	}
}

// isRecovery reports whether compose is the definition with the recovery
// administrator.
func (m *Module) isRecovery(compose []byte) bool {
	return string(compose) == string(m.composeRecovery())
}
