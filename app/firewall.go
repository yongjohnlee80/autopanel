package app

import (
	"context"
	"github.com/yongjohnlee80/autopanel/core/forward"
	"net/netip"
	"strconv"
	"strings"

	corefw "github.com/yongjohnlee80/autopanel/core/firewall"
	"github.com/yongjohnlee80/autopanel/core/mail"
	"github.com/yongjohnlee80/autopanel/core/services"
	hostfirewall "github.com/yongjohnlee80/autopanel/host/firewall"
	"github.com/yongjohnlee80/autopanel/internal/module"
	"github.com/yongjohnlee80/autopanel/internal/sysinfo"
)

// FIREWALL — System → Firewall's verbs: the host's firewall read and changed
// through its manager, every change under one lock, the lockout guard on
// whatever can take access away, and an enable that undoes itself unless a
// new login confirms it. All of it is the admin's alone (sys.admin).
//
// Decision: docs/decisions/firewall.md

// firewallHost is the machine's firewall; a test gives its own.
var firewallHost = func() corefw.Host { return hostfirewall.New() }

// firewallModule is the sys.firewall.* verbs.
type firewallModule struct{ fw *corefw.Module }

func (firewallModule) Name() string { return "firewall" }

func (firewallModule) Errors() []module.PublicError {
	return []module.PublicError{
		{Err: corefw.ErrLockout, Code: -32200, Name: "firewall.lockout", Message: "the change would stop new SSH logins from your address"},
		{Err: corefw.ErrLockoutUnknown, Code: -32201, Name: "firewall.lockout_unknown", Message: "whether SSH logins would still reach this host after the change cannot be told; do it by hand if you are sure"},
		{Err: corefw.ErrUnmanaged, Code: -32202, Name: "firewall.unmanaged", Message: "this host's firewall is not one AutoPanel can change"},
		{Err: corefw.ErrNotApplied, Code: -32203, Name: "firewall.not_applied", Message: "the manager did not make the change"},
		{Err: corefw.ErrNoSuchRule, Code: -32204, Name: "firewall.no_such_rule", Message: "no rule has that id; read the firewall again"},
		{Err: corefw.ErrChanged, Code: -32205, Name: "firewall.changed", Message: "the host changed since the plan was made; review the new plan"},
		{Err: corefw.ErrNotPlanned, Code: -32206, Name: "firewall.not_planned", Message: "a port to allow is not one the plan lists"},
		{Err: corefw.ErrNotArmed, Code: -32207, Name: "firewall.not_armed", Message: "no enable is waiting to be confirmed"},
		{Err: corefw.ErrSameLogin, Code: -32208, Name: "firewall.same_login", Message: "confirm from a new login: log in again in a second terminal and confirm there"},
		{Err: corefw.ErrConfirmBySSH, Code: -32209, Name: "firewall.confirm_by_ssh", Message: "the firewall was turned on over SSH; confirm from a new SSH login"},
		{Err: corefw.ErrBadAllow, Code: -32210, Name: "firewall.bad_allow", Message: "a rule needs tcp or udp, a port from 1 to 65535, and addresses of one family"},
		{Err: corefw.ErrUndoArmed, Code: -32211, Name: "firewall.undo_armed", Message: "an enable is already waiting to be confirmed"},
		{Err: corefw.ErrActive, Code: -32212, Name: "firewall.active", Message: "the firewall is already on"},
		{Err: hostfirewall.ErrUnsupported, Code: -32213, Name: "firewall.unsupported", Message: "this host's firewall manager is not one AutoPanel can change yet"},
		{Err: hostfirewall.ErrNotModelled, Code: -32214, Name: "firewall.not_modelled", Message: "the rule is not one AutoPanel can write; change it with the manager's own tool"},
	}
}

// RevokeAsk is sys.firewall.revoke's parameter.
type RevokeAsk struct {
	ID string `json:"id"`
}

func (f firewallModule) Verbs() []module.Verb {
	admin := func(c module.Contract) module.Contract {
		c.Area, c.Since = "sys.admin", 7
		if c.Mutates {
			c.Privileged = true
		}
		return c
	}
	none := func(fn func(context.Context) (sysinfo.Firewall, error)) func(context.Context, struct{}) (sysinfo.Firewall, error) {
		return func(ctx context.Context, _ struct{}) (sysinfo.Firewall, error) { return fn(ctx) }
	}
	return []module.Verb{
		module.Handle(admin(module.Contract{Verb: "sys.firewall.get", Public: true, Discloses: module.Plain,
			Result: "{manager, active, default, rules: [{id, action, family, proto, from, to, source, dest, scope, service, raw, by, …}], limits}",
			Doc:    "The host's firewall as its manager reports it, each rule with the owner AutoPanel made it for, or none."}), none(f.fw.Read)),
		module.Handle(admin(module.Contract{Verb: "sys.firewall.allow", Mutates: true, Param: "{proto, from, to?, source?, dest?, family?, zone?}", Result: "the firewall",
			Doc: "Allows incoming tcp or udp to a port or range, from anywhere or a source, to any address or one. The rule is the administrator's: no owner removes it."}), f.fw.Allow),
		module.Handle(admin(module.Contract{Verb: "sys.firewall.revoke", Mutates: true, Param: "{id}", Result: "the firewall",
			Doc: "Deletes a rule by its id, after the lockout guard: refused when new SSH logins from your address would no longer get in, or when that cannot be told."}),
			func(ctx context.Context, p RevokeAsk) (sysinfo.Firewall, error) { return f.fw.Revoke(ctx, p.ID) }),
		module.Handle(admin(module.Contract{Verb: "sys.firewall.plan", Discloses: module.Plain, Result: "{sha256, manager, ssh, complete, blocked: [{key, use, owner, suggest}], default}",
			Doc: "What turning the firewall on would do now: the SSH ports allowed first, and the listening ports it would block unless allowed. Changes nothing."}),
			func(ctx context.Context, _ struct{}) (corefw.EnablePlan, error) { return f.fw.Plan(ctx) }),
		module.Handle(admin(module.Contract{Verb: "sys.firewall.enable", Mutates: true, Param: "{plan, allow: [key]}", Result: "{firewall, confirm_by}",
			Doc: "Turns the firewall on as the plan showed, with the ports chosen allowed. Undone after 120 s unless a new login confirms it."}), f.fw.Enable),
		module.Handle(admin(module.Contract{Verb: "sys.firewall.confirm", Mutates: true, Result: "the firewall",
			Doc: "Keeps an enable. Refused from the login that enabled it: log in again, in a second terminal, and confirm there."}), none(f.fw.Confirm)),
		module.Handle(admin(module.Contract{Verb: "sys.firewall.disable", Mutates: true, Result: "the firewall",
			Doc: "Turns the firewall off, and stops an enable's undo timer."}), none(f.fw.Disable)),
	}
}

// firewallUses names the ports the rest of the core knows, for an enable's
// plan: the gate's two, suggested; mail's, as mail's, once it is set up; and
// each port a stack's last apply opened, as that stack's; and each forward's
// public port, as that forward's.
func firewallUses(cfg Config, mailOn func(context.Context) bool, stacks services.Store, forwards forward.Store) func(context.Context) map[string]corefw.Use {
	return func(ctx context.Context) map[string]corefw.Use {
		out := map[string]corefw.Use{}
		for _, a := range []string{cfg.HTTPAddr, cfg.HTTPSAddr} {
			if p := portOf(a); p != 0 {
				out["tcp/"+strconv.Itoa(p)] = corefw.Use{Name: "the gate", Suggest: true}
			}
		}
		if mailOn(ctx) {
			for _, p := range mail.Ports {
				out["tcp/"+strconv.Itoa(p.Public)] = corefw.Use{Name: "mail", Owner: corefw.OwnerMail}
			}
		}
		all, _ := stacks.All(ctx)
		for _, s := range all {
			for _, w := range s.Applied.Open {
				if w.From == w.To && !w.Addr.IsValid() {
					out[w.Proto+"/"+strconv.Itoa(w.From)] = corefw.Use{Name: "stack " + s.Name, Owner: corefw.StackOwner(s.Name)}
				}
			}
		}
		// A forward's public port, as that forward's (a range is opened from
		// the forward's own form).
		fs, _ := forwards.All(ctx)
		for _, f := range fs {
			if f.From == f.To {
				out[f.Proto+"/"+strconv.Itoa(f.From)] = corefw.Use{Name: "forward " + f.Name, Owner: f.Owner()}
			}
		}
		return out
	}
}

// ownerChecks are the host checks that need the owners: a mail port, a port
// a stack chose to open or a forward's public port that the firewall now
// blocks, and a rule an owner made that was removed by hand since.
//
// Decision: docs/decisions/firewall.md#host-checks
func ownerChecks(mailOn func(context.Context) bool, stacks services.Store, forwards forward.Store, rows corefw.Store) func(context.Context, sysinfo.Firewall) []Check {
	blocked := func(fw sysinfo.Firewall, w corefw.Want) bool {
		addr := w.Addr
		if !addr.IsValid() {
			addr = netip.IPv6Unspecified()
		}
		v, _ := fw.VerdictRange(w.Proto, addr, w.From, w.To)
		return v == sysinfo.VerdictBlocked
	}
	return func(ctx context.Context, fw sysinfo.Firewall) []Check {
		var out []Check
		if mailOn(ctx) {
			var ports []string
			for _, p := range mail.Ports {
				if blocked(fw, corefw.Want{Proto: "tcp", From: p.Public, To: p.Public}) {
					ports = append(ports, strconv.Itoa(p.Public))
				}
			}
			if len(ports) > 0 {
				out = append(out, Check{ID: "mail-port-blocked", Severity: alert, Detail: strings.Join(ports, ", ")})
			}
		}
		all, _ := stacks.All(ctx)
		var stackPorts []string
		for _, s := range all {
			for _, w := range s.Applied.Open {
				if blocked(fw, w) {
					stackPorts = append(stackPorts, s.Name+" "+w.Key())
				}
			}
		}
		if len(stackPorts) > 0 {
			out = append(out, Check{ID: "stack-port-blocked", Severity: alert, Detail: strings.Join(stackPorts, ", ")})
		}
		fs, _ := forwards.All(ctx)
		var forwardPorts []string
		for _, f := range fs {
			if w := f.Want(); blocked(fw, w) {
				forwardPorts = append(forwardPorts, f.Name+" "+w.Key())
			}
		}
		if len(forwardPorts) > 0 {
			out = append(out, Check{ID: "forward-port-blocked", Severity: alert, Detail: strings.Join(forwardPorts, ", ")})
		}
		have := map[string]bool{}
		for _, r := range fw.Rules {
			have[r.ID] = true
		}
		owned, _ := rows.FirewallRows(ctx)
		var missing []string
		for _, r := range owned {
			if r.State == corefw.StateOpen && !have[r.ID] {
				missing = append(missing, r.Owner+" "+r.Rule.Raw)
			}
		}
		if len(missing) > 0 {
			out = append(out, Check{ID: "firewall-owned-missing", Severity: notice, Detail: strings.Join(missing, ", ")})
		}
		return out
	}
}
