package ui

import (
	"context"
	"strconv"
	"strings"
	"time"

	tuidecl "github.com/yongjohnlee80/golib/tui/decl"

	corefw "github.com/yongjohnlee80/autopanel/core/firewall"
	"github.com/yongjohnlee80/autopanel/internal/sysinfo"
)

// SYSTEM › FIREWALL AND HOST CHECKS — the host's firewall, read through its
// manager and changed from here (an admin's), and the host's posture
// findings. Where AutoPanel will not make a change, the daemon's refusal
// carries the manager's own commands: they are shown with a Copy button.
//
// Decision: docs/decisions/firewall.md

// firewallView is the two panels' models and what they were last read from.
type firewallView struct {
	rules  *tuidecl.ListModel // App.firewallRules
	checks *tuidecl.ListModel // App.checks
	planM  *tuidecl.ListModel // App.planRows

	last       *sysinfo.Firewall
	lastChecks []Check
	at         int
	checksAt   int
	commands   []string // the last refusal's commands, for Copy
	refusal    string   // and its text
	plan       *corefw.EnablePlan
	planOpen   map[string]bool
	planAt     int
	confirmBy  int64 // the undo's time while an enable waits to be confirmed; 0 for none
}

func newFirewallView() firewallView {
	return firewallView{
		rules:  tuidecl.NewListModel("key", "action", "proto", "ports", "from", "to", "by"),
		checks: tuidecl.NewListModel("key", "severity", "what"),
		planM:  tuidecl.NewListModel("key", "allow", "port", "use"),
	}
}

func (f *firewallView) state() map[string]any {
	return map[string]any{
		"App.firewallRules":       f.rules,
		"App.checks":              f.checks,
		"App.planRows":            f.planM,
		"App.firewallTitle":       "",
		"App.firewallSummary":     "",
		"App.firewallDetail":      "",
		"App.firewallHasCommands": false,
		"App.firewallCopyNote":    "",
		"App.firewallCopyShown":   false,
		"App.firewallArmed":       false,
		"App.firewallArmedText":   "",
		"App.checksTitle":         "",
		"App.checksDetail":        "",
		"App.planSummary":         "",
		"App.planDetail":          "",
		"App.planToggleText":      englishText("autopanel.button.plan.allow"),
		"App.planAllowed":         false,
	}
}

// ruleRow is a rule as the list shows it.
func ruleRow(w wording, r sysinfo.Rule) tuidecl.Row {
	ports := "*"
	if r.From != 0 {
		ports = strconv.Itoa(r.From)
		if r.To != r.From {
			ports += "-" + strconv.Itoa(r.To)
		}
	}
	if r.Service != "" {
		ports += " (" + r.Service + ")"
	}
	proto := r.Proto
	if proto == "" {
		proto = "tcp+udp"
	}
	from := orAny(r.Source)
	if r.Family != "both" {
		from += " " + r.Family
	}
	action := r.Action
	if r.Direction != "in" {
		action += " " + r.Direction
	}
	if !r.Modelled {
		return tuidecl.Row{"key": r.ID, "action": "?", "proto": "", "ports": r.Raw, "from": "", "to": "", "by": ""}
	}
	return tuidecl.Row{"key": r.ID, "action": action, "proto": proto, "ports": ports, "from": from, "to": orAny(r.Dest), "by": orDash(r.By)}
}

func orAny(s string) string {
	if s == "" {
		return "any"
	}
	return s
}

// ruleDetail is a rule whole.
func ruleDetail(w wording, r sysinfo.Rule) string {
	by := r.By
	if by == "" {
		by = w.tr("autopanel.value.firewall.byAdministrator")
	}
	out := facts(w,
		[2]string{"autopanel.label.firewall.rule", r.Raw},
		[2]string{"autopanel.label.firewall.family", r.Family},
		[2]string{"autopanel.label.firewall.allowedBy", by},
		[2]string{"autopanel.label.firewall.note", orDash(r.Note)},
		[2]string{"autopanel.label.firewall.id", r.ID})
	if !r.Modelled {
		out += "\n\n" + w.tr("autopanel.notice.firewall.notModelled")
	}
	return out
}

// summary is the firewall's state in one line, and what its read cannot see.
func firewallSummary(w wording, fw sysinfo.Firewall) string {
	state := w.tr("autopanel.value.firewall.off")
	if fw.Active {
		state = w.trf("autopanel.value.firewall.on", fw.Default)
	}
	out := w.trf("autopanel.value.firewall.summary", fw.Manager, state, len(fw.Rules))
	for _, l := range fw.Limits {
		out += "\n" + w.tr("autopanel.value.firewallLimit."+camel(l))
	}
	return out
}

// commandsIn are the commands a refusal carries ("…: run: a; b").
func commandsIn(err error) []string {
	if err == nil {
		return nil
	}
	_, after, ok := strings.Cut(err.Error(), "run: ")
	if !ok {
		return nil
	}
	after = strings.TrimSuffix(strings.TrimSpace(after), ")")
	var out []string
	for _, c := range strings.Split(after, "; ") {
		if c = strings.TrimSpace(c); c != "" {
			out = append(out, c)
		}
	}
	return out
}

// renderFirewall composes the firewall panel in the UI's language now.
func (h *host) renderFirewall() {
	f := &h.fw
	vals := map[string]any{"App.firewallTitle": h.listTitle("firewall", "autopanel.title.list.firewall", 0)}
	if f.last != nil {
		rows := make([]tuidecl.Row, 0, len(f.last.Rules))
		for _, r := range f.last.Rules {
			rows = append(rows, ruleRow(h, r))
		}
		f.rules.Reset(rows)
		vals["App.firewallTitle"] = h.listTitle("firewall", "autopanel.title.list.firewall", len(rows))
		vals["App.firewallSummary"] = firewallSummary(h, *f.last)
	}
	vals["App.firewallDetail"] = h.firewallDetailAt(f.at)
	vals["App.firewallHasCommands"] = len(f.commands) > 0
	vals["App.firewallArmed"] = f.confirmBy > 0
	if f.confirmBy > 0 {
		vals["App.firewallArmedText"] = h.trf("autopanel.notice.firewall.armed", time.Unix(f.confirmBy, 0).Format("15:04:05"))
	}
	_ = h.p.SetMany(vals)
}

// firewallDetailAt is the selected rule whole; after a refusal, its text and
// the commands that would make the change by hand.
func (h *host) firewallDetailAt(row int) string {
	f := &h.fw
	if f.refusal != "" {
		out := f.refusal
		if len(f.commands) > 0 {
			out += "\n\n" + h.tr("autopanel.notice.firewall.byHand") + "\n  " + strings.Join(f.commands, "\n  ")
		}
		return out
	}
	if f.last == nil || row < 0 || row >= len(f.last.Rules) {
		return ""
	}
	return ruleDetail(h, f.last.Rules[row])
}

// loadFirewall reads the firewall off the loop.
func (h *host) loadFirewall() {
	var fw sysinfo.Firewall
	h.background(func(ctx context.Context) (err error) {
		fw, err = h.client.Firewall(ctx)
		return err
	}, func(err error) {
		h.mon.errs["firewall"] = err
		if err == nil {
			h.mon.readAt["firewall"] = time.Now()
			h.fw.last = &fw
		}
		h.renderFirewall()
	})
}

func (h *host) openFirewall() error {
	h.fw.refusal, h.fw.commands = "", nil
	h.loadFirewall()
	return h.openPanel("firewall")
}

func (h *host) reloadFirewall() error {
	h.fw.refusal, h.fw.commands = "", nil
	h.loadFirewall()
	return nil
}

func (h *host) firewallMoved(row int) error {
	h.fw.at, h.fw.refusal, h.fw.commands = row, "", nil
	return h.p.SetMany(map[string]any{"App.firewallDetail": h.firewallDetailAt(row), "App.firewallHasCommands": false, "App.firewallCopyShown": false})
}

// firewallChange runs one change off the loop. A refusal is shown in the
// details pane, with its commands; the firewall is read again either way.
func (h *host) firewallChange(done string, call func(ctx context.Context) error) {
	if h.busy {
		h.say(h.tr("autopanel.notice.app.busy"))
		return
	}
	h.busy = true
	h.background(call, func(err error) {
		h.busy = false
		h.fw.refusal, h.fw.commands = "", nil
		if err != nil {
			h.fw.refusal, h.fw.commands = h.trf("autopanel.notice.app.error", err.Error()), commandsIn(err)
			h.failed(err)
		} else if done != "" {
			h.say(h.tr(done))
		}
		h.loadFirewall()
	})
}

// parseAllow reads Allow's one line: "tcp/8443", "udp/49152-49160",
// "tcp/22 from 192.0.2.0/24".
func parseAllow(s string) (corefw.AllowAsk, error) {
	var a corefw.AllowAsk
	f := strings.Fields(s)
	if len(f) != 1 && !(len(f) == 3 && f[1] == "from") {
		return a, corefw.ErrBadAllow
	}
	proto, ports, ok := strings.Cut(f[0], "/")
	if !ok {
		return a, corefw.ErrBadAllow
	}
	from, to, isRange := strings.Cut(ports, "-")
	var err error
	if a.From, err = strconv.Atoi(from); err != nil {
		return a, corefw.ErrBadAllow
	}
	if isRange {
		if a.To, err = strconv.Atoi(to); err != nil {
			return a, corefw.ErrBadAllow
		}
	}
	a.Proto = proto
	if len(f) == 3 {
		a.Source = f[2]
	}
	if _, err := corefw.AllowRule(a); err != nil {
		return a, err
	}
	return a, nil
}

// firewallAllow is Allow…: one line, then the rule.
func (h *host) firewallAllow() error {
	return h.prompt("autopanel.title.prompt.firewallAllow", "autopanel.label.prompt.firewallAllow", "tcp/", func(text string) error {
		a, err := parseAllow(text)
		if err != nil {
			h.promptRefused(h.tr("autopanel.notice.firewall.badAllow"))
			return nil
		}
		h.promptDone()
		h.firewallChange("autopanel.notice.firewall.allowed", func(ctx context.Context) error { return h.client.FirewallAllow(ctx, a) })
		return nil
	})
}

// firewallRevoke is Revoke on the selected rule, asked first.
func (h *host) firewallRevoke(row int) error {
	f := &h.fw
	if f.last == nil || row < 0 || row >= len(f.last.Rules) {
		return nil
	}
	r := f.last.Rules[row]
	return h.ask("autopanel.title.confirm.firewallRevoke", h.trf("autopanel.question.firewall.revoke", r.Raw), func() error {
		h.firewallChange("autopanel.notice.firewall.revoked", func(ctx context.Context) error { return h.client.FirewallRevoke(ctx, r.ID) })
		return nil
	})
}

// firewallDisable is Turn off, asked first.
func (h *host) firewallDisable() error {
	return h.ask("autopanel.title.confirm.firewallOff", h.tr("autopanel.question.firewall.off"), func() error {
		h.fw.confirmBy = 0
		h.firewallChange("autopanel.notice.firewall.off", func(ctx context.Context) error { return h.client.FirewallDisable(ctx) })
		return nil
	})
}

// firewallConfirm is Confirm: it keeps an enable, from another login.
func (h *host) firewallConfirm() error {
	h.firewallChange("autopanel.notice.firewall.confirmed", func(ctx context.Context) error {
		err := h.client.FirewallConfirm(ctx)
		if err == nil {
			h.fw.confirmBy = 0
		}
		return err
	})
	return nil
}

// firewallPlan is Turn on…: the plan read, then shown with what it would
// block, each ticked when it is suggested.
func (h *host) firewallPlan() error {
	var plan corefw.EnablePlan
	h.background(func(ctx context.Context) (err error) {
		plan, err = h.client.FirewallPlan(ctx)
		return err
	}, func(err error) {
		if err != nil {
			h.failed(err)
			return
		}
		h.fw.plan, h.fw.planAt = &plan, 0
		h.fw.planOpen = map[string]bool{}
		for _, b := range plan.Blocked {
			h.fw.planOpen[b.Key] = b.Suggest
		}
		h.renderPlan()
		if err := h.p.Call("planDialog", "open"); err != nil {
			h.failed(err)
		}
	})
	return nil
}

// renderPlan composes the plan dialog.
func (h *host) renderPlan() {
	f := &h.fw
	if f.plan == nil {
		return
	}
	rows := make([]tuidecl.Row, 0, len(f.plan.Blocked))
	for _, b := range f.plan.Blocked {
		mark := h.tr("autopanel.value.plan.block")
		if f.planOpen[b.Key] {
			mark = h.tr("autopanel.value.plan.allow")
		}
		rows = append(rows, tuidecl.Row{"key": b.Key, "allow": mark, "port": b.Key, "use": orDash(b.Use)})
	}
	f.planM.Reset(rows)
	var ssh []string
	for _, e := range f.plan.SSH {
		ssh = append(ssh, e.String())
	}
	summary := h.trf("autopanel.value.plan.summary", f.plan.Manager, strings.Join(ssh, ", "), corefw.UndoAfter/time.Second)
	if !f.plan.Complete {
		summary += "\n" + h.tr("autopanel.notice.plan.incomplete")
	}
	toggle := "autopanel.button.plan.allow"
	if f.planAt >= 0 && f.planAt < len(f.plan.Blocked) && f.planOpen[f.plan.Blocked[f.planAt].Key] {
		toggle = "autopanel.button.plan.block"
	}
	_ = h.p.SetMany(map[string]any{
		"App.planSummary":    summary,
		"App.planDetail":     h.planDetailAt(f.planAt),
		"App.planToggleText": h.tr(toggle),
		"App.planAllowed":    f.plan.Complete,
	})
}

func (h *host) planDetailAt(row int) string {
	f := &h.fw
	if f.plan == nil || row < 0 || row >= len(f.plan.Blocked) {
		return h.tr("autopanel.notice.plan.none")
	}
	b := f.plan.Blocked[row]
	owner := b.Owner
	if owner == "" {
		owner = h.tr("autopanel.value.firewall.byAdministrator")
	}
	return facts(h,
		[2]string{"autopanel.label.firewall.port", b.Key},
		[2]string{"autopanel.label.plan.use", orDash(b.Use)},
		[2]string{"autopanel.label.plan.ruleFor", owner}) + "\n\n" + h.tr("autopanel.notice.plan.blocked")
}

func (h *host) planMoved(row int) error {
	h.fw.planAt = row
	h.renderPlan()
	return nil
}

// planToggle allows or leaves blocked the selected port.
func (h *host) planToggle() error {
	f := &h.fw
	if f.plan == nil || f.planAt < 0 || f.planAt >= len(f.plan.Blocked) {
		return nil
	}
	k := f.plan.Blocked[f.planAt].Key
	f.planOpen[k] = !f.planOpen[k]
	h.renderPlan()
	return nil
}

// planAccept is Turn on: the enable as the plan showed, with the ticked
// ports allowed. It is undone unless a new login confirms it in time.
func (h *host) planAccept() error {
	f := &h.fw
	if f.plan == nil || !f.plan.Complete {
		return nil
	}
	plan := f.plan.SHA256
	var allow []string
	for _, b := range f.plan.Blocked {
		if f.planOpen[b.Key] {
			allow = append(allow, b.Key)
		}
	}
	var armed corefw.Armed
	h.firewallChange("", func(ctx context.Context) (err error) {
		armed, err = h.client.FirewallEnable(ctx, plan, allow)
		if err == nil {
			f.confirmBy = armed.ConfirmBy
			h.say(h.trf("autopanel.notice.firewall.armed", time.Unix(armed.ConfirmBy, 0).Format("15:04:05")))
		}
		return err
	})
	return nil
}

// --- Host checks ---------------------------------------------------------------

// checkText is a finding's message, with its data.
func checkText(w wording, c Check) string {
	return w.trf("autopanel.value.check."+camel(c.ID), c.Detail)
}

// camel is an id of the daemon's ("docker-group") as a message's slug
// ("dockerGroup").
func camel(s string) string {
	parts := strings.Split(s, "-")
	for i := 1; i < len(parts); i++ {
		if parts[i] != "" {
			parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
		}
	}
	return strings.Join(parts, "")
}

func (h *host) renderChecks() {
	f := &h.fw
	rows := make([]tuidecl.Row, 0, len(f.lastChecks))
	for i, c := range f.lastChecks {
		rows = append(rows, tuidecl.Row{"key": strconv.Itoa(i) + c.ID, "severity": h.tr("autopanel.value.check." + c.Severity), "what": checkText(h, c)})
	}
	f.checks.Reset(rows)
	detail := ""
	if f.checksAt >= 0 && f.checksAt < len(f.lastChecks) {
		c := f.lastChecks[f.checksAt]
		detail = checkText(h, c) + "\n\n" + h.tr("autopanel.notice.check."+camel(c.ID))
	} else if len(f.lastChecks) == 0 && h.mon.errs["checks"] == nil {
		detail = h.tr("autopanel.notice.checks.none")
	}
	_ = h.p.SetMany(map[string]any{
		"App.checksTitle":  h.listTitle("checks", "autopanel.title.list.checks", len(f.lastChecks)),
		"App.checksDetail": detail,
	})
}

func (h *host) loadChecks() {
	var cs []Check
	h.background(func(ctx context.Context) (err error) {
		cs, err = h.client.Checks(ctx)
		return err
	}, func(err error) {
		h.mon.errs["checks"] = err
		if err == nil {
			h.mon.readAt["checks"] = time.Now()
			h.fw.lastChecks = orEmpty(cs)
		}
		h.renderChecks()
	})
}

func (h *host) openChecks() error {
	h.loadChecks()
	return h.openPanel("checks")
}

func (h *host) reloadChecks() error {
	h.loadChecks()
	return nil
}

func (h *host) checksMoved(row int) error {
	h.fw.checksAt = row
	h.renderChecks()
	return nil
}

// firewallCopy copies the commands of the last refusal.
func (h *host) firewallCopy() error {
	if len(h.fw.commands) == 0 {
		return nil
	}
	note := h.tr("autopanel.notice.firewall.noClipboard")
	if app := h.p.App(); app != nil && app.CopyToClipboard(strings.Join(h.fw.commands, "\n")+"\n") {
		note = h.tr("autopanel.notice.firewall.copied")
	}
	return h.p.SetMany(map[string]any{"App.firewallCopyNote": note, "App.firewallCopyShown": true})
}
