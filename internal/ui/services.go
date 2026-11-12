package ui

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	tuidecl "github.com/yongjohnlee80/golib/tui/decl"
)

// THE SERVICES MENU — the deployed services in a floating panel, and what is
// done to one: deployed from a form, changed, started, stopped, restarted,
// removed, its log and its secrets read. Every one is a verb of the daemon's,
// which records the ones that change the host before it runs them. The panel
// reads the list again after each, and r in the panel reads it again.

// turnTemplate is the template the deploy form is for.
const turnTemplate = "turn"

// deployed is the Services panels' models and what they were last filled
// from.
type deployed struct {
	model   *tuidecl.ListModel // App.services: the table's rows
	logs    *tuidecl.ListModel // App.serviceLogs: one service's journal lines
	secrets *tuidecl.ListModel // App.serviceSecrets: one service's secrets

	rows      []Service // the table's rows, as the daemon gave them
	read      bool      // the services have been read once
	readAt    time.Time
	templates map[string]ServiceTemplate

	logsOf   string // the service the log panel shows
	logLines int
	logsAt   time.Time

	editName    string // the service the form changes; "" deploys one
	removeName  string // the service the confirmation names
	removePurge bool   // and whether its directory goes too
}

func newDeployed() deployed {
	return deployed{
		model:   tuidecl.NewListModel("key", "name", "kind", "state", "memory", "ports", "user"),
		logs:    tuidecl.NewListModel("key", "line"),
		secrets: tuidecl.NewListModel("key", "name", "value"),
	}
}

// state is the Services panels' part of the App singleton's state.
func (d *deployed) state() map[string]any {
	return map[string]any{
		"App.services":        d.model,
		"App.serviceLogs":     d.logs,
		"App.serviceSecrets":  d.secrets,
		"App.servicesNote":    "",
		"App.serviceLogsNote": "",
		"App.secretsTitle":    "",
		"App.turnTitle":       englishText("autopanel.services.form.deploy"),
		"App.turnHelp":        englishText("autopanel.form.hint"),
		"App.turnNew":         true,
		"App.turnName":        "",
		"App.turnRealm":       "",
		"App.turnPort":        "",
		"App.turnRelayPorts":  "",
	}
}

// portsText is a service's ports on one line: "udp 3478, udp 49152-49999".
func portsText(ports []ServicePort) string {
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		s := p.Proto + " " + strconv.Itoa(p.From)
		if p.To != p.From {
			s += "-" + strconv.Itoa(p.To)
		}
		parts = append(parts, s)
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, ", ")
}

// serviceState is where a service is: a deploy or a removal that did not
// finish, in the UI's language, or else its unit as systemd names it,
// "active (running)".
func serviceState(w wording, s Service) string {
	switch s.State {
	case "deploying", "removing":
		return w.tr("autopanel.services.state." + s.State)
	}
	switch {
	case s.Active == "":
		return "-"
	case s.Sub == "" || s.Sub == s.Active:
		return s.Active
	}
	return s.Active + " (" + s.Sub + ")"
}

// kindText is a template's title in the UI's language, or its name when the
// panel has not read the templates or knows no such message.
func (h *host) kindText(template string) string {
	if t, ok := h.svc.templates[template]; ok && t.Title != "" {
		if title := h.tr(t.Title); title != t.Title {
			return title
		}
	}
	return template
}

// renderServices composes the services' rows and note from the last read, in
// the UI's language now. On the loop.
func (h *host) renderServices() {
	d := &h.svc
	if !d.read {
		return
	}
	rows := make([]tuidecl.Row, 0, len(d.rows))
	for _, s := range d.rows {
		memory := "-"
		if s.Memory > 0 {
			memory = bytesText(s.Memory)
		}
		rows = append(rows, tuidecl.Row{"key": s.Name, "name": s.Name, "kind": h.kindText(s.Template),
			"state": serviceState(h, s), "memory": memory, "ports": portsText(s.Ports), "user": orDash(s.User)})
	}
	d.model.Reset(rows)
	notes := map[string]any{"App.servicesNote": h.trf("autopanel.monitor.readAt", len(rows), d.readAt.Format("15:04:05"))}
	if d.logsOf != "" {
		notes["App.serviceLogsNote"] = h.trf("autopanel.services.logs.note", d.logsOf, d.logLines, d.logsAt.Format("15:04:05"))
	}
	_ = h.p.SetMany(notes)
}

// loadServices reads the services and the templates off the loop and shows
// them. A failed read is said on the status bar and in the panel's note, and
// the rows stay as they were.
func (h *host) loadServices() {
	var (
		rows      []Service
		templates []ServiceTemplate
	)
	h.background(func(ctx context.Context) (err error) {
		if rows, err = h.client.Services(ctx); err != nil {
			return err
		}
		templates, err = h.client.ServiceTemplates(ctx)
		return err
	}, func(err error) {
		if err != nil {
			msg := h.trf("autopanel.notice.error", err.Error())
			h.say(msg)
			_ = h.p.Set("App.servicesNote", msg)
			return
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
		h.svc.rows, h.svc.read, h.svc.readAt = rows, true, time.Now()
		h.setTemplates(templates)
		h.renderServices()
	})
}

func (h *host) setTemplates(ts []ServiceTemplate) {
	h.svc.templates = make(map[string]ServiceTemplate, len(ts))
	for _, t := range ts {
		h.svc.templates[t.Name] = t
	}
}

// openServices opens the services panel and reads it.
func (h *host) openServices() error {
	h.loadServices()
	return h.openPanel("services", "servicesPanel", "servicesTable")
}

// reloadServices is r in the services panel: read it again.
func (h *host) reloadServices() error {
	h.loadServices()
	return nil
}

// service is the service at a row the document passed, if there is one.
func (h *host) service(row int) (Service, bool) {
	if row < 0 || row >= len(h.svc.rows) {
		h.say(h.tr("autopanel.services.none"))
		return Service{}, false
	}
	return h.svc.rows[row], true
}

// deployTurn opens the TURN form to deploy a relay: empty, but for the
// template's defaults, which are read first.
func (h *host) deployTurn() error {
	var templates []ServiceTemplate
	h.background(func(ctx context.Context) (err error) {
		templates, err = h.client.ServiceTemplates(ctx)
		return err
	}, func(err error) {
		if err != nil {
			h.say(h.trf("autopanel.notice.error", err.Error()))
			return
		}
		h.setTemplates(templates)
		t, ok := h.svc.templates[turnTemplate]
		if !ok {
			h.say(h.trf("autopanel.services.unknownTemplate", turnTemplate))
			return
		}
		options := map[string]string{}
		for _, o := range t.Options {
			options[o.Key] = o.Default
		}
		h.svc.editName = ""
		_ = h.openTurnForm(h.tr("autopanel.services.form.deploy"), "", options) // an empty name is the template's
	})
	return nil
}

// editService opens the form on the service at row. The panel has a form for
// a TURN relay; another template's service is changed with --call.
func (h *host) editService(row int) error {
	s, ok := h.service(row)
	if !ok {
		return nil
	}
	if s.Template != turnTemplate {
		h.say(h.trf("autopanel.services.unknownTemplate", s.Template))
		return nil
	}
	h.svc.editName = s.Name
	return h.openTurnForm(h.trf("autopanel.services.form.change", s.Name), s.Name, s.Options)
}

// openTurnForm fills the TURN form and opens it. A new relay's name can be
// typed; a deployed one's is fixed, and is in the title.
func (h *host) openTurnForm(title, name string, options map[string]string) error {
	if err := h.fill(map[string]any{"App.turnName": name, "App.turnRealm": options["realm"],
		"App.turnPort": options["port"], "App.turnRelayPorts": options["relay_ports"]}); err != nil {
		return err
	}
	if err := h.p.SetMany(map[string]any{"App.turnTitle": title, "App.turnHelp": h.tr("autopanel.form.hint"),
		"App.turnNew": h.svc.editName == ""}); err != nil {
		return err
	}
	return h.p.Call("turnDialog", "open")
}

// turnSpec is the relay the form's fields describe, trimmed. An option left
// empty is left out, so the daemon uses its default or says it is required.
func turnSpec(name, realm, port, relayPorts string) ServiceSpec {
	options := map[string]string{}
	for k, v := range map[string]string{"realm": realm, "port": port, "relay_ports": relayPorts} {
		if v = strings.TrimSpace(v); v != "" {
			options[k] = v
		}
	}
	return ServiceSpec{Template: turnTemplate, Name: strings.TrimSpace(name), Options: options}
}

// submitTurn deploys or changes the relay the form describes, off the loop.
// On success the form closes and the services are read again; on failure it
// stays open, as typed, with the reason in its help line and the status bar.
func (h *host) submitTurn(name, realm, port, relayPorts string) error {
	if h.busy {
		h.say(h.tr("autopanel.notice.busy"))
		return nil
	}
	s := turnSpec(name, realm, port, relayPorts)
	done, call := "autopanel.services.done.deploy", h.client.DeployService
	if h.svc.editName != "" {
		s.Name = h.svc.editName
		done, call = "autopanel.services.done.change", h.client.UpdateService
	}
	h.busy = true
	h.background(func(ctx context.Context) error { return call(ctx, s) }, func(err error) {
		h.busy = false
		if err != nil {
			h.say(h.trf("autopanel.notice.error", err.Error()))
			_ = h.p.Set("App.turnHelp", h.trf("autopanel.notice.error", err.Error()))
			h.loadServices() // a deploy that failed half-way left a row
			return
		}
		_ = h.p.Call("turnDialog", "close")
		shown := s.Name
		if shown == "" {
			shown = turnTemplate
		}
		h.say(h.trf(done, shown))
		h.loadServices()
	})
	return nil
}

// change runs one change of a service off the loop, says how it ended, and
// reads the services again either way.
func (h *host) change(done, name string, call func(ctx context.Context) error) {
	if h.busy {
		h.say(h.tr("autopanel.notice.busy"))
		return
	}
	h.busy = true
	h.background(call, func(err error) {
		h.busy = false
		if err != nil {
			h.say(h.trf("autopanel.notice.error", err.Error()))
		} else {
			h.say(h.trf(done, name))
		}
		h.loadServices()
	})
}

// serviceUnit starts, stops or restarts the unit of the service at row.
func (h *host) serviceUnit(action string, row int) error {
	s, ok := h.service(row)
	if !ok {
		return nil
	}
	h.change("autopanel.services.done."+action, s.Name, func(ctx context.Context) error {
		return h.client.ServiceUnit(ctx, action, s.Name)
	})
	return nil
}

// removeService asks before removing the service at row; with purge, its
// directory too.
func (h *host) removeService(row int, purge bool) error {
	s, ok := h.service(row)
	if !ok {
		return nil
	}
	h.svc.removeName, h.svc.removePurge = s.Name, purge
	question := "autopanel.services.confirm.remove"
	if purge {
		question = "autopanel.services.confirm.purge"
	}
	return h.ask("autopanel.services.confirm.title", h.trf(question, s.Name, orDash(s.User)), h.removeServiceConfirmed)
}

// removeServiceConfirmed removes the service the confirmation named.
func (h *host) removeServiceConfirmed() error {
	name, purge := h.svc.removeName, h.svc.removePurge
	done := "autopanel.services.done.remove"
	if purge {
		done = "autopanel.services.done.purge"
	}
	h.change(done, name, func(ctx context.Context) error { return h.client.RemoveService(ctx, name, purge) })
	return nil
}

// loadLogs reads a service's newest journal lines and shows them, oldest
// first.
func (h *host) loadLogs(name string) {
	var lines []string
	h.background(func(ctx context.Context) (err error) {
		lines, err = h.client.ServiceLogs(ctx, name)
		return err
	}, func(err error) {
		if err != nil {
			msg := h.trf("autopanel.notice.error", err.Error())
			h.say(msg)
			_ = h.p.Set("App.serviceLogsNote", msg)
			return
		}
		rows := make([]tuidecl.Row, 0, len(lines))
		for i, l := range lines {
			rows = append(rows, tuidecl.Row{"key": strconv.Itoa(i), "line": l})
		}
		h.svc.logs.Reset(rows)
		h.svc.logsOf, h.svc.logLines, h.svc.logsAt = name, len(lines), time.Now()
		_ = h.p.Set("App.serviceLogsNote", h.trf("autopanel.services.logs.note", name, len(lines), h.svc.logsAt.Format("15:04:05")))
	})
}

// openLogs opens the log panel on the service at row.
func (h *host) openLogs(row int) error {
	s, ok := h.service(row)
	if !ok {
		return nil
	}
	if s.Name != h.svc.logsOf {
		h.svc.logs.Reset(nil) // never one service's lines under another's name
	}
	h.loadLogs(s.Name)
	return h.openPanel("serviceLogs", "serviceLogsPanel", "serviceLogsTable")
}

// reloadLogs is r in the log panel: read the same service's lines again.
func (h *host) reloadLogs() error {
	if h.svc.logsOf != "" {
		h.loadLogs(h.svc.logsOf)
	}
	return nil
}

// openSecrets reads the secrets the daemon generated for the service at row
// and shows them. The daemon records each read in its audit log. The panel
// keeps them only while they are on screen (secretsClosed).
func (h *host) openSecrets(row int) error {
	s, ok := h.service(row)
	if !ok {
		return nil
	}
	keys := h.svc.templates[s.Template].Secrets
	if len(keys) == 0 {
		h.say(h.trf("autopanel.services.secret.none", s.Name))
		return nil
	}
	values := make([]string, len(keys))
	h.background(func(ctx context.Context) error {
		for i, k := range keys {
			v, err := h.client.ServiceSecret(ctx, s.Name, k)
			if err != nil {
				return err
			}
			values[i] = v
		}
		return nil
	}, func(err error) {
		if err != nil {
			h.say(h.trf("autopanel.notice.error", err.Error()))
			return
		}
		rows := make([]tuidecl.Row, 0, len(keys))
		for i, k := range keys {
			rows = append(rows, tuidecl.Row{"key": k, "name": k, "value": values[i]})
		}
		h.svc.secrets.Reset(rows)
		_ = h.p.Set("App.secretsTitle", h.trf("autopanel.services.secret.title", s.Name))
		if err := h.openPanel("serviceSecrets", "serviceSecretsPanel", "serviceSecretsTable"); err != nil {
			h.svc.secrets.Reset(nil)
			h.say(h.trf("autopanel.notice.error", err.Error()))
		}
	})
	return nil
}

// secretsClosed forgets the secrets once their panel has closed.
func (h *host) secretsClosed() error {
	h.svc.secrets.Reset(nil)
	return h.panelLeft()
}
