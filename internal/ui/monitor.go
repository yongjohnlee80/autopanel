package ui

import (
	"context"
	"fmt"
	"strconv"
	"time"

	tuidecl "github.com/yongjohnlee80/golib/tui/decl"
)

// THE SYSTEM MENU'S MONITORS — metrics, the audit log, login attempts and
// open ports, each a floating panel over a table. Opening one reads it, and r
// in the panel reads it again. Nothing is polled: a monitor shows when it was
// read, and the daemon bounds every answer.

// monitors are the panels' models, and the last answer of each, kept so a
// change of language composes the rows again without another read.
type monitors struct {
	metrics, audit, logins, ports *tuidecl.ListModel

	lastMetrics *Metrics
	lastAudit   []AuditEntry
	lastLogins  *Logins
	lastPorts   []Port
	readAt      map[string]time.Time // when each was last read, by panel
}

func newMonitors() monitors {
	return monitors{
		metrics: tuidecl.NewListModel("key", "name", "value"),
		audit:   tuidecl.NewListModel("key", "time", "actor", "action", "subject", "detail"),
		logins:  tuidecl.NewListModel("key", "time", "source", "user", "from", "result", "detail"),
		ports:   tuidecl.NewListModel("key", "proto", "port", "address", "process", "user", "use"),
		readAt:  map[string]time.Time{},
	}
}

// state is the monitors' part of the App singleton's state.
func (m *monitors) state() map[string]any {
	return map[string]any{
		"App.metrics":     m.metrics,
		"App.audit":       m.audit,
		"App.logins":      m.logins,
		"App.ports":       m.ports,
		"App.metricsNote": "",
		"App.auditNote":   "",
		"App.loginsNote":  "",
		"App.portsNote":   "",
	}
}

// stamp is a Unix time as the panels show it: the panel's local time.
func stamp(at int64) string {
	if at == 0 {
		return "-"
	}
	return time.Unix(at, 0).Format("2006-01-02 15:04:05")
}

// bytesText is a size in the unit that reads best: 1536 → "1.5 KiB".
func bytesText(n uint64) string {
	const unit = 1024
	if n < unit {
		return strconv.FormatUint(n, 10) + " B"
	}
	div, exp := uint64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// metricRows are the metrics panel's rows: a name and its value.
func metricRows(w wording, m Metrics) [][2]string {
	gate := w.tr("autopanel.metrics.gateSilent")
	if m.Gate.Running {
		gate = w.trf("autopanel.metrics.gateMemoryValue", bytesText(m.Gate.MemoryBytes), strconv.Itoa(m.Gate.PID))
	}
	return [][2]string{
		{w.tr("autopanel.metrics.uptime"), orDash(m.Uptime)},
		{w.tr("autopanel.metrics.httpsRequests"), strconv.FormatInt(m.HTTPSRequests, 10)},
		{w.tr("autopanel.metrics.httpRequests"), strconv.FormatInt(m.HTTPRequests, 10)},
		{w.tr("autopanel.metrics.routes"), strconv.Itoa(m.Routes)},
		{w.tr("autopanel.metrics.serviceMemory"), w.trf("autopanel.metrics.serviceMemoryValue", bytesText(m.HeapBytes), bytesText(m.RuntimeBytes))},
		{w.tr("autopanel.metrics.goroutines"), strconv.Itoa(m.Goroutines)},
		{w.tr("autopanel.metrics.gateMemory"), gate},
		{w.tr("autopanel.metrics.load"), w.trf("autopanel.metrics.loadValue",
			fmt.Sprintf("%.2f", m.Host.Load.One), fmt.Sprintf("%.2f", m.Host.Load.Five), fmt.Sprintf("%.2f", m.Host.Load.Fifteen))},
		{w.tr("autopanel.metrics.hostMemory"), w.trf("autopanel.metrics.availableOf", bytesText(m.Host.MemAvailable), bytesText(m.Host.MemTotal))},
		{w.tr("autopanel.metrics.disk"), w.trf("autopanel.metrics.freeOf", bytesText(m.Host.DiskFree), bytesText(m.Host.DiskTotal))},
	}
}

// holder is the process that holds a port, with its number: "sshd (612)".
func holder(p Port) string {
	switch {
	case p.Process == "":
		return "-"
	case p.PID == 0:
		return p.Process
	}
	return p.Process + " (" + strconv.Itoa(p.PID) + ")"
}

// resultText is a login's result in the UI's language.
func resultText(w wording, result string) string {
	switch result {
	case "ok", "failed", "closed":
		return w.tr("autopanel.logins.result." + result)
	}
	return result
}

// render composes every monitor's rows and note from its last answer, in the
// UI's language now. On the loop.
func (m *monitors) render(h *host) {
	note := func(panel string, rows int) string {
		at, ok := m.readAt[panel]
		if !ok {
			return ""
		}
		return h.trf("autopanel.monitor.readAt", rows, at.Format("15:04:05"))
	}
	notes := map[string]any{}
	if m.lastMetrics != nil {
		facts := metricRows(h, *m.lastMetrics)
		rows := make([]tuidecl.Row, 0, len(facts))
		for i, f := range facts {
			rows = append(rows, tuidecl.Row{"key": strconv.Itoa(i), "name": f[0], "value": f[1]})
		}
		m.metrics.Reset(rows)
		notes["App.metricsNote"] = h.trf("autopanel.monitor.readAtOnly", m.readAt["metrics"].Format("15:04:05"))
	}
	if m.lastAudit != nil {
		rows := make([]tuidecl.Row, 0, len(m.lastAudit))
		for _, e := range m.lastAudit {
			rows = append(rows, tuidecl.Row{"key": strconv.FormatInt(e.ID, 10), "time": stamp(e.At),
				"actor": e.Actor, "action": e.Action, "subject": e.Subject, "detail": e.Detail})
		}
		m.audit.Reset(rows)
		notes["App.auditNote"] = note("audit", len(rows))
	}
	if m.lastLogins != nil {
		rows := make([]tuidecl.Row, 0, len(m.lastLogins.Attempts))
		for i, a := range m.lastLogins.Attempts {
			rows = append(rows, tuidecl.Row{"key": strconv.Itoa(i), "time": stamp(a.At), "source": a.Source,
				"user": a.User, "from": a.From, "result": resultText(h, a.Result), "detail": a.Detail})
		}
		m.logins.Reset(rows)
		n := note("logins", len(rows))
		if m.lastLogins.SSHNote != "" {
			n += " · " + m.lastLogins.SSHNote
		}
		notes["App.loginsNote"] = n
	}
	if m.lastPorts != nil {
		rows := make([]tuidecl.Row, 0, len(m.lastPorts))
		for _, p := range m.lastPorts {
			rows = append(rows, tuidecl.Row{"key": p.Proto + "/" + p.Address + "/" + strconv.Itoa(p.Port) + "/" + strconv.Itoa(p.PID),
				"proto": p.Proto, "port": p.Port, "address": p.Address, "process": holder(p), "user": orDash(p.User), "use": p.Use})
		}
		m.ports.Reset(rows)
		notes["App.portsNote"] = note("ports", len(rows))
	}
	if len(notes) > 0 {
		_ = h.p.SetMany(notes)
	}
}

// load reads one monitor off the loop and shows it. A failed read is said on
// the status bar and in the panel's note, and the rows stay as they were.
func (h *host) load(panel string) {
	var (
		metrics Metrics
		audit   []AuditEntry
		logins  Logins
		ports   []Port
	)
	h.background(func(ctx context.Context) (err error) {
		switch panel {
		case "metrics":
			metrics, err = h.client.Metrics(ctx)
		case "audit":
			audit, err = h.client.AuditLog(ctx)
		case "logins":
			logins, err = h.client.Logins(ctx)
		case "ports":
			ports, err = h.client.Ports(ctx)
		}
		return err
	}, func(err error) {
		if err != nil {
			msg := h.trf("autopanel.notice.error", err.Error())
			h.say(msg)
			_ = h.p.Set("App."+panel+"Note", msg)
			return
		}
		h.mon.readAt[panel] = time.Now()
		switch panel {
		case "metrics":
			h.mon.lastMetrics = &metrics
		case "audit":
			if audit == nil {
				audit = []AuditEntry{}
			}
			h.mon.lastAudit = audit
		case "logins":
			h.mon.lastLogins = &logins
		case "ports":
			if ports == nil {
				ports = []Port{}
			}
			h.mon.lastPorts = ports
		}
		h.mon.render(h)
	})
}

// monitorPanels are the System panels: each one's panel id and view id in the
// document. Its window key is its name.
var monitorPanels = map[string][2]string{
	"metrics": {"metricsPanel", "metricsTable"},
	"audit":   {"auditPanel", "auditTable"},
	"logins":  {"loginsPanel", "loginsTable"},
	"ports":   {"portsPanel", "portsTable"},
}

// openMonitor opens a System panel and reads it.
func (h *host) openMonitor(panel string) error {
	ids, ok := monitorPanels[panel]
	if !ok {
		return fmt.Errorf("no monitor named %q", panel)
	}
	h.load(panel)
	return h.openPanel(panel, ids[0], ids[1])
}

// reloadMonitor is r in a System panel: read it again.
func (h *host) reloadMonitor(panel string) error {
	if _, ok := monitorPanels[panel]; !ok {
		return fmt.Errorf("no monitor named %q", panel)
	}
	h.load(panel)
	return nil
}
