package ui

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/yongjohnlee80/golib/tui"
	tuidecl "github.com/yongjohnlee80/golib/tui/decl"
)

// THE SYSTEM MENU'S MONITORS — metrics, the audit log, login attempts and
// open ports, each a panel. The metrics are a table of facts; the other three
// are two panes, the rows on the left and the selected row whole on the
// right. Opening one reads it, and each is read again with the screen while
// it is open. The list's frame says how many rows were read, and when.

// monitors are the panels' models, and the last answer of each, kept so a
// change of language composes the rows again without another read.
type monitors struct {
	metrics, audit, logins, ports *tuidecl.ListModel

	lastMetrics *Metrics
	lastAudit   []AuditEntry
	lastLogins  *Logins
	lastPorts   []Port
	readAt      map[string]time.Time // when each was last read, by panel
	errs        map[string]error     // each one's last read that failed, by panel
	at          map[string]int       // the row under each list's cursor, by panel
}

func newMonitors() monitors {
	return monitors{
		metrics: tuidecl.NewListModel("key", "name", "value"),
		audit:   tuidecl.NewListModel("key", "time", "actor", "action"),
		logins:  tuidecl.NewListModel("key", "time", "source", "user", "result"),
		ports:   tuidecl.NewListModel("key", "proto", "port", "address", "process"),
		readAt:  map[string]time.Time{},
		errs:    map[string]error{},
		at:      map[string]int{},
	}
}

// state is the monitors' part of the App singleton's state.
func (m *monitors) state() map[string]any {
	return map[string]any{
		"App.metrics":      m.metrics,
		"App.audit":        m.audit,
		"App.logins":       m.logins,
		"App.ports":        m.ports,
		"App.metricsTitle": "",
		"App.auditTitle":   "",
		"App.loginsTitle":  "",
		"App.portsTitle":   "",
		"App.auditDetail":  "",
		"App.loginsDetail": "",
		"App.portsDetail":  "",
		"App.loginsNote":   "",
		"App.loginsNoted":  false,
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

// facts are lines of a label and its value, the values lined up after the
// widest label: a details pane's text. The labels are messages' ids.
func facts(w wording, pairs ...[2]string) string {
	width := 0
	labels := make([]string, len(pairs))
	for i, p := range pairs {
		labels[i] = w.tr(p[0])
		width = max(width, tui.StringWidth(labels[i]))
	}
	var b strings.Builder
	for i, p := range pairs {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(labels[i])
		b.WriteString(strings.Repeat(" ", width-tui.StringWidth(labels[i])+2))
		b.WriteString(p[1])
	}
	return b.String()
}

// metricRows are the metrics panel's rows: a name and its value.
func metricRows(w wording, m Metrics) [][2]string {
	gate := w.tr("autopanel.value.metrics.gateSilent")
	if m.Gate.Running {
		gate = w.trf("autopanel.value.metrics.gateMemory", bytesText(m.Gate.MemoryBytes), strconv.Itoa(m.Gate.PID))
	}
	return [][2]string{
		{w.tr("autopanel.label.metrics.uptime"), orDash(m.Uptime)},
		{w.tr("autopanel.label.metrics.httpsRequests"), strconv.FormatInt(m.HTTPSRequests, 10)},
		{w.tr("autopanel.label.metrics.httpRequests"), strconv.FormatInt(m.HTTPRequests, 10)},
		{w.tr("autopanel.label.metrics.routes"), strconv.Itoa(m.Routes)},
		{w.tr("autopanel.label.metrics.coreMemory"), w.trf("autopanel.value.metrics.coreMemory", bytesText(m.HeapBytes), bytesText(m.RuntimeBytes))},
		{w.tr("autopanel.label.metrics.goroutines"), strconv.Itoa(m.Goroutines)},
		{w.tr("autopanel.label.metrics.gateMemory"), gate},
		{w.tr("autopanel.label.metrics.load"), w.trf("autopanel.value.metrics.load",
			fmt.Sprintf("%.2f", m.Host.Load.One), fmt.Sprintf("%.2f", m.Host.Load.Five), fmt.Sprintf("%.2f", m.Host.Load.Fifteen))},
		{w.tr("autopanel.label.metrics.hostMemory"), w.trf("autopanel.value.metrics.availableOf", bytesText(m.Host.MemAvailable), bytesText(m.Host.MemTotal))},
		{w.tr("autopanel.label.metrics.disk"), w.trf("autopanel.value.metrics.freeOf", bytesText(m.Host.DiskFree), bytesText(m.Host.DiskTotal))},
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
		return w.tr("autopanel.value.logins." + result)
	}
	return result
}

// auditDetail is an audit entry whole, for the details pane.
func auditDetail(w wording, e AuditEntry) string {
	return facts(w,
		[2]string{"autopanel.label.audit.time", stamp(e.At)},
		[2]string{"autopanel.label.audit.actor", orDash(e.Actor)},
		[2]string{"autopanel.label.audit.action", orDash(e.Action)},
		[2]string{"autopanel.label.audit.subject", orDash(e.Subject)},
		[2]string{"autopanel.label.audit.detail", orDash(e.Detail)},
		[2]string{"autopanel.label.audit.outcome", orDash(e.Outcome)},
		[2]string{"autopanel.label.audit.entry", "#" + strconv.FormatInt(e.ID, 10)})
}

// loginDetail is a login attempt whole, for the details pane.
func loginDetail(w wording, a LoginAttempt) string {
	return facts(w,
		[2]string{"autopanel.label.logins.time", stamp(a.At)},
		[2]string{"autopanel.label.logins.to", a.Source},
		[2]string{"autopanel.label.logins.user", orDash(a.User)},
		[2]string{"autopanel.label.logins.from", orDash(a.From)},
		[2]string{"autopanel.label.logins.result", resultText(w, a.Result)},
		[2]string{"autopanel.label.logins.detail", orDash(a.Detail)})
}

// portDetail is a listening socket whole, for the details pane.
func portDetail(w wording, p Port) string {
	return facts(w,
		[2]string{"autopanel.label.ports.protocol", p.Proto},
		[2]string{"autopanel.label.ports.port", strconv.Itoa(p.Port)},
		[2]string{"autopanel.label.ports.address", orDash(p.Address)},
		[2]string{"autopanel.label.ports.process", holder(p)},
		[2]string{"autopanel.label.ports.user", orDash(p.User)},
		[2]string{"autopanel.label.ports.use", orDash(p.Use)})
}

// listTitle is a list frame's title: what it shows, how many rows, and when
// they were read; or why the last read failed.
func (h *host) listTitle(panel, what string, rows int) string {
	if err := h.mon.errs[panel]; err != nil {
		return h.trf("autopanel.title.list.failed", h.tr(what), err.Error())
	}
	at, ok := h.mon.readAt[panel]
	if !ok {
		return h.tr(what)
	}
	return h.trf("autopanel.title.list.readAt", h.tr(what), rows, at.Format("15:04:05"))
}

// render composes every monitor's rows, details and titles from its last
// answer, in the UI's language now. On the loop.
func (m *monitors) render(h *host) {
	vals := map[string]any{}
	if m.lastMetrics != nil {
		facts := metricRows(h, *m.lastMetrics)
		rows := make([]tuidecl.Row, 0, len(facts))
		for i, f := range facts {
			rows = append(rows, tuidecl.Row{"key": strconv.Itoa(i), "name": f[0], "value": f[1]})
		}
		m.metrics.Reset(rows)
	}
	vals["App.metricsTitle"] = h.listTitle("metrics", "autopanel.title.list.metrics", m.metrics.RowCount(nil))
	if m.lastAudit != nil {
		rows := make([]tuidecl.Row, 0, len(m.lastAudit))
		for _, e := range m.lastAudit {
			rows = append(rows, tuidecl.Row{"key": strconv.FormatInt(e.ID, 10), "time": stamp(e.At), "actor": e.Actor, "action": e.Action})
		}
		m.audit.Reset(rows)
	}
	vals["App.auditTitle"] = h.listTitle("audit", "autopanel.title.list.audit", len(m.lastAudit))
	vals["App.auditDetail"] = m.auditDetailAt(h, m.at["audit"])
	rows := 0
	if m.lastLogins != nil {
		list := make([]tuidecl.Row, 0, len(m.lastLogins.Attempts))
		for i, a := range m.lastLogins.Attempts {
			list = append(list, tuidecl.Row{"key": strconv.Itoa(i), "time": stamp(a.At), "source": a.Source,
				"user": a.User, "result": resultText(h, a.Result)})
		}
		m.logins.Reset(list)
		rows = len(list)
		vals["App.loginsNote"], vals["App.loginsNoted"] = m.lastLogins.SSHNote, m.lastLogins.SSHNote != ""
	}
	vals["App.loginsTitle"] = h.listTitle("logins", "autopanel.title.list.logins", rows)
	vals["App.loginsDetail"] = m.loginDetailAt(h, m.at["logins"])
	if m.lastPorts != nil {
		list := make([]tuidecl.Row, 0, len(m.lastPorts))
		for _, p := range m.lastPorts {
			list = append(list, tuidecl.Row{"key": portKey(p), "proto": p.Proto, "port": p.Port, "address": p.Address, "process": holder(p)})
		}
		m.ports.Reset(list)
	}
	vals["App.portsTitle"] = h.listTitle("ports", "autopanel.title.list.ports", len(m.lastPorts))
	vals["App.portsDetail"] = m.portDetailAt(h, m.at["ports"])
	_ = h.p.SetMany(vals)
}

func (m *monitors) auditDetailAt(w wording, row int) string {
	if row < 0 || row >= len(m.lastAudit) {
		return ""
	}
	return auditDetail(w, m.lastAudit[row])
}

func (m *monitors) loginDetailAt(w wording, row int) string {
	if m.lastLogins == nil || row < 0 || row >= len(m.lastLogins.Attempts) {
		return ""
	}
	return loginDetail(w, m.lastLogins.Attempts[row])
}

func (m *monitors) portDetailAt(w wording, row int) string {
	if row < 0 || row >= len(m.lastPorts) {
		return ""
	}
	return portDetail(w, m.lastPorts[row])
}

// monitorMoved is a monitor list's cursor moved: its details pane follows.
func (h *host) monitorMoved(panel string, row int) error {
	m := &h.mon
	m.at[panel] = row
	switch panel {
	case "audit":
		return h.p.Set("App.auditDetail", m.auditDetailAt(h, row))
	case "logins":
		return h.p.Set("App.loginsDetail", m.loginDetailAt(h, row))
	case "ports":
		return h.p.Set("App.portsDetail", m.portDetailAt(h, row))
	}
	return fmt.Errorf("no monitor list %q", panel)
}

// load reads one monitor off the loop and shows it. A failed read is said in
// the list's title, and the rows stay as they were.
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
		h.mon.errs[panel] = err
		if err == nil {
			h.mon.readAt[panel] = time.Now()
			switch panel {
			case "metrics":
				h.mon.lastMetrics, h.wid.metrics = &metrics, &metrics
			case "audit":
				h.mon.lastAudit = orEmpty(audit)
			case "logins":
				h.mon.lastLogins = &logins
			case "ports":
				h.mon.lastPorts = orEmpty(ports)
			}
		}
		h.mon.render(h)
	})
}

// monitorPanels are the System panels, by window key.
var monitorPanels = map[string]bool{"metrics": true, "audit": true, "logins": true, "ports": true}

// openMonitor opens a System panel and reads it.
func (h *host) openMonitor(panel string) error {
	if !monitorPanels[panel] {
		return fmt.Errorf("no monitor named %q", panel)
	}
	h.load(panel)
	return h.openPanel(panel)
}

// reloadMonitor is a monitor's Reload: read it again.
func (h *host) reloadMonitor(panel string) error {
	if !monitorPanels[panel] {
		return fmt.Errorf("no monitor named %q", panel)
	}
	h.load(panel)
	return nil
}
