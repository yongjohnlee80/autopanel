package ui

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	tuidecl "github.com/yongjohnlee80/golib/tui/decl"

	"github.com/yongjohnlee80/autopanel/core/gate"
	"github.com/yongjohnlee80/autopanel/core/services"
	"github.com/yongjohnlee80/autopanel/internal/sysinfo"
)

// THE MAIN SCREEN'S WIDGETS — each a tile, each reading a verb of the
// daemon's every few seconds while it is shown:
//
//	Host          sys.metrics: CPU, memory, swap, disk, load, uptime
//	Network       sys.metrics: each interface's rates and totals
//	Stacks        services.list: each container's state, health, memory
//	Traffic       sys.metrics and gate.domain.list: the gate's requests, the domains
//	Certificates  sys.status and gate.route.list: the CA in use, the hosts it serves
//	Ports         sys.ports: the listening sockets
//	Activity      sys.audit.list: the newest audit entries
//
// A read that fails shows in its widget, in one line, and the widget keeps
// what it last showed: a dialog would stop the screen every few seconds. Each
// widget's text is composed here from the last answer, so a change of
// language composes it again without a read.
//
// Decision: docs/decisions/ui.md#the-main-screen-is-tiled-widgets

// barCells is how wide a widget's gauge is.
const barCells = 16

// hotPercent is the share of a gauge at which it shows in the alert colour.
const hotPercent = 85

// widgets are the widgets' models and the last answers they show.
type widgets struct {
	network, stacks, domains, hosts, ports, activity *tuidecl.ListModel

	metrics    *Metrics
	metricsErr error
	stacksErr  error
	domainErr  error
	certErr    error
	portsErr   error
	auditErr   error
}

func newWidgets() widgets {
	return widgets{
		network:  tuidecl.NewListModel("key", "name", "rx", "tx", "rxTotal", "txTotal", "errors"),
		stacks:   tuidecl.NewListModel("key", "name", "state", "health", "memory"),
		domains:  tuidecl.NewListModel("key", "name", "routes"),
		hosts:    tuidecl.NewListModel("key", "host", "domain"),
		ports:    tuidecl.NewListModel("key", "proto", "port", "process", "use"),
		activity: tuidecl.NewListModel("key", "time", "actor", "action", "subject"),
	}
}

// state is the widgets' part of the App singleton's state.
func (w *widgets) state() map[string]any {
	s := map[string]any{
		"App.network":         w.network,
		"App.stackSummary":    w.stacks,
		"App.trafficDomains":  w.domains,
		"App.certHosts":       w.hosts,
		"App.portSummary":     w.ports,
		"App.activity":        w.activity,
		"App.trafficRequests": "",
		"App.certIssuer":      "",
		"App.certChallenge":   "",
		"App.hostLoad":        "",
		"App.hostUptime":      "",
		"App.hostCpuBar":      bar(0),
		"App.hostCpuValue":    "",
		"App.hostCpuHot":      false,
		"App.hostMemoryBar":   bar(0),
		"App.hostMemoryValue": "",
		"App.hostMemoryHot":   false,
		"App.hostSwapBar":     bar(0),
		"App.hostSwapValue":   "",
		"App.hostSwapHot":     false,
		"App.hostDiskBar":     bar(0),
		"App.hostDiskValue":   "",
		"App.hostDiskHot":     false,
	}
	for _, name := range []string{"host", "network", "stacksWidget", "traffic", "certs", "ports", "activity"} {
		s["App."+name+"Error"] = ""
		s["App."+name+"ErrorShown"] = false
	}
	return s
}

// bar is a gauge of percent, barCells wide: filled, then empty.
func bar(percent float64) string {
	percent = max(0, min(100, percent))
	n := int(math.Round(percent / 100 * barCells))
	return strings.Repeat("█", n) + strings.Repeat("░", barCells-n)
}

// share is used as a percent of total; 0 for a total of 0.
func share(used, total uint64) float64 {
	if total == 0 {
		return 0
	}
	return float64(used) / float64(total) * 100
}

// rateText is a rate in bytes a second in the unit that reads best: "0 B/s",
// "1.5 KB/s", "2.3 MB/s".
func rateText(perSec uint64) string {
	const unit = 1000
	if perSec < unit {
		return strconv.FormatUint(perSec, 10) + " B/s"
	}
	div, exp := uint64(unit), 0
	for v := perSec / unit; v >= unit && exp < 4; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB/s", float64(perSec)/float64(div), "KMGTP"[exp])
}

// uptimeText is the host's uptime in days, hours and minutes.
func uptimeText(w wording, seconds int64) string {
	if seconds <= 0 {
		return "-"
	}
	d, h, m := seconds/86400, seconds%86400/3600, seconds%3600/60
	if d > 0 {
		return w.trf("autopanel.value.host.uptimeDays", d, h)
	}
	return w.trf("autopanel.value.host.uptimeHours", h, m)
}

// hostGauge is one gauge of the host widget: its bar, its words, and whether
// it is in the alert colour.
type hostGauge struct {
	bar, value string
	hot        bool
}

// hostGauges are the host widget's four gauges, CPU, memory, swap and disk,
// and its two lines, load and uptime.
func hostGauges(w wording, m Metrics) (cpu, memory, swap, disk hostGauge, load, uptime string) {
	a := m.Activity
	if a.CPUPercent < 0 {
		cpu = hostGauge{bar: bar(0), value: w.tr("autopanel.value.host.measuring")}
	} else {
		cpu = hostGauge{bar: bar(a.CPUPercent), value: w.trf("autopanel.value.host.cpu", fmt.Sprintf("%.0f", a.CPUPercent), a.CPUs),
			hot: a.CPUPercent >= hotPercent}
	}
	used := m.Host.MemTotal - min(m.Host.MemAvailable, m.Host.MemTotal)
	pct := share(used, m.Host.MemTotal)
	memory = hostGauge{bar: bar(pct), value: w.trf("autopanel.value.host.usedOf", bytesText(used), bytesText(m.Host.MemTotal)), hot: pct >= hotPercent}
	if a.SwapTotal == 0 {
		swap = hostGauge{bar: bar(0), value: w.tr("autopanel.value.host.noSwap")}
	} else {
		used := a.SwapTotal - min(a.SwapFree, a.SwapTotal)
		pct := share(used, a.SwapTotal)
		swap = hostGauge{bar: bar(pct), value: w.trf("autopanel.value.host.usedOf", bytesText(used), bytesText(a.SwapTotal)), hot: pct >= hotPercent}
	}
	used = m.Host.DiskTotal - min(m.Host.DiskFree, m.Host.DiskTotal)
	pct = share(used, m.Host.DiskTotal)
	disk = hostGauge{bar: bar(pct), value: w.trf("autopanel.value.host.usedOf", bytesText(used), bytesText(m.Host.DiskTotal)), hot: pct >= hotPercent}
	load = fmt.Sprintf("%.2f · %.2f · %.2f", m.Host.Load.One, m.Host.Load.Five, m.Host.Load.Fifteen)
	return cpu, memory, swap, disk, load, uptimeText(w, a.Uptime)
}

// networkRows are the network widget's rows: an interface each, by name.
func networkRows(ifaces []sysinfo.IfaceRate) []tuidecl.Row {
	sorted := append([]sysinfo.IfaceRate(nil), ifaces...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	rows := make([]tuidecl.Row, 0, len(sorted))
	for _, n := range sorted {
		rows = append(rows, tuidecl.Row{"key": n.Name, "name": n.Name, "rx": rateText(n.RxPerSec), "tx": rateText(n.TxPerSec),
			"rxTotal": bytesText(n.RxBytes), "txTotal": bytesText(n.TxBytes), "errors": strconv.FormatUint(n.RxErrors+n.TxErrors, 10)})
	}
	return rows
}

// stackSummaryRows are the stacks widget's rows: a container each, named
// stack/service, or the stack alone while it has none.
func stackSummaryRows(w wording, views []services.View) []tuidecl.Row {
	var rows []tuidecl.Row
	for _, v := range views {
		if len(v.Containers) == 0 {
			state := stackState(w, v)
			if state == "" {
				state = v.State
			}
			rows = append(rows, tuidecl.Row{"key": v.Name + "/", "name": v.Name, "state": state, "health": "-", "memory": "-"})
			continue
		}
		for _, c := range v.Containers {
			memory := "-"
			if c.MemoryBytes > 0 {
				memory = bytesText(c.MemoryBytes)
			}
			rows = append(rows, tuidecl.Row{"key": v.Name + "/" + c.Service, "name": v.Name + "/" + c.Service,
				"state": containerState(w, v, c), "health": orDash(c.Health), "memory": memory})
		}
	}
	return rows
}

// domainRows are the traffic widget's rows: each domain and its routes.
func domainRows(domains []gate.DomainView) []tuidecl.Row {
	rows := make([]tuidecl.Row, 0, len(domains))
	for _, d := range domains {
		rows = append(rows, tuidecl.Row{"key": d.Name, "name": d.Name, "routes": d.Routes})
	}
	return rows
}

// hostRows are the certificates widget's rows: each host a route serves, once,
// with the domain it is under.
func hostRows(routes []gate.RouteView, domains []gate.DomainView) []tuidecl.Row {
	seen := map[string]bool{}
	var hosts []string
	for _, r := range routes {
		if !seen[r.Host] {
			seen[r.Host] = true
			hosts = append(hosts, r.Host)
		}
	}
	sort.Strings(hosts)
	rows := make([]tuidecl.Row, 0, len(hosts))
	for _, host := range hosts {
		rows = append(rows, tuidecl.Row{"key": host, "host": host, "domain": orDash(domainOf(host, domains))})
	}
	return rows
}

// portSummaryRows are the ports widget's rows: protocol, port, the process
// and what it is for.
func portSummaryRows(ports []Port) []tuidecl.Row {
	rows := make([]tuidecl.Row, 0, len(ports))
	for _, p := range ports {
		use := p.Use
		if use == "" {
			use = "-"
		}
		rows = append(rows, tuidecl.Row{"key": portKey(p), "proto": p.Proto, "port": p.Port, "process": orDash(p.Process), "use": use})
	}
	return rows
}

// portKey names a socket across reads.
func portKey(p Port) string {
	return p.Proto + "/" + p.Address + "/" + strconv.Itoa(p.Port) + "/" + strconv.Itoa(p.PID)
}

// activityRows are the activity widget's rows: the newest audit entries, at
// most twenty.
func activityRows(entries []AuditEntry) []tuidecl.Row {
	n := min(len(entries), 20)
	rows := make([]tuidecl.Row, 0, n)
	for _, e := range entries[:n] {
		rows = append(rows, tuidecl.Row{"key": strconv.FormatInt(e.ID, 10), "time": clock(e.At), "actor": e.Actor, "action": e.Action, "subject": e.Subject})
	}
	return rows
}

// clock is a Unix time as a widget shows it: the time of day for today, the
// date and time otherwise.
func clock(at int64) string {
	if at == 0 {
		return "-"
	}
	t := time.Unix(at, 0)
	if y, m, d := t.Date(); y == time.Now().Year() && m == time.Now().Month() && d == time.Now().Day() {
		return t.Format("15:04:05")
	}
	return t.Format("01-02 15:04")
}

// widgetError is a widget's error line: a read that failed, in the UI's
// language, or none.
func (h *host) widgetError(name string, err error) map[string]any {
	text := ""
	if err != nil {
		text = h.trf("autopanel.notice.widget.readFailed", err.Error())
	}
	return map[string]any{"App." + name + "Error": text, "App." + name + "ErrorShown": err != nil}
}

// renderHost and the render functions after it put each widget's last answer
// on screen, in the UI's language now. On the loop.
func (h *host) renderHost() {
	vals := h.widgetError("host", h.wid.metricsErr)
	if m := h.wid.metrics; m != nil {
		cpu, memory, swap, disk, load, uptime := hostGauges(h, *m)
		for name, g := range map[string]hostGauge{"Cpu": cpu, "Memory": memory, "Swap": swap, "Disk": disk} {
			vals["App.host"+name+"Bar"], vals["App.host"+name+"Value"], vals["App.host"+name+"Hot"] = g.bar, g.value, g.hot
		}
		vals["App.hostLoad"], vals["App.hostUptime"] = load, uptime
	}
	_ = h.p.SetMany(vals)
}

func (h *host) renderNetwork() {
	if m := h.wid.metrics; m != nil {
		h.wid.network.Reset(networkRows(m.Activity.Network))
	}
	_ = h.p.SetMany(h.widgetError("network", h.wid.metricsErr))
}

func (h *host) renderTraffic() {
	vals := h.widgetError("traffic", firstErr(h.wid.metricsErr, h.wid.domainErr))
	if m := h.wid.metrics; m != nil {
		vals["App.trafficRequests"] = h.trf("autopanel.value.traffic.requests", m.HTTPSRequests, m.HTTPRequests)
	}
	h.wid.domains.Reset(domainRows(h.domains))
	_ = h.p.SetMany(vals)
}

func (h *host) renderCerts() {
	vals := h.widgetError("certs", h.wid.certErr)
	if h.status != nil {
		vals["App.certIssuer"] = h.trf("autopanel.value.certs.issuer", caName(h, h.status.CA))
		vals["App.certChallenge"] = h.trf("autopanel.value.certs.challenge", orDash(h.status.Challenge))
	}
	h.wid.hosts.Reset(hostRows(h.routes, h.domains))
	_ = h.p.SetMany(vals)
}

func (h *host) renderStackSummary() {
	if h.stk.read {
		h.wid.stacks.Reset(stackSummaryRows(h, h.stk.views))
	}
	_ = h.p.SetMany(h.widgetError("stacksWidget", h.wid.stacksErr))
}

func (h *host) renderPortSummary() {
	if h.mon.lastPorts != nil {
		h.wid.ports.Reset(portSummaryRows(h.mon.lastPorts))
	}
	_ = h.p.SetMany(h.widgetError("ports", h.wid.portsErr))
}

func (h *host) renderActivity() {
	if h.mon.lastAudit != nil {
		h.wid.activity.Reset(activityRows(h.mon.lastAudit))
	}
	_ = h.p.SetMany(h.widgetError("activity", h.wid.auditErr))
}

// renderWidgets puts every widget's last answer on screen again.
func (h *host) renderWidgets() {
	h.renderHost()
	h.renderNetwork()
	h.renderTraffic()
	h.renderCerts()
	h.renderStackSummary()
	h.renderPortSummary()
	h.renderActivity()
}

func firstErr(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// startPolling reads the screen now, and again every pollEvery until the
// panel quits. Once: a second login does not start a second poller.
func (h *host) startPolling() {
	h.poll()
	if h.polled {
		return
	}
	h.polled = true
	every := h.pollEvery
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-h.ctx.Done():
				return
			case <-t.C:
				h.p.Post(h.poll)
			}
		}
	}()
}

// poll reads what the screen shows now: the status and the routes always,
// for the status bar; each other verb only while a widget or an open panel
// shows its answer. One poll at a time: a slow daemon is not asked twice.
func (h *host) poll() {
	if !h.signedIn || h.polling {
		return
	}
	h.refresh()
	wantMetrics := h.shown("hostWidget") || h.shown("networkWidget") || h.shown("trafficWidget") || h.panelShown("metrics")
	wantStacks := h.shown("stacksWidget") || h.panelShown("stacks")
	wantPorts := h.shown("portsWidget") || h.panelShown("ports")
	wantAudit := h.shown("activityWidget") || h.panelShown("audit")
	wantLogins := h.panelShown("logins")
	var (
		metrics                                           Metrics
		views                                             []services.View
		ports                                             []Port
		audit                                             []AuditEntry
		logins                                            Logins
		metricsErr, stacksErr, portsErr, auditErr, logErr error
	)
	h.polling = true
	h.background(func(ctx context.Context) error {
		if wantMetrics {
			metrics, metricsErr = h.client.Metrics(ctx)
		}
		if wantStacks {
			views, stacksErr = h.client.Stacks(ctx)
		}
		if wantPorts {
			ports, portsErr = h.client.Ports(ctx)
		}
		if wantAudit {
			audit, auditErr = h.client.AuditLog(ctx)
		}
		if wantLogins {
			logins, logErr = h.client.Logins(ctx)
		}
		return nil
	}, func(error) {
		h.polling = false
		now := time.Now()
		if wantMetrics {
			h.wid.metricsErr = metricsErr
			if metricsErr == nil {
				h.mon.lastMetrics, h.mon.readAt["metrics"] = &metrics, now
				h.wid.metrics = &metrics
			}
			h.renderHost()
			h.renderNetwork()
			h.renderTraffic()
		}
		if wantStacks {
			h.wid.stacksErr = stacksErr
			if stacksErr == nil {
				h.setStacks(views)
			}
			h.renderStackSummary()
		}
		if wantPorts {
			h.wid.portsErr = portsErr
			if portsErr == nil {
				h.mon.lastPorts, h.mon.readAt["ports"] = orEmpty(ports), now
			}
			h.renderPortSummary()
		}
		if wantAudit {
			h.wid.auditErr = auditErr
			if auditErr == nil {
				h.mon.lastAudit, h.mon.readAt["audit"] = orEmpty(audit), now
			}
			h.renderActivity()
		}
		if wantLogins && logErr == nil {
			h.mon.lastLogins, h.mon.readAt["logins"] = &logins, now
		}
		h.mon.errs = map[string]error{"metrics": metricsErr, "ports": portsErr, "audit": auditErr, "logins": logErr}
		h.mon.render(h)
	})
}

// orEmpty is s, or an empty slice for nil: a read that answered nothing
// still answered.
func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
