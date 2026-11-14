package app

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"os/user"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	hostgate "github.com/yongjohnlee80/autopanel/host/gate"
	"github.com/yongjohnlee80/autopanel/internal/module"
	"github.com/yongjohnlee80/autopanel/internal/sysinfo"
	"github.com/yongjohnlee80/autopanel/store"
)

// MONITORING — what the panel's System menu shows: the metrics, the audit
// log, the login attempts and the open ports, and the panel's two
// preferences. All of it is read-only but the preferences, and every row is
// bounded: a monitoring verb never reads a table or a log whole.

// The host reads behind sys.ports and sys.logins. They are variables so the
// daemon's test gives its own: a test reads no real socket table or journal.
var (
	readListeners = sysinfo.Listeners
	readSSHLogins = sysinfo.SSHLogins
)

// counters are what the gate last reported over the link (link.report): its
// request counts, one per listener, its process, its memory, and when the
// report came (Unix nanoseconds; 0 for a gate that has not reported).
type counters struct {
	https, http atomic.Int64
	pid, seen   atomic.Int64
	memory      atomic.Uint64
}

// gateQuiet is how long after its last report the gate still counts as
// running: a report may be late, or lost to a redial.
func gateQuiet() time.Duration { return 4*hostgate.ReportEvery + 5*time.Second }

// gatePID is the gate's process, 0 when it has not reported lately.
func (c *counters) gatePID() int {
	seen := c.seen.Load()
	if seen == 0 || time.Since(time.Unix(0, seen)) > gateQuiet() {
		return 0
	}
	return int(c.pid.Load())
}

// userName is a user's name by its number, and the number when the host has
// no name for it. A variable so a test gives its own.
var userName = func(uid int) string {
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
		return u.Username
	}
	return strconv.Itoa(uid)
}

// Metrics is sys.metrics's answer.
type Metrics struct {
	Uptime        string         `json:"uptime"`
	Goroutines    int            `json:"goroutines"`
	HeapBytes     uint64         `json:"heap_bytes"`    // the core's live heap
	RuntimeBytes  uint64         `json:"runtime_bytes"` // all memory the core's runtime holds
	HTTPSRequests int64          `json:"https_requests"`
	HTTPRequests  int64          `json:"http_requests"`
	Routes        int            `json:"routes"`
	Gate          GateMetrics    `json:"gate"`
	Host          sysinfo.Host   `json:"host"`
	Activity      sysinfo.Sample `json:"activity"` // CPU, swap, uptime and the network, with rates since the last read
}

// GateMetrics is what the gate last reported of itself. Running is false for
// a gate that has not reported lately: stopped, or cut off from the core.
type GateMetrics struct {
	Running     bool   `json:"running"`
	PID         int    `json:"pid"`
	MemoryBytes uint64 `json:"memory_bytes"`
}

// Limit is the param of the verbs that list rows: how many, newest first.
type Limit struct {
	Limit int `json:"limit"`
}

// rowLimit bounds a list verb's rows: 200 unless asked, 1000 at most.
func rowLimit(p Limit) int {
	switch {
	case p.Limit <= 0:
		return 200
	case p.Limit > 1000:
		return 1000
	}
	return p.Limit
}

// LoginAttempt is one row of sys.logins: a login to the panel, or to the host
// over SSH.
type LoginAttempt struct {
	At     int64  `json:"at"`     // Unix seconds
	Source string `json:"source"` // "panel" or "ssh"
	User   string `json:"user"`
	From   string `json:"from"`   // the SSH client's address; the panel's caller ("local:<uid>")
	Result string `json:"result"` // "ok", "failed" or "closed"
	Detail string `json:"detail"`
}

// Logins is sys.logins's answer. SSHNote says why there are no SSH rows when
// the journal could not be read; it is empty when it was.
type Logins struct {
	Attempts []LoginAttempt `json:"attempts"`
	SSHNote  string         `json:"ssh_note"`
}

// Port is one row of sys.ports: a listening socket, and what it is for when
// AutoPanel knows.
type Port struct {
	Proto   string `json:"proto"`
	Address string `json:"address"`
	Port    int    `json:"port"`
	Process string `json:"process"` // the program that holds it; "" when the host does not say
	PID     int    `json:"pid"`     // 0 when the host does not say
	User    string `json:"user"`    // the user it belongs to; "" when the host does not say
	Use     string `json:"use"`
}

// Prefs are the panel's preferences, kept in the store so every panel on this
// AutoPanel opens the same way. An empty field is one never chosen.
type Prefs struct {
	Theme    string `json:"theme"`
	Language string `json:"language"`
}

const (
	prefTheme    = "ui.theme"
	prefLanguage = "ui.language"
)

// prefValue is what a preference may hold: a theme's or a language's name.
var prefValue = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,39}$`)

var (
	errBadPref       = errors.New("sys: a preference is a name of letters, digits and underscores")
	errNoGateControl = errors.New("sys: this core does not run the gate's unit")
	errGateControl   = errors.New("sys: the gate's unit did not do it")
)

func (m *sysModule) metrics(context.Context, struct{}) (Metrics, error) {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	var g GateMetrics
	if pid := m.counts.gatePID(); pid != 0 {
		g = GateMetrics{Running: true, PID: pid, MemoryBytes: m.counts.memory.Load()}
	}
	return Metrics{
		Uptime:     time.Since(m.started).Round(time.Second).String(),
		Goroutines: runtime.NumGoroutine(), HeapBytes: ms.HeapAlloc, RuntimeBytes: ms.Sys,
		HTTPSRequests: m.counts.https.Load(), HTTPRequests: m.counts.http.Load(),
		Routes: len(m.table.Routes()), Gate: g, Host: sysinfo.ReadHost(m.cfg.StateDir),
		Activity: m.sampler.Read(),
	}, nil
}

func (m *sysModule) auditLog(ctx context.Context, p Limit) ([]store.AuditEntry, error) {
	return m.st.AuditLog(ctx, "", rowLimit(p))
}

// logins merges the panel's logins (the audit log's auth.login entries, but
// for the "attempt" each one opens with) and the host's SSH logins, newest
// first.
func (m *sysModule) logins(ctx context.Context, p Limit) (Logins, error) {
	limit := rowLimit(p)
	entries, err := m.st.AuditLog(ctx, "auth.login", 2*limit) // each login writes two entries
	if err != nil {
		return Logins{}, err
	}
	out := Logins{Attempts: []LoginAttempt{}}
	for _, e := range entries {
		if e.Detail == "attempt" {
			continue
		}
		out.Attempts = append(out.Attempts, LoginAttempt{At: e.At, Source: "panel",
			User: strings.TrimPrefix(e.Subject, "user "), From: e.Actor, Result: e.Detail})
	}
	ssh, err := m.sshLogins(ctx, limit)
	switch {
	case errors.Is(err, sysinfo.ErrUnsupported):
		out.SSHNote = "SSH logins are not shown: this host has no journal to read them from."
	case err != nil:
		m.log.Warn("reading SSH logins", "err", err)
		out.SSHNote = "SSH logins are not shown: the journal could not be read."
	}
	for _, l := range ssh {
		out.Attempts = append(out.Attempts, LoginAttempt{At: l.At, Source: "ssh", User: l.User, From: l.From, Result: l.Result, Detail: l.Detail})
	}
	sortAttempts(out.Attempts)
	if len(out.Attempts) > limit {
		out.Attempts = out.Attempts[:limit]
	}
	return out, nil
}

// sortAttempts orders as newest first; equal times keep their order.
func sortAttempts(as []LoginAttempt) {
	for i := 1; i < len(as); i++ { // both halves arrive sorted: an insertion sort is a merge
		for j := i; j > 0 && as[j].At > as[j-1].At; j-- {
			as[j], as[j-1] = as[j-1], as[j]
		}
	}
}

// wellKnown names the usual service of a port, for a socket whose process the
// host did not name. It is a hint, said as one.
var wellKnown = map[string]string{
	"tcp/22": "SSH", "tcp/25": "SMTP", "tcp/53": "DNS", "udp/53": "DNS", "udp/67": "DHCP", "udp/68": "DHCP",
	"tcp/80": "HTTP", "tcp/110": "POP3", "udp/123": "NTP", "tcp/143": "IMAP", "tcp/443": "HTTPS", "udp/443": "HTTP/3",
	"tcp/465": "SMTP (TLS)", "tcp/587": "SMTP submission", "tcp/993": "IMAP (TLS)", "tcp/995": "POP3 (TLS)",
	"tcp/3306": "MySQL", "tcp/3478": "TURN/STUN", "udp/3478": "TURN/STUN", "tcp/5349": "TURN (TLS)", "udp/5349": "TURN (DTLS)",
	"tcp/5432": "PostgreSQL", "tcp/6379": "Redis", "udp/51820": "WireGuard",
}

// portOf is the port of a listen address ("127.0.0.1:8443", ":443"), 0 for none.
func portOf(addr string) int {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(p)
	return n
}

// upstreamPort is the port of a route's upstream on this host: the port its
// URL names, or its scheme's. An upstream on another host is 0: its port says
// nothing of a socket here.
func upstreamPort(upstream string) int {
	u, err := url.Parse(upstream)
	if err != nil {
		return 0
	}
	if h := u.Hostname(); h != "localhost" {
		if ip, err := netip.ParseAddr(h); err != nil || !ip.IsLoopback() {
			return 0
		}
	}
	if p := u.Port(); p != "" {
		n, _ := strconv.Atoi(p)
		return n
	}
	switch u.Scheme {
	case "http":
		return 80
	case "https":
		return 443
	}
	return 0
}

// ports lists the listening sockets with who holds each. A socket is called
// AutoPanel's own when it is on one of the gate's two ports and its process is
// the gate, or is not known: another program on port 443 is named as itself.
func (m *sysModule) ports(ctx context.Context, _ struct{}) ([]Port, error) {
	ls, err := m.listeners(ctx)
	if err != nil {
		return nil, err
	}
	upstream := map[int]string{}
	for _, r := range m.table.Routes() { // an upstream on this host: the port a route forwards to
		if p := upstreamPort(r.Upstream); p != 0 {
			if _, seen := upstream[p]; !seen {
				upstream[p] = "upstream of " + r.Host
			}
		}
	}
	own := map[int]string{}
	if p := portOf(m.cfg.HTTPAddr); p != 0 {
		own[p] = "AutoPanel: HTTP (certificate checks, redirect to HTTPS)"
	}
	if p := portOf(m.cfg.HTTPSAddr); p != 0 {
		own[p] = "AutoPanel: HTTPS (the proxy)"
	}
	gate := m.counts.gatePID()
	var svc map[string]string // a service's user → its name
	if m.serviceUsers != nil {
		if svc, err = m.serviceUsers(ctx); err != nil {
			return nil, err
		}
	}
	out := make([]Port, 0, len(ls))
	for _, l := range ls {
		p := Port{Proto: l.Proto, Address: l.Address, Port: l.Port, Process: l.Process, PID: l.PID}
		if l.UID != sysinfo.NoUID {
			p.User = userName(l.UID)
		}
		if l.Proto == "tcp" {
			if name, ok := own[l.Port]; ok && (l.PID == 0 || l.PID == gate) {
				p.Use = name
			} else if !ok {
				p.Use = upstream[l.Port]
			}
		}
		// A socket held by a service's user is that service's, whatever its port.
		if name, ok := svc[p.User]; ok && p.User != "" {
			p.Use = "service " + name
		}
		if p.Use == "" && l.Process == "" {
			if name, ok := wellKnown[l.Proto+"/"+strconv.Itoa(l.Port)]; ok {
				p.Use = name + " (usual for this port)"
			}
		}
		out = append(out, p)
	}
	return out, nil
}

func (m *sysModule) prefs(ctx context.Context, _ struct{}) (Prefs, error) {
	var p Prefs
	var err error
	if p.Theme, _, err = m.st.Setting(ctx, prefTheme); err != nil {
		return Prefs{}, err
	}
	if p.Language, _, err = m.st.Setting(ctx, prefLanguage); err != nil {
		return Prefs{}, err
	}
	return p, nil
}

// setPrefs keeps the fields given; an empty field is left as it is.
func (m *sysModule) setPrefs(ctx context.Context, p Prefs) (Prefs, error) {
	for key, v := range map[string]string{prefTheme: p.Theme, prefLanguage: p.Language} {
		if v == "" {
			continue
		}
		if !prefValue.MatchString(v) {
			return Prefs{}, errBadPref
		}
		if err := m.st.PutSetting(ctx, key, v); err != nil {
			return Prefs{}, err
		}
	}
	return m.prefs(ctx, struct{}{})
}

// gateDo runs one of the gate's lifecycle actions. Both verbs are privileged:
// the control socket writes the audit entry first, refuses the verb if it
// cannot, and sets the outcome on the entry afterwards.
func (m *sysModule) gateDo(ctx context.Context, action string, do func(GateControl) func(context.Context) error) (struct{}, error) {
	if m.gate == nil {
		return struct{}{}, errNoGateControl
	}
	if err := do(m.gate)(ctx); err != nil {
		m.log.Error(action, "err", err)
		return struct{}{}, errGateControl
	}
	return struct{}{}, nil
}

func (m *sysModule) gateRestart(ctx context.Context, _ struct{}) (struct{}, error) {
	return m.gateDo(ctx, "gate.restart", func(g GateControl) func(context.Context) error { return g.Restart })
}

func (m *sysModule) gateStop(ctx context.Context, _ struct{}) (struct{}, error) {
	return m.gateDo(ctx, "gate.stop", func(g GateControl) func(context.Context) error { return g.Stop })
}

// monitorVerbs are the sys.* verbs beyond sys.status.
func (m *sysModule) monitorVerbs() []module.Verb {
	return []module.Verb{
		module.Handle(module.Contract{Verb: "sys.metrics", Since: 1,
			Result: "{uptime, goroutines, heap_bytes, runtime_bytes, https_requests, http_requests, routes, gate: {running, pid, memory_bytes}, host: {load, mem_total, mem_available, disk_total, disk_free}}",
			Doc:    "The core's memory and goroutines; the gate's request counts since it started, its process and its memory, as it last reported them (running is false when it has stopped reporting); and the host's load, memory and the disk the store is on."}, m.metrics),
		module.Handle(module.Contract{Verb: "sys.audit.list", Since: 1, Param: "{limit?}", Result: "[{id, at, actor, action, subject, detail, outcome}]",
			Doc: "The newest audit entries, newest first: 200 unless limit says, 1000 at most. outcome is set on a privileged action's entry: attempt until it ends, then ok or the error's name."}, m.auditLog),
		module.Handle(module.Contract{Verb: "sys.logins", Since: 1, Param: "{limit?}", Result: "{attempts: [{at, source, user, from, result, detail}], ssh_note}",
			Doc: "Login attempts, newest first: to the panel, from the audit log, and to the host over SSH, from the journal. ssh_note says why when the journal could not be read."}, m.logins),
		module.Handle(module.Contract{Verb: "sys.ports", Since: 1, Result: "[{proto, address, port, process, pid, user, use}]",
			Doc: "The host's listening TCP sockets and bound UDP sockets, each with the process and the user that hold it when the host says. use names AutoPanel's own, a route's upstream, or, for a socket whose process is not known, the port's usual service."}, m.ports),
		module.Handle(module.Contract{Verb: "sys.prefs.get", Since: 1, Result: "{theme, language}",
			Doc: "The panel's preferences; an empty one was never chosen."}, m.prefs),
		module.Handle(module.Contract{Verb: "sys.prefs.set", Since: 1, Param: "{theme?, language?}", Result: "{theme, language}", Mutates: true,
			Doc: "Keeps the panel's theme or language; a field left out is unchanged."}, m.setPrefs),
		module.Handle(module.Contract{Verb: "sys.gate.restart", Since: 2, Mutates: true, Privileged: true,
			Doc: "Restarts the gate process: the two listeners close and open again. Audited before it takes effect."}, m.gateRestart),
		module.Handle(module.Contract{Verb: "sys.gate.stop", Since: 2, Mutates: true, Privileged: true,
			Doc: "Stops the gate process: nothing is served until sys.gate.restart, or the core's next start. Audited before it takes effect."}, m.gateStop),
	}
}
