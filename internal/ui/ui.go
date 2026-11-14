// Package ui is AutoPanel's admin TUI. The main screen is a set of widgets
// tiled over the window (host, network, stacks, traffic, certificates, ports
// and activity), each read again every few seconds while it is shown. A menu
// bar sits above them, with the dock in its right corner: an icon for each
// widget and each open panel, which a click hides or shows. The status bar is
// below.
//
// The menus open the panels: the proxy routes and the domains, the System
// monitors (metrics, the audit log, login attempts, open ports), the stacks
// and a stack's log, and the terminal. A list and what acts on it are two
// panes: the rows on the left, the selected row's details on the right, the
// buttons under both. Every button carries its key in its label; Help › Keys
// is the one place the keys are listed.
//
// The panel opens on a login dialog and reads nothing until a panel user has
// signed in. All of it is over a Client that talks to the daemon. The panel
// keeps no state of its own: every change goes through the Client, and what it
// changed is read again after it.
//
// Decision: docs/decisions/ui.md
package ui

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/caddyserver/certmagic"
	"github.com/yongjohnlee80/golib/tui"
	tuidecl "github.com/yongjohnlee80/golib/tui/decl"
	"github.com/yongjohnlee80/golib/tui/term"

	"github.com/yongjohnlee80/autopanel/core/gate"
	"github.com/yongjohnlee80/autopanel/core/services"
	"github.com/yongjohnlee80/autopanel/internal/sysinfo"
)

// Status is what the status bar shows: sys.status's answer.
type Status struct {
	Version   string `json:"version"`
	HTTPS     string `json:"https"`
	HTTP      string `json:"http"`
	Store     string `json:"store"`
	CA        string `json:"ca"`
	Challenge string `json:"challenge"`
	Routes    int    `json:"routes"`
	Uptime    string `json:"uptime"`
}

// Metrics is sys.metrics's answer.
type Metrics struct {
	Uptime        string `json:"uptime"`
	Goroutines    int    `json:"goroutines"`
	HeapBytes     uint64 `json:"heap_bytes"`
	RuntimeBytes  uint64 `json:"runtime_bytes"`
	HTTPSRequests int64  `json:"https_requests"`
	HTTPRequests  int64  `json:"http_requests"`
	Routes        int    `json:"routes"`
	Gate          struct {
		Running     bool   `json:"running"`
		PID         int    `json:"pid"`
		MemoryBytes uint64 `json:"memory_bytes"`
	} `json:"gate"`
	Host struct {
		Load struct {
			One     float64 `json:"one"`
			Five    float64 `json:"five"`
			Fifteen float64 `json:"fifteen"`
		} `json:"load"`
		MemTotal     uint64 `json:"mem_total"`
		MemAvailable uint64 `json:"mem_available"`
		DiskTotal    uint64 `json:"disk_total"`
		DiskFree     uint64 `json:"disk_free"`
	} `json:"host"`
	// Activity is the host's CPU, swap, uptime and network, with the rates
	// since the daemon's last read.
	Activity sysinfo.Sample `json:"activity"`
}

// AuditEntry is one row of sys.audit.list.
type AuditEntry struct {
	ID      int64  `json:"id"`
	At      int64  `json:"at"`
	Actor   string `json:"actor"`
	Action  string `json:"action"`
	Subject string `json:"subject"`
	Detail  string `json:"detail"`
	// Outcome is set on a privileged action's entry: "attempt" until it
	// ends, then "ok" or the error's name.
	Outcome string `json:"outcome"`
}

// LoginAttempt is one row of sys.logins.
type LoginAttempt struct {
	At     int64  `json:"at"`
	Source string `json:"source"`
	User   string `json:"user"`
	From   string `json:"from"`
	Result string `json:"result"`
	Detail string `json:"detail"`
}

// Logins is sys.logins's answer.
type Logins struct {
	Attempts []LoginAttempt `json:"attempts"`
	SSHNote  string         `json:"ssh_note"`
}

// Port is one row of sys.ports.
type Port struct {
	Proto   string `json:"proto"`
	Address string `json:"address"`
	Port    int    `json:"port"`
	Process string `json:"process"`
	PID     int    `json:"pid"`
	User    string `json:"user"`
	Use     string `json:"use"`
}

// Prefs are the panel's kept preferences; an empty field is one not chosen
// (read) or left as it is (written).
type Prefs struct {
	Theme    string `json:"theme"`
	Language string `json:"language"`
}

// Client is everything the TUI may do.
type Client interface {
	// Login logs the connection in as a panel user. Every other call is
	// refused until one has succeeded.
	Login(ctx context.Context, user, passphrase string) error

	Routes(ctx context.Context) ([]gate.RouteView, error)
	Status(ctx context.Context) (Status, error)
	Add(ctx context.Context, s gate.RouteSpec) error
	Update(ctx context.Context, s gate.RouteSpec) error
	Remove(ctx context.Context, id int64) error
	// SetCA chooses the certificate service: "staging" or "production".
	SetCA(ctx context.Context, ca string) error

	// Domains are the registered domains, each with its routes' count.
	Domains(ctx context.Context) ([]gate.DomainView, error)
	AddDomain(ctx context.Context, name string) error
	// RemoveDomain is refused with gate.ErrDomainInUse while a route would
	// be left under no domain.
	RemoveDomain(ctx context.Context, name string) error

	// The System menu's monitors, and the widgets'.
	Metrics(ctx context.Context) (Metrics, error)
	AuditLog(ctx context.Context) ([]AuditEntry, error)
	Logins(ctx context.Context) (Logins, error)
	Ports(ctx context.Context) ([]Port, error)

	// The Services menu: the stacks. Each is a verb of the daemon's.
	Stacks(ctx context.Context) ([]services.View, error)
	// Browse lists a folder of the host for the file browser. A path it
	// cannot read is services.ErrBadPath.
	Browse(ctx context.Context, path string) (services.Listing, error)
	// Preview is a file's text, its secrets masked. A file outside a stack's
	// folder is services.ErrNotInStack; one that is not text,
	// services.ErrNotText.
	Preview(ctx context.Context, path string) (services.PreviewText, error)
	// ImportStack copies a folder's definition in as a new stack; it runs
	// nothing.
	ImportStack(ctx context.Context, from, name string) (services.Imported, error)
	// ReimportStack copies a stack's definition from its source again; what
	// runs does not change until an apply.
	ReimportStack(ctx context.Context, name string) (services.Imported, error)
	// CheckStack reviews a stack's definition and changes nothing.
	CheckStack(ctx context.Context, name string) (services.Review, error)
	// ApplyStack runs a reviewed definition: verb is "prepare", "add" or
	// "apply", and accept is the review's sha256. A definition that changed
	// since its review is refused with services.ErrChanged.
	ApplyStack(ctx context.Context, verb, name, accept string) error
	// PullStack pulls the images of a stack again, or of one service of it.
	PullStack(ctx context.Context, name, service string) error
	// StackUnit starts, stops or restarts a stack, or one service of it:
	// action is "start", "stop" or "restart", and service is "" for all.
	StackUnit(ctx context.Context, action, name, service string) error
	// RemoveStack deletes a stack's units and user; with purge, its
	// directory too.
	RemoveStack(ctx context.Context, name string, purge bool) error
	// StackLogs are the newest journal lines of a stack, or of one service.
	StackLogs(ctx context.Context, name, service string) ([]string, error)

	// The panel's preferences, kept by the daemon.
	Prefs(ctx context.Context) (Prefs, error)
	SetPrefs(ctx context.Context, p Prefs) error
}

// Run shows the TUI until the user quits or ctx ends. version is the panel's
// own, for About; the daemon reports its own in the status.
//
// The screen is QML (qml/Main.qml and the folders beside it): this package
// builds no widget. It publishes what it read as the App singleton's sources
// and runs the commands the document invokes (commands.go).
func Run(ctx context.Context, c Client, version string) error {
	if c == nil {
		return errors.New("ui: nil client")
	}
	backend, err := term.Open()
	if err != nil {
		return fmt.Errorf("ui: cannot open the terminal: %w", err)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	h := newHost(ctx, c, version)
	// Handler errors go to the status bar as they happen, rather than being
	// kept until the panel closes.
	p, err := tuidecl.NewProgram(h.options(func(err error) { h.say(h.trf("autopanel.notice.app.error", err.Error())) }, tui.WithBackend(backend))...)
	if err != nil {
		return fmt.Errorf("ui: %w", err)
	}
	h.attach(p)
	return p.Run(ctx)
}

// orDash is v, or "-" for nothing to show.
func orDash(v string) string {
	if strings.TrimSpace(v) == "" {
		return "-"
	}
	return v
}

// shortCA names an ACME directory for the status bar: Let's Encrypt's two by
// name, any other by its URL.
func shortCA(w wording, ca string) string {
	switch strings.TrimSpace(ca) {
	case certmagic.LetsEncryptStagingCA:
		return w.tr("autopanel.value.ca.shortStaging")
	case certmagic.LetsEncryptProductionCA:
		return w.tr("autopanel.value.ca.shortProduction")
	case "":
		return "-"
	}
	return ca
}

// statusLine is the status bar's summary of s.
func statusLine(w wording, s Status) string {
	return w.trf("autopanel.status.bar.line", orDash(s.Version), shortCA(w, s.CA), s.Routes, orDash(s.Uptime))
}

// caName names an ACME directory: Let's Encrypt's two by name, any other by
// its URL.
func caName(w wording, ca string) string {
	switch strings.TrimSpace(ca) {
	case certmagic.LetsEncryptStagingCA:
		return w.tr("autopanel.value.ca.nameStaging")
	case certmagic.LetsEncryptProductionCA:
		return w.tr("autopanel.value.ca.nameProduction")
	case "":
		return "-"
	}
	return ca
}

// formHost is the host a route form names: the subdomain under the domain
// chosen, the domain alone for no subdomain, or the subdomain field alone when
// no domain is chosen. A trailing or leading dot typed in either is dropped.
func formHost(sub, domain string) string {
	sub = strings.Trim(strings.TrimSpace(sub), ".")
	domain = strings.Trim(strings.TrimSpace(domain), ".")
	switch {
	case domain == "":
		return sub
	case sub == "":
		return domain
	}
	return sub + "." + domain
}

// splitHost is a stored host as the form shows it: the part under the longest
// domain it is under, and that domain. A host under none is all subdomain,
// with no domain.
func splitHost(host string, domains []gate.DomainView) (sub, domain string) {
	for _, d := range domains {
		if gate.Under(host, d.Name) && len(d.Name) > len(domain) {
			domain = d.Name
		}
	}
	if domain == "" {
		return host, ""
	}
	return strings.TrimSuffix(strings.TrimSuffix(host, domain), "."), domain
}

// formSpec is the route the form's fields describe: trimmed, with "/" for an
// empty path prefix. id is 0 for a new route.
func formSpec(id int64, host, prefix, upstream string) gate.RouteSpec {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		prefix = "/"
	}
	return gate.RouteSpec{ID: id, Host: strings.TrimSpace(host), PathPrefix: prefix, Upstream: strings.TrimSpace(upstream)}
}

// describe is one route on one line, for messages.
func describe(r gate.RouteView) string {
	return "#" + strconv.FormatInt(r.ID, 10) + " " + r.Host + r.PathPrefix + " → " + r.Upstream
}

// domainOf is the longest registered domain host is under, or "".
func domainOf(host string, domains []gate.DomainView) string {
	_, d := splitHost(host, domains)
	return d
}
