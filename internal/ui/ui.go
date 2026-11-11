// Package ui is AutoPanel's admin TUI: a menu bar over an overview of the
// running AutoPanel, with a status bar beneath. The menus open the panel's
// parts as floating windows that move, resize, maximize, minimize and close:
// the proxy routes, with a form to add or edit one and a confirmation to
// remove one, and the System menu's monitors (metrics, the audit log, login
// attempts, open ports). The certificate service, the theme and the language
// are chosen in the menus. It opens on a login dialog, and reads nothing
// until a panel user has signed in. All of it is over a Client that talks to
// the daemon. The panel keeps no state of its own: every change goes through the
// Client, and the routes and status are read again after it.
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
	Host          struct {
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
}

// AuditEntry is one row of sys.audit.list.
type AuditEntry struct {
	ID      int64  `json:"id"`
	At      int64  `json:"at"`
	Actor   string `json:"actor"`
	Action  string `json:"action"`
	Subject string `json:"subject"`
	Detail  string `json:"detail"`
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

	// The System menu's monitors.
	Metrics(ctx context.Context) (Metrics, error)
	AuditLog(ctx context.Context) ([]AuditEntry, error)
	Logins(ctx context.Context) (Logins, error)
	Ports(ctx context.Context) ([]Port, error)

	// The panel's preferences, kept by the daemon.
	Prefs(ctx context.Context) (Prefs, error)
	SetPrefs(ctx context.Context, p Prefs) error
}

// Run shows the TUI until the user quits or ctx ends. version is the panel's
// own, for About; the daemon reports its own in the status.
//
// The screen is QML (qml/Main.qml and the folders beside it): this package
// builds no widget. It publishes the routes and the status as the App
// singleton's sources and runs the commands the document invokes
// (commands.go).
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
	p, err := tuidecl.NewProgram(h.options(func(err error) { h.say(h.trf("autopanel.notice.error", err.Error())) }, tui.WithBackend(backend))...)
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
		return w.tr("autopanel.ca.short.staging")
	case certmagic.LetsEncryptProductionCA:
		return w.tr("autopanel.ca.short.production")
	case "":
		return "-"
	}
	return ca
}

// statusLine is the status bar's summary of s.
func statusLine(w wording, s Status) string {
	return w.trf("autopanel.status.line", orDash(s.Version), shortCA(w, s.CA), s.Routes, orDash(s.Uptime))
}

// caNote says what a certificate service's certificates are good for, for the
// overview.
func caNote(w wording, ca string) string {
	switch strings.TrimSpace(ca) {
	case certmagic.LetsEncryptStagingCA:
		return w.tr("autopanel.ca.note.staging")
	case certmagic.LetsEncryptProductionCA:
		return w.tr("autopanel.ca.note.production")
	case "":
		return "-"
	}
	return ca
}

// overview is the main screen's rows: the running AutoPanel, a fact per row,
// each a name and its value.
func overview(w wording, s Status) [][2]string {
	return [][2]string{
		{w.tr("autopanel.overview.version"), orDash(s.Version)},
		{w.tr("autopanel.overview.https"), orDash(s.HTTPS)},
		{w.tr("autopanel.overview.http"), w.trf("autopanel.overview.httpNote", orDash(s.HTTP))},
		{w.tr("autopanel.overview.store"), orDash(s.Store)},
		{w.tr("autopanel.overview.certificates"), caNote(w, s.CA)},
		{w.tr("autopanel.overview.challenge"), orDash(s.Challenge)},
		{w.tr("autopanel.overview.routes"), strconv.Itoa(s.Routes)},
		{w.tr("autopanel.overview.uptime"), orDash(s.Uptime)},
	}
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
