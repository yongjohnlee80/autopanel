// Package ui is AutoPanel's admin TUI: a menu bar over an overview of the
// running AutoPanel, with a status bar beneath. The menus open the panel's
// parts: the proxy routes in a manager, with a form to add or edit one and a
// confirmation to remove one; the certificate service; About. All of it is
// over a Client that talks to the daemon. The panel keeps no state of its
// own: every change goes through the Client, and the routes and status are
// read again after it.
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

// Client is everything the TUI may do.
type Client interface {
	Routes(ctx context.Context) ([]gate.RouteView, error)
	Status(ctx context.Context) (Status, error)
	Add(ctx context.Context, s gate.RouteSpec) error
	Update(ctx context.Context, s gate.RouteSpec) error
	Remove(ctx context.Context, id int64) error
	// SetCA chooses the certificate service: "staging" or "production".
	SetCA(ctx context.Context, ca string) error
}

// Run shows the TUI until the user quits or ctx ends. version is the panel's
// own, for About; the daemon reports its own in the status.
//
// The screen is QML (qml/Main.qml, qml/dialogs and qml/views): this package
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
	p, err := tuidecl.NewProgram(h.options(func(err error) { h.say("error: " + err.Error()) }, tui.WithBackend(backend))...)
	if err != nil {
		return fmt.Errorf("ui: %w", err)
	}
	h.attach(p)
	return p.Run(ctx)
}

// shortCA names an ACME directory for the status bar: Let's Encrypt's two by
// name, any other by its URL.
func shortCA(ca string) string {
	switch strings.TrimSpace(ca) {
	case certmagic.LetsEncryptStagingCA:
		return "LE staging"
	case certmagic.LetsEncryptProductionCA:
		return "LE production"
	case "":
		return "-"
	}
	return ca
}

// orDash is v, or "-" for nothing to show.
func orDash(v string) string {
	if strings.TrimSpace(v) == "" {
		return "-"
	}
	return v
}

// statusLine is the status bar's summary of s.
func statusLine(s Status) string {
	return fmt.Sprintf("%s · CA %s · %d routes · up %s", orDash(s.Version), shortCA(s.CA), s.Routes, orDash(s.Uptime))
}

// caNote says what a certificate service's certificates are good for, for the
// overview.
func caNote(ca string) string {
	switch strings.TrimSpace(ca) {
	case certmagic.LetsEncryptStagingCA:
		return "Let's Encrypt staging: test certificates, which browsers do not trust. Switch in Certs → Type."
	case certmagic.LetsEncryptProductionCA:
		return "Let's Encrypt production: real certificates, trusted by browsers."
	case "":
		return "-"
	}
	return ca
}

// overview is the main screen's text: the running AutoPanel, a line per fact.
func overview(s Status) string {
	rows := [][2]string{
		{"Version", orDash(s.Version)},
		{"HTTPS", orDash(s.HTTPS)},
		{"HTTP", orDash(s.HTTP) + " (certificate checks, and the redirect to HTTPS)"},
		{"Store", orDash(s.Store)},
		{"Certificates", caNote(s.CA)},
		{"Challenge", orDash(s.Challenge)},
		{"Routes", strconv.Itoa(s.Routes)},
		{"Uptime", orDash(s.Uptime)},
	}
	var b strings.Builder
	for _, r := range rows {
		fmt.Fprintf(&b, "%-14s%s\n", r[0], r[1])
	}
	b.WriteString("\nMenus: Alt and the menu's letter, or F10. r refreshes, q quits.")
	return b.String()
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
