// Package ui is AutoPanel's admin TUI: the proxy routes in a table, with a
// form to add or edit one and a confirmation to remove one, over a Client
// that talks to the daemon. The panel keeps no state of its own: every change
// goes through the Client, and the routes and status are read again after it.
package ui

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/caddyserver/certmagic"
	"github.com/yongjohnlee80/golib/tui"
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
}

// Run shows the TUI until the user quits or ctx ends.
func Run(ctx context.Context, c Client) error {
	if c == nil {
		return errors.New("ui: nil client")
	}
	backend, err := term.Open()
	if err != nil {
		return fmt.Errorf("ui: cannot open the terminal: %w", err)
	}
	return run(ctx, c, tui.WithBackend(backend))
}

// run is Run on any backend: the tests drive it on tui.TestBackend.
func run(ctx context.Context, c Client, opts ...tui.AppOption) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	p := newPanel(c, cancel)
	app := tui.NewApp(p, append([]tui.AppOption{tui.WithQuit(cancel)}, opts...)...)
	return app.Run(ctx)
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

// statusLine is the status bar's summary of s.
func statusLine(s Status) string {
	or := func(v string) string {
		if v == "" {
			return "-"
		}
		return v
	}
	return fmt.Sprintf("%s · https %s · http %s · store %s · CA %s · %s · %d routes · up %s",
		or(s.Version), or(s.HTTPS), or(s.HTTP), or(s.Store), shortCA(s.CA), or(s.Challenge), s.Routes, or(s.Uptime))
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
