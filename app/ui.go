package app

import (
	"context"
	"fmt"
	"io"

	"github.com/yongjohnlee80/autopanel/core/gate"
	hostcontrol "github.com/yongjohnlee80/autopanel/host/control"
	"github.com/yongjohnlee80/autopanel/internal/ui"
)

// uiClient is the TUI's Client over the control socket: every call is a verb,
// on a connection already logged in.
type uiClient struct{ c *hostcontrol.Client }

func (u uiClient) Routes(ctx context.Context) ([]gate.RouteView, error) {
	var rs []gate.RouteView
	return rs, u.c.Call(ctx, "gate.route.list", nil, &rs)
}

func (u uiClient) Status(ctx context.Context) (ui.Status, error) {
	var s ui.Status
	return s, u.c.Call(ctx, "sys.status", nil, &s)
}

func (u uiClient) Add(ctx context.Context, s gate.RouteSpec) error {
	return u.c.Call(ctx, "gate.route.add", s, nil)
}

func (u uiClient) Update(ctx context.Context, s gate.RouteSpec) error {
	return u.c.Call(ctx, "gate.route.update", s, nil)
}

func (u uiClient) Remove(ctx context.Context, id int64) error {
	return u.c.Call(ctx, "gate.route.remove", gate.RouteRef{ID: id}, nil)
}

func (u uiClient) SetCA(ctx context.Context, ca string) error {
	return u.c.Call(ctx, "certs.ca.set", CA{CA: ca}, nil)
}

func (u uiClient) Metrics(ctx context.Context) (ui.Metrics, error) {
	var m ui.Metrics
	return m, u.c.Call(ctx, "sys.metrics", nil, &m)
}

func (u uiClient) AuditLog(ctx context.Context) ([]ui.AuditEntry, error) {
	var es []ui.AuditEntry
	return es, u.c.Call(ctx, "sys.audit.list", nil, &es)
}

func (u uiClient) Logins(ctx context.Context) (ui.Logins, error) {
	var l ui.Logins
	return l, u.c.Call(ctx, "sys.logins", nil, &l)
}

func (u uiClient) Ports(ctx context.Context) ([]ui.Port, error) {
	var ps []ui.Port
	return ps, u.c.Call(ctx, "sys.ports", nil, &ps)
}

func (u uiClient) Prefs(ctx context.Context) (ui.Prefs, error) {
	var p ui.Prefs
	return p, u.c.Call(ctx, "sys.prefs.get", nil, &p)
}

func (u uiClient) SetPrefs(ctx context.Context, p ui.Prefs) error {
	return u.c.Call(ctx, "sys.prefs.set", Prefs{Theme: p.Theme, Language: p.Language}, nil)
}

func init() {
	runUI = func(stderr io.Writer) int {
		ctx := context.Background()
		c, err := dial(ctx)
		if err != nil {
			fmt.Fprintf(stderr, "connecting to AutoPanel: %v\n", err)
			return 1
		}
		defer c.Close()
		if _, err := login(ctx, c); err != nil {
			fmt.Fprintln(stderr, "login:", err)
			return 1
		}
		if err := ui.Run(ctx, uiClient{c}, Version); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	}
}
