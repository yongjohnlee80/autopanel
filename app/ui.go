package app

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/yongjohnlee80/golib/server/rpc"

	"github.com/yongjohnlee80/autopanel/core/gate"
	"github.com/yongjohnlee80/autopanel/core/services"
	hostcontrol "github.com/yongjohnlee80/autopanel/host/control"
	"github.com/yongjohnlee80/autopanel/internal/auth"
	"github.com/yongjohnlee80/autopanel/internal/ui"
)

// uiClient is the TUI's Client over the control socket: every call is a verb.
// The panel's login dialog logs the connection in (Login); until then the
// service refuses every other verb.
type uiClient struct{ c *hostcontrol.Client }

func (u uiClient) Login(ctx context.Context, user, passphrase string) error {
	return u.c.Call(ctx, "auth.login", auth.Login{User: user, Passphrase: passphrase}, nil)
}

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

func (u uiClient) Stacks(ctx context.Context) ([]services.View, error) {
	var vs []services.View
	return vs, u.c.Call(ctx, "services.list", nil, &vs)
}

func (u uiClient) AvailableStacks(ctx context.Context) ([]services.Folder, error) {
	var fs []services.Folder
	return fs, u.c.Call(ctx, "services.available", nil, &fs)
}

func (u uiClient) CheckStack(ctx context.Context, name string) (services.Review, error) {
	var r services.Review
	return r, u.c.Call(ctx, "services.check", services.Ref{Name: name}, &r)
}

// changedCode is the wire code of services.changed.
var changedCode = func() int64 {
	for _, e := range (&services.Module{}).Errors() {
		if e.Err == services.ErrChanged {
			return e.Code
		}
	}
	return 0
}()

func (u uiClient) ApplyStack(ctx context.Context, verb, name, accept string) error {
	switch verb {
	case "prepare", "add", "apply":
	default:
		return fmt.Errorf("no apply verb %q", verb)
	}
	err := u.c.Call(ctx, "services."+verb, services.Accept{Name: name, Accept: accept}, nil)
	// The panel reviews the definition again on this one, so it is named.
	var re *rpc.Error
	if errors.As(err, &re) && re.Code == changedCode {
		return fmt.Errorf("%w (%s)", services.ErrChanged, re.Message)
	}
	return err
}

func (u uiClient) PullStack(ctx context.Context, name, service string) error {
	return u.c.Call(ctx, "services.pull", services.Ref{Name: name, Service: service}, nil)
}

func (u uiClient) StackUnit(ctx context.Context, action, name, service string) error {
	switch action {
	case "start", "stop", "restart":
		return u.c.Call(ctx, "services."+action, services.Ref{Name: name, Service: service}, nil)
	}
	return fmt.Errorf("no unit action %q", action)
}

func (u uiClient) RemoveStack(ctx context.Context, name string, purge bool) error {
	return u.c.Call(ctx, "services.remove", services.Remove{Name: name, Purge: purge}, nil)
}

func (u uiClient) StackLogs(ctx context.Context, name, service string) ([]string, error) {
	var l services.Logs
	return l.Lines, u.c.Call(ctx, "services.logs", services.LogsAsk{Name: name, Service: service}, &l)
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
		if err := ui.Run(ctx, uiClient{c}, Version); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	}
}
