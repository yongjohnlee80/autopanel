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
