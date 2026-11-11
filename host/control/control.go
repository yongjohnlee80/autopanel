// Package control is the control-plane host: msgpack-RPC on a private unix
// socket. The OS identifies the peer, so there is no login: a connection from
// another user is dropped at accept, and the directory holding the socket must
// be the owner's alone (R18). The CLI and the admin TUI are its clients.
package control

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"

	"github.com/yongjohnlee80/golib/msgpack"
	"github.com/yongjohnlee80/golib/server/rpc"
	"github.com/yongjohnlee80/golib/server/rpc/msgpackrpc"

	"github.com/yongjohnlee80/autopanel/core/audit"
	"github.com/yongjohnlee80/autopanel/internal/module"
	"github.com/yongjohnlee80/autopanel/internal/peercred"
)

// Server serves every module's verbs on the socket.
type Server struct {
	rpc  *rpc.Server
	path string
}

// Listen binds the socket at path. Its directory must be private (CheckDir);
// a socket left by a crashed run is replaced, a live one is refused.
func Listen(path string, log *slog.Logger, mods ...module.Module) (*Server, error) {
	if err := peercred.CheckDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	if c, err := net.Dial("unix", path); err == nil {
		_ = c.Close()
		return nil, fmt.Errorf("control: %s is in use by a running AutoPanel", path)
	}
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return nil, err
	}
	refused := func(err error) { log.Warn("control: refused a connection", "err", err) }
	srv := rpc.New(msgpackrpc.New(msgpack.DefaultLimits()), rpc.WithListener(peercred.Listener(ln, refused)))
	actor := "local:" + strconv.Itoa(os.Getuid()) // peercred admits only our own user
	seen := map[string]bool{}
	for _, m := range mods {
		errs := m.Errors()
		for _, v := range m.Verbs() {
			if seen[v.Verb] {
				_ = ln.Close()
				return nil, fmt.Errorf("control: verb %s is registered twice", v.Verb)
			}
			seen[v.Verb] = true
			srv.Handle(v.Verb, handler(v, errs, actor, log))
		}
	}
	return &Server{rpc: srv, path: path}, nil
}

// handler adapts a verb to the wire: the caller is named for the audit log, a
// declared error crosses with its code and message, and any other error
// crosses as a bare internal error (R13), its detail kept in the log.
func handler(v module.Verb, errs []module.PublicError, actor string, log *slog.Logger) rpc.Handler {
	return func(ctx context.Context, req *rpc.Request) (any, error) {
		res, err := v.Call(audit.WithActor(ctx, actor), req.Params)
		if err == nil {
			return res, nil
		}
		if errors.Is(err, module.ErrInvalidParams) {
			return nil, &rpc.Error{Code: rpc.CodeInvalidParams, Message: err.Error()}
		}
		if pe, ok := module.Public(err, errs); ok {
			return nil, &rpc.Error{Code: pe.Code, Message: pe.Message}
		}
		log.Error("control: verb failed", "verb", v.Verb, "err", err)
		return nil, err
	}
}

// Run serves until ctx ends, then drains and removes the socket.
func (s *Server) Run(ctx context.Context) error {
	defer os.Remove(s.path)
	return s.rpc.Run(ctx)
}

// Client calls verbs on a running AutoPanel's socket.
type Client struct{ c *rpc.Client }

// Dial connects to the socket; it refuses a server run by another user.
func Dial(ctx context.Context, path string) (*Client, error) {
	c, err := rpc.Dial(ctx, path, msgpackrpc.New(nil), rpc.ClientNetwork("unix"), rpc.WithConnDialer(peercred.Dial))
	if err != nil {
		return nil, err
	}
	return &Client{c: c}, nil
}

// Call calls verb with at most one param and decodes the result into out
// (nil to drop it).
func (c *Client) Call(ctx context.Context, verb string, param any, out any) error {
	var params []any
	if param != nil {
		w, err := module.Wire(param)
		if err != nil {
			return err
		}
		params = []any{w}
	}
	res, err := c.c.Call(ctx, verb, params...)
	if err != nil || out == nil {
		return err
	}
	return module.Decode(res, out)
}

// Close closes the connection.
func (c *Client) Close() error { return c.c.Close() }
