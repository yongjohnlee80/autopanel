// Package control is the control-plane host: msgpack-RPC on a private unix
// socket. The OS identifies the peer: a connection from a user the socket does
// not name is dropped at accept, and the directory holding the socket must be
// one no other user can write (R18). The core serves two such sockets: the
// control socket, for the CLI and the admin TUI, and the link socket, for the
// gate process alone.
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

// InUse reports whether a running AutoPanel answers on the socket at path.
func InUse(path string) bool {
	c, err := net.Dial("unix", path)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// Access says who may connect to a socket.
type Access struct {
	// Peers are the users whose processes may connect. Empty means this
	// process's own user.
	Peers []int
	// Mode is the socket file's mode. Zero means 0600; a socket for another
	// user's process is 0660, in a directory only its group can enter.
	Mode os.FileMode
	// Concurrent bounds the calls one connection runs at once. Zero means
	// golib's default (8); a socket with a long-poll verb needs more.
	Concurrent int
}

func (a Access) peers() []int {
	if len(a.Peers) == 0 {
		return []int{os.Getuid()}
	}
	return a.Peers
}

// Listen binds the socket at path for the peers acc names. Its directory must
// be one no other user can write (CheckDir); a socket left by a crashed run is
// replaced, a live one is refused.
func Listen(path string, log *slog.Logger, acc Access, mods ...module.Module) (*Server, error) {
	if err := peercred.CheckDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	if InUse(path) {
		return nil, fmt.Errorf("control: %s is in use by a running AutoPanel", path)
	}
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	mode := acc.Mode
	if mode == 0 {
		mode = 0o600
	}
	if err := os.Chmod(path, mode); err != nil {
		_ = ln.Close()
		return nil, err
	}
	refused := func(err error) { log.Warn("control: refused a connection", "socket", path, "err", err) }
	opts := []rpc.Option{
		rpc.WithListener(peercred.ListenerFor(ln, peercred.Allow(acc.peers()...), refused)),
		// The peer's user, from the kernel's record: what the audit log names.
		rpc.WithSessionAttach(func(nc net.Conn) any { return "local:" + strconv.Itoa(peercred.PeerUID(nc)) }),
	}
	if acc.Concurrent > 0 {
		opts = append(opts, rpc.MaxConcurrent(acc.Concurrent))
	}
	srv := rpc.New(msgpackrpc.New(msgpack.DefaultLimits()), opts...)
	seen := map[string]bool{}
	for _, m := range mods {
		errs := m.Errors()
		for _, v := range m.Verbs() {
			if seen[v.Verb] {
				_ = ln.Close()
				return nil, fmt.Errorf("control: verb %s is registered twice", v.Verb)
			}
			seen[v.Verb] = true
			srv.Handle(v.Verb, handler(v, errs, log))
		}
	}
	return &Server{rpc: srv, path: path}, nil
}

// sessionUser is the session value a successful login sets.
const sessionUser = "autopanel.user"

// handler adapts a verb to the wire. Every verb but an open one needs a
// logged-in connection; the caller is named for the audit log, by the user the
// kernel says is at the other end; a declared error crosses
// with its code and message, and any other error crosses as a bare internal
// error (R13), its detail kept in the log.
func handler(v module.Verb, errs []module.PublicError, log *slog.Logger) rpc.Handler {
	return func(ctx context.Context, req *rpc.Request) (any, error) {
		local, _ := req.Session.Attachment().(string)
		actor := local
		user, _ := req.Session.Value(sessionUser).(string)
		switch {
		case user != "":
			actor = user + " (" + local + ")"
		case !v.Open:
			return nil, &rpc.Error{Code: rpc.CodeAccessDenied, Message: "log in first (auth.login)"}
		}
		res, err := v.Call(audit.WithActor(ctx, actor), req.Params)
		if err == nil {
			if v.Login {
				if m, ok := res.(map[string]any); ok {
					if u, ok := m["user"].(string); ok && u != "" {
						req.Session.SetValue(sessionUser, u)
					}
				}
			}
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

// Dial connects to the socket; it refuses a server run by a user other than
// servers name. With none named, the server must run as this process's user.
func Dial(ctx context.Context, path string, servers ...int) (*Client, error) {
	if len(servers) == 0 {
		servers = []int{os.Getuid()}
	}
	c, err := rpc.Dial(ctx, path, msgpackrpc.New(nil), rpc.ClientNetwork("unix"),
		rpc.WithConnDialer(peercred.DialFor(peercred.Allow(servers...))))
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
