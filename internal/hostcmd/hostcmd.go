// Package hostcmd runs the host's own tools for the core. It is the one
// package that imports os/exec, and it runs only the tools it names: a Tool
// cannot be made outside it, so no verb can run a command its caller supplies.
// There is no shell, the environment is fixed, and the output is bounded.
//
// Every argument a caller passes must be built from a value it has already
// validated: a name matching a pattern, a number, or a constant.
package hostcmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os/exec"
	"strings"
	"time"
)

// Tool is one of the host's programs, by absolute path.
type Tool struct{ path string }

// The tools the core may run. The table grows with the verbs that need them.
var (
	Systemctl  = Tool{"/usr/bin/systemctl"}
	Journalctl = Tool{"/usr/bin/journalctl"}
	Loginctl   = Tool{"/usr/bin/loginctl"}
	Useradd    = Tool{"/usr/sbin/useradd"}
	Usermod    = Tool{"/usr/sbin/usermod"}
	Userdel    = Tool{"/usr/sbin/userdel"}
	Pkill      = Tool{"/usr/bin/pkill"}
	Podman     = Tool{"/usr/bin/podman"}
	Runuser    = Tool{"/usr/sbin/runuser"}
)

const (
	// deadline bounds a run whose context has none.
	deadline = 30 * time.Second
	// maxOutput bounds what a run may print before it is cut.
	maxOutput = 4 << 20
)

// ErrNoTool is a tool this host does not have.
var ErrNoTool = errors.New("hostcmd: the host has no such tool")

// Run runs tool with args and returns what it printed. A failed run's error
// carries the tool's own message.
func Run(ctx context.Context, tool Tool, args ...string) ([]byte, error) {
	if tool.path == "" {
		return nil, ErrNoTool
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, deadline)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, tool.path, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	var out, errOut bounded
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	switch {
	case err == nil:
		return out.Bytes(), nil
	case errors.Is(err, exec.ErrNotFound) || errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("%w: %s", ErrNoTool, tool.path)
	}
	msg := strings.TrimSpace(errOut.String())
	if len(msg) > 300 {
		msg = msg[:300]
	}
	if msg == "" {
		return out.Bytes(), fmt.Errorf("%s: %w", tool.path, err)
	}
	return out.Bytes(), fmt.Errorf("%s: %w: %s", tool.path, err, msg)
}

// ExitCode is the code a failed run's tool exited with; ok is false for an
// error that is not a tool's own exit.
func ExitCode(err error) (code int, ok bool) {
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), true
	}
	return 0, false
}

// bounded keeps the first maxOutput bytes written to it and drops the rest.
type bounded struct{ bytes.Buffer }

func (b *bounded) Write(p []byte) (int, error) {
	if room := maxOutput - b.Len(); room > 0 {
		if len(p) > room {
			b.Buffer.Write(p[:room])
		} else {
			b.Buffer.Write(p)
		}
	}
	return len(p), nil
}
