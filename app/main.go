// Package app is AutoPanel's modes as one function: --serve runs the daemon,
// --call calls one verb on it, --ui opens the admin TUI, --contracts prints
// every verb's contract with no daemon.
package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"time"

	"github.com/yongjohnlee80/autopanel/core/gate"
	hostcontrol "github.com/yongjohnlee80/autopanel/host/control"
	"github.com/yongjohnlee80/autopanel/internal/auth"
	"github.com/yongjohnlee80/autopanel/internal/module"
)

const usage = `usage:
  autopanel --init [--user root]    make the root user, the master key and the service keyfile;
                                    the master passphrase is read from stdin (install.sh does this)
  autopanel --serve                 run the daemon (configured from AUTOPANEL_* environment variables)
  autopanel --call <verb> [json]    call one verb on the running daemon and print its JSON answer
  autopanel --ui                    open the admin TUI on the running daemon
  autopanel --contracts             print every verb's contract (no daemon needed)
  autopanel --version
`

// Main runs one mode and returns the process's exit code.
func Main(args []string, stdout, stderr io.Writer) int {
	log := slog.New(slog.NewTextHandler(stderr, nil))
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "--version":
		fmt.Fprintln(stdout, "autopanel", Version)
		return 0
	case "--contracts":
		return printContracts(stdout)
	case "--init":
		user := "root"
		if len(args) == 3 && args[1] == "--user" {
			user = args[2]
		} else if len(args) != 1 {
			fmt.Fprint(stderr, usage)
			return 2
		}
		cfg, err := LoadConfig()
		if err == nil {
			err = Init(context.Background(), cfg, user, os.Stdin)
		}
		if err != nil {
			fmt.Fprintln(stderr, "autopanel --init:", err)
			return 1
		}
		fmt.Fprintf(stdout, "initialized: user %q, master key sealed; keyfile %s\n", user, cfg.Keyfile)
		return 0
	case "--serve":
		cfg, err := LoadConfig()
		if err == nil {
			err = Serve(cfg, log)
		}
		if err != nil {
			log.Error("autopanel stopped", "err", err)
			return 1
		}
		return 0
	case "--call":
		if len(args) < 2 || len(args) > 3 {
			fmt.Fprint(stderr, usage)
			return 2
		}
		return call(args[1], args[2:], stdout, stderr)
	case "--ui":
		return runUI(stderr)
	default:
		fmt.Fprint(stderr, usage)
		return 2
	}
}

// contractModules are the modules whose verbs --contracts lists. Built with no
// store: a contract is data, and listing one runs nothing.
func contractModules() []module.Module {
	return []module.Module{&auth.Module{}, gate.NewModule(nil, nil), &certsModule{}, &sysModule{}}
}

func printContracts(stdout io.Writer) int {
	var cs []module.Contract
	for _, m := range contractModules() {
		for _, v := range m.Verbs() {
			cs = append(cs, v.Contract)
		}
	}
	sort.Slice(cs, func(i, j int) bool { return cs[i].Verb < cs[j].Verb })
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(cs); err != nil {
		return 1
	}
	return 0
}

func dial(ctx context.Context) (*hostcontrol.Client, error) {
	cfg, err := LoadConfig()
	if err != nil {
		return nil, err
	}
	return hostcontrol.Dial(ctx, cfg.Socket)
}

func call(verb string, rest []string, stdout, stderr io.Writer) int {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute) // the login prompt is inside it
	defer cancel()
	var param any
	if len(rest) == 1 {
		if err := json.Unmarshal([]byte(rest[0]), &param); err != nil {
			fmt.Fprintf(stderr, "the param is not JSON: %v\n", err)
			return 2
		}
	}
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
	var out any
	if err := c.Call(ctx, verb, param, &out); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
	return 0
}

// runUI opens the admin TUI (ui.go).
var runUI func(stderr io.Writer) int
