// Command autopanel-agent is the far end of an AutoPanel tunnel: it runs on a
// machine with no open port, dials AutoPanel's gate, and serves the services
// its own file names (see internal/agent).
package main

import (
	"os"

	"github.com/yongjohnlee80/autopanel/internal/agent"
)

// version is set at build time (-ldflags "-X main.version=…").
var version = "dev"

func main() { os.Exit(agent.Main(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, version)) }
