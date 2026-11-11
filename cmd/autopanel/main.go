// Command autopanel is AutoPanel's one binary: the daemon, its CLI and its
// admin TUI (see app.Main).
package main

import (
	"os"

	"github.com/yongjohnlee80/autopanel/app"
)

func main() { os.Exit(app.Main(os.Args[1:], os.Stdout, os.Stderr)) }
