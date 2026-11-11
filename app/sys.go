package app

import (
	"context"
	"net/http"
	"time"

	"github.com/yongjohnlee80/autopanel/core/gate"
	"github.com/yongjohnlee80/autopanel/internal/module"
)

// Version is set at build time (-ldflags "-X …/app.Version=…").
var Version = "dev"

// sysModule is the sys.* verbs: what the TUI's status bar shows.
type sysModule struct {
	cfg       Config
	table     *gate.Table[http.Handler]
	engine    string
	started   time.Time
	challenge func() string
	ca        func() string // the ACME directory in use: the panel's choice, or the configuration's
}

// Status is sys.status's answer.
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

func (m *sysModule) Name() string                 { return "sys" }
func (m *sysModule) Errors() []module.PublicError { return nil }

func (m *sysModule) Verbs() []module.Verb {
	return []module.Verb{module.Handle(module.Contract{Verb: "sys.status", Since: 1,
		Result: "{version, https, http, store, ca, challenge, routes, uptime}",
		Doc:    "The running AutoPanel: its listeners, store, certificate issuer and route count."}, m.status)}
}

func (m *sysModule) status(context.Context, struct{}) (Status, error) {
	return Status{Version: Version, HTTPS: m.cfg.HTTPSAddr, HTTP: m.cfg.HTTPAddr, Store: m.engine, CA: m.ca(),
		Challenge: m.challenge(), Routes: len(m.table.Routes()), Uptime: time.Since(m.started).Round(time.Second).String()}, nil
}
