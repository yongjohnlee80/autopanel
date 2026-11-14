package app

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/yongjohnlee80/autopanel/core/gate"
	"github.com/yongjohnlee80/autopanel/internal/module"
	"github.com/yongjohnlee80/autopanel/internal/sysinfo"
	"github.com/yongjohnlee80/autopanel/store"
)

// Version is set at build time (-ldflags "-X …/app.Version=…").
var Version = "dev"

// sysModule is the sys.* verbs: what the panel's status bar and its System
// menu show (monitor.go).
type sysModule struct {
	cfg       Config
	table     *gate.Table[http.Handler]
	engine    string
	started   time.Time
	challenge func() string
	ca        func() string // the ACME directory in use: the panel's choice, or the configuration's

	st     *store.Store
	log    *slog.Logger
	counts *counters
	// The host reads, as fields so a test gives its own.
	listeners func(ctx context.Context) ([]sysinfo.Listener, error)
	sshLogins func(ctx context.Context, limit int) ([]sysinfo.SSHLogin, error)
	// gate runs the gate process's unit; nil when this core does not (a
	// development run).
	gate GateControl
	// serviceUsers are the deployed services' host users, each with its
	// service's name; nil when this core deploys none.
	serviceUsers func(ctx context.Context) (map[string]string, error)
	// sampler answers each metrics read with the host's rates since the read
	// before it, whoever made that one.
	sampler *sysinfo.Sampler
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

func (m *sysModule) Name() string { return "sys" }

func (m *sysModule) Errors() []module.PublicError {
	return []module.PublicError{
		{Err: errBadPref, Code: -32180, Name: "sys.bad_preference", Message: "a preference is a name of letters, digits and underscores"},
		{Err: sysinfo.ErrUnsupported, Code: -32181, Name: "sys.unsupported", Message: "this host has no source for it"},
		{Err: errNoGateControl, Code: -32182, Name: "sys.no_gate_control", Message: "this core does not run the gate's unit; start and stop the gate by hand"},
		{Err: errGateControl, Code: -32183, Name: "sys.gate_control_failed", Message: "the gate's unit did not do it; the core's log says why"},
	}
}

func (m *sysModule) Verbs() []module.Verb {
	return append([]module.Verb{module.Handle(module.Contract{Verb: "sys.status", Since: 1,
		Result: "{version, https, http, store, ca, challenge, routes, uptime}",
		Doc:    "The running AutoPanel: its listeners, store, certificate issuer and route count."}, m.status)}, m.monitorVerbs()...)
}

func (m *sysModule) status(context.Context, struct{}) (Status, error) {
	return Status{Version: Version, HTTPS: m.cfg.HTTPSAddr, HTTP: m.cfg.HTTPAddr, Store: m.engine, CA: m.ca(),
		Challenge: m.challenge(), Routes: len(m.table.Routes()), Uptime: time.Since(m.started).Round(time.Second).String()}, nil
}
