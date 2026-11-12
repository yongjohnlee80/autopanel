package services

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/yongjohnlee80/autopanel/internal/module"
)

// State is where a service's deployment got to. Whether it is running is the
// host's to say, and is read when asked, never kept.
type State string

const (
	// Deploying is a service whose row is written and whose user, files or
	// unit may not be: a deploy that was interrupted leaves it, and remove
	// clears it.
	Deploying State = "deploying"
	Deployed  State = "deployed"
	Removing  State = "removing"
)

// Service is a deployed service as the store keeps it: what was asked for.
type Service struct {
	Name     string
	Template string
	Options  map[string]string
	State    State
}

// Store is where services are kept.
type Store interface {
	All(ctx context.Context) ([]Service, error)
	Get(ctx context.Context, name string) (Service, error) // ErrNotFound
	Add(ctx context.Context, s Service) error              // ErrDuplicate
	SetOptions(ctx context.Context, name string, options map[string]string) error
	SetState(ctx context.Context, name string, state State) error
	Remove(ctx context.Context, name string) error
}

// Secrets keeps a service's generated secrets, sealed.
type Secrets interface {
	Get(ctx context.Context, name string) (value []byte, ok bool, err error)
	Put(ctx context.Context, name string, value []byte) error
	Delete(ctx context.Context, name string) error
}

// Unit is a service as the host installs it: its name, and the files of its
// directory, the Podman unit file among them.
type Unit struct {
	Name  string
	Files []File
}

// Running is a service's unit as systemd reports it.
type Running struct {
	Active      string `json:"active"` // "active", "activating", "failed", "inactive"; "absent" with no user or unit
	Sub         string `json:"sub"`
	MemoryBytes uint64 `json:"memory_bytes"`
}

// Host is the machine the services run on. Every method names a service by a
// name the module has validated; none takes a command.
type Host interface {
	// Podman is the host's Podman version, or ErrNoPodman.
	Podman(ctx context.Context) (major, minor int, err error)
	// Install makes the service's user and directory when they are missing,
	// writes its files, and has the user's systemd read the unit. It is safe
	// to run again.
	Install(ctx context.Context, u Unit) error
	Start(ctx context.Context, name string) error
	Stop(ctx context.Context, name string) error
	Restart(ctx context.Context, name string) error
	// Uninstall stops the unit and deletes the user; with purge, its
	// directory too. Each step tolerates the one before having already
	// happened.
	Uninstall(ctx context.Context, name string, purge bool) error
	Running(ctx context.Context, name string) (Running, error)
	Logs(ctx context.Context, name string, limit int) ([]string, error)
}

var (
	ErrNoTemplate = errors.New("services: no such template")
	ErrNotFound   = errors.New("services: no such service")
	ErrDuplicate  = errors.New("services: a service of this name exists")
	ErrPortTaken  = errors.New("services: another service has the port")
	ErrNoPodman   = errors.New("services: the host has no Podman")
	ErrOldPodman  = errors.New("services: the host's Podman is older than 4.4")
	ErrNoSecret   = errors.New("services: the service has no such secret")
	ErrBusy       = errors.New("services: the service is being removed")
)

// Module is the services.* verbs.
type Module struct {
	templates map[string]Template
	store     Store
	secrets   Secrets
	host      Host
	// mu orders the verbs that change a service: two deploys of one name, or
	// a remove under an update, would otherwise interleave on the host.
	mu sync.Mutex
}

// NewModule returns the verbs over the built-in templates.
func NewModule(store Store, secrets Secrets, host Host) *Module {
	return &Module{templates: map[string]Template{TURN.Name: TURN}, store: store, secrets: secrets, host: host}
}

func (m *Module) Name() string { return "services" }

func (m *Module) Errors() []module.PublicError {
	return []module.PublicError{
		{Err: ErrNoTemplate, Code: -32190, Name: "services.no_template", Message: "no such template"},
		{Err: ErrNotFound, Code: -32191, Name: "services.not_found", Message: "no such service"},
		{Err: ErrDuplicate, Code: -32192, Name: "services.duplicate", Message: "a service of this name exists"},
		{Err: ErrBadName, Code: -32193, Name: "services.bad_name", Message: "a service name is a lower-case letter, then letters, digits and hyphens, 29 characters at most"},
		{Err: ErrBadOption, Code: -32194, Name: "services.bad_option", Message: "an option was refused"},
		{Err: ErrPortTaken, Code: -32195, Name: "services.port_taken", Message: "another service has the port"},
		{Err: ErrNoPodman, Code: -32196, Name: "services.no_podman", Message: "the host has no Podman; install it (4.4 or newer) to deploy a service"},
		{Err: ErrOldPodman, Code: -32197, Name: "services.old_podman", Message: "the host's Podman is older than 4.4, which deploying a service needs"},
		{Err: ErrNoSecret, Code: -32198, Name: "services.no_secret", Message: "the service has no such secret"},
		{Err: ErrBusy, Code: -32199, Name: "services.busy", Message: "the service is being removed"},
	}
}

// TemplateView is a template as a client sees it.
type TemplateView struct {
	Name    string   `json:"name"`
	Title   string   `json:"title"`
	Image   string   `json:"image"`
	Network Network  `json:"network"`
	Memory  string   `json:"memory"`
	Options []Option `json:"options"`
	Secrets []string `json:"secrets"`
}

// View is a service as a client sees it: what was asked for, and what the
// host says is running.
type View struct {
	Name     string            `json:"name"`
	Template string            `json:"template"`
	Options  map[string]string `json:"options"`
	State    State             `json:"state"`
	User     string            `json:"user"`
	Ports    []PortUse         `json:"ports"`
	Running
}

// Deploy is services.deploy's param.
type Deploy struct {
	Template string            `json:"template"`
	Name     string            `json:"name,omitempty"`
	Options  map[string]string `json:"options,omitempty"`
}

// Update is services.update's param.
type Update struct {
	Name    string            `json:"name"`
	Options map[string]string `json:"options,omitempty"`
}

// Ref names one service.
type Ref struct {
	Name string `json:"name"`
}

// Remove is services.remove's param.
type Remove struct {
	Name  string `json:"name"`
	Purge bool   `json:"purge,omitempty"`
}

// LogsAsk is services.logs's param.
type LogsAsk struct {
	Name  string `json:"name"`
	Limit int    `json:"limit,omitempty"`
}

// Logs is services.logs's answer.
type Logs struct {
	Lines []string `json:"lines"`
}

// SecretAsk is services.secret's param.
type SecretAsk struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

// SecretValue is services.secret's answer.
type SecretValue struct {
	Value string `json:"value"`
}

const (
	viewShape = "{name, template, options, state, user, ports: [{proto, from, to}], active, sub, memory_bytes}"
	deploy    = "services.deploy"
)

func (m *Module) Verbs() []module.Verb {
	return []module.Verb{
		module.Handle(module.Contract{Verb: "services.templates", Since: 3,
			Result: "[{name, title, image, network, memory, options: [{key, label, kind, default?, choices?}], secrets}]",
			Doc:    "The kinds of service this AutoPanel can deploy, each with the options its deploy form asks."}, m.listTemplates),
		module.Handle(module.Contract{Verb: "services.list", Since: 3, Result: "[" + viewShape + "]",
			Doc: "Every deployed service: what was asked for, and what the host's systemd says of its unit now."}, m.list),
		module.Handle(module.Contract{Verb: "services.deploy", Since: 3, Param: "{template, name?, options?}", Result: viewShape,
			Mutates: true, Privileged: true, Right: deploy,
			Doc: "Deploys a service from a template: makes its user and directory, writes its configuration and its Podman unit, and starts it. Its image is pulled as it starts, so a new service is activating for a while. Needs Podman 4.4 or newer."}, m.deploy),
		module.Handle(module.Contract{Verb: "services.update", Since: 3, Param: "{name, options?}", Result: viewShape,
			Mutates: true, Privileged: true, Right: deploy,
			Doc: "Changes a service's options and restarts it. An option left out goes back to its default. Its secrets are kept. Also finishes a deploy that was interrupted."}, m.update),
		module.Handle(module.Contract{Verb: "services.start", Since: 3, Param: "{name}", Result: viewShape,
			Mutates: true, Privileged: true, Right: deploy, Doc: "Starts a service's unit."}, m.start),
		module.Handle(module.Contract{Verb: "services.stop", Since: 3, Param: "{name}", Result: viewShape,
			Mutates: true, Privileged: true, Right: deploy, Doc: "Stops a service's unit. It stays stopped until it is started, or the host restarts."}, m.stop),
		module.Handle(module.Contract{Verb: "services.restart", Since: 3, Param: "{name}", Result: viewShape,
			Mutates: true, Privileged: true, Right: deploy, Doc: "Restarts a service's unit."}, m.restart),
		module.Handle(module.Contract{Verb: "services.remove", Since: 3, Param: "{name, purge?}",
			Mutates: true, Privileged: true, Right: deploy,
			Doc: "Stops a service and deletes its unit, its user and its secrets. Its directory is kept, as root's, unless purge says to delete it."}, m.remove),
		module.Handle(module.Contract{Verb: "services.logs", Since: 3, Param: "{name, limit?}", Result: "{lines}",
			Doc: "The newest journal lines of a service's user, oldest first: 100 unless limit says, 500 at most."}, m.logs),
		module.Handle(module.Contract{Verb: "services.secret", Since: 3, Param: "{name, key}", Result: "{value}",
			Privileged: true, Right: deploy,
			Doc: "A secret AutoPanel generated for a service, such as a TURN relay's auth-secret, for the application that needs it. Audited."}, m.secret),
	}
}

func (m *Module) listTemplates(context.Context, struct{}) ([]TemplateView, error) {
	out := make([]TemplateView, 0, len(m.templates))
	for _, t := range m.templates {
		out = append(out, TemplateView{Name: t.Name, Title: t.Title, Image: t.Image, Network: t.Network, Memory: t.Memory,
			Options: t.Options, Secrets: t.Secrets})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// view is s with what the host says of it. A host that cannot say leaves the
// unit "unknown": the row is still worth showing.
func (m *Module) view(ctx context.Context, s Service) View {
	v := View{Name: s.Name, Template: s.Template, Options: s.Options, State: s.State, User: UserOf(s.Name), Ports: []PortUse{}}
	if t, ok := m.templates[s.Template]; ok && t.Ports != nil {
		if vals, err := t.Validate(s.Options); err == nil {
			v.Ports = t.Ports(vals)
		}
	}
	r, err := m.host.Running(ctx, s.Name)
	if err != nil {
		r = Running{Active: "unknown"}
	}
	v.Running = r
	return v
}

func (m *Module) list(ctx context.Context, _ struct{}) ([]View, error) {
	all, err := m.store.All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]View, 0, len(all))
	for _, s := range all {
		out = append(out, m.view(ctx, s))
	}
	return out, nil
}

// Users are the host users of the deployed services, each with its service's
// name: what Open ports names a service's sockets by.
func (m *Module) Users(ctx context.Context) (map[string]string, error) {
	all, err := m.store.All(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(all))
	for _, s := range all {
		out[UserOf(s.Name)] = s.Name
	}
	return out, nil
}

// podman refuses a host that cannot run a service.
func (m *Module) podman(ctx context.Context) error {
	major, minor, err := m.host.Podman(ctx)
	if err != nil {
		return err
	}
	if major < 4 || (major == 4 && minor < 4) {
		return ErrOldPodman
	}
	return nil
}

// free refuses ports that another service has. Whether a process outside
// AutoPanel holds one is for the unit to find when it starts.
func (m *Module) free(ctx context.Context, name string, ports []PortUse) error {
	all, err := m.store.All(ctx)
	if err != nil {
		return err
	}
	for _, s := range all {
		t, ok := m.templates[s.Template]
		if s.Name == name || !ok || t.Ports == nil {
			continue
		}
		vals, err := t.Validate(s.Options)
		if err != nil {
			continue
		}
		if distinct(append(t.Ports(vals), ports...)) != nil {
			return ErrPortTaken
		}
	}
	return nil
}

func (m *Module) deploy(ctx context.Context, p Deploy) (View, error) {
	t, ok := m.templates[p.Template]
	if !ok {
		return View{}, ErrNoTemplate
	}
	name := p.Name
	if name == "" {
		name = t.Name
	}
	if !ValidName(name) {
		return View{}, ErrBadName
	}
	v, err := t.Validate(p.Options)
	if err != nil {
		return View{}, err
	}
	if err := m.podman(ctx); err != nil {
		return View{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.free(ctx, name, t.Ports(v)); err != nil {
		return View{}, err
	}
	// The row first: a crash from here on leaves a row the panel shows and
	// remove clears, never a user or a unit nobody knows about.
	svc := Service{Name: name, Template: t.Name, Options: v.Raw(), State: Deploying}
	if err := m.store.Add(ctx, svc); err != nil {
		return View{}, err
	}
	return m.apply(ctx, t, svc, v)
}

func (m *Module) update(ctx context.Context, p Update) (View, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	svc, t, err := m.known(ctx, p.Name)
	if err != nil {
		return View{}, err
	}
	v, err := t.Validate(p.Options)
	if err != nil {
		return View{}, err
	}
	if err := m.podman(ctx); err != nil {
		return View{}, err
	}
	if err := m.free(ctx, svc.Name, t.Ports(v)); err != nil {
		return View{}, err
	}
	svc.Options, svc.State = v.Raw(), Deploying
	if err := m.store.SetOptions(ctx, svc.Name, svc.Options); err != nil {
		return View{}, err
	}
	if err := m.store.SetState(ctx, svc.Name, Deploying); err != nil {
		return View{}, err
	}
	return m.apply(ctx, t, svc, v)
}

// known is the service name with its template. A service being removed is
// refused: only remove may touch it.
func (m *Module) known(ctx context.Context, name string) (Service, Template, error) {
	if !ValidName(name) {
		return Service{}, Template{}, ErrBadName
	}
	svc, err := m.store.Get(ctx, name)
	if err != nil {
		return Service{}, Template{}, err
	}
	if svc.State == Removing {
		return Service{}, Template{}, ErrBusy
	}
	t, ok := m.templates[svc.Template]
	if !ok {
		return Service{}, Template{}, ErrNoTemplate
	}
	return svc, t, nil
}

// apply makes the host match the row: the user, the files, the unit, a
// restart. It is the same for a first deploy and for an update.
func (m *Module) apply(ctx context.Context, t Template, svc Service, v Values) (View, error) {
	secrets, err := m.secretsOf(ctx, svc.Name, t.Secrets)
	if err != nil {
		return View{}, err
	}
	files := append(t.Files(v, secrets), File{Path: unitPath(svc.Name), Mode: 0o600, Body: []byte(quadlet(t, svc.Name, v))})
	if err := m.host.Install(ctx, Unit{Name: svc.Name, Files: files}); err != nil {
		return View{}, fmt.Errorf("services: installing %s: %w", svc.Name, err)
	}
	if err := m.host.Restart(ctx, svc.Name); err != nil {
		return View{}, fmt.Errorf("services: starting %s: %w", svc.Name, err)
	}
	if err := m.store.SetState(ctx, svc.Name, Deployed); err != nil {
		return View{}, err
	}
	svc.State = Deployed
	return m.view(ctx, svc), nil
}

func secretName(service, key string) string { return "service/" + service + "/" + key }

// secretsOf reads the service's secrets, generating the ones it has not got:
// 32 random bytes, in hex.
func (m *Module) secretsOf(ctx context.Context, service string, keys []string) (map[string]string, error) {
	out := make(map[string]string, len(keys))
	for _, k := range keys {
		b, ok, err := m.secrets.Get(ctx, secretName(service, k))
		if err != nil {
			return nil, err
		}
		if !ok {
			raw := make([]byte, 32)
			if _, err := rand.Read(raw); err != nil {
				return nil, err
			}
			b = []byte(hex.EncodeToString(raw))
			if err := m.secrets.Put(ctx, secretName(service, k), b); err != nil {
				return nil, err
			}
		}
		out[k] = string(b)
	}
	return out, nil
}

func (m *Module) unit(ctx context.Context, name string, do func(context.Context, string) error) (View, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	svc, _, err := m.known(ctx, name)
	if err != nil {
		return View{}, err
	}
	if err := do(ctx, svc.Name); err != nil {
		return View{}, fmt.Errorf("services: %s: %w", svc.Name, err)
	}
	return m.view(ctx, svc), nil
}

func (m *Module) start(ctx context.Context, r Ref) (View, error) {
	return m.unit(ctx, r.Name, m.host.Start)
}

func (m *Module) stop(ctx context.Context, r Ref) (View, error) {
	return m.unit(ctx, r.Name, m.host.Stop)
}

func (m *Module) restart(ctx context.Context, r Ref) (View, error) {
	return m.unit(ctx, r.Name, m.host.Restart)
}

func (m *Module) remove(ctx context.Context, p Remove) (struct{}, error) {
	if !ValidName(p.Name) {
		return struct{}{}, ErrBadName
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	svc, err := m.store.Get(ctx, p.Name)
	if err != nil {
		return struct{}{}, err
	}
	if err := m.store.SetState(ctx, svc.Name, Removing); err != nil {
		return struct{}{}, err
	}
	if err := m.host.Uninstall(ctx, svc.Name, p.Purge); err != nil {
		return struct{}{}, fmt.Errorf("services: removing %s: %w", svc.Name, err)
	}
	if t, ok := m.templates[svc.Template]; ok {
		for _, k := range t.Secrets {
			if err := m.secrets.Delete(ctx, secretName(svc.Name, k)); err != nil {
				return struct{}{}, err
			}
		}
	}
	return struct{}{}, m.store.Remove(ctx, svc.Name)
}

func (m *Module) logs(ctx context.Context, p LogsAsk) (Logs, error) {
	svc, _, err := m.known(ctx, p.Name)
	if err != nil {
		return Logs{}, err
	}
	limit := p.Limit
	switch {
	case limit <= 0:
		limit = 100
	case limit > 500:
		limit = 500
	}
	lines, err := m.host.Logs(ctx, svc.Name, limit)
	if err != nil {
		return Logs{}, err
	}
	if lines == nil {
		lines = []string{}
	}
	return Logs{Lines: lines}, nil
}

func (m *Module) secret(ctx context.Context, p SecretAsk) (SecretValue, error) {
	svc, t, err := m.known(ctx, p.Name)
	if err != nil {
		return SecretValue{}, err
	}
	for _, k := range t.Secrets {
		if k != p.Key {
			continue
		}
		b, ok, err := m.secrets.Get(ctx, secretName(svc.Name, k))
		if err != nil {
			return SecretValue{}, err
		}
		if !ok {
			break
		}
		return SecretValue{Value: string(b)}, nil
	}
	return SecretValue{}, ErrNoSecret
}

// unitPath is where a user's systemd looks for Podman unit files (Quadlet),
// relative to the user's home.
func unitPath(name string) string { return ".config/containers/systemd/" + name + ".container" }

// quadlet renders the service's Podman unit file. The service's user's
// systemd turns it into <name>.service. Every value is the template's own or
// a validated option.
func quadlet(t Template, name string, v Values) string {
	var b strings.Builder
	b.WriteString("# Written by AutoPanel. Changed through the panel, not here: a deploy writes it again.\n")
	fmt.Fprintf(&b, "[Unit]\nDescription=AutoPanel service %s (%s)\n\n", name, t.Name)
	fmt.Fprintf(&b, "[Container]\nImage=%s\n", t.Image)
	if t.Args != nil {
		if args := t.Args(v); len(args) > 0 {
			fmt.Fprintf(&b, "Exec=%s\n", strings.Join(args, " "))
		}
	}
	if t.Network == HostNetwork {
		b.WriteString("Network=host\n")
	} else if t.Ports != nil {
		for _, p := range t.Ports(v) {
			if p.From == p.To {
				fmt.Fprintf(&b, "PublishPort=%d:%d/%s\n", p.From, p.From, p.Proto)
			} else {
				fmt.Fprintf(&b, "PublishPort=%d-%d:%d-%d/%s\n", p.From, p.To, p.From, p.To, p.Proto)
			}
		}
	}
	dirs := make([]string, 0, len(t.Mounts))
	for d := range t.Mounts {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	for _, d := range dirs {
		fmt.Fprintf(&b, "Volume=%%h/%s:%s:ro,Z\n", d, t.Mounts[d])
	}
	// What every service gets, whatever its template: a read-only root, no
	// capability but the ones its template keeps, and no way to gain one.
	b.WriteString("ReadOnly=true\nDropCapability=ALL\n")
	for _, c := range t.Keeps {
		fmt.Fprintf(&b, "AddCapability=%s\n", c)
	}
	// Its own user inside as outside (%U and %G are the unit's user and
	// group): the process is the service's user on the host, so it reads the
	// files only that user may, and Open ports and the journal name it. An
	// image's own user would be one of the user's sub-ids, which can read
	// none of them.
	b.WriteString("NoNewPrivileges=true\nUserNS=keep-id\nUser=%U\nGroup=%G\n\n")
	// The first start pulls the image: give it time.
	fmt.Fprintf(&b, "[Service]\nMemoryMax=%s\nMemorySwapMax=0\nRestart=always\nTimeoutStartSec=600\n\n", t.Memory)
	b.WriteString("[Install]\nWantedBy=default.target\n")
	return b.String()
}
