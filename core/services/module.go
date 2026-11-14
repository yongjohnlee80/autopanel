package services

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/yongjohnlee80/autopanel/internal/module"
)

// State is where a stack's deployment got to, as the store keeps it. Whether
// its containers run is the host's to say, and is read when asked, never kept.
type State string

const (
	// Deploying is a stack whose row is written and that no apply has
	// finished for.
	Deploying State = "deploying"
	Deployed  State = "deployed"
	Removing  State = "removing"
)

// Service is a stack as the store keeps it.
type Service struct {
	Name  string
	State State
	// Legacy marks a row an older AutoPanel made from a template. It has no
	// definition, and can only be removed.
	Legacy    bool
	Applied   Applied
	AppliedAt time.Time
	Stopped   []string // the services a person stopped
	Pending   *Pending // an apply that did not finish
}

// Store is where stacks are kept.
type Store interface {
	All(ctx context.Context) ([]Service, error)
	Get(ctx context.Context, name string) (Service, error) // ErrNotFound
	Add(ctx context.Context, name string) error            // ErrDuplicate
	SetState(ctx context.Context, name string, state State) error
	SetPending(ctx context.Context, name string, p Pending) error
	// SetApplied records what an apply left, clears what was pending, and
	// makes the stack Deployed.
	SetApplied(ctx context.Context, name string, a Applied) error
	SetStopped(ctx context.Context, name string, services []string) error
	Remove(ctx context.Context, name string) error
	// Source is where a stack's definition was imported from; ok is false for
	// one written into the stacks' directory by hand. It outlives the stack, as
	// the definition does.
	Source(ctx context.Context, name string) (src Source, ok bool, err error)
	SetSource(ctx context.Context, name string, src Source) error
}

// Unit is what the host writes into a stack's home: its unit files.
type Unit struct {
	Name  string
	Files []File
}

// Running is a unit as systemd reports it.
type Running struct {
	Active      string `json:"active"` // "active", "activating", "failed", "inactive"; "absent" with no user or unit
	Sub         string `json:"sub"`
	MemoryBytes uint64 `json:"memory_bytes"`
	Restarts    int    `json:"restarts"`  // the times systemd restarted it on its own
	Since       int64  `json:"since"`     // when it last became active, Unix seconds; 0 when never
	CPUNanos    uint64 `json:"cpu_nanos"` // the processor time it has used
}

// Commit is what an apply moves into a stack's own folder.
type Commit struct {
	Managed   []string // the staged files that replace the folder's
	Stale     []string // managed files, and folders of them, the definition no longer has
	Data      []string // paths made when absent, and never written otherwise
	Generated []File   // the files the core writes itself; any other it wrote before goes
}

// Host is the machine the stacks run on. Every method names a stack by a
// name the module has validated; none takes a command.
type Host interface {
	// Podman is the host's Podman version, or ErrNoPodman.
	Podman(ctx context.Context) (major, minor int, err error)
	// Available are the folders that hold a stack's definition.
	Available(ctx context.Context) ([]string, error)
	// Stage reads a stack's compose.yaml and .env once, into a folder only
	// root reaches, and answers them: ErrNoDefinition without a compose.yaml.
	Stage(ctx context.Context, name string) (compose, env []byte, err error)
	// StagePaths adds the files at paths to the staged copy and answers every
	// staged file. missing are the paths the definition does not have; links
	// are the ones that are, or hold, a symbolic link.
	StagePaths(ctx context.Context, name string, paths []string) (files []Input, missing, links []string, err error)
	// Look says which of paths are in the stack's own folder already, and
	// which of those are, or pass through, a symbolic link.
	Look(ctx context.Context, name string, paths []string) (present map[string]bool, links []string, err error)
	// Changed reports whether the definition differs from m, by each file's
	// size and time: enough to say a review is due, never to skip one.
	Changed(ctx context.Context, name string, m Manifest, since time.Time) bool
	// EnsureUser makes the stack's user, with its sub-id range and a systemd
	// of its own. It is safe to run again.
	EnsureUser(ctx context.Context, name string) error
	Commit(ctx context.Context, name string, c Commit) error
	// Install writes the unit files and has the user's systemd read them.
	Install(ctx context.Context, u Unit) error
	// DeleteUnits removes unit files and has the user's systemd forget them.
	DeleteUnits(ctx context.Context, name string, paths []string) error
	// HasImage reports whether the stack's user holds the image ref.
	HasImage(ctx context.Context, name, ref string) (bool, error)
	// Pull pulls ref as the stack's user and answers the digest it resolved.
	Pull(ctx context.Context, name, ref string) (digest string, err error)
	Start(ctx context.Context, name string, units []string) error
	Stop(ctx context.Context, name string, units []string) error
	Restart(ctx context.Context, name string, units []string) error
	// Uninstall stops the units and deletes the user; with purge, its
	// directory too. Each step tolerates the one before having already
	// happened.
	Uninstall(ctx context.Context, name string, purge bool) error
	Running(ctx context.Context, name string, units []string) (map[string]Running, error)
	// Health is each container's health by its name: "healthy", "unhealthy",
	// "starting", or "" with no check.
	Health(ctx context.Context, name string) (map[string]string, error)
	Logs(ctx context.Context, name, container string, limit int) ([]string, error)
	// Listening are the host's listening sockets that the stack's own user,
	// and the ids under it, do not hold.
	Listening(ctx context.Context, name string) ([]PortUse, error)

	// Browse lists a folder of the host; a link is listed, never followed.
	Browse(ctx context.Context, dir string) (Listing, error)
	// Preview reads a file inside a stack's folder, as text, bounded.
	Preview(ctx context.Context, file string) (text []byte, cut bool, err error)
	// ReadSource reads a source folder's compose.yaml and .env.
	ReadSource(ctx context.Context, from string) (compose, env []byte, err error)
	// SourceManifest hashes a source folder's definition files as an import
	// would copy them: compose.yaml, .env and paths.
	SourceManifest(ctx context.Context, from string, paths []string) (files []Input, missing, links []string, err error)
	// Import copies a source folder's definition into the stacks' directory
	// as name; with replace, over the one there.
	Import(ctx context.Context, from, name string, paths []string, replace bool) (files []Input, missing, links []string, err error)
}

var (
	ErrNoDefinition = errors.New("services: no definition of that name")
	ErrNotFound     = errors.New("services: no such stack")
	ErrDuplicate    = errors.New("services: a stack of this name exists")
	ErrRefused      = errors.New("services: the stack was refused")
	ErrChanged      = errors.New("services: the definition changed since its review")
	ErrNoPodman     = errors.New("services: the host has no Podman")
	ErrOldPodman    = errors.New("services: the host's Podman is older than 4.9")
	ErrStoppedNeed  = errors.New("services: a service it depends on is stopped")
	ErrBusy         = errors.New("services: the stack is being removed")
	ErrNoService    = errors.New("services: the stack has no such service")
	ErrLegacy       = errors.New("services: the stack was deployed from a template")
	ErrTooLarge     = errors.New("services: the definition is too large")
	ErrNotApplied   = errors.New("services: the stack has not been applied")
	ErrIncomplete   = errors.New("services: the apply did not finish")
	ErrReserved     = errors.New("services: the name is AutoPanel's own")
)

// Guard is a module that owns a stack: mail owns the stack named mail, whose
// definition AutoPanel writes, and the loopback ports it publishes. The
// services module asks it about every review and import.
type Guard interface {
	// Owns reports whether name is a stack only its owner may write.
	Owns(name string) bool
	// Review adds the owner's findings about a stack's staged compose file.
	Review(ctx context.Context, name string, compose []byte) []Finding
	// Reserved are ports no stack but their owner may publish.
	Reserved() []Claim
	// Mask hides what an owned stack's log lines must not show (a credential
	// its service prints), before services.logs answers them.
	Mask(name string, lines []string) []string
}

// detailed is a declared error that names what it is about.
type detailed struct {
	err    error
	detail string
}

func (e *detailed) Error() string        { return e.err.Error() + ": " + e.detail }
func (e *detailed) Unwrap() error        { return e.err }
func (e *detailed) PublicDetail() string { return e.detail }

func with(err error, detail string) error { return &detailed{err: err, detail: short(detail)} }

// Module is the services.* verbs.
type Module struct {
	store Store
	host  Host
	// mu guards locks and busy; ports orders the checks that claim ports, so
	// two stacks cannot both be given one. A caller that holds several takes
	// them in this order: a stack's lock, then ports.
	mu    sync.Mutex
	locks map[string]*sync.Mutex
	busy  map[string]bool
	ports sync.Mutex
	guard Guard // nil: no stack is anyone's
}

// SetGuard names the module that owns stacks of its own. It is set once,
// before the verbs are served.
func (m *Module) SetGuard(g Guard) { m.guard = g }

// NewModule returns the verbs.
func NewModule(store Store, host Host) *Module {
	return &Module{store: store, host: host, locks: map[string]*sync.Mutex{}, busy: map[string]bool{}}
}

func (m *Module) Name() string { return "services" }

func (m *Module) Errors() []module.PublicError {
	return []module.PublicError{
		{Err: ErrBadPath, Code: -32179, Name: "services.bad_path", Message: "the browser cannot read that path"},
		{Err: ErrNotInStack, Code: -32180, Name: "services.not_in_stack", Message: "only a file in a stack's folder (one that holds a compose.yaml) can be previewed"},
		{Err: ErrNotText, Code: -32181, Name: "services.not_text", Message: "the file is not text"},
		{Err: ErrNoSource, Code: -32182, Name: "services.no_source", Message: "the stack was not imported from a folder"},
		{Err: ErrIncomplete, Code: -32183, Name: "services.incomplete", Message: "the apply did not finish; fix the cause and apply again to finish it"},
		{Err: ErrTooLarge, Code: -32184, Name: "services.too_large", Message: "the stack's definition is too large: 1,000 files and 64 MB at most"},
		{Err: ErrNotApplied, Code: -32185, Name: "services.not_applied", Message: "the stack has not been applied yet"},
		{Err: ErrLegacy, Code: -32186, Name: "services.legacy", Message: "the stack was deployed from a template by an older AutoPanel; remove it, and add it again as a stack"},
		{Err: ErrNoService, Code: -32187, Name: "services.no_service", Message: "the stack has no such service"},
		{Err: ErrReserved, Code: -32188, Name: "services.reserved", Message: "that stack is AutoPanel's own: it is written and changed from its menu (Mail), never imported"},
		{Err: ErrNoDefinition, Code: -32190, Name: "services.no_definition", Message: "no folder of that name with a compose.yaml in it"},
		{Err: ErrNotFound, Code: -32191, Name: "services.not_found", Message: "no such stack"},
		{Err: ErrDuplicate, Code: -32192, Name: "services.duplicate", Message: "a stack of this name exists"},
		{Err: ErrBadName, Code: -32193, Name: "services.bad_name", Message: "a stack's name is a lower-case letter, then letters, digits and hyphens, 29 characters at most"},
		{Err: ErrRefused, Code: -32194, Name: "services.refused", Message: "the stack was refused"},
		{Err: ErrChanged, Code: -32195, Name: "services.changed", Message: "the definition changed since its review; review it again"},
		{Err: ErrNoPodman, Code: -32196, Name: "services.no_podman", Message: "the host has no Podman; install it (4.9 or newer) to run a stack"},
		{Err: ErrOldPodman, Code: -32197, Name: "services.old_podman", Message: "the host's Podman is older than 4.9, which running a stack needs"},
		{Err: ErrStoppedNeed, Code: -32198, Name: "services.stopped_dependency", Message: "a service it depends on is stopped; start that one first"},
		{Err: ErrBusy, Code: -32199, Name: "services.busy", Message: "the stack is being removed"},
	}
}

// View states beyond the stored ones.
const (
	Prepared   = "prepared"   // its user, files and images are in place; nothing runs
	Incomplete = "incomplete" // an apply did not finish
	LegacyRow  = "legacy"     // deployed from a template by an older AutoPanel
)

// View is a stack as a client sees it.
type View struct {
	Name       string      `json:"name"`
	State      string      `json:"state"`
	Step       string      `json:"step"` // for Incomplete: the step the apply stopped at
	User       string      `json:"user"`
	SHA256     string      `json:"sha256"`           // of the manifest last applied
	Changed    bool        `json:"changed"`          // the definition differs from the one applied
	Source     *SourceView `json:"source,omitempty"` // where it was imported from, and whether that changed since
	Containers []Container `json:"containers"`
}

// Container is one of a stack's containers, as the host reports it now.
type Container struct {
	Service string    `json:"service"`
	Image   string    `json:"image"`
	Digest  string    `json:"digest"`
	Ports   []PortUse `json:"ports"`
	Stopped bool      `json:"stopped"` // a person stopped it: it stays so across a boot
	Health  string    `json:"health"`
	Running
}

// Ref names a stack, and one service of it or all.
type Ref struct {
	Name    string `json:"name"`
	Service string `json:"service,omitempty"`
}

// Accept is the param of the verbs that apply a definition.
type Accept struct {
	Name   string `json:"name"`
	Accept string `json:"accept"` // the review's sha256
}

// Remove is services.remove's param.
type Remove struct {
	Name  string `json:"name"`
	Purge bool   `json:"purge,omitempty"`
}

// LogsAsk is services.logs's param.
type LogsAsk struct {
	Name    string `json:"name"`
	Service string `json:"service,omitempty"`
	Limit   int    `json:"limit,omitempty"`
}

// Logs is services.logs's answer.
type Logs struct {
	Lines []string `json:"lines"`
}

// Folder is a definition folder that no stack is registered for.
type Folder struct {
	Name string `json:"name"`
}

const (
	viewShape = "{name, state, step, user, sha256, changed, source?: {path, imported_at, state}, containers: [{service, image, digest, ports: [{proto, from, to}], stopped, health, active, sub, memory_bytes, restarts, since, cpu_nanos}]}"
	deploy    = "services.deploy"
)

func (m *Module) Verbs() []module.Verb {
	change := func(verb, param, doc string) module.Contract {
		return module.Contract{Verb: verb, Since: 4, Param: param, Result: viewShape, Mutates: true, Privileged: true, Right: deploy, Doc: doc}
	}
	return []module.Verb{
		module.Handle(module.Contract{Verb: "services.available", Since: 4, Result: "[{name}]",
			Doc: "The folders under the stacks' directory that hold a compose.yaml and that no stack is registered for."}, m.available),
		module.Handle(module.Contract{Verb: "services.check", Since: 4, Param: "{name}",
			Result: "{sha256, files: [{path, mode, size, sha256}], containers: [{service, image, user, network, ports, mounts, memory, read_only, restart, depends_on, cap_add, cap_drop}], findings: [{id, severity, service, detail}], removes}",
			Doc:    "Reviews a stack's definition and changes nothing: every file that defines it, by hash; each container it would run; and what the policy refuses or warns of. Its sha256 is what an apply must be given."}, m.check),
		module.Handle(change("services.prepare", "{name, accept}",
			"Registers a stack, makes its user, copies its definition and pulls its images. It writes no unit and starts nothing, so its data can be put in place first."), m.prepare),
		module.Handle(change("services.add", "{name, accept}",
			"Registers a stack and applies it; on a prepared stack, starts it. Refused unless accept is the sha256 its review answered. Needs Podman 4.9 or newer."), m.add),
		module.Handle(change("services.apply", "{name, accept}",
			"Applies a registered stack's definition as it is now: stops and removes what it no longer has, replaces its configuration, restarts what changed. Also finishes an apply that did not end. A stack's data is never written."), m.applyVerb),
		module.Handle(change("services.pull", "{name, service?}",
			"Pulls a stack's images again, records the digests they resolve to now, and restarts the containers whose image changed."), m.pull),
		module.Handle(module.Contract{Verb: "services.browse", Since: 5, Param: "{path}", Result: "{path, stack, entries: [{name, kind, size, stack}], truncated}",
			Doc: "A folder of the host, for the file browser: its entries, folders first, each folder saying whether it holds a compose.yaml. A link is listed, never followed."}, m.browse),
		module.Handle(module.Contract{Verb: "services.preview", Since: 5, Param: "{path}", Result: "{path, text, masked, cut}",
			Doc: "A file inside a stack's folder, as text, for the browser's preview: 64 KB at most, every value of a .env and each secret's value masked."}, m.preview),
		module.Handle(module.Contract{Verb: "services.import", Since: 5, Param: "{from, name?}", Result: "{name, from, sha256, files: [{path, mode, size, sha256}]}",
			Mutates: true, Privileged: true, Right: deploy,
			Doc: "Copies a folder's stack definition (compose.yaml, .env, its env_files and read-only mounts; not its data) into the stacks' directory, root's alone, and records where it came from. Runs nothing: services.check reviews it, services.add starts it."}, m.importVerb),
		module.Handle(module.Contract{Verb: "services.reimport", Since: 5, Param: "{name}", Result: "{name, from, sha256, files: [{path, mode, size, sha256}]}",
			Mutates: true, Privileged: true, Right: deploy,
			Doc: "Copies a stack's definition from its source again. What runs does not change until services.apply, which reviews it first."}, m.reimport),
		module.Handle(module.Contract{Verb: "services.list", Since: 3, Result: "[" + viewShape + "]",
			Doc: "Every stack: what was applied, and what the host says of each container now."}, m.list),
		module.Handle(change("services.start", "{name, service?}",
			"Starts a stack's containers, or one of them. Refused for a service whose requirement is stopped."), m.start),
		module.Handle(change("services.stop", "{name, service?}",
			"Stops a stack's containers, or one of them with the services that depend on it. They stay stopped across a boot, until they are started."), m.stop),
		module.Handle(change("services.restart", "{name, service?}", "Restarts a stack's containers that are not stopped, or one of them."), m.restart),
		module.Handle(module.Contract{Verb: "services.remove", Since: 3, Param: "{name, purge?}",
			Mutates: true, Privileged: true, Right: deploy,
			Doc: "Stops a stack and deletes its units and its user. Its directory, with its data, is kept as root's unless purge says to delete it. Its definition folder is never deleted."}, m.remove),
		module.Handle(module.Contract{Verb: "services.logs", Since: 3, Param: "{name, service?, limit?}", Result: "{lines}",
			Doc: "The newest journal lines of a stack, or of one of its containers, oldest first: 100 unless limit says, 500 at most."}, m.logs),
	}
}

// lock takes the stack's own lock: one change to a stack at a time.
func (m *Module) lock(name string) func() {
	if !ValidName(name) {
		return func() {} // the verb refuses the name; no lock is kept for it
	}
	m.mu.Lock()
	l, ok := m.locks[name]
	if !ok {
		l = &sync.Mutex{}
		m.locks[name] = l
	}
	m.mu.Unlock()
	l.Lock()
	return l.Unlock
}

// working marks a stack whose apply is running, for the list.
func (m *Module) working(name string, on bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if on {
		m.busy[name] = true
	} else {
		delete(m.busy, name)
	}
}

func (m *Module) available(ctx context.Context, _ struct{}) ([]Folder, error) {
	names, err := m.host.Available(ctx)
	if err != nil {
		return nil, err
	}
	all, err := m.store.All(ctx)
	if err != nil {
		return nil, err
	}
	have := map[string]bool{}
	for _, s := range all {
		have[s.Name] = true
	}
	out := []Folder{}
	sort.Strings(names)
	for _, n := range names {
		if ValidName(n) && !have[n] {
			out = append(out, Folder{Name: n})
		}
	}
	return out, nil
}

// view is s with what the host says of it. A host that cannot say leaves a
// container "unknown": the row is still worth showing.
func (m *Module) view(ctx context.Context, s Service) View {
	v := View{Name: s.Name, State: string(s.State), User: UserOf(s.Name), SHA256: s.Applied.Manifest.SHA256, Containers: []Container{}}
	m.mu.Lock()
	busy := m.busy[s.Name]
	m.mu.Unlock()
	switch {
	case s.Legacy:
		v.State = LegacyRow
	case s.State == Removing || busy:
	case s.Pending != nil && s.Pending.Prepared && len(s.Applied.Units) == 0:
		v.State = Prepared
	case s.Pending != nil:
		v.State, v.Step = Incomplete, s.Pending.Step
	}
	if src, ok, err := m.store.Source(ctx, s.Name); err == nil && ok {
		v.Source = m.sourceView(ctx, src)
	}
	var units []string
	for _, u := range s.Applied.Units {
		if u.Kind == KindContainer {
			units = append(units, u.systemdName())
		}
	}
	if len(units) == 0 {
		return v
	}
	v.Changed = m.host.Changed(ctx, s.Name, s.Applied.Manifest, s.AppliedAt)
	running, err := m.host.Running(ctx, s.Name, units)
	health, _ := m.host.Health(ctx, s.Name)
	stopped := map[string]bool{}
	for _, name := range s.Stopped {
		stopped[name] = true
	}
	for _, u := range s.Applied.Units {
		if u.Kind != KindContainer {
			continue
		}
		c := Container{Service: u.Service, Image: u.Image, Digest: u.Digest, Ports: u.Ports, Stopped: stopped[u.Service],
			Health: health[s.Name+"-"+u.Service], Running: Running{Active: "unknown"}}
		if c.Ports == nil {
			c.Ports = []PortUse{}
		}
		if r, ok := running[u.systemdName()]; ok && err == nil {
			c.Running = r
		}
		v.Containers = append(v.Containers, c)
	}
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

// Users are the host users of the stacks, each with its stack's name: what
// Open ports names a stack's sockets by.
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

// podman refuses a host that cannot run a stack.
func (m *Module) podman(ctx context.Context) error {
	major, minor, err := m.host.Podman(ctx)
	if err != nil {
		return err
	}
	if major < 4 || (major == 4 && minor < 9) {
		return ErrOldPodman
	}
	return nil
}

// known is the stack name, for a verb that works on what was applied. A stack
// being removed is refused: only remove may touch it.
func (m *Module) known(ctx context.Context, name string) (Service, error) {
	if !ValidName(name) {
		return Service{}, ErrBadName
	}
	svc, err := m.store.Get(ctx, name)
	switch {
	case err != nil:
		return Service{}, err
	case svc.State == Removing:
		return Service{}, ErrBusy
	case svc.Legacy:
		return Service{}, ErrLegacy
	}
	return svc, nil
}

// applied is known for a stack that an apply has finished for, with the
// service the caller named checked against it.
func (m *Module) applied(ctx context.Context, r Ref) (Service, error) {
	svc, err := m.known(ctx, r.Name)
	if err != nil {
		return Service{}, err
	}
	if len(svc.Applied.Units) == 0 {
		return Service{}, ErrNotApplied
	}
	if r.Service != "" {
		if _, ok := svc.Applied.unit(r.Service); !ok {
			return Service{}, ErrNoService
		}
	}
	return svc, nil
}

// unitFiles are the files of units as the host is to write them: a stopped
// service's without its [Install] section.
func unitFiles(units []UnitFile, stopped []string) []File {
	off := map[string]bool{}
	for _, s := range stopped {
		off[s] = true
	}
	out := make([]File, 0, len(units))
	for _, u := range units {
		body := u.Body
		if u.Kind == KindContainer && off[u.Service] {
			body = withoutInstall(body)
		}
		out = append(out, File{Path: u.Path, Mode: 0o600, Body: []byte(body)})
	}
	return out
}

// systemdNames are the services of the container units of services; of every
// container unit when services is nil.
func systemdNames(units []UnitFile, services []string) []string {
	want := map[string]bool{}
	for _, s := range services {
		want[s] = true
	}
	var out []string
	for _, u := range units {
		if u.Kind == KindContainer && (services == nil || want[u.Service]) {
			out = append(out, u.systemdName())
		}
	}
	return out
}

func (m *Module) start(ctx context.Context, r Ref) (View, error) {
	defer m.lock(r.Name)()
	svc, err := m.applied(ctx, r)
	if err != nil {
		return View{}, err
	}
	stopped := map[string]bool{}
	for _, s := range svc.Stopped {
		stopped[s] = true
	}
	var starting []string
	if r.Service == "" {
		stopped = map[string]bool{}
	} else {
		u, _ := svc.Applied.unit(r.Service)
		for _, need := range u.Needs {
			if stopped[need] {
				// Starting it would start what a person stopped.
				return View{}, with(ErrStoppedNeed, need)
			}
		}
		delete(stopped, r.Service)
		starting = []string{r.Service}
	}
	svc.Stopped = keys(stopped)
	if err := m.remember(ctx, svc); err != nil {
		return View{}, err
	}
	if err := m.host.Start(ctx, svc.Name, systemdNames(svc.Applied.Units, starting)); err != nil {
		return View{}, fmt.Errorf("services: starting %s: %w", svc.Name, err)
	}
	return m.view(ctx, svc), nil
}

func (m *Module) stop(ctx context.Context, r Ref) (View, error) {
	defer m.lock(r.Name)()
	svc, err := m.applied(ctx, r)
	if err != nil {
		return View{}, err
	}
	stopped := map[string]bool{}
	for _, s := range svc.Stopped {
		stopped[s] = true
	}
	var stopping []string
	if r.Service == "" {
		for _, u := range svc.Applied.Units {
			if u.Kind == KindContainer {
				stopping = append(stopping, u.Service)
			}
		}
	} else {
		// With it, every service that needs it: one of those starting again
		// would start it too.
		stopping = append([]string{r.Service}, dependants(svc.Applied.Units, r.Service)...)
	}
	for _, s := range stopping {
		stopped[s] = true
	}
	svc.Stopped = keys(stopped)
	if err := m.remember(ctx, svc); err != nil {
		return View{}, err
	}
	if err := m.host.Stop(ctx, svc.Name, systemdNames(svc.Applied.Units, stopping)); err != nil {
		return View{}, fmt.Errorf("services: stopping %s: %w", svc.Name, err)
	}
	return m.view(ctx, svc), nil
}

// remember records which services are stopped, and writes each unit with or
// without its [Install] section to match: the store first, so that a failure
// leaves a record an apply acts on.
func (m *Module) remember(ctx context.Context, svc Service) error {
	if err := m.store.SetStopped(ctx, svc.Name, svc.Stopped); err != nil {
		return err
	}
	if err := m.host.Install(ctx, Unit{Name: svc.Name, Files: unitFiles(svc.Applied.Units, svc.Stopped)}); err != nil {
		return fmt.Errorf("services: writing the units of %s: %w", svc.Name, err)
	}
	return nil
}

func (m *Module) restart(ctx context.Context, r Ref) (View, error) {
	defer m.lock(r.Name)()
	svc, err := m.applied(ctx, r)
	if err != nil {
		return View{}, err
	}
	stopped := map[string]bool{}
	for _, s := range svc.Stopped {
		stopped[s] = true
	}
	var which []string
	for _, u := range svc.Applied.Units {
		if u.Kind == KindContainer && !stopped[u.Service] && (r.Service == "" || r.Service == u.Service) {
			which = append(which, u.Service)
		}
	}
	if len(which) == 0 {
		// A restart never starts what a person stopped.
		return m.view(ctx, svc), nil
	}
	if err := m.host.Restart(ctx, svc.Name, systemdNames(svc.Applied.Units, which)); err != nil {
		return View{}, fmt.Errorf("services: restarting %s: %w", svc.Name, err)
	}
	return m.view(ctx, svc), nil
}

func (m *Module) remove(ctx context.Context, p Remove) (struct{}, error) {
	if !ValidName(p.Name) {
		return struct{}{}, ErrBadName
	}
	defer m.lock(p.Name)()
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
	return struct{}{}, m.store.Remove(ctx, svc.Name)
}

func (m *Module) logs(ctx context.Context, p LogsAsk) (Logs, error) {
	svc, err := m.known(ctx, p.Name)
	if err != nil {
		return Logs{}, err
	}
	container := ""
	if p.Service != "" {
		if _, ok := svc.Applied.unit(p.Service); !ok {
			return Logs{}, ErrNoService
		}
		container = svc.Name + "-" + p.Service
	}
	limit := p.Limit
	switch {
	case limit <= 0:
		limit = 100
	case limit > 500:
		limit = 500
	}
	lines, err := m.host.Logs(ctx, svc.Name, container, limit)
	if err != nil {
		return Logs{}, err
	}
	if m.guard != nil {
		lines = m.guard.Mask(svc.Name, lines)
	}
	if lines == nil {
		lines = []string{}
	}
	return Logs{Lines: lines}, nil
}

// Owned is what the module that owns a stack (mail) may ask of it. It goes
// past the verbs' review: the owner wrote the definition itself.

// Up is a stack's state, and when every container of it became active (0
// while one is not). ErrNotFound for a stack never added.
func (m *Module) Up(ctx context.Context, name string) (state string, since int64, err error) {
	svc, err := m.known(ctx, name)
	if err != nil {
		return "", 0, err
	}
	v := m.view(ctx, svc)
	if len(v.Containers) == 0 {
		return v.State, 0, nil
	}
	for _, c := range v.Containers {
		if c.Active != "active" {
			return v.State, 0, nil
		}
		if c.Since > since {
			since = c.Since
		}
	}
	return v.State, since, nil
}

// Restart restarts every running service of a stack, for its owner.
func (m *Module) Restart(ctx context.Context, name string) error {
	_, err := m.restart(ctx, Ref{Name: name})
	return err
}

// EnsureUser makes a stack's user before its first apply, for an owner that
// must know its id first (mail orders its loopback rule before that user's
// systemd).
func (m *Module) EnsureUser(ctx context.Context, name string) error {
	if !ValidName(name) {
		return ErrBadName
	}
	return m.host.EnsureUser(ctx, name)
}
