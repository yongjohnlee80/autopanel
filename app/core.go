package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/yongjohnlee80/autopanel/core/gate"
	"github.com/yongjohnlee80/autopanel/core/services"
	hostcontrol "github.com/yongjohnlee80/autopanel/host/control"
	hostgate "github.com/yongjohnlee80/autopanel/host/gate"
	hostservices "github.com/yongjohnlee80/autopanel/host/services"
	"github.com/yongjohnlee80/autopanel/internal/auth"
	"github.com/yongjohnlee80/autopanel/internal/hostcmd"
	"github.com/yongjohnlee80/autopanel/internal/keyslot"
	"github.com/yongjohnlee80/autopanel/internal/module"
	"github.com/yongjohnlee80/autopanel/store"
)

// THE CORE — the process that holds the store, the vault, the ACME account
// and every administrative right. It listens on two unix sockets and on no
// network (a test holds that): the control socket, for the panel and the CLI,
// and the link socket, for the gate process. The gate is the core's to run.

// unlockWithKeyfile opens the master key with the service keyfile. A store
// with no keyslots is refused: run --init first.
func unlockWithKeyfile(ctx context.Context, cfg Config, st *store.Store, vault *keyslot.Vault) error {
	slot, err := st.ServiceSlot(ctx)
	if err != nil {
		return err
	}
	kf, err := keyslot.ReadKeyfile(cfg.Keyfile)
	if err != nil {
		return err
	}
	mk, err := keyslot.OpenService(slot, kf)
	if err != nil {
		return err
	}
	return vault.Unlock(mk)
}

// GateControl is how the core runs the gate process: it starts it once its
// own sockets answer, and restarts or stops it on request.
type GateControl interface {
	Start(ctx context.Context) error
	Restart(ctx context.Context) error
	Stop(ctx context.Context) error
}

// unitGate runs the gate as a systemd unit. The unit has no [Install] section,
// so nothing but the core starts it.
type unitGate struct{ unit string }

func (g unitGate) Start(ctx context.Context) error {
	_, err := hostcmd.Run(ctx, hostcmd.Systemctl, "start", g.unit)
	return err
}

func (g unitGate) Restart(ctx context.Context) error {
	_, err := hostcmd.Run(ctx, hostcmd.Systemctl, "restart", g.unit)
	return err
}

func (g unitGate) Stop(ctx context.Context) error {
	_, err := hostcmd.Run(ctx, hostcmd.Systemctl, "stop", g.unit)
	return err
}

// serviceHost is the machine the core deploys services on. A variable so a
// test gives its own: a test makes no user and starts no unit.
var serviceHost = func(cfg Config) services.Host {
	if os.Getuid() != 0 {
		return notRoot{}
	}
	return hostservices.New(cfg.Services)
}

// errNotRoot is a core that runs as another user than root: a development
// run. It serves the panel, and can deploy nothing.
var errNotRoot = errors.New("services: this core does not run as root")

// notRoot is the services' host for such a core. It lists what the store
// holds, with nothing running.
type notRoot struct{}

func (notRoot) Podman(context.Context) (int, int, error)            { return 0, 0, errNotRoot }
func (notRoot) Install(context.Context, services.Unit) error        { return errNotRoot }
func (notRoot) Start(context.Context, string) error                 { return errNotRoot }
func (notRoot) Stop(context.Context, string) error                  { return errNotRoot }
func (notRoot) Restart(context.Context, string) error               { return errNotRoot }
func (notRoot) Uninstall(context.Context, string, bool) error       { return errNotRoot }
func (notRoot) Logs(context.Context, string, int) ([]string, error) { return nil, errNotRoot }
func (notRoot) Running(context.Context, string) (services.Running, error) {
	return services.Running{Active: "absent"}, nil
}

// serviceSecrets keeps the services' generated secrets in the store's secret
// table, sealed under the master key as the Cloudflare token is.
type serviceSecrets struct {
	st    *store.Store
	vault *keyslot.Vault
}

func (s serviceSecrets) Get(ctx context.Context, name string) ([]byte, bool, error) {
	b, err := s.st.Secret(ctx, s.vault, name)
	if errors.Is(err, store.ErrNoSecret) {
		return nil, false, nil
	}
	return b, err == nil, err
}

func (s serviceSecrets) Put(ctx context.Context, name string, value []byte) error {
	return s.st.PutSecret(ctx, s.vault, name, value)
}

func (s serviceSecrets) Delete(ctx context.Context, name string) error {
	return s.st.DeleteSecret(ctx, name)
}

// servicesModule is services.* with the two errors only this host can
// answer: a locked vault, and a core that is not root.
type servicesModule struct{ *services.Module }

func (m servicesModule) Errors() []module.PublicError {
	return append(m.Module.Errors(),
		module.PublicError{Err: keyslot.ErrLocked, Code: -32188, Name: "services.locked", Message: "the vault is locked; log in as root to unlock it"},
		module.PublicError{Err: errNotRoot, Code: -32189, Name: "services.not_root", Message: "this core does not run as root, so it can deploy nothing"})
}

// gateUnit is the gate's unit, as install.sh installs it.
const gateUnit = "autopanel-gate.service"

// Core runs the core until SIGINT or SIGTERM. As root it runs the gate's
// unit; as any other user (a development run) the gate is started by hand,
// with autopanel --gate.
func Core(cfg Config, log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var gc GateControl
	if os.Getuid() == 0 {
		gc = unitGate{unit: gateUnit}
	} else {
		log.Warn("not root: the gate is not started; run autopanel --gate as this user")
	}
	return CoreContext(ctx, cfg, log, gc)
}

// linkAccess is who may open the link socket. With a gate user configured
// (the units: the core is root, the gate is not), that user alone, through a
// socket its group can open in a directory its group can enter. With none,
// this process's own user: the gate then runs as the same one.
func linkAccess(cfg Config) (acc hostcontrol.Access, gid int, err error) {
	if cfg.GateUser == "" {
		return hostcontrol.Access{Concurrent: 64}, -1, nil
	}
	u, err := user.Lookup(cfg.GateUser)
	if err != nil {
		return acc, -1, fmt.Errorf("the gate's user %q: %w", cfg.GateUser, err)
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil {
		return acc, -1, fmt.Errorf("the gate's user %q has no numeric ids", cfg.GateUser)
	}
	return hostcontrol.Access{Peers: []int{uid}, Mode: 0o660, Concurrent: 64}, gid, nil
}

// CoreContext is Core until ctx ends, running the gate through gc (nil: not at all).
func CoreContext(ctx context.Context, cfg Config, log *slog.Logger, gc GateControl) error {
	if cfg.Email == "" {
		return errors.New("AUTOPANEL_ACME_EMAIL is required: the ACME account's contact")
	}

	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return err
	}
	st, err := store.Open(ctx, store.Config{Engine: cfg.Engine, Path: filepath.Join(cfg.StateDir, "autopanel.db"), DSN: cfg.DSN})
	if err != nil {
		return err
	}
	defer st.Close()
	// The holder is the host, not the process: a restart after a crash takes its
	// own lease back at once instead of waiting out LeaseTTL. A second AutoPanel
	// on this host is caught by its live socket before it touches the lease.
	if hostcontrol.InUse(cfg.Socket) {
		return fmt.Errorf("an AutoPanel is already running on %s", cfg.Socket)
	}
	holder, _ := os.Hostname()
	if holder == "" {
		holder = "autopanel"
	}
	if err := st.Lease(ctx, holder); err != nil {
		return err
	}
	started := false
	defer func() {
		if started { // only an instance that fully started gives the store back
			_ = st.Release(context.Background(), holder)
		}
	}()

	// The core keeps a table too: it decides which names may have a
	// certificate, and it is what the gate is sent.
	table := gate.NewTable[http.Handler]()
	rev := newRevision(time.Now().Unix())
	reload := func(ctx context.Context) error {
		rs, err := st.Routes().All(ctx)
		if err != nil {
			return err
		}
		snap, err := hostgate.Build(rs, cfg.Trusted)
		if err != nil {
			return err
		}
		table.Swap(snap)
		rev.bump()
		return nil
	}
	if err := reload(ctx); err != nil {
		return fmt.Errorf("loading routes: %w", err)
	}

	vault := &keyslot.Vault{}
	if err := unlockWithKeyfile(ctx, cfg, st, vault); err != nil {
		if errors.Is(err, store.ErrNotInitialized) {
			return err
		}
		log.Warn("the vault stays locked until root logs in", "err", err)
	}
	sw := &certSwitch{cfg: cfg, st: st, vault: vault, table: table, log: log}
	if err := sw.rebuild(ctx); err != nil {
		return err
	}

	counts := &counters{}
	gm := gate.NewModule(st.Routes(), reload)
	svcs := services.NewModule(st.Services(), serviceSecrets{st: st, vault: vault}, serviceHost(cfg))
	sys := &sysModule{cfg: cfg, table: table, engine: st.Engine(), started: time.Now(), challenge: sw.Challenge, ca: sw.CA,
		st: st, log: log, counts: counts, listeners: readListeners, sshLogins: readSSHLogins, gate: gc, serviceUsers: svcs.Users}
	am, err := auth.New(st, st, vault, func(ctx context.Context) {
		if err := sw.rebuild(ctx); err != nil {
			log.Error("certificates after unlock", "err", err)
		}
	}, keyslot.DefaultParams)
	if err != nil {
		return err
	}
	// The control socket: this user's processes only, so root's under the unit.
	// A privileged verb's entry goes to the store's audit log before it runs.
	ctl, err := hostcontrol.Listen(cfg.Socket, log, hostcontrol.Access{Audit: st}, am, gm, &certsModule{sw: sw}, sys, servicesModule{svcs})
	if err != nil {
		return err
	}
	acc, gid, err := linkAccess(cfg)
	if err != nil {
		return err
	}
	if gid >= 0 { // the gate's group may enter the link's directory, and nothing more
		dir := filepath.Dir(cfg.LinkSocket)
		if err := os.Chown(dir, 0, gid); err != nil {
			return err
		}
		if err := os.Chmod(dir, 0o750); err != nil {
			return err
		}
	}
	lnk, err := hostcontrol.Listen(cfg.LinkSocket, log, acc, &linkModule{cfg: cfg, table: table, rev: rev, sw: sw, counts: counts})
	if err != nil {
		return err
	}
	if gid >= 0 {
		if err := os.Chown(cfg.LinkSocket, 0, gid); err != nil {
			return err
		}
	}
	started = true

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	run := func(name string, fn func(context.Context) error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := fn(ctx); err != nil && !errors.Is(err, context.Canceled) {
				errs <- fmt.Errorf("%s: %w", name, err)
				cancel()
			}
		}()
	}
	run("control", ctl.Run)
	run("link", lnk.Run)
	run("lease", func(ctx context.Context) error { return renewLease(ctx, st, holder) })
	log.Info("autopanel core serving", "socket", cfg.Socket, "link", cfg.LinkSocket,
		"store", st.Engine(), "ca", sw.CA(), "challenge", sw.Challenge(), "routes", len(table.Routes()))
	if gc != nil {
		// The sockets answer: the gate may start. A gate already running (the
		// core restarted under it) is left as it is, and reconnects.
		run("gate start", func(ctx context.Context) error {
			if err := gc.Start(ctx); err != nil && ctx.Err() == nil {
				log.Error("the gate did not start; the panel still answers", "err", err)
			}
			return nil
		})
	}
	<-ctx.Done()
	wg.Wait()
	close(errs)
	return <-errs // nil on a clean stop
}

// renewLease keeps the store's lease live; losing it stops AutoPanel, since
// another may now hold the store.
func renewLease(ctx context.Context, st *store.Store, holder string) error {
	t := time.NewTicker(store.LeaseTTL / 4)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if err := st.Renew(ctx, holder); err != nil && ctx.Err() == nil {
				return err
			}
		}
	}
}
