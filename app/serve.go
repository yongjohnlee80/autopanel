package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	httpserver "github.com/yongjohnlee80/golib/server/http"

	"github.com/yongjohnlee80/autopanel/core/gate"
	hostcontrol "github.com/yongjohnlee80/autopanel/host/control"
	hostgate "github.com/yongjohnlee80/autopanel/host/gate"
	"github.com/yongjohnlee80/autopanel/internal/auth"
	"github.com/yongjohnlee80/autopanel/internal/keyslot"
	"github.com/yongjohnlee80/autopanel/store"
)

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

// Serve runs AutoPanel until SIGINT or SIGTERM: the store, the gate's two
// listeners, certificates, and the control socket.
func Serve(cfg Config, log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return ServeContext(ctx, cfg, log)
}

// ServeContext is Serve until ctx ends.
func ServeContext(ctx context.Context, cfg Config, log *slog.Logger) error {
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

	table := gate.NewTable[http.Handler]()
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

	gateHandler := hostgate.Handler(table)
	https := httpserver.New(httpserver.Addr(cfg.HTTPSAddr), httpserver.WithTLSConfig(sw.tlsConfig()),
		httpserver.ReadHeaderTimeout(10*time.Second), httpserver.IdleTimeout(120*time.Second),
		httpserver.MaxHeaderBytes(64<<10), httpserver.NotFound(gateHandler.ServeHTTP)) // no routes: every request is the gate's
	plain := httpserver.New(httpserver.Addr(cfg.HTTPAddr),
		httpserver.ReadHeaderTimeout(10*time.Second), httpserver.IdleTimeout(60*time.Second),
		httpserver.MaxHeaderBytes(16<<10), httpserver.NotFound(sw.httpChallenge(http.HandlerFunc(toHTTPS)).ServeHTTP))

	gm := gate.NewModule(st.Routes(), reload)
	sys := &sysModule{cfg: cfg, table: table, engine: st.Engine(), started: time.Now(), challenge: sw.Challenge}
	am, err := auth.New(st, st, vault, func(ctx context.Context) {
		if err := sw.rebuild(ctx); err != nil {
			log.Error("certificates after unlock", "err", err)
		}
	}, keyslot.DefaultParams)
	if err != nil {
		return err
	}
	ctl, err := hostcontrol.Listen(cfg.Socket, log, am, gm, &certsModule{sw: sw}, sys)
	if err != nil {
		return err
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
	run("gate https", https.Run)
	run("gate http", plain.Run)
	run("control", ctl.Run)
	run("lease", func(ctx context.Context) error { return renewLease(ctx, st, holder) })
	log.Info("autopanel serving", "https", cfg.HTTPSAddr, "http", cfg.HTTPAddr, "socket", cfg.Socket,
		"store", st.Engine(), "ca", cfg.CA, "challenge", sw.Challenge(), "routes", len(table.Routes()))
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

// toHTTPS redirects plain HTTP to the same host and path over HTTPS. The host
// is canonicalised first; a request naming no valid host gets 404.
func toHTTPS(w http.ResponseWriter, r *http.Request) {
	host, err := gate.CanonicalHost(r.Host)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusPermanentRedirect)
}
