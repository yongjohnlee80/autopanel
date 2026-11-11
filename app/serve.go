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
	"strconv"
	"sync"
	"syscall"
	"time"

	httpserver "github.com/yongjohnlee80/golib/server/http"

	"github.com/yongjohnlee80/autopanel/core/gate"
	hostcontrol "github.com/yongjohnlee80/autopanel/host/control"
	hostgate "github.com/yongjohnlee80/autopanel/host/gate"
	"github.com/yongjohnlee80/autopanel/internal/certs"
	"github.com/yongjohnlee80/autopanel/store"
)

// Serve runs AutoPanel until SIGINT or SIGTERM: the store, the gate's two
// listeners, certificates, and the control socket.
func Serve(cfg Config, log *slog.Logger) error {
	if cfg.Email == "" {
		return errors.New("AUTOPANEL_ACME_EMAIL is required: the ACME account's contact")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return err
	}
	st, err := store.Open(ctx, store.Config{Engine: cfg.Engine, Path: filepath.Join(cfg.StateDir, "autopanel.db"), DSN: cfg.DSN})
	if err != nil {
		return err
	}
	defer st.Close()
	host, _ := os.Hostname()
	holder := host + ":" + strconv.Itoa(os.Getpid())
	if err := st.Lease(ctx, holder); err != nil {
		return err
	}
	defer func() { _ = st.Release(context.Background(), holder) }()

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

	opts := certs.Options{Blobs: st.Blobs(), Allowed: table.Holds, CA: cfg.CA, Email: cfg.Email}
	if cfg.CFToken != "" {
		p, err := certs.Cloudflare(cfg.CFToken)
		if err != nil {
			return err
		}
		opts.DNS = p
	}
	cm, err := certs.New(opts)
	if err != nil {
		return err
	}

	gateHandler := hostgate.Handler(table)
	https := httpserver.New(httpserver.Addr(cfg.HTTPSAddr), httpserver.WithTLSConfig(cm.TLSConfig()),
		httpserver.ReadHeaderTimeout(10*time.Second), httpserver.IdleTimeout(120*time.Second),
		httpserver.MaxHeaderBytes(64<<10), httpserver.NotFound(gateHandler.ServeHTTP)) // no routes: every request is the gate's
	plain := httpserver.New(httpserver.Addr(cfg.HTTPAddr),
		httpserver.ReadHeaderTimeout(10*time.Second), httpserver.IdleTimeout(60*time.Second),
		httpserver.MaxHeaderBytes(16<<10), httpserver.NotFound(cm.HTTPChallengeHandler(http.HandlerFunc(toHTTPS)).ServeHTTP))

	gm := gate.NewModule(st.Routes(), reload)
	sys := &sysModule{cfg: cfg, table: table, engine: st.Engine(), started: time.Now()}
	ctl, err := hostcontrol.Listen(cfg.Socket, log, gm, sys)
	if err != nil {
		return err
	}

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
		"store", st.Engine(), "ca", cfg.CA, "challenge", cfg.Challenge(), "routes", len(table.Routes()))
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
