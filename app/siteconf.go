package app

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"

	coresite "github.com/yongjohnlee80/autopanel/core/site"
	"github.com/yongjohnlee80/autopanel/internal/hostcmd"
)

// The site's directories and the serving process's socket.
const (
	systemSiteDir    = "/var/lib/autopanel-site" // not under the core's own state: the serving process reads it
	systemSiteSocket = "/run/autopanel-site/site.sock"
)

// SiteDir is where the live pages of every site are.
func SiteDir() string { return env("AUTOPANEL_SITE_DIR", systemSiteDir) }

// SiteSocket is the serving process's socket: it listens there, and the gate
// is told it at its start, for every site's route.
func SiteSocket() string { return env("AUTOPANEL_SITE_SOCKET", systemSiteSocket) }

// siteUnit is the serving process's unit, as install.sh installs it.
const siteUnit = "autopanel-site.service"

// keepSiteUnit runs the serving process while a site exists and stops it when
// none does: as root, on a host where its unit is installed. Pages already
// built stay served while the core is down, so it is not stopped with it.
func keepSiteUnit(ctx context.Context, sites func(context.Context) ([]coresite.Site, error), log *slog.Logger) {
	if os.Getuid() != 0 {
		return
	}
	if _, err := os.Stat(filepath.Join("/etc/systemd/system", siteUnit)); err != nil {
		return
	}
	ss, err := sites(ctx)
	if err != nil {
		log.Warn("site: the sites, to run their serving process", "err", err)
		return
	}
	verb := "stop"
	if len(ss) > 0 {
		verb = "start"
	}
	if _, err := hostcmd.Run(ctx, hostcmd.Systemctl, verb, siteUnit); err != nil {
		log.Warn("site: the serving process's unit", "verb", verb, "err", err)
	}
}
