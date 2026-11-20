//go:build linux

package app

import (
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"os"

	hostsite "github.com/yongjohnlee80/autopanel/host/site"
)

// The site's directories and the serving process's socket.
const (
	systemSiteDir    = "/var/lib/autopanel/site"
	systemSiteSocket = "/run/autopanel-site/site.sock"
)

// SiteDir is where the live pages of every site are.
func SiteDir() string { return env("AUTOPANEL_SITE_DIR", systemSiteDir) }

// Site is the serving process (autopanel --site): it reads the live pages,
// read-only, and answers the gate on a unix socket. It holds no secret and
// decides nothing but which file a request names; its unit confines it to
// that directory and that socket.
func Site(log *slog.Logger) error {
	sock := env("AUTOPANEL_SITE_SOCKET", systemSiteSocket)
	if err := os.Remove(sock); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	l, err := net.Listen("unix", sock)
	if err != nil {
		return err
	}
	defer l.Close()
	// The gate's user opens it through the socket's group; nobody else.
	if err := os.Chmod(sock, 0o660); err != nil {
		return err
	}
	log.Info("autopanel site serving", "dir", SiteDir(), "socket", sock)
	return hostsite.Server{Dir: SiteDir()}.Serve(l)
}
