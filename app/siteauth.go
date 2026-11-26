//go:build linux

package app

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	coresite "github.com/yongjohnlee80/autopanel/core/site"
	hostsite "github.com/yongjohnlee80/autopanel/host/site"
	"github.com/yongjohnlee80/autopanel/internal/peercred"
)

const systemSiteAuthSocket = "/run/autopanel-site-auth/auth.sock"

// SiteAuthSocket is where the serving process asks the core whether a reader
// may have a held file.
func SiteAuthSocket() string { return env("AUTOPANEL_SITE_AUTH_SOCKET", systemSiteAuthSocket) }

// serveSiteAuth listens on the auth socket until ctx ends: as root, on a host
// that has the serving process's user. The socket is that user's alone
// (0600), in a directory only root and its group enter, and a peer of any
// other user is refused. With no such user nothing listens, and held pages
// answer 503.
func serveSiteAuth(ctx context.Context, sm *coresite.Module, log *slog.Logger) error {
	if os.Getuid() != 0 {
		return nil
	}
	u, err := user.Lookup(siteUser)
	if err != nil {
		log.Info("site: no serving user on this host; held documents are not served", "user", siteUser)
		return nil
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	sock := SiteAuthSocket()
	dir := filepath.Dir(sock)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	if err := os.Lchown(dir, 0, gid); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o750); err != nil {
		return err
	}
	if err := os.Remove(sock); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	l, err := net.Listen("unix", sock)
	if err != nil {
		return err
	}
	if err := os.Lchown(sock, uid, gid); err != nil {
		l.Close()
		return err
	}
	if err := os.Chmod(sock, 0o600); err != nil {
		l.Close()
		return err
	}
	checked := peercred.ListenerFor(l, peercred.Allow(uid), func(err error) {
		log.Warn("site: a peer refused on the auth socket", "err", err)
	})
	go func() {
		<-ctx.Done()
		_ = checked.Close()
	}()
	go func() {
		if err := hostsite.ServeAuth(checked, sm); err != nil && ctx.Err() == nil {
			log.Error("site: the auth socket stopped", "err", err)
		}
	}()
	return nil
}
