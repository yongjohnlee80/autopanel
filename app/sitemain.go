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

// Site is the serving process (autopanel --site): it reads the live pages,
// read-only, and answers the gate on a unix socket. It holds no secret and
// decides nothing but which file a request names; its unit confines it to
// that directory and that socket.
func Site(log *slog.Logger) error {
	sock := SiteSocket()
	if err := os.Remove(sock); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	l, err := net.Listen("unix", sock)
	if err != nil {
		return err
	}
	defer l.Close()
	// Its directory is the gate's group's, setgid (the unit's), so the socket
	// takes that group: the gate's group alone may connect. This process is
	// not in that group.
	if err := os.Chmod(sock, 0o660); err != nil {
		return err
	}
	log.Info("autopanel site serving", "dir", SiteDir(), "socket", sock)
	return hostsite.NewServer(SiteDir(), SiteAuthSocket()).Serve(l)
}
