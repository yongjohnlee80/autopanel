// Package services is the machine side of core/services: it makes a service's
// user and directory, writes its files, and asks that user's systemd to run
// its Podman unit. Every command it runs is one of internal/hostcmd's tools,
// with arguments built from a service name the module has validated.
package services

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/yongjohnlee80/autopanel/core/services"
	"github.com/yongjohnlee80/autopanel/internal/hostcmd"
)

// Host runs services on this machine. It must run as root.
type Host struct {
	// root holds one directory per service, each the home of that service's
	// user: /var/lib/autopanel-services.
	root string
	// subuid and subgid are the host's tables of subordinate ids.
	subuid, subgid string
}

// New is the host whose services live under root.
func New(root string) *Host {
	return &Host{root: root, subuid: "/etc/subuid", subgid: "/etc/subgid"}
}

// Podman is the host's Podman version.
func (h *Host) Podman(ctx context.Context) (major, minor int, err error) {
	out, err := hostcmd.Run(ctx, hostcmd.Podman, "--version")
	if errors.Is(err, hostcmd.ErrNoTool) {
		return 0, 0, services.ErrNoPodman
	}
	if err != nil {
		return 0, 0, err
	}
	major, minor, ok := parseVersion(string(out))
	if !ok {
		return 0, 0, fmt.Errorf("services: podman --version said %q", firstLine(string(out)))
	}
	return major, minor, nil
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}

// parseVersion reads "podman version 5.4.2".
func parseVersion(out string) (major, minor int, ok bool) {
	f := strings.Fields(firstLine(out))
	if len(f) == 0 {
		return 0, 0, false
	}
	parts := strings.Split(f[len(f)-1], ".")
	if len(parts) < 2 {
		return 0, 0, false
	}
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	return major, minor, err1 == nil && err2 == nil
}

func (h *Host) home(name string) string { return filepath.Join(h.root, name) }

// ids are a user's numbers; ok is false for a user the host does not have.
func ids(name string) (uid, gid int, ok bool, err error) {
	u, err := user.Lookup(name)
	var unknown user.UnknownUserError
	if errors.As(err, &unknown) {
		return 0, 0, false, nil
	}
	if err != nil {
		return 0, 0, false, err
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil {
		return 0, 0, false, fmt.Errorf("services: user %s has no numeric ids", name)
	}
	return uid, gid, true, nil
}

// manager addresses a user's systemd from root: systemctl --user -M <user>@.
func manager(usr string, args ...string) []string {
	return append([]string{"--user", "-M", usr + "@"}, args...)
}

// Install makes the service's user (with its sub-id ranges and a systemd of
// its own that runs without a login) and its directory, writes the files, and
// has the user's systemd read the unit file.
func (h *Host) Install(ctx context.Context, u services.Unit) error {
	usr, home := services.UserOf(u.Name), h.home(u.Name)
	// The services' directory lets each user reach its own, and list nothing.
	if err := os.MkdirAll(h.root, 0o711); err != nil {
		return err
	}
	if err := os.Chmod(h.root, 0o711); err != nil {
		return err
	}
	uid, gid, ok, err := ids(usr)
	if err != nil {
		return err
	}
	if !ok {
		if _, err := hostcmd.Run(ctx, hostcmd.Useradd, "--system", "--create-home", "--home-dir", home, "--shell", "/usr/sbin/nologin", usr); err != nil {
			return err
		}
		if uid, gid, ok, err = ids(usr); err != nil || !ok {
			return fmt.Errorf("services: user %s was not made: %v", usr, err)
		}
	}
	if err := os.Chmod(home, 0o700); err != nil {
		return err
	}
	if err := h.subIDs(ctx, usr); err != nil {
		return err
	}
	if err := linger(ctx, usr, uid); err != nil {
		return err
	}
	if err := writeFiles(home, uid, gid, u.Files); err != nil {
		return err
	}
	_, err = hostcmd.Run(ctx, hostcmd.Systemctl, manager(usr, "daemon-reload")...)
	return err
}

// linger has usr's systemd run without a login, now and after a boot, and
// waits for it. It is safe to run again.
func linger(ctx context.Context, usr string, uid int) error {
	if _, err := hostcmd.Run(ctx, hostcmd.Loginctl, "enable-linger", usr); err != nil {
		return err
	}
	if err := waitFor(ctx, 30*time.Second, func() bool {
		_, err := hostcmd.Run(ctx, hostcmd.Systemctl, "is-active", "--quiet", "user@"+strconv.Itoa(uid)+".service")
		return err == nil
	}); err != nil {
		return fmt.Errorf("services: the systemd of user %s did not start: %w", usr, err)
	}
	return nil
}

// waitFor polls ok until it holds, ctx ends or the time is up.
func waitFor(ctx context.Context, d time.Duration, ok func() bool) error {
	deadline := time.Now().Add(d)
	for !ok() {
		if time.Now().After(deadline) {
			return errors.New("timed out")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	return nil
}

// subIDs gives usr a range of subordinate user and group ids, which rootless
// Podman maps a container's users onto. useradd gives a system user none.
func (h *Host) subIDs(ctx context.Context, usr string) error {
	uids, err := os.ReadFile(h.subuid)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	gids, err := os.ReadFile(h.subgid)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	start, has := nextSubID(usr, string(uids), string(gids))
	if has {
		return nil
	}
	r := strconv.Itoa(start) + "-" + strconv.Itoa(start+subIDCount-1)
	_, err = hostcmd.Run(ctx, hostcmd.Usermod, "--add-subuids", r, "--add-subgids", r, usr)
	return err
}

const (
	subIDCount = 65536
	subIDFirst = 100000
)

// nextSubID reads the sub-id tables ("name:start:count" lines): has says usr
// is in both already; start is the first id above every range in either.
func nextSubID(usr string, tables ...string) (start int, has bool) {
	start, has = subIDFirst, true
	for _, table := range tables {
		found := false
		for _, line := range strings.Split(table, "\n") {
			f := strings.Split(strings.TrimSpace(line), ":")
			if len(f) != 3 {
				continue
			}
			first, err1 := strconv.Atoi(f[1])
			count, err2 := strconv.Atoi(f[2])
			if err1 != nil || err2 != nil {
				continue
			}
			if f[0] == usr {
				found = true
			}
			if end := first + count; end > start {
				start = end
			}
		}
		has = has && found
	}
	return start, has
}

// writeFiles writes files under home as the service's user's. home is opened
// as a root no path can leave: the directory is the service's own, so a link
// planted in it must not send a write by root elsewhere.
func writeFiles(home string, uid, gid int, files []services.File) error {
	root, err := os.OpenRoot(home)
	if err != nil {
		return err
	}
	defer root.Close()
	for _, f := range files {
		name := path.Clean(f.Path)
		if name == "." || path.IsAbs(name) || strings.HasPrefix(name, "../") {
			return fmt.Errorf("services: %q is not a path inside the service's directory", f.Path)
		}
		// Each directory on the way, made 0700 and the user's.
		dir := ""
		for _, part := range strings.Split(path.Dir(name), "/") {
			if part == "." {
				continue
			}
			dir = path.Join(dir, part)
			if err := root.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
				return err
			}
			if err := root.Lchown(dir, uid, gid); err != nil {
				return err
			}
		}
		// Written beside its place, then moved into it: the unit never reads
		// half a file.
		tmp := name + ".autopanel-new"
		_ = root.Remove(tmp)
		w, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		_, err = w.Write(f.Body)
		if err == nil {
			err = w.Chown(uid, gid)
		}
		if err == nil {
			err = w.Chmod(f.Mode.Perm())
		}
		if cerr := w.Close(); err == nil {
			err = cerr
		}
		if err == nil {
			err = root.Rename(tmp, name)
		}
		if err != nil {
			_ = root.Remove(tmp)
			return err
		}
	}
	return nil
}

func (h *Host) unit(ctx context.Context, name string, args ...string) error {
	_, err := hostcmd.Run(ctx, hostcmd.Systemctl, manager(services.UserOf(name), append(args, name+".service")...)...)
	return err
}

// Start asks for the unit to start and does not wait for it: a first start
// pulls the image. Running says how it went.
func (h *Host) Start(ctx context.Context, name string) error {
	return h.up(ctx, name, "start")
}

// up starts or restarts the unit, with the user's systemd brought up first:
// the uninstaller's --apply stops it, and a reinstall starts from there.
func (h *Host) up(ctx context.Context, name, verb string) error {
	usr := services.UserOf(name)
	uid, _, ok, err := ids(usr)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("services: %s has no user %s", name, usr)
	}
	if err := linger(ctx, usr, uid); err != nil {
		return err
	}
	return h.unit(ctx, name, "--no-block", verb)
}

// Restart is Start for a unit that may be running.
func (h *Host) Restart(ctx context.Context, name string) error {
	return h.up(ctx, name, "restart")
}

func (h *Host) Stop(ctx context.Context, name string) error { return h.unit(ctx, name, "stop") }

// Uninstall stops the unit, ends the user's systemd and deletes the user.
// With purge the directory goes too; without, it is kept as root's, under a
// name no later service takes. Every step tolerates the one before having
// already happened: an uninstall that was interrupted is run again.
func (h *Host) Uninstall(ctx context.Context, name string, purge bool) error {
	usr, home := services.UserOf(name), h.home(name)
	uid, _, ok, err := ids(usr)
	if err != nil {
		return err
	}
	if ok {
		_ = h.Stop(ctx, name) // the unit, or the user's systemd, may be gone already
		_, _ = hostcmd.Run(ctx, hostcmd.Loginctl, "disable-linger", usr)
		_, _ = hostcmd.Run(ctx, hostcmd.Loginctl, "terminate-user", usr)
		_ = waitFor(ctx, 20*time.Second, func() bool {
			_, err := hostcmd.Run(ctx, hostcmd.Systemctl, "is-active", "--quiet", "user@"+strconv.Itoa(uid)+".service")
			return err != nil
		})
		if _, err := hostcmd.Run(ctx, hostcmd.Userdel, usr); err != nil {
			// A process of the user's that outlived its systemd: userdel's
			// --force deletes the user regardless.
			if _, err := hostcmd.Run(ctx, hostcmd.Userdel, "--force", usr); err != nil {
				return err
			}
		}
	}
	if _, err := os.Lstat(home); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if purge {
		return os.RemoveAll(home)
	}
	// Kept, but root's and closed: the deleted user's number may be given to
	// another user later.
	if err := os.Lchown(home, 0, 0); err != nil {
		return err
	}
	if err := os.Chmod(home, 0o700); err != nil {
		return err
	}
	return os.Rename(home, home+".removed-"+strconv.FormatInt(time.Now().Unix(), 10))
}

// Running is the unit's state as the user's systemd reports it.
func (h *Host) Running(ctx context.Context, name string) (services.Running, error) {
	usr := services.UserOf(name)
	if _, _, ok, err := ids(usr); err != nil {
		return services.Running{}, err
	} else if !ok {
		return services.Running{Active: "absent"}, nil
	}
	out, err := hostcmd.Run(ctx, hostcmd.Systemctl, manager(usr, "show", name+".service", "-p", "ActiveState,SubState,MemoryCurrent")...)
	if err != nil {
		return services.Running{}, err
	}
	return parseShow(string(out)), nil
}

// parseShow reads systemctl show's "Key=value" lines.
func parseShow(out string) services.Running {
	var r services.Running
	for _, line := range strings.Split(out, "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(line), "=")
		switch k {
		case "ActiveState":
			r.Active = v
		case "SubState":
			r.Sub = v
		case "MemoryCurrent":
			r.MemoryBytes, _ = strconv.ParseUint(v, 10, 64) // "[not set]" for a unit that is not running
		}
	}
	return r
}

// Logs are the newest journal lines of the service's user: the unit's own and
// its container's, and nothing of another user's.
func (h *Host) Logs(ctx context.Context, name string, limit int) ([]string, error) {
	uid, _, ok, err := ids(services.UserOf(name))
	if err != nil || !ok {
		return nil, err
	}
	out, err := hostcmd.Run(ctx, hostcmd.Journalctl, "_UID="+strconv.Itoa(uid), "-n", strconv.Itoa(limit), "--no-pager", "-o", "short-iso")
	if err != nil {
		return nil, err
	}
	return logLines(string(out)), nil
}

// logLines splits a journal's text into lines a terminal can show: printable
// characters only, 400 at most.
func logLines(out string) []string {
	var lines []string
	for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		line = strings.Map(func(r rune) rune {
			if r == '\t' {
				return ' '
			}
			if r < 0x20 || r == 0x7f {
				return -1
			}
			return r
		}, line)
		if r := []rune(line); len(r) > 400 {
			line = string(r[:400])
		}
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}
