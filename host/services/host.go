// Package services is the machine side of core/services: it makes a stack's
// user and directory, stages and commits its definition, writes its unit
// files, and asks that user's systemd and Podman to run them. Every command it
// runs is one of internal/hostcmd's tools, with arguments built from names and
// references the module has validated.
package services

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/yongjohnlee80/autopanel/core/services"
	"github.com/yongjohnlee80/autopanel/internal/hostcmd"
)

// Host runs stacks on this machine. It must run as root.
type Host struct {
	// root holds one directory per stack, each the home of that stack's user:
	// /var/lib/autopanel-services.
	root string
	// defs holds one folder per stack's definition, written by the
	// administrator: /etc/autopanel/stacks.
	defs string
	// subuid and subgid are the host's tables of subordinate ids.
	subuid, subgid string
}

// New is the host whose stacks live under root and are defined under defs.
func New(root, defs string) *Host {
	return &Host{root: root, defs: defs, subuid: "/etc/subuid", subgid: "/etc/subgid"}
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

// StackDir is where a stack's definition and data live inside its home, under
// the stacks' root: its compose file's folder, as the containers see it.
func StackDir(root, name string) string { return filepath.Join(root, name, "stack") }

// staging is where a stack's definition is copied for a review and an apply:
// root's alone, outside the stack user's home, so that user cannot change a
// file after its hash was taken.
func (h *Host) staging(name string) string { return filepath.Join(h.root, ".staging", name) }

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

// userSystemctl runs systemctl against a user's own systemd, as that user:
// runuser, with the user's runtime directory named, so systemctl finds the
// manager's private socket. systemctl's own way from root (-M <user>@) needs
// the user's D-Bus session bus, which a server need not have.
func userSystemctl(ctx context.Context, usr string, uid int, args ...string) ([]byte, error) {
	run := []string{"-u", usr, "--", "/usr/bin/env", "XDG_RUNTIME_DIR=/run/user/" + strconv.Itoa(uid), "/usr/bin/systemctl", "--user"}
	return hostcmd.Run(ctx, hostcmd.Runuser, append(run, args...)...)
}

// userPodman runs Podman as a user, in that user's home: its storage and its
// containers are the user's own.
func (h *Host) userPodman(ctx context.Context, name string, args ...string) ([]byte, error) {
	usr := services.UserOf(name)
	uid, _, ok, err := ids(usr)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("services: %s has no user %s", name, usr)
	}
	run := []string{"-u", usr, "--", "/usr/bin/env", "-C", h.home(name), "XDG_RUNTIME_DIR=/run/user/" + strconv.Itoa(uid),
		"HOME=" + h.home(name), "/usr/bin/podman"}
	return hostcmd.Run(ctx, hostcmd.Runuser, append(run, args...)...)
}

// EnsureUser makes the stack's user (with its sub-id ranges and a systemd of
// its own that runs without a login) and its directory.
func (h *Host) EnsureUser(ctx context.Context, name string) error {
	usr, home := services.UserOf(name), h.home(name)
	// The services' directory lets each user reach its own, and list nothing.
	if err := os.MkdirAll(h.root, 0o711); err != nil {
		return err
	}
	if err := os.Chmod(h.root, 0o711); err != nil {
		return err
	}
	uid, _, ok, err := ids(usr)
	if err != nil {
		return err
	}
	if !ok {
		if _, err := hostcmd.Run(ctx, hostcmd.Useradd, "--system", "--create-home", "--home-dir", home, "--shell", "/usr/sbin/nologin", usr); err != nil {
			return err
		}
		if uid, _, ok, err = ids(usr); err != nil || !ok {
			return fmt.Errorf("services: user %s was not made: %v", usr, err)
		}
	}
	if err := os.Chmod(home, 0o700); err != nil {
		return err
	}
	if err := h.subIDs(ctx, usr); err != nil {
		return err
	}
	return linger(ctx, usr, uid)
}

// stackUser is the stack's user, with its numbers.
func stackUser(name string) (usr string, uid, gid int, err error) {
	usr = services.UserOf(name)
	uid, gid, ok, err := ids(usr)
	if err == nil && !ok {
		err = fmt.Errorf("services: %s has no user %s", name, usr)
	}
	return usr, uid, gid, err
}

// Install writes the unit files and has the user's systemd read them.
func (h *Host) Install(ctx context.Context, u services.Unit) error {
	usr, uid, gid, err := stackUser(u.Name)
	if err != nil {
		return err
	}
	if err := writeFiles(h.home(u.Name), uid, gid, u.Files); err != nil {
		return err
	}
	_, err = userSystemctl(ctx, usr, uid, "daemon-reload")
	return err
}

// DeleteUnits removes unit files and has the user's systemd forget them. A
// file that is gone already is no error.
func (h *Host) DeleteUnits(ctx context.Context, name string, paths []string) error {
	usr, uid, _, err := stackUser(name)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(h.home(name))
	if err != nil {
		return err
	}
	defer root.Close()
	for _, p := range paths {
		c := path.Clean(p)
		if !strings.HasPrefix(c, ".config/containers/systemd/") {
			return fmt.Errorf("services: %q is not a unit file", p)
		}
		if err := root.Remove(c); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	_, err = userSystemctl(ctx, usr, uid, "daemon-reload")
	return err
}

var digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// pullTime bounds one pull: an image is hundreds of megabytes.
const pullTime = 10 * time.Minute

// HasImage reports whether the stack's user holds the image ref.
func (h *Host) HasImage(ctx context.Context, name, ref string) (bool, error) {
	_, err := h.userPodman(ctx, name, "image", "exists", ref)
	if code, ok := hostcmd.ExitCode(err); ok && code == 1 {
		return false, nil
	}
	return err == nil, err
}

// pull runs "podman pull" as a transient unit of the stack user's own systemd,
// and waits for it. Run as the core's own child it would count against the
// core's memory limit, and unpacking an image takes more than the core has.
func (h *Host) pull(ctx context.Context, name, ref string) error {
	usr, uid, _, err := stackUser(name)
	if err != nil {
		return err
	}
	home := h.home(name)
	_, err = hostcmd.Run(ctx, hostcmd.Runuser, "-u", usr, "--", "/usr/bin/env", "-C", home,
		"XDG_RUNTIME_DIR=/run/user/"+strconv.Itoa(uid), "HOME="+home,
		"/usr/bin/systemd-run", "--user", "--quiet", "--wait", "--collect", "--pipe", "--working-directory="+home,
		"--setenv=HOME="+home, "/usr/bin/podman", "pull", "--quiet", ref)
	return err
}

// Pull pulls ref as the stack's user and answers the digest it resolved.
func (h *Host) Pull(ctx context.Context, name, ref string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, pullTime)
	defer cancel()
	if err := h.pull(ctx, name, ref); err != nil {
		return "", err
	}
	out, err := h.userPodman(ctx, name, "image", "inspect", "--format", "{{.Digest}}", ref)
	if err != nil {
		return "", err
	}
	d := strings.TrimSpace(string(out))
	if !digestRE.MatchString(d) {
		return "", fmt.Errorf("services: the image %s has no digest", firstLine(ref))
	}
	return d, nil
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

// Start asks for the units to start and does not wait for them. Running says
// how it went.
func (h *Host) Start(ctx context.Context, name string, units []string) error {
	return h.up(ctx, name, "start", units)
}

// up starts or restarts units, with the user's systemd brought up first: the
// uninstaller's --apply stops it, and a reinstall starts from there.
func (h *Host) up(ctx context.Context, name, verb string, units []string) error {
	if len(units) == 0 {
		return nil
	}
	usr, uid, _, err := stackUser(name)
	if err != nil {
		return err
	}
	if err := linger(ctx, usr, uid); err != nil {
		return err
	}
	_, err = userSystemctl(ctx, usr, uid, append([]string{"--no-block", verb}, units...)...)
	return err
}

// Restart is Start for units that may be running.
func (h *Host) Restart(ctx context.Context, name string, units []string) error {
	return h.up(ctx, name, "restart", units)
}

// notLoaded is systemctl's exit code for a unit it does not have.
const notLoaded = 5

// Stop stops the units, and waits for them. A stack with no user has nothing
// to stop, and a unit systemd does not have is stopped already: an apply that
// failed before it wrote a unit leaves that unit's name on record.
func (h *Host) Stop(ctx context.Context, name string, units []string) error {
	usr := services.UserOf(name)
	uid, _, ok, err := ids(usr)
	if err != nil || !ok || len(units) == 0 {
		return err
	}
	_, err = userSystemctl(ctx, usr, uid, append([]string{"stop"}, units...)...)
	if code, ok := hostcmd.ExitCode(err); !ok || code != notLoaded {
		return err
	}
	// One of them is not loaded, and systemctl stopped none: each on its own.
	for _, u := range units {
		_, err := userSystemctl(ctx, usr, uid, "stop", u)
		if code, ok := hostcmd.ExitCode(err); err != nil && (!ok || code != notLoaded) {
			return err
		}
	}
	return nil
}

// Uninstall ends the user's systemd, and every unit with it, and deletes the user.
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
		_, _ = hostcmd.Run(ctx, hostcmd.Loginctl, "disable-linger", usr)
		_, _ = hostcmd.Run(ctx, hostcmd.Loginctl, "terminate-user", usr)
		_ = waitFor(ctx, 20*time.Second, func() bool {
			_, err := hostcmd.Run(ctx, hostcmd.Systemctl, "is-active", "--quiet", "user@"+strconv.Itoa(uid)+".service")
			return err != nil
		})
		// A process of the user's started outside its systemd (by an
		// administrator, with runuser) is not ended with it. None may outlive
		// the user: it would hold its ports under a number that is nobody's.
		// pkill exits 1 when there is none.
		_, _ = hostcmd.Run(ctx, hostcmd.Pkill, "-KILL", "-U", strconv.Itoa(uid))
		if _, err := hostcmd.Run(ctx, hostcmd.Userdel, usr); err != nil {
			// A process of the user's that outlived its systemd: userdel's
			// --force deletes the user regardless.
			if _, err := hostcmd.Run(ctx, hostcmd.Userdel, "--force", usr); err != nil {
				return err
			}
		}
	}
	if err := os.RemoveAll(h.staging(name)); err != nil {
		return err
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
	// What is kept is the service's own: its configuration and its data.
	// Podman's store is the image, pulled again by the next deploy, and is
	// hundreds of megabytes.
	for _, podmans := range []string{".local/share/containers", ".cache"} {
		if err := os.RemoveAll(filepath.Join(home, podmans)); err != nil {
			return err
		}
	}
	return os.Rename(home, home+".removed-"+strconv.FormatInt(time.Now().Unix(), 10))
}

// Running is each unit's state as the user's systemd reports it, by unit.
func (h *Host) Running(ctx context.Context, name string, units []string) (map[string]services.Running, error) {
	usr := services.UserOf(name)
	uid, _, ok, err := ids(usr)
	if err != nil {
		return nil, err
	}
	out := map[string]services.Running{}
	if !ok {
		for _, u := range units {
			out[u] = services.Running{Active: "absent"}
		}
		return out, nil
	}
	if len(units) == 0 {
		return out, nil
	}
	args := append([]string{"show", "--timestamp=unix", "-p", "Id,ActiveState,SubState,MemoryCurrent,NRestarts,ActiveEnterTimestamp,CPUUsageNSec"}, units...)
	text, err := userSystemctl(ctx, usr, uid, args...)
	if err != nil {
		return nil, err
	}
	return parseShow(string(text)), nil
}

// parseShow reads systemctl show's blocks of "Key=value" lines, one block per
// unit, by each block's Id. A property a unit has no value for is "[not set]"
// or empty, and reads as zero.
func parseShow(out string) map[string]services.Running {
	units := map[string]services.Running{}
	for _, block := range strings.Split(out, "\n\n") {
		var r services.Running
		id := ""
		for _, line := range strings.Split(block, "\n") {
			k, v, _ := strings.Cut(strings.TrimSpace(line), "=")
			switch k {
			case "Id":
				id = v
			case "ActiveState":
				r.Active = v
			case "SubState":
				r.Sub = v
			case "MemoryCurrent":
				r.MemoryBytes, _ = strconv.ParseUint(v, 10, 64)
			case "NRestarts":
				r.Restarts, _ = strconv.Atoi(v)
			case "ActiveEnterTimestamp":
				r.Since, _ = strconv.ParseInt(strings.TrimPrefix(v, "@"), 10, 64)
			case "CPUUsageNSec":
				r.CPUNanos, _ = strconv.ParseUint(v, 10, 64)
			}
		}
		if id != "" {
			units[id] = r
		}
	}
	return units
}

// Health is each container's health, by its name, as Podman's listing says it
// in a status such as "Up 2 minutes (healthy)".
func (h *Host) Health(ctx context.Context, name string) (map[string]string, error) {
	if _, _, ok, err := ids(services.UserOf(name)); err != nil || !ok {
		return map[string]string{}, err
	}
	out, err := h.userPodman(ctx, name, "ps", "--all", "--format", "{{.Names}}\t{{.Status}}")
	if err != nil {
		return nil, err
	}
	return parseHealth(string(out)), nil
}

func parseHealth(out string) map[string]string {
	health := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		n, status, ok := strings.Cut(line, "\t")
		if !ok {
			continue
		}
		for _, word := range []string{"healthy", "unhealthy", "starting"} {
			if strings.HasSuffix(strings.TrimSpace(status), "("+word+")") {
				health[n] = word
			}
		}
	}
	return health
}

// Logs are the newest journal lines of the stack's user, or of one of its
// containers: nothing of another user's.
func (h *Host) Logs(ctx context.Context, name, container string, limit int) ([]string, error) {
	uid, _, ok, err := ids(services.UserOf(name))
	if err != nil || !ok {
		return nil, err
	}
	args := []string{"_UID=" + strconv.Itoa(uid)}
	if container != "" {
		args = append(args, "CONTAINER_NAME="+container)
	}
	out, err := hostcmd.Run(ctx, hostcmd.Journalctl, append(args, "-n", strconv.Itoa(limit), "--no-pager", "-o", "short-iso")...)
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
