package sysinfo

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/yongjohnlee80/autopanel/internal/hostcmd"
)

// procRoot is where the kernel's process table is; a test gives its own.
var procRoot = "/proc"

// Listeners reads the host's listening sockets from /proc/net, with the user
// each belongs to, and names the process that holds each from the process
// table. A table that cannot be read (IPv6 off) is left out.
func Listeners(context.Context) ([]Listener, error) {
	var out []Listener
	read := 0
	for _, t := range []struct{ proto, file string }{
		{"tcp", "net/tcp"}, {"tcp", "net/tcp6"}, {"udp", "net/udp"}, {"udp", "net/udp6"},
	} {
		f, err := os.Open(filepath.Join(procRoot, t.file))
		if err != nil {
			continue
		}
		out = append(out, ParseListeners(t.proto, f)...)
		_ = f.Close()
		read++
	}
	if read == 0 {
		return nil, ErrUnsupported
	}
	want := map[uint64]bool{}
	for _, l := range out {
		if l.inode != 0 {
			want[l.inode] = true
		}
	}
	return SortListeners(Owned(out, socketHolders(want))), nil
}

// socketHolders finds the processes that hold the sockets in want, by reading
// each process's open files: the kernel names a socket there by its inode.
// It reads no name a process chose: a process is named by its executable.
// A process whose files may not be read (the core is root, so only inside a
// container that withholds it) is skipped, and its sockets stay unnamed.
func socketHolders(want map[uint64]bool) map[uint64][]Holder {
	out := map[uint64][]Holder{}
	if len(want) == 0 {
		return out
	}
	procs, err := os.ReadDir(procRoot)
	if err != nil {
		return out
	}
	for _, p := range procs {
		pid, err := strconv.Atoi(p.Name())
		if err != nil || pid <= 0 {
			continue
		}
		dir := filepath.Join(procRoot, p.Name())
		fds, err := os.ReadDir(filepath.Join(dir, "fd"))
		if err != nil {
			continue
		}
		name := ""
		held := map[uint64]bool{}
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(dir, "fd", fd.Name()))
			if err != nil {
				continue
			}
			v, ok := strings.CutPrefix(target, "socket:[")
			if !ok {
				continue
			}
			inode, err := strconv.ParseUint(strings.TrimSuffix(v, "]"), 10, 64)
			if err != nil || !want[inode] || held[inode] {
				continue
			}
			held[inode] = true
			if name == "" {
				name = executable(dir)
			}
			out[inode] = append(out[inode], Holder{PID: pid, Name: name})
		}
	}
	return out
}

// executable is the file name of the program a process runs. A program
// replaced on disk since it started still names the file it was started from.
func executable(dir string) string {
	exe, err := os.Readlink(filepath.Join(dir, "exe"))
	if err != nil {
		return "?"
	}
	return filepath.Base(strings.TrimSuffix(exe, " (deleted)"))
}

// SSHLogins reads the newest SSH login attempts from the journal, newest
// first, at most limit. It runs journalctl with fixed arguments, bounded in
// time, in how far back it reads and in what it keeps of each line. It needs
// the journal to be readable: the core runs as root, so it is. With no
// journalctl it answers ErrUnsupported; a journal it may not read is an error
// naming why.
func SSHLogins(ctx context.Context, limit int) ([]SSHLogin, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// Newest first, at most 5000 of sshd's lines: a host under a password
	// scan writes several lines per attempt. Only the message is kept of each
	// (the timestamp always comes with it).
	out, err := hostcmd.Run(ctx, hostcmd.Journalctl, "--no-pager", "-q", "-o", "json", "--output-fields=MESSAGE", "-r", "-n", "5000",
		"-t", "sshd", "-t", "sshd-session", "--since", "-"+strconv.Itoa(30*24)+"h")
	if errors.Is(err, hostcmd.ErrNoTool) {
		return nil, ErrUnsupported
	}
	if err != nil {
		return nil, err
	}
	return ParseSSHJournal(bytes.NewReader(out), limit), nil
}

// ReadHost reads the load, the memory, and the disk path is on.
func ReadHost(path string) Host {
	var h Host
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		h.Load, _ = ParseLoad(string(b))
	}
	if f, err := os.Open("/proc/meminfo"); err == nil {
		h.MemTotal, h.MemAvailable = ParseMeminfo(f)
		_ = f.Close()
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err == nil {
		h.DiskTotal = st.Blocks * uint64(st.Bsize)
		h.DiskFree = st.Bavail * uint64(st.Bsize)
	}
	return h
}
