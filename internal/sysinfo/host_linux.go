package sysinfo

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strconv"
	"syscall"
	"time"

	"github.com/yongjohnlee80/autopanel/internal/hostcmd"
)

// Listeners reads the host's listening sockets from /proc/net. A table that
// cannot be read (IPv6 off) is left out.
func Listeners() ([]Listener, error) {
	var out []Listener
	read := 0
	for _, t := range []struct{ proto, file string }{
		{"tcp", "/proc/net/tcp"}, {"tcp", "/proc/net/tcp6"}, {"udp", "/proc/net/udp"}, {"udp", "/proc/net/udp6"},
	} {
		f, err := os.Open(t.file)
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
	return SortListeners(out), nil
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
