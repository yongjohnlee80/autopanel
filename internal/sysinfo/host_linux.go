package sysinfo

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"
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

// journalctl is where the journal's reader is, on every distribution with
// systemd; PATH is not trusted for it.
var journalctlPaths = []string{"/usr/bin/journalctl", "/bin/journalctl"}

// SSHLogins reads the newest SSH login attempts from the journal, newest
// first, at most limit. It runs journalctl with fixed arguments, bounded in
// time and in how far back it reads. It needs the journal to be readable: the
// unit gives the service the systemd-journal group for it. With no journalctl
// it answers ErrUnsupported; a journal it may not read is an error naming why.
func SSHLogins(ctx context.Context, limit int) ([]SSHLogin, error) {
	bin := ""
	for _, p := range journalctlPaths {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			bin = p
			break
		}
	}
	if bin == "" {
		return nil, ErrUnsupported
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// Newest first, at most 5000 of sshd's lines: a host under a password
	// scan writes several lines per attempt.
	cmd := exec.CommandContext(ctx, bin, "--no-pager", "-q", "-o", "json", "-r", "-n", "5000",
		"-t", "sshd", "-t", "sshd-session", "--since", "-"+strconv.Itoa(30*24)+"h")
	cmd.Env = []string{"LC_ALL=C"}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		msg := bytes.TrimSpace(stderr.Bytes())
		if len(msg) > 200 {
			msg = msg[:200]
		}
		if len(msg) == 0 {
			return nil, fmt.Errorf("journalctl: %w", err)
		}
		return nil, errors.New("journalctl: " + string(msg))
	}
	return ParseSSHJournal(&stdout, limit), nil
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
