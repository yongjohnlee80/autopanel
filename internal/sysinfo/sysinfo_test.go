package sysinfo

import (
	"reflect"
	"strings"
	"testing"
)

const procTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1234 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 1235 1 0000000000000000 100 0 0 10 0
   2: 0A00020F:0016 0A000202:D2F0 01 00000000:00000000 02:000A1B2C 00000000     0        0 1236 4 0000000000000000 20 4 30 10 -1
   3: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 1237 1 0000000000000000 100 0 0 10 0
   4: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 1237 1 0000000000000000 100 0 0 10 0
garbage
`

const procTCP6 = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2234 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000001000000:0CEA 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2235 1 0000000000000000 100 0 0 10 0
`

const procUDP = `   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  512: 00000000:0D96 00000000:0000 07 00000000:00000000 00:00000000 00000000   110        0 3234 2 0000000000000000 0
  600: 3500007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   101        0 3235 2 0000000000000000 0
`

// TestListenersAreTheListeningSockets: only TCP sockets in LISTEN and bound
// UDP sockets are kept, the kernel's hex addresses are read in their byte
// order, a line that does not parse is skipped, and a repeat is listed once.
func TestListenersAreTheListeningSockets(t *testing.T) {
	var ls []Listener
	ls = append(ls, ParseListeners("tcp", strings.NewReader(procTCP))...)
	ls = append(ls, ParseListeners("tcp", strings.NewReader(procTCP6))...)
	ls = append(ls, ParseListeners("udp", strings.NewReader(procUDP))...)
	got := SortListeners(ls)
	want := []Listener{
		{"tcp", "0.0.0.0", 22},
		{"tcp", "::", 22},
		{"udp", "127.0.0.53", 53},
		{"tcp", "0.0.0.0", 443},
		{"tcp", "::1", 3306},
		{"udp", "0.0.0.0", 3478},
		{"tcp", "127.0.0.1", 8080},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("listeners =\n%+v\nwant\n%+v", got, want)
	}
}

const journal = `{"__REALTIME_TIMESTAMP":"1794211200000000","MESSAGE":"Accepted publickey for root from 192.0.2.10 port 51000 ssh2: ED25519 SHA256:abc"}
{"__REALTIME_TIMESTAMP":"1794211100000000","MESSAGE":"Failed password for invalid user admin from 192.0.2.66 port 40000 ssh2"}
{"__REALTIME_TIMESTAMP":"1794211090000000","MESSAGE":"Failed password for root from 2001:db8::7 port 40001 ssh2"}
{"__REALTIME_TIMESTAMP":"1794211080000000","MESSAGE":"Invalid user oracle from 192.0.2.67 port 40002"}
{"__REALTIME_TIMESTAMP":"1794211070000000","MESSAGE":"Connection closed by authenticating user root 192.0.2.68 port 40003 [preauth]"}
{"__REALTIME_TIMESTAMP":"1794211060000000","MESSAGE":"pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)"}
{"__REALTIME_TIMESTAMP":"1794211050000000","MESSAGE":[70,97,105,108,101,100]}
not json
{"__REALTIME_TIMESTAMP":"1794211040000000","MESSAGE":"Accepted password for deploy from 192.0.2.11 port 51001 ssh2"}
`

// TestSSHJournalKeepsTheLoginAttempts: accepted, failed, invalid-user and
// closed-before-login lines are kept with their time, user and address; other
// sshd lines, a message that is not text and a line that is not JSON are
// skipped; the limit holds.
func TestSSHJournalKeepsTheLoginAttempts(t *testing.T) {
	got := ParseSSHJournal(strings.NewReader(journal), 100)
	want := []SSHLogin{
		{1794211200, "root", "192.0.2.10", "ok", "publickey"},
		{1794211100, "admin", "192.0.2.66", "failed", "password, invalid user"},
		{1794211090, "root", "2001:db8::7", "failed", "password"},
		{1794211080, "oracle", "192.0.2.67", "failed", "invalid user"},
		{1794211070, "root", "192.0.2.68", "closed", "closed before login"},
		{1794211040, "deploy", "192.0.2.11", "ok", "password"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("logins =\n%+v\nwant\n%+v", got, want)
	}
	if got := ParseSSHJournal(strings.NewReader(journal), 2); len(got) != 2 || got[1].User != "admin" {
		t.Fatalf("with a limit of 2: %+v", got)
	}
}

func TestLoadAndMeminfo(t *testing.T) {
	l, ok := ParseLoad("0.42 1.05 2.10 1/123 4567\n")
	if !ok || l != (Load{0.42, 1.05, 2.10}) {
		t.Fatalf("load = %+v, %v", l, ok)
	}
	if _, ok := ParseLoad("nonsense"); ok {
		t.Fatal("a line with no averages parsed")
	}
	total, avail := ParseMeminfo(strings.NewReader("MemTotal:        2048000 kB\nMemFree:          100000 kB\nMemAvailable:    1024000 kB\n"))
	if total != 2048000<<10 || avail != 1024000<<10 {
		t.Fatalf("meminfo = %d, %d", total, avail)
	}
}
