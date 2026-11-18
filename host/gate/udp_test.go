package gate

import (
	"context"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// udpTarget is a UDP service on loopback: it answers each datagram with
// replies copies of it (0: it stays silent), and counts what it was sent.
type udpTarget struct {
	conn    *net.UDPConn
	replies atomic.Int32
	got     atomic.Int64
	largest atomic.Int64
}

func newUDPTarget(t *testing.T, replies int) *udpTarget {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	tg := &udpTarget{conn: c}
	tg.replies.Store(int32(replies))
	go func() {
		buf := make([]byte, 65536)
		for {
			n, from, err := c.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			tg.got.Add(1)
			if int64(n) > tg.largest.Load() {
				tg.largest.Store(int64(n))
			}
			for range tg.replies.Load() {
				_, _ = c.WriteToUDPAddrPort(buf[:n], from)
			}
		}
	}()
	return tg
}

func freeUDPAddr(t *testing.T) string {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().String()
}

// startUDP runs one UDP stream to tg until the test ends.
func startUDP(t *testing.T, tg *udpTarget, change func(*Stream), setup ...func(*udpForwarder)) (*udpForwarder, Stream) {
	t.Helper()
	s := Stream{Name: "forward:dns", Proto: "udp", Listen: freeUDPAddr(t), To: tg.conn.LocalAddr().String()}
	if change != nil {
		change(&s)
	}
	u := newUDPForwarder(slog.New(slog.NewTextHandler(io.Discard, nil)))
	for _, fn := range setup { // before anything runs: a clock, say
		fn(u)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { u.stopAll(); cancel() })
	u.apply(ctx, []Stream{s})
	deadline := time.Now().Add(3 * time.Second)
	for {
		u.mu.Lock()
		bound := u.running[s.Listen] != nil && u.running[s.Listen].conn != nil
		u.mu.Unlock()
		if bound {
			return u, s
		}
		if time.Now().After(deadline) {
			t.Fatal("the UDP stream never bound its port")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// udpClientConn is a client socket to the stream's public port.
func udpClientConn(t *testing.T, s Stream) *net.UDPConn {
	t.Helper()
	addr, _ := net.ResolveUDPAddr("udp", s.Listen)
	c, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// recv reads datagrams until none comes for a short while, and returns them.
func recv(c *net.UDPConn, wait time.Duration) []string {
	var out []string
	buf := make([]byte, 4096)
	for {
		_ = c.SetReadDeadline(time.Now().Add(wait))
		n, err := c.Read(buf)
		if err != nil {
			return out
		}
		out = append(out, string(buf[:n]))
	}
}

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatal(what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestAUDPStreamCarriesEachClientsDatagramsAndAnswers: a client's datagram
// reaches the target, and the answer comes back to that client and to no other.
func TestAUDPStreamCarriesEachClientsDatagramsAndAnswers(t *testing.T) {
	tg := newUDPTarget(t, 1)
	u, s := startUDP(t, tg, nil)
	a, b := udpClientConn(t, s), udpClientConn(t, s)
	_, _ = a.Write([]byte("from a"))
	if got := recv(a, 300*time.Millisecond); len(got) != 1 || got[0] != "from a" {
		t.Fatalf("a's answer: %q", got)
	}
	if got := recv(b, 150*time.Millisecond); len(got) != 0 {
		t.Fatalf("b was sent what was a's: %q", got)
	}
	_, _ = b.Write([]byte("from b"))
	if got := recv(b, 300*time.Millisecond); len(got) != 1 || got[0] != "from b" {
		t.Fatalf("b's answer: %q", got)
	}
	if got := recv(a, 150*time.Millisecond); len(got) != 0 {
		t.Fatalf("a was sent what was b's: %q", got)
	}
	if n := u.open(); n != 2 {
		t.Fatalf("%d pairings for two clients", n)
	}
}

// TestAnUnansweredPairingIsShortLivedAndSentLittle: until the target has
// answered and the client has sent again, a pairing gets at most a few
// datagrams back and is gone in seconds; answered, it gets them all and lasts
// its idle time.
func TestAnUnansweredPairingIsShortLivedAndSentLittle(t *testing.T) {
	defer func(d time.Duration) { udpSweep = d }(udpSweep)
	udpSweep = 10 * time.Millisecond
	tg := newUDPTarget(t, 10) // ten answers to every datagram: an amplifier
	var mu sync.Mutex
	clock := time.Now()
	u, s := startUDP(t, tg, func(s *Stream) { s.IdleSecs = 30 }, func(u *udpForwarder) {
		u.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	})
	forward := func(d time.Duration) { mu.Lock(); clock = clock.Add(d); mu.Unlock() }

	c := udpClientConn(t, s)
	_, _ = c.Write([]byte("one"))
	if got := recv(c, 300*time.Millisecond); len(got) != udpEarlyReplies {
		t.Fatalf("a client that sent once was sent %d datagrams; want %d", len(got), udpEarlyReplies)
	}
	// It sends again: it saw the answers, so it is who it says. Now all ten come.
	_, _ = c.Write([]byte("two"))
	if got := recv(c, 300*time.Millisecond); len(got) != 10 {
		t.Fatalf("an answered pairing was sent %d of 10", len(got))
	}
	// Another client sends once and never again: gone after five seconds.
	silent := udpClientConn(t, s)
	_, _ = silent.Write([]byte("x"))
	eventually(t, "the second pairing was never made", func() bool { return u.open() == 2 })
	forward(udpUnanswered + time.Second)
	eventually(t, "an unanswered pairing outlived its five seconds", func() bool { return u.open() == 1 })
	// The answered one lasts its idle time, and no longer.
	forward(20 * time.Second)
	time.Sleep(50 * time.Millisecond)
	if u.open() != 1 {
		t.Fatal("an answered pairing ended before its idle time")
	}
	forward(15 * time.Second)
	eventually(t, "an answered pairing outlived its idle time", func() bool { return u.open() == 0 })
}

// TestForgedSourcesCannotHoldTheTable: with every pairing taken by clients
// that never answered, a new client still gets in, and a client that was
// answered is never the one to go.
func TestForgedSourcesCannotHoldTheTable(t *testing.T) {
	tg := newUDPTarget(t, 1)
	u, s := startUDP(t, tg, func(s *Stream) { s.PerClient = 100000 })
	real := udpClientConn(t, s)
	_, _ = real.Write([]byte("hello"))
	recv(real, 200*time.Millisecond)
	_, _ = real.Write([]byte("again")) // answered
	recv(real, 200*time.Millisecond)

	// Many "clients" that each send once: on loopback they do get an answer,
	// but never send again, as a forged source could not.
	for i := range udpPairings + 50 {
		c := udpClientConn(t, s)
		_, _ = c.Write([]byte("flood " + strconv.Itoa(i)))
	}
	eventually(t, "the flood never filled the table", func() bool { return u.open() == udpPairings })
	if n := u.open(); n > udpPairings {
		t.Fatalf("%d pairings; the most is %d", n, udpPairings)
	}
	_, _ = real.Write([]byte("still here"))
	if got := recv(real, 500*time.Millisecond); len(got) != 1 || got[0] != "still here" {
		t.Fatalf("the answered client after the flood: %q; want it still served", got)
	}
	late := udpClientConn(t, s)
	_, _ = late.Write([]byte("late"))
	if got := recv(late, 500*time.Millisecond); len(got) != 1 {
		t.Fatalf("a new client with the table full of unanswered pairings: %q; want it let in", got)
	}
}

// TestAUDPStreamsLimits: a datagram over the size is dropped, not cut; a
// client outside the sources is not carried; one client holds only so many
// pairings.
func TestAUDPStreamsLimits(t *testing.T) {
	tg := newUDPTarget(t, 1)
	u, s := startUDP(t, tg, func(s *Stream) { s.PerClient = 3 })
	c := udpClientConn(t, s)
	_, _ = c.Write(make([]byte, udpPayload+100))
	_, _ = c.Write(make([]byte, udpPayload))
	eventually(t, "the datagram at the limit never arrived", func() bool { return tg.got.Load() == 1 })
	time.Sleep(50 * time.Millisecond)
	if tg.got.Load() != 1 || tg.largest.Load() != udpPayload {
		t.Fatalf("the target got %d datagrams, the largest of %d bytes; want the one of %d", tg.got.Load(), tg.largest.Load(), udpPayload)
	}
	if u.dropped.Load() < 1 {
		t.Fatal("the oversized datagram was not counted as dropped")
	}
	// Three pairings for this client, and no fourth.
	for range 5 {
		x := udpClientConn(t, s)
		_, _ = x.Write([]byte("p"))
	}
	time.Sleep(100 * time.Millisecond)
	if n := u.open(); n != 3 {
		t.Fatalf("one client holds %d pairings; its limit is 3", n)
	}

	// Sources named, and loopback is not among them: nothing is carried.
	tg2 := newUDPTarget(t, 1)
	u2, s2 := startUDP(t, tg2, func(s *Stream) { s.Allow = "192.0.2.0/24" })
	out := udpClientConn(t, s2)
	_, _ = out.Write([]byte("no"))
	if got := recv(out, 200*time.Millisecond); len(got) != 0 || tg2.got.Load() != 0 || u2.open() != 0 {
		t.Fatalf("a client outside the sources: answered %q, the target got %d", got, tg2.got.Load())
	}
	// A list that cannot be read lets nobody in.
	tg3 := newUDPTarget(t, 1)
	_, s3 := startUDP(t, tg3, func(s *Stream) { s.Allow = "127.0.0.0/8 everyone" })
	in := udpClientConn(t, s3)
	_, _ = in.Write([]byte("no"))
	if got := recv(in, 200*time.Millisecond); len(got) != 0 || tg3.got.Load() != 0 {
		t.Fatalf("a stream whose sources cannot be read carried a datagram: %q", got)
	}
}

// TestTheGatesStreamsAreOfBothKinds: the forwarder sends its UDP streams to
// the UDP forwarder; a TCP and a UDP stream may hold the same port number;
// taking a stream away ends it.
func TestTheGatesStreamsAreOfBothKinds(t *testing.T) {
	tg := newUDPTarget(t, 1)
	f := newForwarder(slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { f.stopAll(); cancel() })
	addr := freeUDPAddr(t) // free for UDP; the same number is asked of TCP too
	udp := Stream{Name: "forward:u", Proto: "udp", Listen: addr, To: tg.conn.LocalAddr().String()}
	tcp := Stream{Name: "forward:t", Listen: addr, To: plainEcho(t), IdleSecs: 30, PerClient: 5, Share: 4, Plain: true}
	f.apply(ctx, 10, []Stream{udp, tcp})
	eventually(t, "the UDP stream never bound", func() bool {
		f.udp.mu.Lock()
		defer f.udp.mu.Unlock()
		return f.udp.running[addr] != nil && f.udp.running[addr].conn != nil
	})
	c := udpClientConn(t, udp)
	_, _ = c.Write([]byte("u"))
	if got := recv(c, 300*time.Millisecond); len(got) != 1 {
		t.Fatalf("through the UDP stream: %q", got)
	}
	eventually(t, "the TCP stream on the same number never answered", func() bool {
		got, err := echoes(t, addr, "t")
		return err == nil && got == "t"
	})
	f.apply(ctx, 10, []Stream{tcp})
	eventually(t, "the UDP stream outlived its removal", func() bool {
		f.udp.mu.Lock()
		defer f.udp.mu.Unlock()
		return len(f.udp.running) == 0 && f.udp.pairings == 0
	})
}
