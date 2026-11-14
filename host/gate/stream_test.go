package gate

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestProxyHeaderIPv4(t *testing.T) {
	h := proxyHeader(netip.MustParseAddrPort("192.0.2.7:41000"), netip.MustParseAddrPort("198.51.100.1:25"))
	want := append([]byte("\r\n\r\n\x00\r\nQUIT\n"), 0x21, 0x11, 0, 12, 192, 0, 2, 7, 198, 51, 100, 1, 0xa0, 0x28, 0, 25)
	if !bytes.Equal(h, want) {
		t.Fatalf("header:\n got %x\nwant %x", h, want)
	}
}

func TestProxyHeaderIPv4Mapped(t *testing.T) {
	// A dual-stack listener reports an IPv4 client as ::ffff:a.b.c.d: still TCP over IPv4.
	h := proxyHeader(netip.MustParseAddrPort("[::ffff:192.0.2.7]:41000"), netip.MustParseAddrPort("[::ffff:198.51.100.1]:993"))
	if h[13] != 0x11 || len(h) != 16+12 {
		t.Fatalf("a mapped address should be TCP over IPv4: family %#x, %d bytes", h[13], len(h))
	}
}

func TestProxyHeaderIPv6(t *testing.T) {
	src := netip.MustParseAddrPort("[2001:db8::7]:41000")
	dst := netip.MustParseAddrPort("[2001:db8::1]:587")
	h := proxyHeader(src, dst)
	if h[12] != 0x21 || h[13] != 0x21 || binary.BigEndian.Uint16(h[14:16]) != 36 || len(h) != 16+36 {
		t.Fatalf("IPv6 header: % x", h[:16])
	}
	s16 := src.Addr().As16()
	if !bytes.Equal(h[16:32], s16[:]) || binary.BigEndian.Uint16(h[48:50]) != 41000 || binary.BigEndian.Uint16(h[50:52]) != 587 {
		t.Fatalf("IPv6 addresses or ports wrong: % x", h[16:])
	}
}

func TestClientPrefix(t *testing.T) {
	for in, want := range map[string]string{
		"192.0.2.7":            "192.0.2.7/32",
		"::ffff:192.0.2.7":     "192.0.2.7/32",
		"2001:db8:1:2:3::9":    "2001:db8:1:2::/64",
		"2001:db8:1:2:ffff::1": "2001:db8:1:2::/64",
	} {
		if got := clientPrefix(netip.MustParseAddr(in)).String(); got != want {
			t.Errorf("clientPrefix(%s) = %s, want %s", in, got, want)
		}
	}
}

// backend is the service behind a stream: it reads the PROXY header, reports
// it, then echoes what follows.
type backend struct {
	l       net.Listener
	headers chan []byte
}

func newBackend(t *testing.T) *backend {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b := &backend{l: l, headers: make(chan []byte, 64)}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				r := bufio.NewReader(c)
				h := make([]byte, 16)
				if _, err := io.ReadFull(r, h); err != nil {
					return
				}
				rest := make([]byte, binary.BigEndian.Uint16(h[14:16]))
				if _, err := io.ReadFull(r, rest); err != nil {
					return
				}
				select { // a test that reads no headers must not stall the echo
				case b.headers <- append(h, rest...):
				default:
				}
				_, _ = io.Copy(c, r)
				if tc, ok := c.(*net.TCPConn); ok {
					_ = tc.CloseWrite()
				}
			}()
		}
	}()
	t.Cleanup(func() { l.Close() })
	return b
}

func startForwarder(t *testing.T, total int, streams ...Stream) *forwarder {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	f := newForwarder(slog.New(slog.NewTextHandler(io.Discard, nil)))
	f.apply(ctx, total, streams)
	t.Cleanup(func() { f.stopAll(); cancel() })
	for _, s := range streams { // wait until each is bound
		deadline := time.Now().Add(3 * time.Second)
		for {
			c, err := net.Dial("tcp", s.Listen)
			if err == nil {
				c.Close()
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("stream %s never listened: %v", s.Name, err)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	// The probes above were forwarded too: wait until each has ended, so a
	// test starts with every limit free.
	deadline := time.Now().Add(3 * time.Second)
	for f.ended.Load() < int64(len(streams)) {
		if time.Now().After(deadline) {
			t.Fatal("the readiness probes never ended")
		}
		time.Sleep(5 * time.Millisecond)
	}
	waitOpen(t, f, 0)
	return f
}

func waitOpen(t *testing.T, f *forwarder, n int64) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for f.openNow() != n {
		if time.Now().After(deadline) {
			t.Fatalf("open connections: %d, want %d", f.openNow(), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestStreamForwardsWithHeader(t *testing.T) {
	b := newBackend(t)
	s := Stream{Name: "smtp", Listen: freeAddr(t), To: b.l.Addr().String(), IdleSecs: 30, PerClient: 5}
	startForwarder(t, 10, s)
	c, err := net.Dial("tcp", s.Listen)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	local := c.LocalAddr().(*net.TCPAddr)
	var h []byte
	for h == nil { // skip the readiness probes' headers
		select {
		case got := <-b.headers:
			if int(binary.BigEndian.Uint16(got[24:26])) == local.Port {
				h = got
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("no header names the client %s", local)
		}
	}
	if h[13] != 0x11 || !bytes.Equal(h[16:20], local.IP.To4()) || int(binary.BigEndian.Uint16(h[24:26])) != local.Port {
		t.Fatalf("the header does not name the client %s: % x", local, h)
	}
	if _, err := c.Write([]byte("EHLO example.com\r\n")); err != nil {
		t.Fatal(err)
	}
	_ = c.(*net.TCPConn).CloseWrite()
	got, err := io.ReadAll(c)
	if err != nil || string(got) != "EHLO example.com\r\n" {
		t.Fatalf("echo through the stream: %q, %v", got, err)
	}
}

func TestStreamPerClientLimit(t *testing.T) {
	b := newBackend(t)
	s := Stream{Name: "imaps", Listen: freeAddr(t), To: b.l.Addr().String(), IdleSecs: 30, PerClient: 2}
	f := startForwarder(t, 10, s)
	var held []net.Conn
	for i := 0; i < 2; i++ {
		c, err := net.Dial("tcp", s.Listen)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, c)
	}
	waitOpen(t, f, 2)
	c, err := net.Dial("tcp", s.Listen)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := c.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatalf("a third connection from one client should be closed at once: n=%d err=%v", n, err)
	}
	c.Close()
	if f.refused.Load() == 0 {
		t.Fatal("the refusal was not counted")
	}
	held[0].Close()
	waitOpen(t, f, 1)
	c, err = net.Dial("tcp", s.Listen)
	if err != nil {
		t.Fatal(err)
	}
	waitOpen(t, f, 2) // room again once one closed
	c.Close()
	held[1].Close()
}

func TestStreamTotalAndShare(t *testing.T) {
	b := newBackend(t)
	a := Stream{Name: "imaps", Listen: freeAddr(t), To: b.l.Addr().String(), IdleSecs: 30, Share: 2}
	o := Stream{Name: "smtp", Listen: freeAddr(t), To: b.l.Addr().String(), IdleSecs: 30}
	f := startForwarder(t, 3, a, o)
	dial := func(addr string) net.Conn {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	dial(a.Listen)
	dial(a.Listen)
	waitOpen(t, f, 2)
	dial(a.Listen) // over imaps' share of 2
	time.Sleep(100 * time.Millisecond)
	waitOpen(t, f, 2)
	dial(o.Listen) // smtp may still take the third of the total
	waitOpen(t, f, 3)
	dial(o.Listen) // over the total
	time.Sleep(100 * time.Millisecond)
	waitOpen(t, f, 3)
	if f.refused.Load() != 2 {
		t.Fatalf("refused: %d, want 2", f.refused.Load())
	}
}

func TestStreamIdleCloses(t *testing.T) {
	b := newBackend(t)
	s := Stream{Name: "smtp", Listen: freeAddr(t), To: b.l.Addr().String(), IdleSecs: 1}
	f := startForwarder(t, 10, s)
	c, err := net.Dial("tcp", s.Listen)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	waitOpen(t, f, 1)
	// Traffic keeps it open past the idle limit...
	for i := 0; i < 4; i++ {
		time.Sleep(400 * time.Millisecond)
		if _, err := c.Write([]byte("NOOP\r\n")); err != nil {
			t.Fatalf("closed while active: %v", err)
		}
		buf := make([]byte, 6)
		if _, err := io.ReadFull(c, buf); err != nil {
			t.Fatalf("closed while active: %v", err)
		}
	}
	// ...and silence closes it.
	start := time.Now()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("an idle connection should be closed")
	}
	if d := time.Since(start); d < 800*time.Millisecond || d > 3*time.Second {
		t.Fatalf("closed after %v, want about the idle limit of 1s", d)
	}
	waitOpen(t, f, 0)
}

func TestStreamOneWayTrafficIsNotIdle(t *testing.T) {
	// A download: the client sends nothing for longer than the idle limit while
	// the service streams to it. The quiet direction must not close it.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		h := make([]byte, 16)
		if _, err := io.ReadFull(r, h); err != nil {
			return
		}
		_, _ = io.ReadFull(r, make([]byte, binary.BigEndian.Uint16(h[14:16])))
		for i := 0; i < 8; i++ {
			time.Sleep(300 * time.Millisecond)
			if _, err := c.Write([]byte("* data\r\n")); err != nil {
				return
			}
		}
	}()
	s := Stream{Name: "imaps", Listen: freeAddr(t), To: l.Addr().String(), IdleSecs: 1}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := newForwarder(slog.New(slog.NewTextHandler(io.Discard, nil)))
	f.apply(ctx, 10, []Stream{s})
	defer f.stopAll()
	var c net.Conn
	for i := 0; i < 100; i++ {
		if c, err = net.Dial("tcp", s.Listen); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if c == nil {
		t.Fatal(err)
	}
	defer c.Close()
	got, _ := io.ReadAll(c)
	if want := bytes.Repeat([]byte("* data\r\n"), 8); !bytes.Equal(got, want) {
		t.Fatalf("got %d bytes of %d: the quiet direction closed a live connection", len(got), len(want))
	}
}

func TestStreamStopClosesConnections(t *testing.T) {
	b := newBackend(t)
	s := Stream{Name: "smtp", Listen: freeAddr(t), To: b.l.Addr().String(), IdleSecs: 30}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := newForwarder(slog.New(slog.NewTextHandler(io.Discard, nil)))
	f.apply(ctx, 10, []Stream{s})
	var c net.Conn
	var err error
	for i := 0; i < 100; i++ {
		if c, err = net.Dial("tcp", s.Listen); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if c == nil {
		t.Fatal(err)
	}
	defer c.Close()
	waitOpen(t, f, 1)

	// The same set again keeps the connection...
	f.apply(ctx, 10, []Stream{s})
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, make([]byte, 1)); err != nil {
		t.Fatalf("an unchanged stream dropped its connection: %v", err)
	}
	// ...and taking the stream away closes it and frees the port.
	f.apply(ctx, 10, nil)
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("a removed stream's connection should be closed")
	}
	if l, err := net.Listen("tcp", s.Listen); err != nil {
		t.Fatalf("a removed stream's port is still held: %v", err)
	} else {
		l.Close()
	}
	waitOpen(t, f, 0)
}

func TestStreamServiceDown(t *testing.T) {
	s := Stream{Name: "smtp", Listen: freeAddr(t), To: freeAddr(t), IdleSecs: 30}
	f := startForwarder(t, 10, s)
	c, err := net.Dial("tcp", s.Listen)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(7 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("with nothing behind the stream, the client should be closed")
	}
	waitOpen(t, f, 0)
}

func TestStreamManyAtOnce(t *testing.T) {
	b := newBackend(t)
	s := Stream{Name: "imaps", Listen: freeAddr(t), To: b.l.Addr().String(), IdleSecs: 30}
	f := startForwarder(t, 200, s)
	var wg sync.WaitGroup
	errs := make(chan error, 150)
	for i := 0; i < 150; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := net.Dial("tcp", s.Listen)
			if err != nil {
				errs <- err
				return
			}
			defer c.Close()
			msg := bytes.Repeat([]byte("a"), 64<<10)
			go func() { _, _ = c.Write(msg); _ = c.(*net.TCPConn).CloseWrite() }()
			got, err := io.ReadAll(c)
			if err != nil || len(got) != len(msg) {
				errs <- fmt.Errorf("echoed %d of %d bytes: %v", len(got), len(msg), err)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	waitOpen(t, f, 0)
}

// TestStreamClientSpeaksLate: a client that sends its first bytes after the
// header's dial deadline has passed is still carried (the header's write
// deadline must not outlive the header).
func TestStreamClientSpeaksLate(t *testing.T) {
	if testing.Short() {
		t.Skip("waits past the dial deadline")
	}
	b := newBackend(t)
	s := Stream{Name: "submission", Listen: freeAddr(t), To: b.l.Addr().String(), IdleSecs: 60}
	startForwarder(t, 10, s)
	c, err := net.Dial("tcp", s.Listen)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	time.Sleep(dialTimeout + time.Second)
	if _, err := c.Write([]byte("EHLO late.example.com\r\n")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("EHLO late.example.com\r\n"))
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("bytes sent after the header's deadline were not carried: %v", err)
	}
}
