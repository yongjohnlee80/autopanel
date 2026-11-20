package gate

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	core "github.com/yongjohnlee80/autopanel/core/gate"
)

func noTrust() Trusted { return nil }

func loopbackTrusted() Trusted { return Trusted{netip.MustParsePrefix("127.0.0.0/8")} }

// buffersOf reads a TCP connection's kernel buffers.
func buffersOf(t *testing.T, c net.Conn) (recv, send int) {
	t.Helper()
	sc, ok := c.(syscall.Conn)
	if !ok {
		t.Fatalf("%T is no socket", c)
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	recv, send, err = socketBuffersOf(raw)
	if err != nil {
		t.Fatal(err)
	}
	return recv, send
}

// TestSocketsHaveFixedBuffers: a connection the listener accepts and one the
// upstream transport dials have the buffers bounds.go names, from the start.
// (Linux counts twice what is set.)
func TestSocketsHaveFixedBuffers(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the kernel's doubling is Linux's")
	}
	ln, err := listenBounded(context.Background(), "127.0.0.1:0", 8, 8, noTrust)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	d := net.Dialer{Control: socketBuffers(upstreamRecvBuffer, upstreamSendBuffer)}
	up, err := d.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	if r, s := buffersOf(t, up); r != 2*upstreamRecvBuffer || s != 2*upstreamSendBuffer {
		t.Errorf("an upstream socket's buffers are %d and %d; want %d and %d", r, s, 2*upstreamRecvBuffer, 2*upstreamSendBuffer)
	}
	c := <-accepted
	defer c.Close()
	if r, s := buffersOf(t, c.(*countedConn).Conn); r != 2*acceptRecvBuffer || s != 2*acceptSendBuffer {
		t.Errorf("an accepted socket's buffers are %d and %d; want %d and %d", r, s, 2*acceptRecvBuffer, 2*acceptSendBuffer)
	}
	// The transport dials through the same control.
	tr := newUpstreamTransport()
	uc, err := tr.DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	if r, s := buffersOf(t, uc); r != 2*upstreamRecvBuffer || s != 2*upstreamSendBuffer {
		t.Errorf("the transport's socket has %d and %d", r, s)
	}
	if tr.MaxResponseHeaderBytes != upstreamHeaderBytes || tr.ForceAttemptHTTP2 || tr.TLSNextProto == nil || tr.MaxIdleConns != upstreamIdleConns {
		t.Errorf("the upstream transport lost a bound: %+v", tr)
	}
}

// held reports whether the listener kept c open: a refused connection is
// closed at once, so a read ends; a held one is silent.
func held(c net.Conn) bool {
	_ = c.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	_, err := c.Read(make([]byte, 1))
	var ne net.Error
	return err != nil && errorsAs(err, &ne) && ne.Timeout()
}

func errorsAs(err error, target *net.Error) bool {
	for err != nil {
		if ne, ok := err.(net.Error); ok {
			*target = ne
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// TestAListenerHoldsItsConnections: one more than a peer's share is closed at
// once, and one more than the listener's; a trusted proxy has no share of its
// own; a closed connection frees its places, exactly once.
func TestAListenerHoldsItsConnections(t *testing.T) {
	for _, tc := range []struct {
		name          string
		trusted       func() Trusted
		max, perPeer  int
		wantHeld      int // of five dialled
		wantPeersLeft int
	}{
		{"an untrusted peer has its share", noTrust, 4, 2, 2, 1},
		{"a trusted proxy has the listener's", loopbackTrusted, 4, 2, 4, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := listenBounded(context.Background(), "127.0.0.1:0", tc.max, tc.perPeer, tc.trusted)
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			var mu sync.Mutex
			var served []net.Conn
			go func() {
				for {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					mu.Lock()
					served = append(served, c)
					mu.Unlock()
				}
			}()
			var clients []net.Conn
			n := 0
			for range 5 {
				c, err := net.Dial("tcp", ln.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				clients = append(clients, c)
				if held(c) {
					n++
				}
			}
			if n != tc.wantHeld || ln.openNow() != tc.wantHeld {
				t.Fatalf("%d of 5 connections were held (the listener counts %d); want %d", n, ln.openNow(), tc.wantHeld)
			}
			if got := int(ln.refused.Load()); got != 5-tc.wantHeld {
				t.Errorf("%d refused; want %d", got, 5-tc.wantHeld)
			}
			ln.mu.Lock()
			peers := len(ln.peers)
			ln.mu.Unlock()
			if peers != tc.wantPeersLeft {
				t.Errorf("%d peers counted; want %d", peers, tc.wantPeersLeft)
			}
			// Closing one twice frees one place; the next connection takes it.
			mu.Lock()
			first := served[0]
			mu.Unlock()
			_ = first.Close()
			_ = first.Close()
			if ln.openNow() != tc.wantHeld-1 {
				t.Fatalf("after a close the listener counts %d; want %d", ln.openNow(), tc.wantHeld-1)
			}
			c, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if !held(c) {
				t.Fatal("a freed place was not given to the next connection")
			}
			mu.Lock()
			for _, s := range served {
				_ = s.Close()
			}
			mu.Unlock()
			ln.mu.Lock()
			defer ln.mu.Unlock()
			if ln.open != 0 || len(ln.peers) != 0 {
				t.Errorf("with every connection closed the listener counts %d, and %d peers", ln.open, len(ln.peers))
			}
		})
	}
}

// TestWhoARequestIsCountedAs: the header names the client only from a trusted
// peer, and only when it is one plain address; IPv6 is counted by /64, and an
// IPv4 address written as IPv6 is that IPv4 address.
func TestWhoARequestIsCountedAs(t *testing.T) {
	cf := Trusted{netip.MustParsePrefix("173.245.48.0/20"), netip.MustParsePrefix("2400:cb00::/32")}
	for _, tc := range []struct {
		name, remote string
		headers      []string
		want         string
	}{
		{"an untrusted peer is itself", "198.51.100.7:4000", nil, "198.51.100.7/32"},
		{"its header is ignored", "198.51.100.7:4000", []string{"203.0.113.9"}, "198.51.100.7/32"},
		{"a trusted peer's header names the client", "173.245.48.5:443", []string{"203.0.113.9"}, "203.0.113.9/32"},
		{"IPv6 is its /64", "173.245.48.5:443", []string{"2001:db8:1:2:3:4:5:6"}, "2001:db8:1:2::/64"},
		{"IPv4 written as IPv6 is IPv4", "173.245.48.5:443", []string{"::ffff:203.0.113.9"}, "203.0.113.9/32"},
		{"a trusted peer over IPv4-in-IPv6", "[::ffff:173.245.48.5]:443", []string{"203.0.113.9"}, "203.0.113.9/32"},
		{"two headers: the peer", "173.245.48.5:443", []string{"203.0.113.9", "203.0.113.10"}, "173.245.48.5/32"},
		{"a list in one header: the peer", "173.245.48.5:443", []string{"203.0.113.9, 203.0.113.10"}, "173.245.48.5/32"},
		{"a zone: the peer", "173.245.48.5:443", []string{"fe80::1%eth0"}, "173.245.48.5/32"},
		{"not an address: the peer", "173.245.48.5:443", []string{"example.com"}, "173.245.48.5/32"},
		{"no header: the peer", "[2400:cb00::1]:443", nil, "2400:cb00::/64"},
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = tc.remote
		for _, h := range tc.headers {
			r.Header.Add(cfConnectingIP, h)
		}
		if got := clientOf(r, cf).String(); got != tc.want {
			t.Errorf("%s: counted as %s; want %s", tc.name, got, tc.want)
		}
	}
}

// TestRequestsInFlightAreBounded: with every place taken the next request is
// answered 503 at once and counted; one client has its share and no more;
// a place given back is the next request's; nothing is left counted.
func TestRequestsInFlightAreBounded(t *testing.T) {
	f := newInFlight(3, 2)
	release := make(chan struct{})
	entered := make(chan struct{}, 8)
	h := proxied(f, loopbackTrusted, time.Minute, time.Minute, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-release
	}))
	srv := httptest.NewServer(h)
	defer srv.Close()
	get := func(client string) (*http.Response, error) {
		req, _ := http.NewRequest("GET", srv.URL, nil)
		req.Header.Set(cfConnectingIP, client)
		return (&http.Client{Timeout: 5 * time.Second}).Do(req)
	}
	var wg sync.WaitGroup
	hold := func(client string) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if res, err := get(client); err == nil {
				res.Body.Close()
			}
		}()
		<-entered
	}
	hold("203.0.113.1")
	hold("203.0.113.1")
	// The client's share is taken, though the gate has a place left.
	res, err := get("203.0.113.1")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusServiceUnavailable || res.Header.Get("Retry-After") == "" {
		t.Fatalf("a client over its share got %d (Retry-After %q); want 503", res.StatusCode, res.Header.Get("Retry-After"))
	}
	hold("203.0.113.2")
	// Every place is taken: another client is refused too.
	start := time.Now()
	res, err = get("203.0.113.3")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusServiceUnavailable || time.Since(start) > time.Second {
		t.Fatalf("a request over the limit got %d after %s; want 503 at once", res.StatusCode, time.Since(start))
	}
	if f.now() != 3 || f.refused.Load() != 2 {
		t.Fatalf("%d in flight, %d refused; want 3 and 2", f.now(), f.refused.Load())
	}
	close(release)
	wg.Wait()
	until(t, "the places were not given back", func() bool { return f.now() == 0 })
	f.mu.Lock()
	left := len(f.clients)
	f.mu.Unlock()
	if left != 0 {
		t.Fatalf("%d clients still counted with nothing in flight", left)
	}
	res, err = get("203.0.113.3")
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("a freed place was not the next request's: %v, %v", res, err)
	}
	res.Body.Close()
}

// proxyTo is a route's proxy to an upstream, behind the bounds.
func proxyTo(t *testing.T, upstream string, stall, upgraded time.Duration) (*httptest.Server, *inFlight) {
	t.Helper()
	u, err := url.Parse(upstream)
	if err != nil {
		t.Fatal(err)
	}
	f := newInFlight(8, 8)
	rp := &httputil.ReverseProxy{Transport: newUpstreamTransport(), BufferPool: proxyBuffers,
		Rewrite:      func(pr *httputil.ProxyRequest) { pr.SetURL(u) },
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) { w.WriteHeader(http.StatusBadGateway) }}
	srv := httptest.NewServer(proxied(f, noTrust, stall, upgraded, rp))
	t.Cleanup(srv.Close)
	return srv, f
}

// TestARequestThatStopsMovingIsEnded: an upstream that never answers, and one
// that stops in the middle of its answer, are given up at the limit and their
// places freed; an upload and an answer that keep moving, slowly, for longer
// than the limit are not.
func TestARequestThatStopsMovingIsEnded(t *testing.T) {
	const stall = 150 * time.Millisecond
	never := make(chan struct{})
	defer close(never)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/never":
			select {
			case <-never:
			case <-r.Context().Done():
			}
		case "/half":
			w.Header().Set("Content-Length", "1000")
			_, _ = w.Write([]byte("half"))
			w.(http.Flusher).Flush()
			select {
			case <-never:
			case <-r.Context().Done():
			}
		case "/slow": // an upload and an answer, a byte every 40 ms for 600 ms
			n, _ := io.Copy(io.Discard, r.Body)
			for range 15 {
				_, _ = w.Write([]byte("x"))
				w.(http.Flusher).Flush()
				time.Sleep(40 * time.Millisecond)
			}
			_, _ = io.WriteString(w, " got "+strings.Repeat("u", int(n)))
		}
	}))
	defer up.Close()
	srv, f := proxyTo(t, up.URL, stall, time.Minute)
	client := &http.Client{Timeout: 10 * time.Second}

	start := time.Now()
	res, err := client.Get(srv.URL + "/never")
	if err == nil {
		res.Body.Close()
		if res.StatusCode == 200 {
			t.Fatal("an upstream that never answers was answered for")
		}
	}
	if d := time.Since(start); d < stall || d > 20*stall {
		t.Fatalf("a wait for the upstream ended after %s; the limit is %s", d, stall)
	}

	start = time.Now()
	res, err = client.Get(srv.URL + "/half")
	if err == nil {
		_, err = io.ReadAll(res.Body)
		res.Body.Close()
	}
	if err == nil {
		t.Fatal("an answer that stopped half way was read whole")
	}
	if d := time.Since(start); d < stall || d > 20*stall {
		t.Fatalf("a stalled answer ended after %s; the limit is %s", d, stall)
	}
	until(t, "the stalled requests kept their places", func() bool { return f.now() == 0 })

	pr, pw := io.Pipe()
	go func() {
		for range 15 {
			_, _ = pw.Write([]byte("u"))
			time.Sleep(40 * time.Millisecond)
		}
		pw.Close()
	}()
	res, err = client.Post(srv.URL+"/slow", "application/octet-stream", pr)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil || !strings.HasSuffix(string(body), " got "+strings.Repeat("u", 15)) {
		t.Fatalf("a slow request that kept moving for longer than the limit was cut: %q, %v", body, err)
	}
}

// TestAnUpgradedConnectionHasItsOwnLimit: once a connection is upgraded (a
// WebSocket) it may be quiet for longer than a request, bytes either way keep
// it, and with none for its own limit it is closed and its place freed.
func TestAnUpgradedConnectionHasItsOwnLimit(t *testing.T) {
	const stall, upgraded = 100 * time.Millisecond, 400 * time.Millisecond
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: echo\r\nConnection: Upgrade\r\n\r\n")
		_ = brw.Flush()
		_, _ = io.Copy(c, brw) // echo
	}))
	defer up.Close()
	srv, f := proxyTo(t, up.URL, stall, upgraded)
	c, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = io.WriteString(c, "GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: echo\r\nConnection: Upgrade\r\n\r\n")
	br := bufio.NewReader(c)
	res, err := http.ReadResponse(br, nil)
	if err != nil || res.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("the upgrade: %v, %v", res, err)
	}
	echo := func(msg string) error {
		if _, err := io.WriteString(c, msg); err != nil {
			return err
		}
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, len(msg))
		_, err := io.ReadFull(br, buf)
		return err
	}
	// Quiet for longer than a request may be, three times over: still up.
	for i := range 3 {
		time.Sleep(2 * stall)
		if err := echo("ping"); err != nil {
			t.Fatalf("the upgraded connection was cut while it kept moving (round %d): %v", i, err)
		}
	}
	// Silent for its own limit: closed.
	_ = c.SetReadDeadline(time.Now().Add(10 * upgraded))
	start := time.Now()
	if _, err := br.ReadByte(); err == nil {
		t.Fatal("a silent upgraded connection sent a byte")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("a silent upgraded connection was never closed")
	}
	if d := time.Since(start); d < upgraded/2 {
		t.Fatalf("the upgraded connection was closed after only %s of silence", d)
	}
	until(t, "the upgraded connection kept its place", func() bool { return f.now() == 0 })
}

// TestAnUpstreamsHeadersAreBounded: an answer whose headers pass the limit,
// in one large field or in many small ones, is a 502 and never reaches the
// client.
func TestAnUpstreamsHeadersAreBounded(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/one":
			w.Header().Set("X-Large", strings.Repeat("a", upstreamHeaderBytes+1024))
		case "/many":
			for i := range upstreamHeaderBytes/14 + 512 { // each line is 14 bytes on the wire
				w.Header().Set(fmt.Sprintf("X-K%05d", i), "v")
			}
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer up.Close()
	srv, _ := proxyTo(t, up.URL, time.Minute, time.Minute)
	for path, want := range map[string]int{"/small": 200, "/one": http.StatusBadGateway, "/many": http.StatusBadGateway} {
		res, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != want {
			t.Errorf("%s: %d; want %d", path, res.StatusCode, want)
		}
	}
}

// TestTheUnitsLimitsHoldTheLedger: the gate's unit gives it the ledger's sum
// and a fifth more, the runtime its own part and room, and the kernel's part
// fits between the two; so a bound cannot be raised without the unit.
func TestTheUnitsLimitsHoldTheLedger(t *testing.T) {
	unit, err := os.ReadFile("../../deploy/autopanel-gate.service")
	if err != nil {
		t.Fatal(err)
	}
	mib := func(key, suffix string) int {
		for _, line := range strings.Split(string(unit), "\n") {
			if v, ok := strings.CutPrefix(line, key); ok {
				n, err := strconv.Atoi(strings.TrimSuffix(v, suffix))
				if err != nil {
					t.Fatalf("%s%s: %v", key, v, err)
				}
				return n << 20
			}
		}
		t.Fatalf("the unit has no %s", key)
		return 0
	}
	max, high, golimit := mib("MemoryMax=", "M"), mib("MemoryHigh=", "M"), mib("Environment=GOMEMLIMIT=", "MiB")
	worst, heap := WorstBytes(), WorstHeapBytes()
	t.Logf("worst %d MiB (heap %d MiB); MemoryMax %d, MemoryHigh %d, GOMEMLIMIT %d MiB", worst>>20, heap>>20, max>>20, high>>20, golimit>>20)
	if high < worst+worst/8 || max < high+high/10 {
		t.Errorf("MemoryHigh %d MiB and MemoryMax %d MiB do not hold the ledger's %d MiB with room", high>>20, max>>20, worst>>20)
	}
	if golimit < heap+heap/8 {
		t.Errorf("GOMEMLIMIT %d MiB does not hold the runtime's part, %d MiB, with room", golimit>>20, heap>>20)
	}
	if kernel := worst - heap; golimit+kernel > high {
		t.Errorf("GOMEMLIMIT %d MiB and the kernel's part %d MiB pass MemoryHigh %d MiB", golimit>>20, kernel>>20, high>>20)
	}
}

// TestAWideGrantIsItsConnectionsForLife: a connection given a wide grant has
// a larger send buffer (as large as the host lets a socket have) and keeps it and
// the grant until it closes; the grants are a fixed number, and one client's
// a share; a closed connection's grant is the next one's.
func TestAWideGrantIsItsConnectionsForLife(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("socket buffers are read back as Linux counts them")
	}
	ln, err := listenBounded(context.Background(), "127.0.0.1:0", 64, 64, noTrust)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ln.cooling = 0 // a grant is the next connection's at once: cooling has its own test
	next := func() *countedConn {
		done := make(chan net.Conn, 1)
		go func() { c, _ := ln.Accept(); done <- c }()
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		s := <-done
		t.Cleanup(func() { s.Close() })
		return s.(*countedConn)
	}
	a, b := netip.MustParsePrefix("203.0.113.1/32"), netip.MustParsePrefix("203.0.113.2/32")
	first := next()
	r0, s0 := buffersOf(t, first.tcp)
	if r0 != 2*acceptRecvBuffer || s0 != 2*acceptSendBuffer {
		t.Fatalf("a new connection's buffers are %d and %d; want %d and %d", r0, s0, 2*acceptRecvBuffer, 2*acceptSendBuffer)
	}
	if !first.widen(a) || !first.widen(a) { // asked twice: one grant
		t.Fatal("a grant was refused with every one free")
	}
	if r, s := buffersOf(t, first.tcp); r != r0 || s <= s0 {
		t.Fatalf("a widened connection's buffers are %d to receive and %d to send; they were %d and %d, and only the second grows", r, s, r0, s0)
	}
	if ln.wide.now() != 1 {
		t.Fatalf("%d grants counted for one connection", ln.wide.now())
	}
	held := []*countedConn{first}
	for len(held) < widePerClient {
		c := next()
		if !c.widen(a) {
			t.Fatalf("grant %d of a client's %d was refused", len(held)+1, widePerClient)
		}
		held = append(held, c)
	}
	if next().widen(a) {
		t.Fatal("a client took more than its share of the grants")
	}
	for ln.wide.now() < wideGrants {
		c := next()
		if !c.widen(b) {
			break
		}
		held = append(held, c)
	}
	if got := ln.wide.now(); got != min(wideGrants, 2*widePerClient) {
		t.Fatalf("%d grants held by two clients; want %d", got, min(wideGrants, 2*widePerClient))
	}
	// A grant comes back only when its connection closes, and once.
	_ = held[0].Close()
	_ = held[0].Close()
	if got := ln.wide.now(); got != min(wideGrants, 2*widePerClient)-1 {
		t.Fatalf("after a close %d grants are held", got)
	}
	if held[0].widen(a) {
		t.Fatal("a closed connection was given a grant")
	}
	if !next().widen(a) {
		t.Fatal("a freed grant was not the next connection's")
	}
}

// TestALargeDownloadWidensItsConnection: through a server on the bounded
// listener, an answer that has sent more than wideAfter takes a grant for
// its connection; a small one takes none, and so does an upload however
// large; the grant goes when the connection closes.
func TestALargeDownloadWidensItsConnection(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		want, _ := strconv.Atoi(r.URL.Query().Get("send"))
		_, _ = io.WriteString(w, strconv.FormatInt(n, 10)+" "+strings.Repeat("d", want))
	}))
	defer up.Close()
	u, _ := url.Parse(up.URL)
	ln, err := listenBounded(context.Background(), "127.0.0.1:0", 16, 16, noTrust)
	if err != nil {
		t.Fatal(err)
	}
	ln.cooling = 0
	f := newInFlight(8, 8)
	rp := &httputil.ReverseProxy{Transport: newUpstreamTransport(), BufferPool: proxyBuffers, Rewrite: func(pr *httputil.ProxyRequest) { pr.SetURL(u) }}
	srv := &http.Server{Handler: proxied(f, noTrust, time.Minute, time.Minute, rp), ConnContext: connContext}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()
	tr := &http.Transport{}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	ask := func(upload, download int) {
		t.Helper()
		res, err := client.Post("http://"+ln.Addr().String()+"/x?send="+strconv.Itoa(download), "application/octet-stream", strings.NewReader(strings.Repeat("u", upload)))
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if want := strconv.Itoa(upload) + " "; !strings.HasPrefix(string(body), want) || len(body) != len(want)+download {
			t.Fatalf("an upload of %d and a download of %d came back as %d bytes starting %.12q", upload, download, len(body), body)
		}
	}
	ask(10, wideAfter/4)
	if ln.wide.now() != 0 {
		t.Fatal("a small answer took a wide grant")
	}
	ask(3*wideAfter, 10)
	if ln.wide.now() != 0 {
		t.Fatal("an upload took a wide grant: a connection's receive buffer never changes")
	}
	ask(10, 3*wideAfter)
	if ln.wide.now() != 1 {
		t.Fatalf("%d grants after a large download; want its connection's one", ln.wide.now())
	}
	ask(10, 3*wideAfter) // the same connection, kept alive: still the one grant
	if ln.wide.now() != 1 {
		t.Fatalf("%d grants after a second large download on the connection", ln.wide.now())
	}
	tr.CloseIdleConnections()
	until(t, "the grant outlived its connection", func() bool { return ln.wide.now() == 0 })
}

// TestTheGateTurnsAwayWhatIsOverItsLimits drives the whole gate: one client
// may hold its share of the requests in flight and no more, the next is
// answered 503 over TLS, a site's other clients are still served, and the
// gate's report counts what it refused.
func TestTheGateTurnsAwayWhatIsOverItsLimits(t *testing.T) {
	defer func(d time.Duration) { ReportEvery = d }(ReportEvery)
	ReportEvery = 30 * time.Millisecond
	release := make(chan struct{})
	entered := make(chan struct{}, proxyPerClient+4)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hold" {
			entered <- struct{}{}
			<-release
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer up.Close()
	f := newFakeCore(t, freeAddr(t), freeAddr(t))
	f.hold("app.example.com")
	f.mu.Lock()
	f.hello.Trusted = []string{"127.0.0.0/8"} // the test's own address is a proxy: the header names the client
	f.mu.Unlock()
	f.setRoutes(core.RouteView{ID: 1, Host: "app.example.com", PathPrefix: "/", Upstream: up.URL})
	startGate(t, f)
	f.mu.Lock()
	addr, pool := f.hello.HTTPS, f.pool
	f.mu.Unlock()
	client := func() *http.Client {
		return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "app.example.com"},
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "tcp", addr)
			}}}
	}
	ask := func(c *http.Client, path, as string) (int, error) {
		req, _ := http.NewRequest("GET", "https://app.example.com"+path, nil)
		req.Header.Set(cfConnectingIP, as)
		res, err := c.Do(req)
		if err != nil {
			return 0, err
		}
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()
		return res.StatusCode, nil
	}
	var wg sync.WaitGroup
	for range proxyPerClient {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := client()
			defer c.CloseIdleConnections()
			_, _ = ask(c, "/hold", "203.0.113.1")
		}()
	}
	for range proxyPerClient {
		select {
		case <-entered:
		case <-time.After(10 * time.Second):
			t.Fatal("the client's share of requests never reached the upstream")
		}
	}
	c := client()
	defer c.CloseIdleConnections()
	if code, err := ask(c, "/hold", "203.0.113.1"); err != nil || code != http.StatusServiceUnavailable {
		t.Fatalf("a client over its share: %d, %v; want 503", code, err)
	}
	if code, err := ask(c, "/", "203.0.113.2"); err != nil || code != 200 {
		t.Fatalf("another client while one holds its share: %d, %v", code, err)
	}
	until(t, "the gate never reported what it refused", func() bool {
		r := f.lastReport()
		return r.ProxiedRefused == 1 && r.ProxiedNow == proxyPerClient && r.ConnsOpen > 0
	})
	close(release)
	wg.Wait()
}

// blockingConn is a connection whose Close waits to be let go.
type blockingConn struct {
	net.Conn
	closing chan struct{}
	release chan struct{}
}

func (c *blockingConn) Close() error {
	close(c.closing)
	<-c.release
	return nil
}

// TestAPlaceIsFreeOnlyOnceItsSocketIsClosed: while a connection's close is
// still under way its place and its grant are not another's; a wide grant
// comes back only after cooling, and at once after an abort.
func TestAPlaceIsFreeOnlyOnceItsSocketIsClosed(t *testing.T) {
	ln, err := listenBounded(context.Background(), "127.0.0.1:0", 8, 8, noTrust)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ln.cooling = 150 * time.Millisecond
	accept := func() *countedConn {
		done := make(chan net.Conn, 1)
		go func() { c, _ := ln.Accept(); done <- c }()
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return (<-done).(*countedConn)
	}
	client := netip.MustParsePrefix("203.0.113.1/32")
	c := accept()
	if !c.widen(client) {
		t.Fatal("no grant")
	}
	// Something its peer has not taken: the client never reads.
	if _, err := c.tcp.Write(make([]byte, 256<<10)); err != nil {
		t.Fatal(err)
	}
	if n, err := sendQueued(c.tcp); err != nil || n == 0 {
		t.Fatalf("the socket has %d bytes left to send, %v; the test needs some", n, err)
	}
	real := c.Conn
	slow := &blockingConn{Conn: real, closing: make(chan struct{}), release: make(chan struct{})}
	c.Conn = slow
	closed := make(chan struct{})
	go func() { _ = c.Close(); close(closed) }()
	<-slow.closing
	if ln.openNow() != 1 || ln.wide.now() != 1 {
		t.Fatalf("with the close under way the listener counts %d connections and %d grants; want 1 and 1", ln.openNow(), ln.wide.now())
	}
	close(slow.release)
	<-closed
	_ = real.Close()
	if ln.openNow() != 0 {
		t.Fatalf("after the close the listener counts %d", ln.openNow())
	}
	if ln.wide.now() != 1 {
		t.Fatal("the grant came back before it had cooled")
	}
	until(t, "the grant never came back", func() bool { return ln.wide.now() == 0 })

	// A connection that closes with nothing left to send keeps nothing in the
	// kernel: its grant is back at once, however long the cooling.
	ln.cooling = time.Hour
	e := accept()
	if !e.widen(client) {
		t.Fatal("no grant for the connection with nothing to send")
	}
	_ = e.Close()
	if ln.wide.now() != 0 {
		t.Fatal("a connection that closed with nothing left to send had its grant kept to cool")
	}

	// An abort leaves the kernel nothing: the grant is back at once.
	a := accept()
	if !a.widen(client) {
		t.Fatal("no grant for the second connection")
	}
	if _, err := a.tcp.Write(make([]byte, 256<<10)); err != nil {
		t.Fatal(err)
	}
	a.abort()
	_ = a.Close()
	if ln.wide.now() != 0 {
		t.Fatal("an aborted connection's grant was kept to cool")
	}
}

// h2Frame writes one HTTP/2 frame.
func h2Frame(w io.Writer, typ, flags byte, stream uint32, payload []byte) error {
	h := []byte{byte(len(payload) >> 16), byte(len(payload) >> 8), byte(len(payload)), typ, flags, byte(stream >> 24), byte(stream >> 16), byte(stream >> 8), byte(stream)}
	_, err := w.Write(append(h, payload...))
	return err
}

// hpackLiteral is a header field sent as a literal, never indexed, with no
// Huffman coding: the simplest thing a client may send.
func hpackLiteral(name, value string) []byte {
	n := func(v int) []byte { // an integer with a 7-bit prefix
		if v < 127 {
			return []byte{byte(v)}
		}
		out := []byte{127}
		for v -= 127; v >= 128; v /= 128 {
			out = append(out, byte(v%128+128))
		}
		return append(out, byte(v))
	}
	out := []byte{0}
	out = append(append(out, n(len(name))...), name...)
	return append(append(out, n(len(value))...), value...)
}

// TestAnAnswerNobodyTakesIsNotKeptOverHTTP2: a client that gives a stream no
// credit to answer into cannot keep the answer waiting once the request's
// place is given back. An admitted request's answer is flushed under its
// clock, so the stream is reset at the limit; a refusal's is reset at its own
// deadline.
func TestAnAnswerNobodyTakesIsNotKeptOverHTTP2(t *testing.T) {
	defer refusalWriteFor.Store(refusalWriteFor.Load())
	refusalWriteFor.Store(int64(100 * time.Millisecond))
	for _, tc := range []struct {
		name    string
		places  int
		handler http.HandlerFunc
	}{
		{"an admitted request", 1, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }},
		{"a refusal", 0, func(http.ResponseWriter, *http.Request) {}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newInFlight(tc.places, 1)
			srv := httptest.NewUnstartedServer(proxied(f, noTrust, 50*time.Millisecond, time.Second, tc.handler))
			srv.EnableHTTP2 = true
			srv.Config.HTTP2 = &http.HTTP2Config{MaxConcurrentStreams: h2Streams, MaxReceiveBufferPerStream: h2StreamWindow, MaxReceiveBufferPerConnection: h2ConnWindow}
			srv.StartTLS()
			defer srv.Close()
			c, err := tls.Dial("tcp", srv.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_, _ = io.WriteString(c, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
			// SETTINGS: INITIAL_WINDOW_SIZE (4) = 0: no stream may be answered into.
			if err := h2Frame(c, 4, 0, 0, []byte{0, 4, 0, 0, 0, 0}); err != nil {
				t.Fatal(err)
			}
			var block []byte
			for _, h := range [][2]string{{":method", "POST"}, {":scheme", "https"}, {":authority", "example.com"}, {":path", "/"}} {
				block = append(block, hpackLiteral(h[0], h[1])...)
			}
			if err := h2Frame(c, 1, 4, 1, block); err != nil { // HEADERS, END_HEADERS, the body still to come
				t.Fatal(err)
			}
			_ = h2Frame(c, 0, 0, 1, make([]byte, 16384)) // DATA
			// Read frames until the stream is reset, or give up.
			reset := make(chan struct{})
			go func() {
				head := make([]byte, 9)
				for {
					if _, err := io.ReadFull(c, head); err != nil {
						return
					}
					n := int(head[0])<<16 | int(head[1])<<8 | int(head[2])
					if _, err := io.CopyN(io.Discard, c, int64(n)); err != nil {
						return
					}
					if head[3] == 3 && head[8] == 1 { // RST_STREAM for stream 1
						close(reset)
						return
					}
				}
			}()
			select {
			case <-reset:
			case <-time.After(5 * time.Second):
				t.Fatalf("the stream was never reset: its answer waits on a client that takes nothing (%d in flight)", f.now())
			}
			until(t, "the request kept its place", func() bool { return f.now() == 0 })
		})
	}
}

// TestAForwardedConnectionsWindowIsItsBuffers: a forwarded port's listening
// socket has a small receive buffer, for the connections waiting on it; once
// one is accepted its buffer is the forwarder's and its window may grow to
// that, not stay at what the small one allowed.
func TestAForwardedConnectionsWindowIsItsBuffers(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("TCP_WINDOW_CLAMP is read back as Linux keeps it")
	}
	lc := net.ListenConfig{Control: socketBuffers(forwardQueued, clientBuffer)}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); done <- c }()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	accepted := (<-done).(*net.TCPConn)
	defer accepted.Close()
	clamp := func() int {
		raw, err := accepted.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var v int
		var serr error
		if err := raw.Control(func(fd uintptr) {
			v, serr = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_WINDOW_CLAMP)
		}); err != nil || serr != nil {
			t.Fatal(err, serr)
		}
		return v
	}
	if got := clamp(); got >= clientBuffer {
		t.Fatalf("a connection waiting on a forwarded port may already receive %d; the small buffer is not in force", got)
	}
	// As the forwarder does on accept.
	if err := accepted.SetReadBuffer(clientBuffer); err != nil {
		t.Fatal(err)
	}
	if err := widenWindow(accepted, clientBuffer); err != nil {
		t.Fatal(err)
	}
	if got := clamp(); got < clientBuffer {
		t.Fatalf("an accepted forwarded connection's window is held to %d, under its buffer of %d", got, clientBuffer)
	}
}

// TestAConnectionsFramesFitItsAllowance: a connection that has sent only the
// start of the largest HTTP/2 frame the server reads holds no more than a
// connection is counted for. (Left to itself the server reads frames of a
// megabyte, and holds a buffer of that for every connection.)
func TestAConnectionsFramesFitItsAllowance(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.EnableHTTP2 = true
	srv.Config.MaxHeaderBytes = httpsHeaderBytes
	srv.Config.HTTP2 = &http.HTTP2Config{MaxConcurrentStreams: h2Streams, MaxReceiveBufferPerStream: h2StreamWindow,
		MaxReceiveBufferPerConnection: h2ConnWindow, MaxReadFrameSize: h2FrameBytes}
	srv.StartTLS()
	defer srv.Close()
	live := func() uint64 {
		runtime.GC()
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return m.HeapAlloc
	}
	before := live()
	const conns = 16
	for range conns {
		c, err := tls.Dial("tcp", srv.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_, _ = io.WriteString(c, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
		_ = h2Frame(c, 4, 0, 0, nil) // SETTINGS
		// The header of a DATA frame of the largest size, and one byte of it.
		n := h2FrameBytes
		if _, err := c.Write([]byte{byte(n >> 16), byte(n >> 8 & 0xff), byte(n & 0xff), 0, 0, 0, 0, 0, 1, 'x'}); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(200 * time.Millisecond)
	grew := int64(live()) - int64(before)
	t.Logf("%d connections each part way through a frame: %d KiB of live heap each; a connection is counted for %d KiB", conns, grew/conns/1024, costConnHeap/1024)
	if grew > conns*costConnHeap {
		t.Fatalf("%d connections part way through a frame hold %d bytes; they are counted for %d", conns, grew, conns*costConnHeap)
	}
}
