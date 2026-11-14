package gate

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// THE GATE'S STREAMS — ports the gate forwards byte for byte to a loopback
// port, each connection preceded by a PROXY protocol v2 header naming the
// client, so the service behind it sees who connected. Mail's ports are the
// first: 25, 465, 587 and 993, which start in clear text or carry their own
// TLS, so the gate never reads a byte after the header. The core names them
// over the link (link.streams); the gate binds them with the capability it
// already has for :80 and :443.
//
// Decision: docs/decisions/mail.md#the-gate-forwards-the-mail-ports

// dialTimeout bounds the dial to the service behind a stream.
const dialTimeout = 5 * time.Second

// chunk is how much one splice may move before the idle clock is reset. Small
// enough that a slow but live transfer is never taken for an idle one.
const chunk = 256 << 10

// clientBuffer and serviceBuffer cap each forwarded socket's kernel send and
// receive buffers (the kernel doubles what is set). The kernel charges socket
// buffers to the gate's memory, and autotuned ones grow to megabytes: 200
// connections pushing at once took the gate to 115 MB, past its 40. The
// client's side is the internet's, where a 32 KB window is plenty for mail;
// the service's side is loopback, whose 64 KB segments need a larger buffer
// or every transfer crawls, and which the service drains at once.
const (
	clientBuffer  = 16 << 10
	serviceBuffer = 32 << 10
)

// rebindEvery is how long a stream whose port could not be bound waits before
// it tries again. A variable so a test need not wait.
var rebindEvery = 15 * time.Second

// forwarder runs the streams the core names, and holds their limits.
type forwarder struct {
	log *slog.Logger

	mu       sync.Mutex
	total    int                   // at most this many forwarded connections at once, every stream together
	open     int                   // forwarded connections now
	running  map[string]*streamRun // by Stream.Listen
	byPeer   map[peerKey]int       // connections now, per stream and client
	perName  map[string]int        // connections now, per stream
	accepted atomic.Int64          // connections accepted since the start, refused or not
	ended    atomic.Int64          // accepted connections that have ended, refused or not
	served   atomic.Int64          // connections forwarded since the start
	refused  atomic.Int64          // connections closed by a limit
}

// openNow is the forwarded connections now, for link.report.
func (f *forwarder) openNow() int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return int64(f.open)
}

type peerKey struct {
	stream string
	client netip.Prefix
}

// streamRun is one stream being served: its listener and its connections.
type streamRun struct {
	s      Stream
	cancel context.CancelFunc
	done   chan struct{}

	mu    sync.Mutex
	l     net.Listener
	conns map[net.Conn]struct{}
}

func newForwarder(log *slog.Logger) *forwarder {
	return &forwarder{log: log, running: map[string]*streamRun{}, byPeer: map[peerKey]int{}, perName: map[string]int{}}
}

// apply makes the running streams the ones named. A stream that is unchanged
// keeps its listener and its connections; one that changed or went away is
// stopped, its connections closed, and a changed one started again.
func (f *forwarder) apply(ctx context.Context, total int, streams []Stream) {
	want := make(map[string]Stream, len(streams))
	for _, s := range streams {
		want[s.Listen] = s
	}
	f.mu.Lock()
	f.total = total
	var stop []*streamRun
	for listen, r := range f.running {
		if s, ok := want[listen]; !ok || s != r.s {
			stop = append(stop, r)
			delete(f.running, listen)
		}
	}
	var start []*streamRun
	for listen, s := range want {
		if _, ok := f.running[listen]; ok {
			continue
		}
		sctx, cancel := context.WithCancel(ctx)
		r := &streamRun{s: s, cancel: cancel, done: make(chan struct{}), conns: map[net.Conn]struct{}{}}
		f.running[listen] = r
		start = append(start, r)
		go func() { defer close(r.done); f.serve(sctx, r) }()
	}
	f.mu.Unlock()
	for _, r := range stop {
		r.stop()
	}
	for _, r := range start {
		f.log.Info("gate: forwarding", "stream", r.s.Name, "listen", r.s.Listen, "to", r.s.To)
	}
}

// stopAll stops every stream, for the gate's own stop.
func (f *forwarder) stopAll() {
	f.mu.Lock()
	runs := make([]*streamRun, 0, len(f.running))
	for listen, r := range f.running {
		runs = append(runs, r)
		delete(f.running, listen)
	}
	f.mu.Unlock()
	for _, r := range runs {
		r.stop()
	}
}

// stop closes the listener and every connection of r, and waits for its
// accept loop to end.
func (r *streamRun) stop() {
	r.cancel()
	r.mu.Lock()
	if r.l != nil {
		_ = r.l.Close()
	}
	for c := range r.conns {
		_ = c.Close()
	}
	r.conns = nil // a connection still being dialled is refused by track
	r.mu.Unlock()
	<-r.done
}

func (r *streamRun) track(c net.Conn) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.conns == nil {
		return false
	}
	r.conns[c] = struct{}{}
	return true
}

func (r *streamRun) untrack(c net.Conn) {
	r.mu.Lock()
	delete(r.conns, c)
	r.mu.Unlock()
}

// serve binds r's port and accepts on it until ctx ends. A port that cannot
// be bound (another process holds it) is tried again every rebindEvery.
func (f *forwarder) serve(ctx context.Context, r *streamRun) {
	var l net.Listener
	for {
		var err error
		l, err = net.Listen("tcp", r.s.Listen)
		if err == nil {
			break
		}
		f.log.Error("gate: a stream's port cannot be bound; trying again", "stream", r.s.Name, "listen", r.s.Listen, "err", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(rebindEvery):
		}
	}
	r.mu.Lock()
	r.l = l
	r.mu.Unlock()
	if ctx.Err() != nil { // stopped while binding: stop() may have missed the listener
		_ = l.Close()
		return
	}
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			time.Sleep(50 * time.Millisecond) // EMFILE and the like: let the moment pass
			continue
		}
		f.accepted.Add(1)
		tc, ok := c.(*net.TCPConn)
		if !ok {
			_ = c.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			f.forward(ctx, r, tc)
		}()
	}
}

// forward carries one client connection to the stream's service.
func (f *forwarder) forward(ctx context.Context, r *streamRun, c *net.TCPConn) {
	defer f.ended.Add(1)
	defer c.Close()
	client, err := netip.ParseAddrPort(c.RemoteAddr().String())
	if err != nil {
		return
	}
	local, err := netip.ParseAddrPort(c.LocalAddr().String())
	if err != nil {
		return
	}
	_ = c.SetReadBuffer(clientBuffer)
	_ = c.SetWriteBuffer(clientBuffer)
	key := peerKey{stream: r.s.Name, client: clientPrefix(client.Addr())}
	if !f.admit(r.s, key) {
		f.refused.Add(1)
		return
	}
	defer f.release(r.s, key)
	if !r.track(c) {
		return
	}
	defer r.untrack(c)

	d := net.Dialer{Timeout: dialTimeout}
	up, err := d.DialContext(ctx, "tcp", r.s.To)
	if err != nil {
		f.log.Warn("gate: a stream's service does not answer", "stream", r.s.Name, "to", r.s.To, "err", err)
		return
	}
	uc := up.(*net.TCPConn)
	defer uc.Close()
	_ = uc.SetReadBuffer(serviceBuffer)
	_ = uc.SetWriteBuffer(serviceBuffer)
	if !r.track(uc) {
		return
	}
	defer r.untrack(uc)
	_ = uc.SetWriteDeadline(time.Now().Add(dialTimeout))
	if _, err := uc.Write(proxyHeader(client, local)); err != nil {
		return
	}
	_ = uc.SetWriteDeadline(time.Time{}) // the header's deadline only: pipe sets its own
	f.served.Add(1)
	pipe(c, uc, time.Duration(r.s.IdleSecs)*time.Second)
}

// admit counts a connection in, or reports that a limit holds it out: the
// total for every stream, the stream's share of it, and the stream's limit
// per client.
func (f *forwarder) admit(s Stream, key peerKey) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	share := s.Share
	if share <= 0 || share > f.total {
		share = f.total
	}
	switch {
	case f.open >= f.total:
		return false
	case f.perName[s.Name] >= share:
		return false
	case s.PerClient > 0 && f.byPeer[key] >= s.PerClient:
		return false
	}
	f.open++
	f.perName[s.Name]++
	f.byPeer[key]++
	return true
}

func (f *forwarder) release(s Stream, key peerKey) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.open--
	if f.perName[s.Name]--; f.perName[s.Name] <= 0 {
		delete(f.perName, s.Name)
	}
	if f.byPeer[key]--; f.byPeer[key] <= 0 {
		delete(f.byPeer, key)
	}
}

// clientPrefix is what one client is counted by: its address for IPv4, its
// /64 for IPv6, which one host can fill with addresses at will.
func clientPrefix(a netip.Addr) netip.Prefix {
	a = a.Unmap()
	bits := 32
	if a.Is6() {
		bits = 64
	}
	p, _ := a.Prefix(bits)
	return p
}

// pipe copies both ways between a and b until both have ended, or neither has
// moved a byte for idle. Each direction is a splice on Linux (the copy is
// between two TCP connections, unwrapped), so the gate holds no buffer of its
// own per connection. A direction that ends half-closes the other side; an
// error or the idle limit closes both.
//
// A splice reports what it moved only when it returns, so each direction
// wakes every quarter of idle (its deadline), records what it moved, and
// closes the pair only when neither way has moved a byte for idle: a quiet
// direction beside a busy one (a download, an IMAP IDLE answered) stays open.
func pipe(a, b *net.TCPConn, idle time.Duration) {
	if idle <= 0 {
		idle = 10 * time.Minute
	}
	tick := idle / 4
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	var once sync.Once
	closeBoth := func() { once.Do(func() { _ = a.Close(); _ = b.Close() }) }
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src *net.TCPConn) {
		defer wg.Done()
		for {
			// A read deadline only: it ends a wait for bytes, never a splice
			// that holds some. A write deadline could expire with bytes in the
			// splice's pipe, and they would be lost. A peer that stops reading
			// blocks the write until idle passes and closeBoth unblocks it.
			_ = src.SetReadDeadline(time.Now().Add(tick))
			lr := &io.LimitedReader{R: src, N: chunk}
			n, err := dst.ReadFrom(lr)
			if n > 0 {
				last.Store(time.Now().UnixNano())
			}
			switch {
			case err == nil && lr.N > 0: // src ended
				_ = dst.CloseWrite()
				return
			case err == nil: // a whole chunk: carry on
				continue
			case errors.Is(err, os.ErrDeadlineExceeded) && time.Since(time.Unix(0, last.Load())) < idle:
				continue // a wake-up, and a byte moved one way or the other within idle: not idle
			default: // idle, or broken
				closeBoth()
				return
			}
		}
	}
	go cp(b, a)
	go cp(a, b)
	wg.Wait()
	closeBoth()
}

// proxySignature opens every PROXY protocol v2 header.
var proxySignature = []byte("\r\n\r\n\x00\r\nQUIT\n")

// proxyHeader is the PROXY protocol v2 header for a TCP connection from src to
// dst: version 2, command PROXY, over TCP, IPv4 when both ends are, else IPv6.
func proxyHeader(src, dst netip.AddrPort) []byte {
	s, d := src.Addr().Unmap(), dst.Addr().Unmap()
	h := make([]byte, 0, 16+36)
	h = append(h, proxySignature...)
	h = append(h, 0x21) // version 2, PROXY
	if s.Is4() && d.Is4() {
		h = append(h, 0x11, 0, 12) // TCP over IPv4, 12 bytes of addresses
		s4, d4 := s.As4(), d.As4()
		h = append(h, s4[:]...)
		h = append(h, d4[:]...)
	} else {
		h = append(h, 0x21, 0, 36) // TCP over IPv6, 36 bytes of addresses
		s16, d16 := src.Addr().As16(), dst.Addr().As16()
		h = append(h, s16[:]...)
		h = append(h, d16[:]...)
	}
	h = binary.BigEndian.AppendUint16(h, src.Port())
	h = binary.BigEndian.AppendUint16(h, dst.Port())
	return h
}
