package gate

import (
	"context"
	"encoding/binary"
	"errors"
	"github.com/yongjohnlee80/autopanel/internal/tunnel"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
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
	// tunnel reaches a target behind a tunnel agent; nil: no tunnels here.
	tunnel TunnelDial

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

	udp *udpForwarder // the UDP streams

	probed   atomic.Pointer[probeResult] // the last probe; nil before the first
	probeNow chan struct{}               // a change of streams asks for one
}

// probeResult is what a probe found.
type probeResult struct {
	at        int64    // Unix seconds
	unproxied []string // the streams whose target spoke without a PROXY header
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
	share  atomic.Int64   // s.Share as it is now: it may change while the stream runs
	allow  []netip.Prefix // s.Allow, parsed
	bad    bool           // s.Allow names something that is no prefix
	cancel context.CancelFunc
	done   chan struct{}

	mu    sync.Mutex
	l     net.Listener
	conns map[net.Conn]struct{}
}

func newForwarder(log *slog.Logger) *forwarder {
	return &forwarder{log: log, running: map[string]*streamRun{}, byPeer: map[peerKey]int{}, perName: map[string]int{}, probeNow: make(chan struct{}, 1), udp: newUDPForwarder(log)}
}

// apply makes the running streams the ones named. A stream that is unchanged
// keeps its listener and its connections; one that changed or went away is
// stopped, its connections closed, and a changed one started again.
func (f *forwarder) apply(ctx context.Context, total int, streams []Stream) {
	want := make(map[string]Stream, len(streams))
	var udp []Stream
	for _, s := range streams {
		if s.Proto == "udp" {
			udp = append(udp, s) // its own forwarder: a TCP and a UDP stream may share a port number
			continue
		}
		want[s.Listen] = s
	}
	f.udp.apply(ctx, udp)
	f.mu.Lock()
	f.total = total
	var stop []*streamRun
	for listen, r := range f.running {
		s, ok := want[listen]
		if ok && sameButShare(s, r.s) {
			// The same stream, whatever its share of the total is now (another
			// stream came or went): the listener and its connections stay, and
			// the share is set every time, so one that comes back to what the
			// stream started with is taken too. Stopping the stream would cut
			// every client off for nothing.
			r.share.Store(int64(s.Share))
			continue
		}
		if !ok || s != r.s {
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
		r.share.Store(int64(s.Share))
		for _, a := range strings.Fields(s.Allow) {
			pre, err := netip.ParsePrefix(a)
			if err != nil {
				// A list the gate cannot read lets nobody in: a limit that
				// failed open would be worse than a port that does not answer.
				r.bad = true
				f.log.Error("gate: a stream's allowed sources hold something that is no prefix; it lets nobody in", "stream", s.Name, "allow", s.Allow)
				break
			}
			r.allow = append(r.allow, pre.Masked())
		}
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
	if len(stop) > 0 || len(start) > 0 {
		// The targets changed: what the last probe found is about streams
		// that may be gone, so it is forgotten until they are looked at again.
		f.probed.Store(nil)
		select {
		case f.probeNow <- struct{}{}:
		default:
		}
	}
}

// How the probe waits. Variables so a test need not.
var (
	probeEvery  = time.Hour
	probeSettle = 10 * time.Second // after a change: a target just started may not listen yet
	probeListen = 3 * time.Second  // how long a target is given to speak unasked
)

// probes looks at the streams' targets after each change and every
// probeEvery, until ctx ends.
func (f *forwarder) probes(ctx context.Context) error {
	t := time.NewTicker(probeEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-f.probeNow:
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(probeSettle):
			}
		case <-t.C:
		}
		f.probe(ctx)
	}
}

// probe asks each target that greets whether it still waits for the PROXY
// header. The gate connects as it does for a client, but sends nothing: a
// server that trusts the gate's header says nothing until it has read one, and
// one that has stopped trusting it greets at once. Such a server would take
// every client for the gate itself, and its limits and its records by address
// would mean nothing. A target that cannot be reached is not judged.
//
// Decision: docs/decisions/mail.md#what-autopanel-cannot-set
func (f *forwarder) probe(ctx context.Context) {
	f.mu.Lock()
	var targets []Stream
	for _, r := range f.running {
		if r.s.Greets {
			targets = append(targets, r.s)
		}
	}
	f.mu.Unlock()
	res := &probeResult{at: time.Now().Unix()}
	for _, s := range targets {
		if spoke, err := speaksUnasked(ctx, s.To); err == nil && spoke {
			res.unproxied = append(res.unproxied, s.Name)
			f.log.Error("gate: a stream's target greets without a PROXY header: it no longer reads the client's address", "stream", s.Name, "to", s.To)
		}
	}
	sort.Strings(res.unproxied)
	f.probed.Store(res)
}

// speaksUnasked connects to addr, sends nothing, and reports whether the
// other end sent a byte within probeListen.
func speaksUnasked(ctx context.Context, addr string) (bool, error) {
	d := net.Dialer{Timeout: 2 * time.Second}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false, err
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { _ = c.Close() }) // the gate stopping ends the wait at once
	defer stop()
	_ = c.SetReadDeadline(time.Now().Add(probeListen))
	var b [1]byte
	n, err := c.Read(b[:])
	if n > 0 {
		return true, nil
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return false, nil // it waited: what a server that wants the header does
	}
	return false, err // closed on us: not judged
}

// stopAll stops every stream, for the gate's own stop.
func (f *forwarder) stopAll() {
	f.udp.stopAll()
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
		// A connection waiting to be accepted has the listening socket's
		// buffers: the forwarder's own to send, and a small one to receive,
		// which accept raises. The queue of those is short (bounds.go).
		lc := net.ListenConfig{Control: socketBuffers(forwardQueued, clientBuffer)}
		l, err = lc.Listen(ctx, "tcp", r.s.Listen)
		if err == nil {
			if err = shortBacklog(l, forwardBacklog); err == nil {
				break
			}
			_ = l.Close()
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
	if !r.lets(client.Addr()) {
		f.refused.Add(1)
		return
	}
	_ = c.SetReadBuffer(clientBuffer)
	_ = widenWindow(c, clientBuffer) // the listening socket's small buffer fixed the window it would offer: let it grow to this one
	_ = c.SetWriteBuffer(clientBuffer)
	key := peerKey{stream: r.s.Name, client: clientPrefix(client.Addr())}
	if !f.admit(r, key) {
		f.refused.Add(1)
		return
	}
	defer f.release(r.s, key)
	if !r.track(c) {
		return
	}
	defer r.untrack(c)

	if agent, target, ok := tunnel.ParseAddress(r.s.To); ok {
		f.throughTunnel(ctx, r, c, agent, target)
		return
	}
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
	if !r.s.Plain {
		_ = uc.SetWriteDeadline(time.Now().Add(dialTimeout))
		if _, err := uc.Write(proxyHeader(client, local)); err != nil {
			return
		}
		_ = uc.SetWriteDeadline(time.Time{}) // the header's deadline only: pipe sets its own
	}
	f.served.Add(1)
	pipe(c, uc, time.Duration(r.s.IdleSecs)*time.Second)
}

// throughTunnel carries a client's connection to a tunnel agent's target. An
// agent that is away, or full, is a connection closed: there is nothing to
// say to a client in a protocol the gate does not know.
func (f *forwarder) throughTunnel(ctx context.Context, r *streamRun, c *net.TCPConn, agent, target string) {
	if f.tunnel == nil {
		return
	}
	dctx, cancel := context.WithTimeout(ctx, dialTimeout)
	up, err := f.tunnel(dctx, agent, target)
	cancel()
	if err != nil {
		f.log.Warn("gate: a stream's tunnel does not carry it", "stream", r.s.Name, "to", r.s.To, "err", err)
		return
	}
	defer up.Close()
	if !r.track(up) {
		return
	}
	defer r.untrack(up)
	f.served.Add(1)
	pipeStream(c, up, time.Duration(r.s.IdleSecs)*time.Second)
}

// pipeStream is pipe for a connection whose other end is a tunnel's stream,
// which has no deadlines and cannot be spliced: each direction is a copy
// through a small buffer, and a timer closes the pair when neither way has
// moved a byte for idle. The client ending its side half-closes the stream,
// and the target may still answer; the stream ending ends both, since a
// tunnel's stream ends as a whole.
func pipeStream(client *net.TCPConn, stream net.Conn, idle time.Duration) {
	if idle <= 0 {
		idle = 10 * time.Minute
	}
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	var once sync.Once
	done := make(chan struct{})
	closeBoth := func() { once.Do(func() { close(done); _ = client.Close(); _ = stream.Close() }) }
	go func() {
		t := time.NewTicker(idle / 4)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				if time.Since(time.Unix(0, last.Load())) >= idle {
					closeBoth()
					return
				}
			}
		}
	}()
	cp := func(dst io.Writer, src io.Reader) error {
		buf := make([]byte, streamBuffer)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				last.Store(time.Now().UnixNano())
				if _, werr := dst.Write(buf[:n]); werr != nil {
					return werr
				}
				last.Store(time.Now().UnixNano())
			}
			if err != nil {
				if errors.Is(err, io.EOF) {
					return nil
				}
				return err
			}
		}
	}
	go func() { // client → target
		if err := cp(stream, client); err != nil {
			closeBoth()
			return
		}
		if cw, ok := stream.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	_ = cp(client, stream) // target → client, until the stream ends
	closeBoth()
}

// streamBuffer is the copy buffer of each direction of a tunnelled
// connection: with the tunnel's streams at their limit, 4 MB in all.
const streamBuffer = 16 << 10

// lets reports whether the stream takes a connection from ip: any address
// when it names no sources, and otherwise only one of them.
func (r *streamRun) lets(ip netip.Addr) bool {
	if r.bad {
		return false
	}
	if len(r.allow) == 0 {
		return true
	}
	ip = ip.Unmap()
	for _, p := range r.allow {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// sameButShare reports whether a and b differ in nothing but their share.
func sameButShare(a, b Stream) bool {
	a.Share = b.Share
	return a == b
}

// admit counts a connection in, or reports that a limit holds it out: the
// total for every stream, the stream's share of it, and the stream's limit
// per client.
func (f *forwarder) admit(r *streamRun, key peerKey) bool {
	s := r.s
	f.mu.Lock()
	defer f.mu.Unlock()
	share := int(r.share.Load())
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
