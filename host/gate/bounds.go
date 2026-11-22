package gate

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// THE PUBLIC LISTENERS' BOUNDS — what the gate may spend on HTTP and HTTPS.
// Every socket has fixed kernel buffers; a listener holds a fixed number of
// connections, and one peer that is not a trusted proxy a share of them; a
// fixed number of requests are being proxied at once, and one client a share;
// a request that moves no byte either way for long is ended. The unit's
// memory limit is the sum of these and of the gate's other parts.
//
// Decision: docs/decisions/limits.md

const (
	// A socket's kernel buffers. The kernel counts twice what is set, and a
	// transfer's speed over a far link is about half of that a round trip
	// (the window is half the buffer): a download through a 64 KiB send buffer
	// moves about 1 MiB/s at 100 ms. Behind a proxy near the host (Cloudflare)
	// the round trip is a few milliseconds.
	//
	// Both of a client's buffers are the listening socket's, so a connection
	// has them from its first byte, before the gate has accepted it. The
	// receive buffer is therefore fixed for the connection's life: the window
	// a connection may ever offer is settled when it is made.
	acceptRecvBuffer   = 160 << 10
	acceptSendBuffer   = 64 << 10
	upstreamRecvBuffer = 32 << 10
	upstreamSendBuffer = 32 << 10

	// A download that has moved wideAfter may take one of wideGrants, which
	// gives its connection a larger send buffer until it closes. So a few
	// large downloads to far clients run faster, and the many stay small. It
	// is best effort: the kernel gives no more than the host's
	// net.core.wmem_max, and a client may hold a grant idle.
	wideGrants     = 6
	widePerClient  = 3
	wideAfter      = 512 << 10
	wideSendBuffer = 1 << 20

	httpsConns = 192 // connections at once on the HTTPS listener
	plainConns = 32  // on the plain one: it redirects, and answers ACME
	peerConns  = 32  // of one peer that is no trusted proxy (an IPv4 address, an IPv6 /64)

	proxyInFlight  = 96 // requests being proxied at once, every route together
	proxyPerClient = 24 // of one client

	httpsHeaderBytes    = 32 << 10 // a request's headers
	upstreamHeaderBytes = 64 << 10 // an upstream's answer's headers
	upstreamIdleConns   = 32       // idle connections kept to upstreams, and 4 to one
	siteIdleConns       = 8        // idle connections kept to the sites' serving process

	h2Streams      = 16        // streams a connection may have open
	h2StreamWindow = 128 << 10 // unread upload held of one stream
	h2ConnWindow   = 256 << 10 // and of one connection
	h2FrameBytes   = 16 << 10  // the largest frame read: the server holds a buffer of this for each connection

	requestStall  = 5 * time.Minute  // a proxied request with no byte either way for this long is ended
	upgradedStall = 10 * time.Minute // an upgraded connection (a WebSocket): as a forwarded TCP connection
	refusalWrite  = 10 * time.Second // a refusal not taken by its client within this is given up

	// A wide grant is given to another connection only this long after its
	// connection closed: what a closed socket still had queued stays the
	// kernel's until its peer takes it or the kernel gives up.
	wideCooling = 2 * time.Minute
)

// refusalWriteFor is refusalWrite, where a test may shorten it.
var refusalWriteFor atomic.Int64

func init() { refusalWriteFor.Store(int64(refusalWrite)) }

// THE LEDGER — what the gate may hold, counted by the thing that holds it: a
// socket by sockets, a proxied request by requests, and so on. A socket's
// kernel buffers are counted at twice what is set, as the kernel counts them,
// in both directions, whether the socket is in use or not. The heap figures
// are measured on the test host with every one of a kind stalled both ways,
// and rounded up.
const (
	costBase = 8 << 20 // the process with nothing to do

	// An accepted connection, whatever it is doing: its socket's buffers, and
	// its handshake, headers, HTTP/2 state and idle state on the heap.
	costSocket   = 2 * (acceptRecvBuffer + acceptSendBuffer)
	costConnHeap = 96 << 10
	// A proxied request, beside its connection: its upstream socket, and
	// what it holds on the heap (its copy buffers, its unread upload).
	costUpstream    = 2 * (upstreamRecvBuffer + upstreamSendBuffer)
	costProxiedHeap = 512 << 10
	// A wide grant, live or cooling: its connection's larger buffers.
	costWide = 2 * wideSendBuffer

	// A tunnel stream: its HTTP/2 windows both ways and its copy buffers on
	// the heap, and its share of the agent's connection's socket.
	costTunnelStream = 448 << 10
	costTunnelHeap   = 384 << 10
	costAPI          = 21 << 20 // the API's calls in flight, each at its largest: all heap
	costRates        = 1 << 20  // the API's rate table and the sign-ins', each full

	// A forwarded TCP connection: its two sockets, and its goroutines.
	forwardedConns  = 200 // core/forward's Connections and mail's share together
	costForwarded   = 2 * 2 * (clientBuffer + serviceBuffer)
	costForwardHeap = 32 << 10
	// A UDP pairing's socket, and a UDP forward's public one.
	costPairing     = 2 * 2 * udpBuffer
	costPairingHeap = 16 << 10
	udpForwards     = 16 // core/forward's MaxForwards
	costUDPPublic   = 2 * 2 * udpPublicBuffer

	// A connection the kernel has finished and the gate has not yet accepted
	// already has the buffers above, or on a forwarded port a small one that
	// accept raises: what it may hold is the same arithmetic, and it is the
	// host's memory until it is accepted. The queues are short.
	acceptBacklog  = 64
	forwardBacklog = 256     // a burst of connections to a forwarded port waits here rather than being dropped
	forwardQueued  = 2 << 10 // a forwarded port's listening socket's receive buffer: raised to clientBuffer at accept

	// Sockets the gate has closed and the kernel has not yet freed.
	costRetiring = 16 << 20
)

// worstKernelBytes is what the kernel may hold for the gate's sockets.
func worstKernelBytes() int {
	return (httpsConns+plainConns)*costSocket + (proxyInFlight+upstreamIdleConns+siteIdleConns)*costUpstream + wideGrants*costWide +
		tunnelStreamsTotal*(costTunnelStream-costTunnelHeap) + forwardedConns*costForwarded +
		udpPairings*costPairing + udpForwards*costUDPPublic +
		costRetiring
}

// WorstHeapBytes is what the Go runtime may hold: what GOMEMLIMIT must
// exceed.
func WorstHeapBytes() int {
	return costBase + (httpsConns+plainConns)*costConnHeap + proxyInFlight*costProxiedHeap + tunnelStreamsTotal*costTunnelHeap +
		forwardedConns*costForwardHeap + udpPairings*costPairingHeap + costAPI + costRates
}

// WorstBytes is the most the gate may hold when every part is full at once:
// what its unit's MemoryMax must exceed, with room.
func WorstBytes() int { return WorstHeapBytes() + worstKernelBytes() }

// listenBounded listens on addr and holds at most max connections, of which
// one untrusted peer at most perPeer. Each has fixed kernel buffers, the
// listening socket's: a connection has them from its first byte, accepted or
// not. The queue of connections not yet accepted is acceptBacklog.
func listenBounded(ctx context.Context, addr string, max, perPeer int, trusted func() Trusted) (*boundedListener, error) {
	lc := net.ListenConfig{Control: socketBuffers(acceptRecvBuffer, acceptSendBuffer)}
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if err := shortBacklog(ln, acceptBacklog); err != nil {
		_ = ln.Close()
		return nil, err
	}
	return &boundedListener{Listener: ln, max: max, perPeer: perPeer, trusted: trusted, peers: map[netip.Prefix]int{},
		wide: newInFlight(wideGrants, widePerClient), cooling: wideCooling}, nil
}

// boundedListener counts its connections; one over a limit is closed at once.
type boundedListener struct {
	net.Listener
	max, perPeer int
	trusted      func() Trusted

	mu    sync.Mutex
	open  int
	peers map[netip.Prefix]int // connections of each untrusted peer

	refused atomic.Int64

	wide    *inFlight     // the wide grants: counted as requests in flight are
	cooling time.Duration // how long a closed connection's grant is kept from the next
}

func (l *boundedListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		peer, counted, ok := l.admit(c.RemoteAddr())
		if !ok {
			l.refused.Add(1)
			_ = c.Close()
			continue
		}
		tc, isTCP := c.(*net.TCPConn)
		if !isTCP {
			l.release(peer, counted)
			l.refused.Add(1)
			_ = c.Close()
			continue
		}
		return &countedConn{Conn: c, tcp: tc, l: l, peer: peer, counted: counted}, nil
	}
}

// admit takes a place for a connection from addr: one of the listener's, and
// one of its peer's unless the peer is a trusted proxy, which carries many
// clients.
func (l *boundedListener) admit(addr net.Addr) (peer netip.Prefix, counted, ok bool) {
	ap, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return peer, false, false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.open >= l.max {
		return peer, false, false
	}
	if t := l.trusted(); !t.contains(ap.Addr()) {
		peer, counted = clientPrefix(ap.Addr()), true
		if l.peers[peer] >= l.perPeer {
			return peer, false, false
		}
		l.peers[peer]++
	}
	l.open++
	return peer, counted, true
}

func (l *boundedListener) release(peer netip.Prefix, counted bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.open--
	if counted {
		if l.peers[peer]--; l.peers[peer] <= 0 {
			delete(l.peers, peer)
		}
	}
}

func (l *boundedListener) openNow() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.open
}

// countedConn gives its places back when it is closed, once.
type countedConn struct {
	net.Conn
	tcp     *net.TCPConn
	l       *boundedListener
	peer    netip.Prefix
	counted bool
	once    sync.Once

	wmu     sync.Mutex
	wideBy  netip.Prefix // the client its wide grant is counted to
	wideN   int          // 1 once it holds a grant
	closed  bool
	aborted bool
}

// Close closes the socket first and gives its places back after: a place is
// never another connection's while this one is still open. A wide grant
// comes back later still (wideCooling), unless the socket had nothing left
// to send when it closed, or the close was an abort: either leaves the
// kernel nothing to keep.
func (c *countedConn) Close() error {
	// Under the lock, so an abort is either in force for this close or
	// refused as too late: never set while the socket is closing.
	c.wmu.Lock()
	// What the socket still has to send, read before it is closed: with
	// nothing queued, the kernel keeps nothing of it after the close.
	wide := c.wideN > 0
	empty := false
	if wide && !c.closed {
		if n, err := sendQueued(c.tcp); err == nil && n == 0 {
			empty = true
		}
	}
	err := c.Conn.Close()
	first := !c.closed
	by, aborted := c.wideBy, c.aborted || empty
	c.wideN, c.closed = 0, true
	c.wmu.Unlock()
	if !first {
		return err
	}
	c.once.Do(func() {
		c.l.release(c.peer, c.counted)
		switch {
		case !wide:
		case aborted || c.l.cooling <= 0:
			c.l.wide.give(by)
		default:
			time.AfterFunc(c.l.cooling, func() { c.l.wide.give(by) })
		}
	})
	return err
}

// abort makes the connection's close, whenever it comes, discard what is
// queued and reset the peer, so nothing of it outlives the close. For a
// connection the gate is giving up on; never for one that ended well, whose
// last bytes may still be on their way.
func (c *countedConn) abort() {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closed {
		return // too late to change how it closed
	}
	// Only a close the kernel has agreed to make an abort is counted as one:
	// otherwise the grant cools like any other.
	if c.tcp.SetLinger(0) == nil {
		c.aborted = true
	}
}

// widen gives the connection a wide grant, if there is one to give: larger
// buffers until it closes. The grant is the connection's for its life and is
// never taken back while it is open: lowering a socket's buffers frees
// nothing that is already queued, so a grant handed on at once would be
// counted once and held twice. The grant is counted before either buffer
// grows, and stays counted if only one could be set.
func (c *countedConn) widen(client netip.Prefix) bool {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closed {
		return false
	}
	if c.wideN > 0 {
		return true
	}
	if !c.l.wide.take(client) {
		return false
	}
	c.wideBy, c.wideN = client, 1
	_ = c.tcp.SetWriteBuffer(wideSendBuffer)
	return true
}

type connKey struct{}

// connContext keeps a request's connection where proxied can find it. Under
// TLS the server's connection wraps the listener's.
func connContext(ctx context.Context, c net.Conn) context.Context {
	if t, ok := c.(*tls.Conn); ok {
		c = t.NetConn()
	}
	if cc, ok := c.(*countedConn); ok {
		return context.WithValue(ctx, connKey{}, cc)
	}
	return ctx
}

// contains reports whether ip is one of the trusted proxies.
func (t Trusted) contains(ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, p := range t {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// clientOf is who a request is counted as: what CF-Connecting-IP names when
// the peer is a trusted proxy and the header is one address, else the peer.
// It is for sharing places fairly, never for deciding who someone is: a
// client with many addresses is many clients.
func clientOf(r *http.Request, trusted Trusted) netip.Prefix {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	peer, _ := netip.ParseAddr(host)
	peer = peer.Unmap().WithZone("")
	if trusted.contains(peer) {
		if vs := r.Header.Values(cfConnectingIP); len(vs) == 1 {
			if ip, err := netip.ParseAddr(vs[0]); err == nil && ip.Zone() == "" {
				return clientPrefix(ip)
			}
		}
	}
	return clientPrefix(peer)
}

// inFlight is the requests being proxied now.
type inFlight struct {
	max, perClient int

	mu      sync.Mutex
	n       int
	clients map[netip.Prefix]int

	refused atomic.Int64
}

func newInFlight(max, perClient int) *inFlight {
	return &inFlight{max: max, perClient: perClient, clients: map[netip.Prefix]int{}}
}

func (f *inFlight) take(client netip.Prefix) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.n >= f.max || f.clients[client] >= f.perClient {
		return false
	}
	f.n++
	f.clients[client]++
	return true
}

func (f *inFlight) give(client netip.Prefix) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n--
	if f.clients[client]--; f.clients[client] <= 0 {
		delete(f.clients, client)
	}
}

func (f *inFlight) now() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.n
}

// proxied admits a request to the routes' proxies, and ends it when it stops
// moving. A request over a limit is answered 503 at once: it is not queued,
// for a queue of waiting requests is memory held too.
func proxied(f *inFlight, trusted func() Trusted, stall, upgraded time.Duration, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		client := clientOf(r, trusted())
		if !f.take(client) {
			f.refused.Add(1)
			w.Header().Set("Retry-After", "1")
			w.Header().Set("Cache-Control", "no-store")
			// A refusal its client does not take is not waited on: the stream
			// (HTTP/2) or the connection ends at the deadline.
			_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(time.Duration(refusalWriteFor.Load())))
			w.Header().Set("Connection", "close")
			http.Error(w, "busy: try again shortly", http.StatusServiceUnavailable)
			return
		}
		defer f.give(client)
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()
		p := &progress{rc: http.NewResponseController(w), cancel: cancel, upgraded: upgraded, client: client, http1: r.ProtoMajor == 1}
		p.on, _ = r.Context().Value(connKey{}).(*countedConn)
		p.limit.Store(int64(stall))
		p.touch()
		p.timer = time.AfterFunc(stall, p.check)
		defer p.stop()
		r = r.WithContext(ctx)
		if r.Body != nil {
			r.Body = &watchedBody{ReadCloser: r.Body, p: p}
		}
		next.ServeHTTP(&watchedWriter{ResponseWriter: w, p: p}, r)
		// The answer's last bytes are still the request's: the server sends
		// them after the handler returns, and over HTTP/2 a client that gives
		// no credit could hold them for ever, with the place already given
		// back. So they are flushed here, under the clock, and what remains
		// after has a deadline of its own.
		if !p.hijacked() {
			_ = p.rc.Flush()
			_ = p.rc.SetWriteDeadline(time.Now().Add(time.Duration(refusalWriteFor.Load())))
		}
	})
}

// progress is one proxied request's clock: when a byte last moved in either
// direction, and what to end when none has for too long. Ending it cancels
// the request (so a wait for the upstream ends too), and fails the client's
// connection, or closes it when it was taken over for an upgrade.
type progress struct {
	last     atomic.Int64 // UnixNano
	limit    atomic.Int64 // a time.Duration
	upgraded time.Duration
	rc       *http.ResponseController
	cancel   context.CancelFunc

	mu    sync.Mutex
	timer *time.Timer
	conn  net.Conn // the client's connection, once an upgrade took it over
	done  bool
	ended atomic.Bool

	// The bytes sent to the client, for a wide grant (wideAfter).
	client netip.Prefix
	on     *countedConn // the request's connection; nil where there is none to widen
	http1  bool
	down   atomic.Int64
	next   atomic.Int64 // the count past which a grant is asked for again
	wide   atomic.Bool
}

func (p *progress) touch() { p.last.Store(time.Now().UnixNano()) }

func (p *progress) hijacked() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.conn != nil
}

// moved counts n bytes sent to the client, and asks for a wide grant when an
// answer has shown itself to be a large one.
func (p *progress) moved(dir *atomic.Int64, n int) {
	p.touch()
	total := dir.Add(int64(n))
	if p.on == nil || p.wide.Load() {
		return
	}
	if next := p.next.Load(); total >= wideAfter+next && p.next.CompareAndSwap(next, next+wideAfter) {
		if p.on.widen(p.client) {
			p.wide.Store(true)
		}
	}
}

func (p *progress) check() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.done {
		return
	}
	limit := time.Duration(p.limit.Load())
	if idle := time.Since(time.Unix(0, p.last.Load())); idle < limit {
		p.timer.Reset(limit - idle)
		return
	}
	p.ended.Store(true)
	p.cancel()
	if p.conn != nil { // upgraded: the connection is this request's alone
		if p.on != nil {
			p.on.abort()
		}
		_ = p.conn.Close()
		return
	}
	if p.on != nil && p.http1 { // an HTTP/1.1 connection carries this request alone: its close may discard
		p.on.abort()
	}
	now := time.Now()
	_ = p.rc.SetReadDeadline(now)
	_ = p.rc.SetWriteDeadline(now)
}

func (p *progress) stop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.done = true
	p.timer.Stop()
}

// took notes that an upgrade took the connection over: its bytes are counted
// on the connection from here, and it may be quiet for longer.
func (p *progress) took(c net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.conn = c
	p.limit.Store(int64(p.upgraded))
	p.touch()
	if !p.done {
		p.timer.Reset(p.upgraded)
	}
}

type watchedBody struct {
	io.ReadCloser
	p *progress
}

func (b *watchedBody) Read(buf []byte) (int, error) {
	n, err := b.ReadCloser.Read(buf)
	if n > 0 {
		b.p.touch()
	}
	return n, err
}

// watchedWriter counts an answer's bytes as progress. It keeps what the
// writer under it can do (Unwrap), and watches a connection an upgrade takes.
type watchedWriter struct {
	http.ResponseWriter
	p *progress
}

func (w *watchedWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *watchedWriter) Write(buf []byte) (int, error) {
	n, err := w.ResponseWriter.Write(buf)
	if n > 0 {
		w.p.moved(&w.p.down, n)
	}
	return n, err
}

func (w *watchedWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	c, brw, err := w.p.rc.Hijack()
	if err != nil {
		return nil, nil, err
	}
	wc := &watchedConn{Conn: c, p: w.p}
	w.p.took(wc)
	return wc, brw, nil
}

// watchedConn is an upgraded connection: both directions pass through it.
type watchedConn struct {
	net.Conn
	p *progress
}

func (c *watchedConn) Read(buf []byte) (int, error) {
	n, err := c.Conn.Read(buf)
	if n > 0 {
		c.p.touch()
	}
	return n, err
}

func (c *watchedConn) Write(buf []byte) (int, error) {
	n, err := c.Conn.Write(buf)
	if n > 0 {
		c.p.moved(&c.p.down, n)
	}
	return n, err
}

// upstreamTransport reaches a route's upstream: sockets with fixed kernel
// buffers, an answer's headers bounded, HTTP/1.1 only (so one request is one
// connection's cost), and few idle connections kept. One transport serves
// every route.
var upstreamTransport = newUpstreamTransport()

func newUpstreamTransport() *http.Transport {
	d := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second, Control: socketBuffers(upstreamRecvBuffer, upstreamSendBuffer)}
	return &http.Transport{
		Proxy:                  nil, // an upstream is reached directly, whatever the environment says
		DialContext:            d.DialContext,
		TLSHandshakeTimeout:    10 * time.Second,
		ExpectContinueTimeout:  time.Second,
		MaxResponseHeaderBytes: upstreamHeaderBytes,
		MaxIdleConns:           upstreamIdleConns,
		MaxIdleConnsPerHost:    4,
		IdleConnTimeout:        90 * time.Second,
		WriteBufferSize:        4 << 10,
		ReadBufferSize:         4 << 10,
		ForceAttemptHTTP2:      false,
		TLSNextProto:           map[string]func(string, *tls.Conn) http.RoundTripper{}, // no HTTP/2 to an upstream
	}
}

// siteTransport dials the sites' serving process at the socket the core
// named (Hello.SiteSocket), as an upstream is dialled: the same fixed
// buffers, the same small bufio buffers, a dial timeout, and an idle pool of
// its own that the ledger counts. A site's request is a proxied request, so
// the in-flight cap holds it too.
var siteTransport = newSiteTransport()

func newSiteTransport() *http.Transport {
	d := &net.Dialer{Timeout: 5 * time.Second, Control: socketBuffers(upstreamRecvBuffer, upstreamSendBuffer)}
	return &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			p := siteSocket.Load()
			if p == nil || *p == "" {
				return nil, errNoSite
			}
			return d.DialContext(ctx, "unix", *p)
		},
		ExpectContinueTimeout:  time.Second,
		ResponseHeaderTimeout:  30 * time.Second,
		MaxResponseHeaderBytes: upstreamHeaderBytes,
		MaxIdleConns:           siteIdleConns,
		MaxIdleConnsPerHost:    siteIdleConns,
		IdleConnTimeout:        90 * time.Second,
		WriteBufferSize:        4 << 10,
		ReadBufferSize:         4 << 10,
		ForceAttemptHTTP2:      false,
		TLSNextProto:           map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
}

// copyBuffers is the buffer an answer is copied through.
type copyBuffers struct{ pool sync.Pool }

func (b *copyBuffers) Get() []byte {
	if v, ok := b.pool.Get().(*[]byte); ok {
		return *v
	}
	return make([]byte, 16<<10)
}

func (b *copyBuffers) Put(buf []byte) { b.pool.Put(&buf) }

var proxyBuffers = &copyBuffers{}
