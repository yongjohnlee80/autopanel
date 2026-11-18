package gate

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// UDP STREAMS — a public UDP port forwarded to a target. UDP has no
// connection, so the gate keeps a pairing for each client that sent a
// datagram: a socket of its own to the target, so the kernel brings the
// target's answers back to that pairing and to no other. An answer is only
// ever sent to the client whose datagram opened the pairing.
//
// A source address can be forged, since nothing is shaken hands on. So a
// pairing counts as unanswered until the target has answered and the client
// has sent again, which a forger who does not see the answers cannot do. An
// unanswered pairing is short-lived, is the first to go when the table is
// full, and is sent only a few datagrams: a forged source cannot hold the
// table, and can be aimed at with only a handful of the target's answers.
//
// Decision: docs/decisions/forwards.md#udp

// The limits of UDP forwarding. A pairing is a socket and a goroutine, and
// its kernel buffers are charged to the gate's memory.
const (
	udpPairings     = 256             // pairings at once, every UDP stream together
	udpPerClient    = 16              // of one client (an IPv4 address, an IPv6 /64), unless the stream says
	udpPayload      = 1500            // a larger datagram is dropped, not cut
	udpUnanswered   = 5 * time.Second // how long a pairing lives before it is answered
	udpEarlyReplies = 4               // datagrams sent to a pairing before it is answered
	udpIdle         = 60 * time.Second
	udpBuffer       = 8 << 10 // each pairing's kernel buffers (the kernel doubles what is set)
	udpPublicBuffer = 256 << 10
)

// udpSweep is how often pairings past their time are ended. A variable so a
// test need not wait.
var udpSweep = time.Second

// udpForwarder runs the UDP streams.
type udpForwarder struct {
	log *slog.Logger
	now func() time.Time

	mu       sync.Mutex
	running  map[string]*udpRun // by Stream.Listen
	pairings int                // every stream's, now
	byClient map[udpClient]int

	carried atomic.Int64 // datagrams forwarded either way
	dropped atomic.Int64 // datagrams dropped by a limit, a size or a source
}

type udpClient struct {
	stream string
	client netip.Prefix
}

// udpRun is one UDP stream being served.
type udpRun struct {
	s      Stream
	allow  []netip.Prefix
	bad    bool
	conn   *net.UDPConn
	cancel context.CancelFunc
	done   chan struct{}

	pairs map[netip.AddrPort]*pairing // f.mu's
}

// pairing is one client of one stream.
type pairing struct {
	client   netip.AddrPort
	key      udpClient
	upstream *net.UDPConn
	made     time.Time
	seen     atomic.Int64 // Unix nanoseconds of the last datagram either way
	replied  atomic.Bool  // the target has answered
	answered atomic.Bool  // and the client has sent again: it sees the answers
	early    atomic.Int32 // datagrams sent to the client before it was answered
}

func newUDPForwarder(log *slog.Logger) *udpForwarder {
	return &udpForwarder{log: log, now: time.Now, running: map[string]*udpRun{}, byClient: map[udpClient]int{}}
}

// apply makes the running UDP streams the ones named: an unchanged one keeps
// its socket and its pairings.
func (u *udpForwarder) apply(ctx context.Context, streams []Stream) {
	want := make(map[string]Stream, len(streams))
	for _, s := range streams {
		want[s.Listen] = s
	}
	u.mu.Lock()
	var stop []*udpRun
	for listen, r := range u.running {
		if s, ok := want[listen]; !ok || s != r.s {
			stop = append(stop, r)
			delete(u.running, listen)
		}
	}
	var start []*udpRun
	for listen, s := range want {
		if _, ok := u.running[listen]; ok {
			continue
		}
		rctx, cancel := context.WithCancel(ctx)
		r := &udpRun{s: s, cancel: cancel, done: make(chan struct{}), pairs: map[netip.AddrPort]*pairing{}}
		for _, a := range strings.Fields(s.Allow) {
			pre, err := netip.ParsePrefix(a)
			if err != nil {
				r.bad = true
				u.log.Error("gate: a stream's allowed sources hold something that is no prefix; it lets nobody in", "stream", s.Name, "allow", s.Allow)
				break
			}
			r.allow = append(r.allow, pre.Masked())
		}
		u.running[listen] = r
		start = append(start, r)
		go func() { defer close(r.done); u.serve(rctx, r) }()
	}
	u.mu.Unlock()
	for _, r := range stop {
		u.stop(r)
	}
	for _, r := range start {
		u.log.Info("gate: forwarding", "stream", r.s.Name, "listen", "udp "+r.s.Listen, "to", r.s.To)
	}
}

func (u *udpForwarder) stopAll() {
	u.mu.Lock()
	runs := make([]*udpRun, 0, len(u.running))
	for listen, r := range u.running {
		runs = append(runs, r)
		delete(u.running, listen)
	}
	u.mu.Unlock()
	for _, r := range runs {
		u.stop(r)
	}
}

// stop ends a stream: its socket, and every pairing of it.
func (u *udpForwarder) stop(r *udpRun) {
	r.cancel()
	u.mu.Lock()
	if r.conn != nil {
		_ = r.conn.Close()
	}
	for _, p := range r.pairs {
		u.endLocked(r, p)
	}
	u.mu.Unlock()
	<-r.done
}

// open is the pairings now, for the gate's report.
func (u *udpForwarder) open() int64 {
	u.mu.Lock()
	defer u.mu.Unlock()
	return int64(u.pairings)
}

// serve binds the stream's port and carries the clients' datagrams to their
// pairings until ctx ends. A port that cannot be bound is tried again.
func (u *udpForwarder) serve(ctx context.Context, r *udpRun) {
	addr, err := net.ResolveUDPAddr("udp", r.s.Listen)
	if err != nil {
		u.log.Error("gate: a UDP stream's address is no address", "stream", r.s.Name, "listen", r.s.Listen, "err", err)
		return
	}
	var conn *net.UDPConn
	for {
		conn, err = net.ListenUDP("udp", addr)
		if err == nil {
			break
		}
		u.log.Error("gate: a stream's port cannot be bound; trying again", "stream", r.s.Name, "listen", "udp "+r.s.Listen, "err", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(rebindEvery):
		}
	}
	_ = conn.SetReadBuffer(udpPublicBuffer)
	_ = conn.SetWriteBuffer(udpPublicBuffer)
	u.mu.Lock()
	r.conn = conn
	u.mu.Unlock()
	if ctx.Err() != nil {
		_ = conn.Close()
		return
	}
	go u.sweep(ctx, r)

	// One byte more than the limit: a read into a buffer of exactly the limit
	// cuts a larger datagram short and does not say so.
	buf := make([]byte, udpPayload+1)
	for {
		n, from, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(10 * time.Millisecond) // a transient error: let the moment pass
			continue
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		if n > udpPayload || !lets(r.allow, r.bad, from.Addr()) {
			u.dropped.Add(1)
			continue
		}
		p := u.pairingFor(ctx, r, from)
		if p == nil {
			u.dropped.Add(1)
			continue
		}
		if p.replied.Load() {
			p.answered.Store(true) // it has sent again after an answer: it sees the answers
		}
		p.seen.Store(u.now().UnixNano())
		if _, err := p.upstream.Write(buf[:n]); err == nil {
			u.carried.Add(1)
		}
	}
}

// lets is streamRun.lets for a UDP stream.
func lets(allow []netip.Prefix, bad bool, ip netip.Addr) bool {
	if bad {
		return false
	}
	if len(allow) == 0 {
		return true
	}
	for _, p := range allow {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// pairingFor is the client's pairing, made if it has none and the limits
// allow. With the table full, the oldest pairing that was never answered goes
// to make room; with none of those, the newcomer is refused.
func (u *udpForwarder) pairingFor(ctx context.Context, r *udpRun, from netip.AddrPort) *pairing {
	u.mu.Lock()
	defer u.mu.Unlock()
	if p, ok := r.pairs[from]; ok {
		return p
	}
	key := udpClient{stream: r.s.Name, client: clientPrefix(from.Addr())}
	per := r.s.PerClient
	if per <= 0 {
		per = udpPerClient
	}
	if u.byClient[key] >= per {
		return nil
	}
	if u.pairings >= udpPairings && !u.evictUnansweredLocked() {
		return nil
	}
	d := net.Dialer{Timeout: time.Second}
	c, err := d.DialContext(ctx, "udp", r.s.To)
	if err != nil {
		return nil
	}
	up := c.(*net.UDPConn)
	_ = up.SetReadBuffer(udpBuffer)
	_ = up.SetWriteBuffer(udpBuffer)
	p := &pairing{client: from, key: key, upstream: up, made: u.now()}
	p.seen.Store(p.made.UnixNano())
	r.pairs[from] = p
	u.pairings++
	u.byClient[key]++
	go u.answers(r, p)
	return p
}

// evictUnansweredLocked ends the oldest pairing, of any stream, that was never
// answered. It reports whether there was one.
func (u *udpForwarder) evictUnansweredLocked() bool {
	var oldest *pairing
	var of *udpRun
	for _, r := range u.running {
		for _, p := range r.pairs {
			if !p.answered.Load() && (oldest == nil || p.made.Before(oldest.made)) {
				oldest, of = p, r
			}
		}
	}
	if oldest == nil {
		return false
	}
	u.endLocked(of, oldest)
	return true
}

// endLocked ends a pairing: its socket closes, which ends its goroutine.
func (u *udpForwarder) endLocked(r *udpRun, p *pairing) {
	if r.pairs[p.client] != p {
		return
	}
	delete(r.pairs, p.client)
	_ = p.upstream.Close()
	u.pairings--
	if u.byClient[p.key]--; u.byClient[p.key] <= 0 {
		delete(u.byClient, p.key)
	}
}

// answers carries the target's datagrams back to the pairing's client, and to
// no one else, until the pairing ends. Before the pairing is answered, only
// the first few are sent.
func (u *udpForwarder) answers(r *udpRun, p *pairing) {
	buf := make([]byte, udpPayload+1)
	for {
		n, err := p.upstream.Read(buf)
		if err != nil {
			return // closed: the pairing ended
		}
		if n > udpPayload {
			u.dropped.Add(1)
			continue
		}
		p.replied.Store(true)
		if !p.answered.Load() && p.early.Add(1) > udpEarlyReplies {
			u.dropped.Add(1)
			continue
		}
		p.seen.Store(u.now().UnixNano())
		if _, err := r.conn.WriteToUDPAddrPort(buf[:n], p.client); err == nil {
			u.carried.Add(1)
		}
	}
}

// sweep ends the stream's pairings that are past their time: an unanswered
// one after udpUnanswered, an answered one after the stream's idle time
// without a datagram either way.
func (u *udpForwarder) sweep(ctx context.Context, r *udpRun) {
	idle := time.Duration(r.s.IdleSecs) * time.Second
	if idle <= 0 {
		idle = udpIdle
	}
	t := time.NewTicker(udpSweep)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		now := u.now()
		u.mu.Lock()
		for _, p := range r.pairs {
			switch {
			case !p.answered.Load() && now.Sub(p.made) >= udpUnanswered:
				u.endLocked(r, p)
			case p.answered.Load() && now.Sub(time.Unix(0, p.seen.Load())) >= idle:
				u.endLocked(r, p)
			}
		}
		u.mu.Unlock()
	}
}
