package gate

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yongjohnlee80/autopanel/internal/tunnel"
)

// TUNNELS — connections that machines with no open port have dialled to the
// gate, each a way in to the services that machine's agent names.
//
// An agent arrives on the HTTPS port, told apart by the one TLS protocol its
// handshake offers (tunnel.ALPN). Only such a handshake is asked for a client
// certificate; a browser never is. The certificate claims nothing: the agent
// is known by the public key inside, which the handshake proves it holds, and
// which must be one the core says is enrolled. Until a key is enrolled, the
// one thing its holder can do is offer an enrolment token.
//
// The gate asks an agent for a target by name and is given a stream, or
// refused. It never learns an address behind an agent, and can add none.
//
// Decision: docs/decisions/forwards.md#tunnels

// The limits of tunnelling.
const (
	tunnelStreams      = 64  // streams at once through one agent
	tunnelStreamsTotal = 128 // and through all of them
	tunnelTargets      = 64  // target names kept of one agent
	enrolPerClient     = 5   // enrolments a minute from one client (an IPv4 address, an IPv6 /64)
	enrolPerMinute     = 60  // and from everyone
	enrolBody          = 256 // an enrolment token is far shorter
)

var (
	// ErrTunnelDown is an agent that is not connected now.
	ErrTunnelDown = errors.New("gate: the tunnel is down")
	// ErrTunnelFull is every stream the tunnels may carry being in use.
	ErrTunnelFull = errors.New("gate: the tunnels are full")
)

// tunnels is the agents connected now, and the keys that may connect.
type tunnels struct {
	link *link
	log  *slog.Logger
	now  func() time.Time
	ctx  context.Context // the gate's: a tunnel ends with it

	mu   sync.Mutex
	keys map[string]string    // a key's digest → its agent's name
	live map[string]*liveLink // by agent name

	open atomic.Int64 // streams now, every agent's

	enrolMu  sync.Mutex
	enrolAt  int64 // the minute being counted
	enrolAll int
	enrolBy  map[netip.Prefix]int
}

// liveLink is one agent's tunnel.
type liveLink struct {
	name    string
	client  *tunnel.Client
	since   time.Time
	from    string
	targets []string
	open    atomic.Int64
}

func newTunnels(l *link, log *slog.Logger) *tunnels {
	return &tunnels{link: l, log: log, now: time.Now, ctx: context.Background(),
		keys: map[string]string{}, live: map[string]*liveLink{}, enrolBy: map[netip.Prefix]int{}}
}

// isTunnel reports whether a handshake is an agent's: it offers the tunnel's
// protocol and nothing else. A browser offers h2 and http/1.1, so it is never
// taken for one, whatever else it lists.
func isTunnel(h *tls.ClientHelloInfo) bool {
	return len(h.SupportedProtos) == 1 && h.SupportedProtos[0] == tunnel.ALPN
}

// tlsConfig is the TLS settings of an agent's handshake: TLS 1.3 and a client
// certificate, whose signature the handshake checks. Whose key it is, is
// decided after, from the list.
//
// No protocol is agreed in the handshake. The HTTP server closes a connection
// whose agreed protocol it has no handler for, so the agent's offer is read
// (isTunnel) and not answered; the connection is then served as HTTP/1.1,
// which is what the agent speaks for its one request. These are the only
// settings that ask for a client certificate, so a request that carries one
// came by them (or). Sessions are not resumed: each connection proves its key.
func (ts *tunnels) tlsConfig(get func(*tls.ClientHelloInfo) (*tls.Certificate, error)) *tls.Config {
	return &tls.Config{
		GetCertificate:         get,
		MinVersion:             tls.VersionTLS13,
		ClientAuth:             tls.RequireAnyClientCert,
		SessionTicketsDisabled: true,
	}
}

// or serves a request that came by an agent's handshake, and passes every
// other to next. Nothing of a site or of the API is reachable by one: a
// request with a client certificate is the tunnel's, whatever it asks for.
func (ts *tunnels) or(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			next.ServeHTTP(w, r)
			return
		}
		key := tunnel.KeyDigest(r.TLS.PeerCertificates[0])
		switch {
		case r.Method == http.MethodPost && r.URL.Path == tunnel.EnrolPath:
			ts.enrol(w, r, key)
		case r.Method == http.MethodGet && r.URL.Path == tunnel.ConnectPath && strings.EqualFold(r.Header.Get("Upgrade"), tunnel.ALPN):
			ts.connect(w, r, key)
		default:
			http.Error(w, "", http.StatusNotFound)
		}
	})
}

// client is the address a request came from. An agent dials the gate itself:
// no proxy carries this protocol, so no header is believed.
func client(r *http.Request) netip.Addr {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

// mayEnrol counts an enrolment against its client and against everyone, by
// the minute. The token is 256 random bits, so the limit is not what keeps a
// guesser out: it keeps a stranger from costing the core a store read a
// request.
func (ts *tunnels) mayEnrol(from netip.Addr) bool {
	ts.enrolMu.Lock()
	defer ts.enrolMu.Unlock()
	if minute := ts.now().Unix() / 60; minute != ts.enrolAt {
		ts.enrolAt, ts.enrolAll = minute, 0
		clear(ts.enrolBy)
	}
	p := clientPrefix(from)
	if ts.enrolAll >= enrolPerMinute || ts.enrolBy[p] >= enrolPerClient {
		return false
	}
	ts.enrolAll++
	ts.enrolBy[p]++
	return true
}

// enrol offers the core a token, for the key the handshake proved. The core
// decides; every refusal looks the same from outside.
func (ts *tunnels) enrol(w http.ResponseWriter, r *http.Request, key string) {
	from := client(r)
	if !ts.mayEnrol(from) {
		http.Error(w, "", http.StatusTooManyRequests)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, enrolBody+1))
	if err != nil || len(body) > enrolBody {
		http.Error(w, "", http.StatusForbidden)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	var out Enrolled
	if err := ts.link.call(ctx, VerbEnrol, EnrolAsk{Token: strings.TrimSpace(string(body)), Key: key, Client: from.String()}, &out); err != nil {
		if !isVerbError(err) {
			http.Error(w, "", http.StatusServiceUnavailable) // the core is away: the token is not spent
			return
		}
		http.Error(w, "", http.StatusForbidden)
		return
	}
	ts.log.Info("gate: an agent enrolled", "agent", out.Name, "from", from)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// nameOf is the agent a key is enrolled as.
func (ts *tunnels) nameOf(key string) (string, bool) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	name, ok := ts.keys[key]
	return name, ok
}

// connect turns the request's connection into the agent's tunnel, and holds
// it until it ends. The connection leaves the HTTP server here, and its time
// limits with it.
func (ts *tunnels) connect(w http.ResponseWriter, r *http.Request, key string) {
	name, ok := ts.nameOf(key)
	if !ok {
		http.Error(w, "", http.StatusForbidden)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	from := client(r)
	conn, brw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	if brw.Reader.Buffered() > 0 {
		return // it spoke before it was answered: not this protocol
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: "+tunnel.ALPN+"\r\n\r\n"); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{}) // the server's limits were for a request; a tunnel lives on
	ctx, cancel := context.WithTimeout(ts.ctx, 10*time.Second)
	c, err := tunnel.NewClient(ctx, conn, tunnelStreams)
	cancel()
	if err != nil {
		return
	}
	defer c.Close()
	l := &liveLink{name: name, client: c, since: ts.now(), from: from.String()}
	l.targets = ts.askTargets(l)
	if !ts.put(key, l) {
		return // its key was removed while it connected
	}
	ts.log.Info("gate: a tunnel is up", "agent", name, "from", from, "targets", len(l.targets))
	select {
	case <-c.Done():
	case <-ts.ctx.Done():
	}
	ts.drop(l)
	ts.log.Info("gate: a tunnel ended", "agent", name)
}

// askTargets reads the agent's target names: for the panel to offer, and
// nothing more. What a name leads to stays on the agent.
func (ts *tunnels) askTargets(l *liveLink) []string {
	ctx, cancel := context.WithTimeout(ts.ctx, 5*time.Second)
	defer cancel()
	s, err := l.client.Open(ctx, tunnel.TargetsName)
	if err != nil {
		return nil
	}
	defer s.Close()
	stop := context.AfterFunc(ctx, func() { _ = s.Close() })
	defer stop()
	var names []string
	if err := json.NewDecoder(io.LimitReader(s, 8<<10)).Decode(&names); err != nil {
		return nil
	}
	out := names[:0]
	for _, n := range names {
		if tunnel.ValidTarget(n) && len(out) < tunnelTargets {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// put makes l its agent's tunnel, ending the one it had: an agent that
// dials again has lost the old connection, whatever this end still thinks.
func (ts *tunnels) put(key string, l *liveLink) bool {
	ts.mu.Lock()
	if ts.keys[key] != l.name {
		ts.mu.Unlock()
		return false
	}
	old := ts.live[l.name]
	ts.live[l.name] = l
	ts.mu.Unlock()
	if old != nil {
		_ = old.client.Close()
	}
	return true
}

func (ts *tunnels) drop(l *liveLink) {
	ts.mu.Lock()
	if ts.live[l.name] == l {
		delete(ts.live, l.name)
	}
	ts.mu.Unlock()
}

// apply makes the enrolled keys the ones named. A tunnel whose agent is gone,
// or has another key now, is closed at once.
func (ts *tunnels) apply(agents []AgentKey) {
	keys := make(map[string]string, len(agents))
	names := make(map[string]bool, len(agents))
	for _, a := range agents {
		keys[a.Key] = a.Name
		names[a.Name] = true
	}
	ts.mu.Lock()
	var gone []*liveLink
	for name, l := range ts.live {
		if !names[name] {
			gone = append(gone, l)
			delete(ts.live, name)
		}
	}
	ts.keys = keys
	ts.mu.Unlock()
	for _, l := range gone {
		ts.log.Info("gate: an agent was removed; its tunnel is closed", "agent", l.name)
		_ = l.client.Close()
	}
}

// follow keeps the keys current until ctx ends. Like the routes, they outlive
// a core that went away: the tunnels in hand stay up.
func (ts *tunnels) follow(ctx context.Context) error {
	wait := newBackoff()
	var rev int64
	for ctx.Err() == nil {
		var a Agents
		if err := ts.link.call(ctx, VerbAgents, After{After: rev}, &a); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if !isVerbError(err) {
				rev = 0
			}
			if !wait.sleep(ctx) {
				return nil
			}
			continue
		}
		wait.reset()
		rev = a.Rev
		ts.apply(a.Agents)
	}
	return nil
}

// stopAll closes every tunnel: the gate is stopping.
func (ts *tunnels) stopAll() {
	ts.mu.Lock()
	all := make([]*liveLink, 0, len(ts.live))
	for name, l := range ts.live {
		all = append(all, l)
		delete(ts.live, name)
	}
	ts.mu.Unlock()
	for _, l := range all {
		_ = l.client.Close()
	}
}

// dial opens a stream to an agent's target. The connection it answers counts
// against the limits until it is closed.
func (ts *tunnels) dial(ctx context.Context, agent, target string) (net.Conn, error) {
	ts.mu.Lock()
	l := ts.live[agent]
	ts.mu.Unlock()
	if l == nil {
		return nil, ErrTunnelDown
	}
	if ts.open.Add(1) > tunnelStreamsTotal {
		ts.open.Add(-1)
		return nil, ErrTunnelFull
	}
	s, err := l.client.Open(ctx, target)
	if err != nil {
		ts.open.Add(-1)
		switch {
		case errors.Is(err, tunnel.ErrBusy):
			return nil, ErrTunnelFull
		case errors.Is(err, tunnel.ErrClosed):
			return nil, ErrTunnelDown
		}
		return nil, err
	}
	l.open.Add(1)
	return &tunnelConn{Conn: s, ts: ts, l: l}, nil
}

// tunnelConn is a stream that gives its place back when closed.
type tunnelConn struct {
	net.Conn
	ts   *tunnels
	l    *liveLink
	once sync.Once
}

func (c *tunnelConn) Close() error {
	c.once.Do(func() {
		c.ts.open.Add(-1)
		c.l.open.Add(-1)
	})
	return c.Conn.Close()
}

// CloseWrite says this end has no more to send.
func (c *tunnelConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// states is every tunnel now, for the gate's report.
func (ts *tunnels) states() []TunnelState {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	out := make([]TunnelState, 0, len(ts.live))
	for _, l := range ts.live {
		out = append(out, TunnelState{Name: l.name, Since: l.since.Unix(), From: l.from, Streams: int(l.open.Load()), Targets: l.targets})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
