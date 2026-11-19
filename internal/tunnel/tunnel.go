// Package tunnel carries connections to a machine that has no open port. The
// machine's agent dials out and holds one connection; over it the other end
// opens streams, each a two-way byte stream to a target the agent names.
//
// The streams are HTTP/2 with the roles turned round: the side that dialled
// serves, and the side that accepted is the client and opens a stream when it
// needs a connection. Flow control, keep-alive pings and a drained shutdown
// are HTTP/2's own, and both ends are the standard library's.
//
// This package is the carrier only. Who may connect, and which targets exist,
// are its callers' to decide: the agent's dial function is the one place a
// target's name becomes an address.
//
// Decision: docs/decisions/forwards.md#tunnels
package tunnel

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// The limits of one tunnel.
const (
	// StreamWindow is how much one stream may have in flight before the
	// sender must wait: what a slow reader costs the other end in memory.
	StreamWindow = 64 << 10
	// PingEvery is how often an idle connection is checked, and PingWait how
	// long an answer may take before the connection is given up.
	PingEvery = 15 * time.Second
	PingWait  = 15 * time.Second
)

// ErrRefused is the agent refusing a target: it has none of that name.
var ErrRefused = errors.New("tunnel: the agent refused the target")

// ErrClosed is a tunnel whose connection has ended.
var ErrClosed = errors.New("tunnel: the connection has ended")

// ErrBusy is a tunnel with every one of its streams in use.
var ErrBusy = errors.New("tunnel: every stream is in use")

// h2config is HTTP/2 for a tunnel of that many streams. The connection's
// window is every stream's together: bytes a stream's reader has not taken
// count against the connection too, so with less, a few stalled streams would
// stop the others.
func h2config(maxStreams int) *http.HTTP2Config {
	return &http.HTTP2Config{
		MaxConcurrentStreams:          maxStreams,
		MaxReceiveBufferPerStream:     StreamWindow,
		MaxReceiveBufferPerConnection: maxStreams * StreamWindow,
		SendPingTimeout:               PingEvery,
		PingTimeout:                   PingWait,
	}
}

// Dialer turns a target's name into a connection, on the agent's side. It is
// where the agent's own list of targets is held: a name it does not have is
// an error, and nothing the other end sends can add one.
type Dialer func(ctx context.Context, target string) (net.Conn, error)

// Serve is the agent's side: it serves streams on conn until the connection
// ends or ctx does, opening each one's target with dial. maxStreams bounds the
// streams at once, whatever the other end asks.
func Serve(ctx context.Context, conn net.Conn, dial Dialer, maxStreams int) error {
	srv := &http.Server{
		Handler:   http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { serveStream(w, r, dial) }),
		HTTP2:     h2config(maxStreams),
		Protocols: new(http.Protocols),
	}
	srv.Protocols.SetUnencryptedHTTP2(true) // the bytes are HTTP/2 from the first one: conn is already the secured channel
	l := &oneConn{done: make(chan struct{})}
	l.conn = &closeNotify{Conn: conn, closed: l.done}
	stop := context.AfterFunc(ctx, func() { _ = srv.Close() })
	defer stop()
	err := srv.Serve(l)
	<-l.done // Serve returns when the listener has nothing more; the connection may live on
	_ = srv.Close()
	if errors.Is(err, errOneConn) || errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// serveStream is one stream on the agent: dial the target, say so at once,
// then carry bytes both ways.
func serveStream(w http.ResponseWriter, r *http.Request, dial Dialer) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	name, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(r.URL.Path, "/"))
	target := string(name)
	if err != nil || target == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	up, err := dial(r.Context(), target)
	if err != nil {
		w.WriteHeader(http.StatusForbidden) // one answer whatever was wrong: the other end learns nothing of this network
		return
	}
	defer up.Close()
	// A stream given up closes the target whatever each direction was doing:
	// after a half close, nothing else is watching the stream.
	stop := context.AfterFunc(r.Context(), func() { _ = up.Close() })
	defer stop()
	// The answer's headers go now, before a byte is read: a target that
	// speaks first (SSH) would otherwise wait on a client that waits on it.
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	_ = rc.Flush()
	go func() { // the other end → target
		_, err := io.Copy(up, r.Body)
		cw, half := up.(interface{ CloseWrite() error })
		if err == nil && half {
			_ = cw.CloseWrite() // it has no more to send; the target may still answer
			return
		}
		if err != nil {
			_ = up.Close() // the stream was given up: the target is not left waiting
		}
	}()
	// target → the other end. The stream ends when the target has no more to
	// say: an answer cannot be half-closed, and a reader waiting for the
	// target's end must be told of it.
	buf := make([]byte, 32<<10)
	for {
		n, err := up.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			_ = rc.Flush()
		}
		if err != nil {
			return
		}
	}
}

// errOneConn ends the one-connection listener's Accept once its connection
// has been handed over.
var errOneConn = errors.New("tunnel: the one connection is taken")

// oneConn is a listener of the single connection it was given.
type oneConn struct {
	conn net.Conn
	once sync.Once
	done chan struct{} // closed when the connection is
}

func (l *oneConn) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() { c = l.conn })
	if c != nil {
		return c, nil
	}
	<-l.done
	return nil, errOneConn
}

// Close ends the connection: it is all this listener has, and the server
// closing its listener is the server being told to stop.
func (l *oneConn) Close() error   { return l.conn.Close() }
func (l *oneConn) Addr() net.Addr { return l.conn.LocalAddr() }

type closeNotify struct {
	net.Conn
	once   sync.Once
	closed chan struct{}
}

func (c *closeNotify) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

// Client is the other side: it opens streams on the connection an agent
// dialled.
type Client struct {
	cc     *http.ClientConn
	conn   net.Conn
	closed chan struct{}
	slots  chan struct{} // one per stream open now
}

// NewClient takes the connection an agent dialled. The connection is used for
// every stream, and is never dialled again: when it ends, the client is over.
// maxStreams bounds the streams open at once; the agent's own bound holds
// whatever is said here.
func NewClient(ctx context.Context, conn net.Conn, maxStreams int) (*Client, error) {
	c := &Client{closed: make(chan struct{}), slots: make(chan struct{}, maxStreams)}
	c.conn = &closeNotify{Conn: conn, closed: c.closed}
	tr := &http.Transport{
		DialContext:        func(context.Context, string, string) (net.Conn, error) { return c.conn, nil },
		HTTP2:              h2config(maxStreams),
		Protocols:          new(http.Protocols),
		DisableCompression: true,
	}
	tr.Protocols.SetUnencryptedHTTP2(true)
	// One connection, held by hand: a transport's own pool would dial another
	// when this one is busy, and there is no other.
	cc, err := tr.NewClientConn(ctx, "http", "agent:80")
	if err != nil {
		_ = c.conn.Close()
		return nil, err
	}
	c.cc = cc
	// One stream that asks for nothing, before any other: the agent's refusal
	// of it is the first word that it speaks the protocol at all, and by then
	// its settings have arrived, which say how many streams it will serve.
	if _, err := c.Open(ctx, ""); !errors.Is(err, ErrRefused) {
		_ = c.Close()
		if err == nil {
			err = errors.New("tunnel: the agent opened a stream to no target")
		}
		return nil, err
	}
	// The places are the fewer of what was asked and what the agent serves.
	// Counting them here, and not asking the connection each time, is what
	// makes a full tunnel an answer at once: the connection frees a finished
	// stream's place a moment after the stream's owner has let go of it.
	for range 2000 {
		if cc.InFlight() == 0 {
			break
		}
		select {
		case <-ctx.Done():
			_ = c.Close()
			return nil, ctx.Err()
		case <-time.After(time.Millisecond):
		}
	}
	if n := cc.Available(); n > 0 && n < maxStreams {
		c.slots = make(chan struct{}, n)
	}
	return c, nil
}

// Done is closed when the tunnel's connection has ended.
func (c *Client) Done() <-chan struct{} { return c.closed }

// Close ends the tunnel and every stream on it.
func (c *Client) Close() error {
	_ = c.cc.Close()
	return c.conn.Close()
}

// Open opens a stream to the agent's target of that name. The stream is a
// connection like any other: Read, Write and Close; CloseWrite says this end
// has no more to send. With every stream in use it is ErrBusy at once, never
// a wait.
func (c *Client) Open(ctx context.Context, target string) (net.Conn, error) {
	select {
	case <-c.closed:
		return nil, ErrClosed
	default:
	}
	select {
	case c.slots <- struct{}{}:
	default:
		return nil, ErrBusy
	}
	pr, pw := io.Pipe()
	sctx, stop := context.WithCancel(context.WithoutCancel(ctx)) // the stream outlives the call that opened it
	var freed sync.Once
	cancel := func() {
		stop()
		freed.Do(func() { <-c.slots })
	}
	// The name travels encoded, so that nothing on the way reads it as a path
	// and tidies it.
	req, err := http.NewRequestWithContext(sctx, http.MethodPost, "http://agent/"+base64.RawURLEncoding.EncodeToString([]byte(target)), pr)
	if err != nil {
		cancel()
		return nil, err
	}
	type result struct {
		res *http.Response
		err error
	}
	got := make(chan result, 1)
	go func() {
		res, err := c.cc.RoundTrip(req)
		got <- result{res, err}
	}()
	select {
	case r := <-got:
		if r.err != nil {
			cancel()
			_ = pw.Close()
			select {
			case <-c.closed:
				return nil, ErrClosed
			default:
			}
			if c.cc.Err() != nil {
				return nil, ErrClosed
			}
			return nil, r.err
		}
		if r.res.StatusCode != http.StatusOK {
			_ = r.res.Body.Close()
			cancel()
			_ = pw.Close()
			return nil, ErrRefused
		}
		return &stream{body: r.res.Body, w: pw, cancel: cancel}, nil
	case <-ctx.Done():
		stop() // the answer, when it comes, is an error
		_ = pw.Close()
		go func() {
			if r := <-got; r.err == nil {
				_ = r.res.Body.Close()
			}
			cancel()
		}()
		return nil, ctx.Err()
	}
}

// stream is one stream as a connection.
type stream struct {
	body   io.ReadCloser
	w      *io.PipeWriter
	cancel context.CancelFunc
	once   sync.Once
}

func (s *stream) Read(p []byte) (int, error)  { return s.body.Read(p) }
func (s *stream) Write(p []byte) (int, error) { return s.w.Write(p) }
func (s *stream) CloseWrite() error           { return s.w.Close() }
func (s *stream) Close() error {
	s.once.Do(func() {
		_ = s.w.Close()
		_ = s.body.Close()
		s.cancel()
	})
	return nil
}

type tunnelAddr struct{}

func (tunnelAddr) Network() string { return "tunnel" }
func (tunnelAddr) String() string  { return "tunnel" }

func (s *stream) LocalAddr() net.Addr              { return tunnelAddr{} }
func (s *stream) RemoteAddr() net.Addr             { return tunnelAddr{} }
func (s *stream) SetDeadline(time.Time) error      { return nil }
func (s *stream) SetReadDeadline(time.Time) error  { return nil }
func (s *stream) SetWriteDeadline(time.Time) error { return nil }
