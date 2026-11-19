package tunnel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// pair is a connection as the agent dialled it: the agent's end and the end
// that accepted.
func pair(t *testing.T) (agent, gate net.Conn) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	got := make(chan net.Conn, 1)
	go func() {
		c, _ := l.Accept()
		got <- c
	}()
	agent, err = net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	gate = <-got
	if gate == nil {
		t.Fatal("nothing accepted")
	}
	return agent, gate
}

// targets is an agent's list: each name a function that serves the target's
// end of a connection.
type targets map[string]func(net.Conn)

// dial serves the named target over a loopback TCP connection, as a real
// target would be reached.
func (ts targets) dial(t *testing.T) Dialer {
	return func(_ context.Context, name string) (net.Conn, error) {
		serve, ok := ts[name]
		if !ok {
			return nil, errors.New("no such target")
		}
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		defer l.Close()
		up, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			return nil, err
		}
		c, err := l.Accept() // before the listener closes, or the connection is reset
		if err != nil {
			return nil, err
		}
		go func() {
			defer c.Close()
			serve(c)
		}()
		return up, nil
	}
}

func echo(c net.Conn) { _, _ = io.Copy(c, c) }

// tunnelOf is a tunnel between an agent with that dialer and a client.
func tunnelOf(t *testing.T, maxStreams int, dial Dialer) (*Client, net.Conn) {
	t.Helper()
	agent, gate := pair(t)
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- Serve(ctx, agent, dial, maxStreams) }()
	c, err := NewClient(context.Background(), gate, maxStreams)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = c.Close()
		cancel()
		select {
		case <-served:
		case <-time.After(5 * time.Second):
			t.Error("the agent's side never ended")
		}
	})
	return c, agent
}

// within fails the test when f takes longer than d.
func within(t *testing.T, d time.Duration, what string, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); f() }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s: not within %v", what, d)
	}
}

func open(t *testing.T, c *Client, target string) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := c.Open(ctx, target)
	if err != nil {
		t.Fatalf("open %q: %v", target, err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func echoes(t *testing.T, s net.Conn, text string) {
	t.Helper()
	within(t, 5*time.Second, "an echo of "+text, func() {
		if _, err := s.Write([]byte(text)); err != nil {
			t.Errorf("write: %v", err)
			return
		}
		got := make([]byte, len(text))
		if _, err := io.ReadFull(s, got); err != nil || string(got) != text {
			t.Errorf("read %q, %v; want %q", got, err, text)
		}
	})
}

func TestAStreamCarriesBytesBothWays(t *testing.T) {
	c, _ := tunnelOf(t, 4, targets{"echo": echo}.dial(t))
	s := open(t, c, "echo")
	echoes(t, s, "hello")
	echoes(t, s, "and again")
}

// SSH's server speaks first. The stream must be open to the client before the
// client has sent a byte, or each waits on the other.
func TestATargetThatSpeaksFirstIsHeard(t *testing.T) {
	c, _ := tunnelOf(t, 4, targets{"ssh": func(c net.Conn) {
		_, _ = c.Write([]byte("SSH-2.0-test\r\n"))
		_, _ = io.Copy(io.Discard, c)
	}}.dial(t))
	s := open(t, c, "ssh")
	within(t, 5*time.Second, "the target's greeting", func() {
		got := make([]byte, 14)
		if _, err := io.ReadFull(s, got); err != nil || string(got) != "SSH-2.0-test\r\n" {
			t.Errorf("read %q, %v", got, err)
		}
	})
}

func TestALargeTransferArrivesWhole(t *testing.T) {
	c, _ := tunnelOf(t, 4, targets{"echo": echo}.dial(t))
	s := open(t, c, "echo")
	const size = 24 << 20
	sent, got := sha256.New(), sha256.New()
	within(t, 60*time.Second, "24 MiB there and back", func() {
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			if n, err := io.CopyN(got, s, size); err != nil {
				t.Errorf("read %d bytes: %v", n, err)
			}
		}()
		rnd := rand.New(rand.NewSource(1))
		if _, err := io.CopyN(io.MultiWriter(s, sent), rnd, size); err != nil {
			t.Errorf("write: %v", err)
		}
		wg.Wait()
	})
	if !bytes.Equal(sent.Sum(nil), got.Sum(nil)) {
		t.Fatal("what came back is not what was sent")
	}
}

// The client says it has no more to send, and the target still answers.
func TestAStreamHalfClosedStillAnswers(t *testing.T) {
	c, _ := tunnelOf(t, 4, targets{"count": func(c net.Conn) {
		all, _ := io.ReadAll(c)
		_, _ = c.Write(bytes.ToUpper(all))
	}}.dial(t))
	s := open(t, c, "count")
	within(t, 5*time.Second, "an answer after the half close", func() {
		_, _ = s.Write([]byte("no more after this"))
		_ = s.(interface{ CloseWrite() error }).CloseWrite()
		got, err := io.ReadAll(s)
		if err != nil || string(got) != "NO MORE AFTER THIS" {
			t.Errorf("read %q, %v", got, err)
		}
	})
}

// A target that says its piece and hangs up ends the stream for a client that
// is only reading.
func TestATargetHangingUpEndsTheStream(t *testing.T) {
	c, _ := tunnelOf(t, 4, targets{"bye": func(c net.Conn) { _, _ = c.Write([]byte("bye")) }}.dial(t))
	s := open(t, c, "bye")
	within(t, 5*time.Second, "the stream's end", func() {
		got, err := io.ReadAll(s)
		if err != nil || string(got) != "bye" {
			t.Errorf("read %q, %v", got, err)
		}
	})
}

func TestAnUnknownTargetIsRefusedAndTheTunnelLivesOn(t *testing.T) {
	c, _ := tunnelOf(t, 4, targets{"echo": echo}.dial(t))
	for _, name := range []string{"nope", "127.0.0.1:22", "a/b", "ünï côde"} {
		if _, err := c.Open(context.Background(), name); !errors.Is(err, ErrRefused) {
			t.Fatalf("open %q: %v, want ErrRefused", name, err)
		}
	}
	echoes(t, open(t, c, "echo"), "still here")
}

// The name reaches the agent's dialer exactly as it was given.
func TestATargetsNameArrivesAsGiven(t *testing.T) {
	got := make(chan string, 1)
	c, _ := tunnelOf(t, 4, func(_ context.Context, name string) (net.Conn, error) {
		got <- name
		return nil, errors.New("no")
	})
	const name = "a b/c?d#e%2Ff"
	_, _ = c.Open(context.Background(), name)
	if g := <-got; g != name {
		t.Fatalf("the dialer was given %q, want %q", g, name)
	}
}

func TestStreamsAtOnceUpToTheCapAndNoMore(t *testing.T) {
	const max = 8
	c, _ := tunnelOf(t, max, targets{"echo": echo}.dial(t))
	streams := make([]net.Conn, max)
	for i := range streams {
		streams[i] = open(t, c, "echo")
	}
	var wg sync.WaitGroup
	for i, s := range streams {
		wg.Add(1)
		go func() {
			defer wg.Done()
			text := bytes.Repeat([]byte{byte('a' + i)}, 200<<10)
			go func() { _, _ = s.Write(text) }()
			got := make([]byte, len(text))
			if _, err := io.ReadFull(s, got); err != nil || !bytes.Equal(got, text) {
				t.Errorf("stream %d: its own bytes did not come back: %v", i, err)
			}
		}()
	}
	within(t, 30*time.Second, "eight streams at once", wg.Wait)

	if _, err := c.Open(context.Background(), "echo"); !errors.Is(err, ErrBusy) {
		t.Fatalf("a stream past the cap: %v, want ErrBusy", err)
	}
	_ = streams[0].Close()
	echoes(t, open(t, c, "echo"), "a freed place is taken")
}

// The agent's bound holds against a client that claims a larger one.
func TestTheAgentsCapHoldsWhateverTheClientSays(t *testing.T) {
	agent, gate := pair(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var dials atomic.Int32
	hold := make(chan struct{})
	go func() {
		_ = Serve(ctx, agent, func(context.Context, string) (net.Conn, error) {
			dials.Add(1)
			a, b := net.Pipe()
			go func() { <-hold; _ = b.Close() }()
			return a, nil
		}, 2)
	}()
	c, err := NewClient(context.Background(), gate, 16)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	defer close(hold)
	for range 6 {
		go func() {
			octx, ocancel := context.WithTimeout(context.Background(), time.Second)
			defer ocancel()
			_, _ = c.Open(octx, "x")
		}()
	}
	time.Sleep(1500 * time.Millisecond)
	if n := dials.Load(); n != 2 {
		t.Fatalf("the agent dialled %d targets at once, want its cap of 2", n)
	}
}

// stalls waits until n stops rising, and says where it stopped.
func stalls(t *testing.T, n *atomic.Int64) int64 {
	t.Helper()
	last, still := int64(-1), 0
	for range 200 {
		time.Sleep(50 * time.Millisecond)
		if v := n.Load(); v == last && v > 0 {
			if still++; still >= 10 {
				return v
			}
		} else {
			last, still = v, 0
		}
	}
	t.Fatalf("still moving after 10s, at %d bytes", n.Load())
	return 0
}

// A reader that stops reading costs the tunnel a bounded number of bytes, in
// either direction, and stops no other stream. All but one of the streams are
// stalled here, which is the worst the cap allows.
func TestAStalledStreamHoldsLittleAndStopsNoOther(t *testing.T) {
	const max = 6
	var flooded atomic.Int64
	dial := func(ctx context.Context, name string) (net.Conn, error) {
		a, b := net.Pipe() // nothing buffered: what is written has been taken
		switch name {
		case "sink": // never reads
			t.Cleanup(func() { _ = b.Close() })
		case "flood": // never stops writing
			go func() {
				buf := make([]byte, 16<<10)
				for {
					n, err := b.Write(buf)
					flooded.Add(int64(n))
					if err != nil {
						return
					}
				}
			}()
		default:
			go func() { echo(b); _ = b.Close() }()
		}
		return a, nil
	}
	c, _ := tunnelOf(t, max, dial)

	// Three streams whose target never reads, written to without end.
	var sunk [3]atomic.Int64
	for i := range sunk {
		s := open(t, c, "sink")
		go func() {
			buf := make([]byte, 16<<10)
			for {
				n, err := s.Write(buf)
				sunk[i].Add(int64(n))
				if err != nil {
					return
				}
			}
		}()
	}
	// Two streams whose target never stops, and which are never read.
	open(t, c, "flood")
	open(t, c, "flood")

	const bound = 4 * StreamWindow // the window, and a buffer or two each side
	for i := range sunk {
		if v := stalls(t, &sunk[i]); v > bound {
			t.Errorf("a target that never reads took %d bytes before the writer waited, over %d", v, bound)
		}
	}
	if v := stalls(t, &flooded); v > 2*bound {
		t.Errorf("two unread streams took %d bytes from their targets before those waited, over %d", v, 2*bound)
	}
	// The one stream left still works, and at size.
	s := open(t, c, "echo")
	echoes(t, s, "the others are stalled; this one is not")
	within(t, 20*time.Second, "4 MiB on the stream that is not stalled", func() {
		text := bytes.Repeat([]byte("0123456789abcdef"), 4<<20/16)
		go func() { _, _ = s.Write(text) }()
		got := make([]byte, len(text))
		if _, err := io.ReadFull(s, got); err != nil || !bytes.Equal(got, text) {
			t.Errorf("the working stream lost its bytes: %v", err)
		}
	})
}

// A client that gives a stream up frees the target, even one that says nothing.
func TestAStreamGivenUpFreesItsTarget(t *testing.T) {
	gone := make(chan struct{})
	c, _ := tunnelOf(t, 1, targets{"echo": echo, "quiet": func(c net.Conn) {
		_, _ = io.Copy(io.Discard, c)
		close(gone)
	}}.dial(t))
	s := open(t, c, "quiet")
	_, _ = s.Write([]byte("x"))
	_ = s.Close()
	select {
	case <-gone:
	case <-time.After(5 * time.Second):
		t.Fatal("the target was left waiting on a stream nobody holds")
	}
	echoes(t, open(t, c, "echo"), "its place is free")
}

func TestADeadConnectionIsNoticed(t *testing.T) {
	c, agent := tunnelOf(t, 4, targets{"echo": echo}.dial(t))
	s := open(t, c, "echo")
	echoes(t, s, "alive")
	_ = agent.Close() // the agent's machine is gone
	within(t, 5*time.Second, "the stream's end", func() {
		if _, err := io.ReadAll(s); err == nil {
			t.Error("a stream on a dead connection ended as if all had arrived")
		}
	})
	select {
	case <-c.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the client never learnt the connection had ended")
	}
	if _, err := c.Open(context.Background(), "echo"); !errors.Is(err, ErrClosed) {
		t.Fatalf("open on a dead tunnel: %v, want ErrClosed", err)
	}
}

func TestTheAgentEndsWithItsContextAndTheClientLearnsOfIt(t *testing.T) {
	agent, gate := pair(t)
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- Serve(ctx, agent, targets{"echo": echo}.dial(t), 4) }()
	c, err := NewClient(context.Background(), gate, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	echoes(t, open(t, c, "echo"), "up")
	cancel()
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve outlived its context")
	}
	select {
	case <-c.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the client never learnt the agent had gone")
	}
}

// An agent whose target cannot be reached in time gives the client its answer
// when the client stops waiting, and the place is freed.
func TestAnOpenThatIsNotWaitedForFreesItsPlace(t *testing.T) {
	release := make(chan struct{})
	c, _ := tunnelOf(t, 1, func(ctx context.Context, name string) (net.Conn, error) {
		if name == "slow" {
			select {
			case <-release:
			case <-ctx.Done():
			}
			return nil, errors.New("too late")
		}
		a, b := net.Pipe()
		go func() { echo(b); _ = b.Close() }()
		return a, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := c.Open(ctx, "slow"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("open: %v, want the deadline", err)
	}
	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for {
		s, err := c.Open(context.Background(), "echo")
		if err == nil {
			_ = s.Close()
			return
		}
		if !errors.Is(err, ErrBusy) || time.Now().After(deadline) {
			t.Fatalf("the place was never freed: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// closeSeen is a target's connection that says when the agent has closed it.
type closeSeen struct {
	*net.TCPConn
	once   sync.Once
	closed chan struct{}
}

func (c *closeSeen) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.TCPConn.Close()
}

// A client that has said it has no more to send, and then gives the stream
// up, frees a target that is saying nothing: after the half close no copy is
// left to notice.
func TestAStreamGivenUpAfterAHalfCloseFreesItsTarget(t *testing.T) {
	closed := make(chan struct{})
	halved := make(chan struct{})
	quiet := targets{"quiet": func(c net.Conn) {
		_, _ = io.Copy(io.Discard, c) // to the half close
		close(halved)
		<-closed // and then says nothing
	}}.dial(t)
	c, _ := tunnelOf(t, 1, func(ctx context.Context, name string) (net.Conn, error) {
		up, err := quiet(ctx, name)
		if err != nil {
			return nil, err
		}
		return &closeSeen{TCPConn: up.(*net.TCPConn), closed: closed}, nil
	})
	s := open(t, c, "quiet")
	_, _ = s.Write([]byte("x"))
	_ = s.(interface{ CloseWrite() error }).CloseWrite()
	select {
	case <-halved:
	case <-time.After(5 * time.Second):
		t.Fatal("the half close never reached the target")
	}
	select {
	case <-closed:
		t.Fatal("the target was closed at the half close, before it could answer")
	case <-time.After(200 * time.Millisecond):
	}
	_ = s.Close()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("the target was left open on a stream nobody holds")
	}
}
