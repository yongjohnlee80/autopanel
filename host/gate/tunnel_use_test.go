package gate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	core "github.com/yongjohnlee80/autopanel/core/gate"
	"github.com/yongjohnlee80/autopanel/internal/agent"
)

// behindAnAgent is a gate's tunnels with one agent, nas, connected, serving
// the targets given.
func behindAnAgent(t *testing.T, targets map[string]agent.Target) (*tunnels, context.CancelFunc) {
	t.Helper()
	f := newFakeCore(t, "", "")
	ts, srv, pool := tunnelServer(t, f)
	key := newKey(t)
	f.setAgents(AgentKey{Name: "nas", Key: digestOf(t, key)})
	until(t, "the gate never heard of the agent's key", func() bool { _, ok := ts.nameOf(digestOf(t, key)); return ok })
	_, stop := runAgent(t, srv, pool, key, targets)
	until(t, "the tunnel never came up", up(ts, "nas"))
	return ts, stop
}

// site is a web service on the agent's machine: it says what it saw, sends a
// body back, and speaks a small upgraded protocol.
func site(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Header.Get("Upgrade") == "echo":
			conn, brw, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
			_ = brw.Flush()
			_, _ = io.Copy(conn, brw)
		case r.Method == http.MethodPost:
			h := sha256.New()
			n, _ := io.Copy(h, r.Body)
			w.Header().Set("X-Bytes", itoa(n))
			_, _ = w.Write(h.Sum(nil))
		default:
			w.Header().Set("X-Seen-Host", r.Host)
			w.Header().Set("X-Seen-For", r.Header.Get("X-Forwarded-For"))
			w.Header().Set("X-Seen-Proto", r.Header.Get("X-Forwarded-Proto"))
			_, _ = io.WriteString(w, r.URL.RequestURI())
		}
	}))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

// A route whose upstream is behind a tunnel serves a page, a large upload and
// an upgraded connection, as a route to a local port does; with the agent
// away, or a target its file does not list, the answer is 502 and says
// nothing of the tunnel's names.
func TestARouteThroughATunnel(t *testing.T) {
	ts, stopAgent := behindAnAgent(t, map[string]agent.Target{"web": {To: site(t)}})
	snap, err := Build([]core.Route{
		{ID: 1, Host: "photos.example.com", PathPrefix: "/", Upstream: "tunnel://nas/web"},
		{ID: 2, Host: "unlisted.example.com", PathPrefix: "/", Upstream: "tunnel://nas/other"},
		{ID: 3, Host: "away.example.com", PathPrefix: "/", Upstream: "tunnel://attic/web"},
	}, nil, ts.dial)
	if err != nil {
		t.Fatal(err)
	}
	tbl := core.NewTable[http.Handler]()
	tbl.Swap(snap)
	front := httptest.NewServer(Handler(tbl))
	t.Cleanup(front.Close)
	do := func(method, host, path string, body io.Reader) *http.Response {
		t.Helper()
		req, _ := http.NewRequest(method, front.URL+path, body)
		req.Host = host
		req.Header.Set("X-Forwarded-For", "6.6.6.6") // a client naming itself
		res, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}

	res := do("GET", "photos.example.com", "/album/1?page=2", nil)
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || string(body) != "/album/1?page=2" || res.Header.Get("X-Seen-Host") != "photos.example.com" ||
		res.Header.Get("X-Seen-For") != "127.0.0.1" || res.Header.Get("X-Seen-Proto") != "http" {
		t.Fatalf("a page through the tunnel = %d %q %v", res.StatusCode, body, res.Header)
	}

	// 12 MiB up, through the stream's 64 KiB window.
	big := bytes.Repeat([]byte("0123456789abcdef"), 12<<20/16)
	want := sha256.Sum256(big)
	res = do("POST", "photos.example.com", "/upload", bytes.NewReader(big))
	sum, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || !bytes.Equal(sum, want[:]) || res.Header.Get("X-Bytes") != itoa(int64(len(big))) {
		t.Fatalf("an upload through the tunnel = %d, %s bytes seen", res.StatusCode, res.Header.Get("X-Bytes"))
	}

	// An upgraded connection (a WebSocket's shape): bytes both ways after the 101.
	conn, err := net.Dial("tcp", strings.TrimPrefix(front.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = io.WriteString(conn, "GET /live HTTP/1.1\r\nHost: photos.example.com\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
	head := make([]byte, 0, 256)
	one := make([]byte, 1)
	for !bytes.HasSuffix(head, []byte("\r\n\r\n")) {
		if _, err := conn.Read(one); err != nil {
			t.Fatalf("the upgrade's answer: %q, %v", head, err)
		}
		head = append(head, one[0])
	}
	if !strings.HasPrefix(string(head), "HTTP/1.1 101") {
		t.Fatalf("the upgrade was answered %q", head)
	}
	for _, msg := range []string{"first", "and a second, later"} {
		_, _ = io.WriteString(conn, msg)
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(conn, got); err != nil || string(got) != msg {
			t.Fatalf("over the upgraded connection: %q, %v", got, err)
		}
	}
	if n := ts.open.Load(); n != 1 {
		t.Fatalf("%d streams are held; want the upgraded connection's one", n)
	}
	_ = conn.Close()
	until(t, "a finished request kept its stream", func() bool { return ts.open.Load() == 0 })

	for _, host := range []string{"unlisted.example.com", "away.example.com"} {
		res = do("GET", host, "/", nil)
		page, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != http.StatusBadGateway || !strings.Contains(string(page), "tunnel to it is down") {
			t.Fatalf("%s = %d %q", host, res.StatusCode, page)
		}
		for _, secret := range []string{"nas", "attic", "other", "web"} {
			if strings.Contains(string(page), secret) {
				t.Errorf("the 502 page names %q", secret)
			}
		}
	}
	stopAgent()
	until(t, "the tunnel outlived its agent", func() bool { return len(ts.states()) == 0 })
	res = do("GET", "photos.example.com", "/", nil)
	res.Body.Close()
	if res.StatusCode != http.StatusBadGateway {
		t.Fatalf("with the agent gone = %d", res.StatusCode)
	}
	if ts.open.Load() != 0 {
		t.Fatalf("%d places held after refusals", ts.open.Load())
	}
}

// A TCP forward whose target is behind a tunnel: a server that speaks first
// is heard (SSH), bytes go both ways, the client's half close still gets its
// answer, an idle connection is closed, and with the agent away the
// connection is simply closed.
func TestAForwardThroughATunnelCarriesTCP(t *testing.T) {
	greeter, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = greeter.Close() })
	go func() {
		for {
			c, err := greeter.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.WriteString(c, "SSH-2.0-test\r\n")
				all, _ := io.ReadAll(c) // to the client's half close
				_, _ = c.Write(bytes.ToUpper(all))
			}()
		}
	}()
	ts, stopAgent := behindAnAgent(t, map[string]agent.Target{"ssh": {To: greeter.Addr().String()}, "echo": {To: echoTarget(t)}})

	f := newForwarder(quiet())
	f.tunnel = ts.dial
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { f.stopAll(); cancel() })
	sshAddr, idleAddr, awayAddr := freeAddr(t), freeAddr(t), freeAddr(t)
	f.apply(ctx, 20, []Stream{
		{Name: "forward:nas-ssh", Listen: sshAddr, To: "tunnel://nas/ssh", IdleSecs: 30, PerClient: 4, Share: 8, Plain: true},
		{Name: "forward:idle", Listen: idleAddr, To: "tunnel://nas/echo", IdleSecs: 1, PerClient: 4, Share: 8, Plain: true},
		{Name: "forward:away", Listen: awayAddr, To: "tunnel://attic/ssh", IdleSecs: 30, PerClient: 4, Share: 8, Plain: true},
	})
	dial := func(addr string) net.Conn {
		t.Helper()
		var c net.Conn
		until(t, "the forward never listened on "+addr, func() bool {
			var err error
			c, err = net.DialTimeout("tcp", addr, time.Second)
			return err == nil
		})
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		return c
	}

	c := dial(sshAddr)
	greeting := make([]byte, 14)
	if _, err := io.ReadFull(c, greeting); err != nil || string(greeting) != "SSH-2.0-test\r\n" {
		t.Fatalf("the server's greeting = %q, %v", greeting, err)
	}
	_, _ = io.WriteString(c, "hello from outside")
	_ = c.(*net.TCPConn).CloseWrite()
	rest, err := io.ReadAll(c)
	if err != nil || string(rest) != "HELLO FROM OUTSIDE" {
		t.Fatalf("after the half close = %q, %v", rest, err)
	}
	_ = c.Close()
	until(t, "a finished connection kept its stream", func() bool { return ts.open.Load() == 0 })

	// Idle: a second of silence and the pair is closed, the stream given back.
	c = dial(idleAddr)
	_, _ = io.WriteString(c, "x")
	one := make([]byte, 1)
	if _, err := io.ReadFull(c, one); err != nil {
		t.Fatal(err)
	}
	began := time.Now()
	if _, err := c.Read(one); err == nil {
		t.Fatal("an idle connection was sent something")
	}
	if d := time.Since(began); d < 900*time.Millisecond || d > 3*time.Second {
		t.Fatalf("an idle connection was closed after %v; want about a second", d)
	}
	_ = c.Close()
	until(t, "an idle connection kept its stream", func() bool { return ts.open.Load() == 0 })

	// An agent that is not connected, and then this one going away mid-stream.
	c = dial(awayAddr)
	if n, err := c.Read(one); err == nil {
		t.Fatalf("a forward to an agent that is away sent %d bytes", n)
	}
	_ = c.Close()
	c = dial(sshAddr)
	if _, err := io.ReadFull(c, greeting); err != nil {
		t.Fatal(err)
	}
	stopAgent()
	began = time.Now()
	_, _ = io.ReadAll(c)
	if d := time.Since(began); d > 5*time.Second {
		t.Fatalf("a connection through a tunnel that went away hung for %v", d)
	}
	_ = c.Close()
	until(t, "a stream of a tunnel that is gone is still counted", func() bool { return ts.open.Load() == 0 && f.openNow() == 0 })
}
