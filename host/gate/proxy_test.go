package gate

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	core "github.com/yongjohnlee80/autopanel/core/gate"
)

// front serves the gate's handler over a real listener: HTTP/1.1, or TLS
// with HTTP/2 when h2 is set.
func front(t *testing.T, tbl *Table, h2 bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(Handler(tbl))
	if h2 {
		srv.EnableHTTP2 = true
		srv.StartTLS()
	} else {
		srv.Start()
	}
	t.Cleanup(srv.Close)
	return srv
}

// to makes the table serve example.com from upstream.
func to(t *testing.T, tbl *Table, upstream string) {
	t.Helper()
	snap, err := Build([]core.Route{{ID: 1, Host: "example.com", PathPrefix: "/", Upstream: upstream}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tbl.Swap(snap)
}

// named answers every request with its name, after a short wait, so requests
// are in flight when the table changes.
func named(t *testing.T, name string, wait time.Duration) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(wait)
		_, _ = io.WriteString(w, name)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// The table is swapped a few hundred times while clients keep asking: every
// request is answered, by one upstream or the other, and none fails.
func TestAHotReloadUnderLoadDropsNoRequest(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(map[bool]string{false: "http1", true: "http2"}[h2], func(t *testing.T) {
			a, b := named(t, "a", 2*time.Millisecond), named(t, "b", 2*time.Millisecond)
			tbl := core.NewTable[http.Handler]()
			to(t, tbl, a.URL)
			gate := front(t, tbl, h2)
			client := gate.Client()

			stop := make(chan struct{})
			var swaps atomic.Int64
			var swapping sync.WaitGroup
			swapping.Add(1)
			go func() {
				defer swapping.Done()
				ups := []string{b.URL, a.URL}
				for i := 0; ; i++ {
					select {
					case <-stop:
						return
					default:
					}
					snap, err := Build([]core.Route{{ID: 1, Host: "example.com", PathPrefix: "/", Upstream: ups[i%2]}}, nil)
					if err != nil {
						t.Error(err)
						return
					}
					tbl.Swap(snap)
					swaps.Add(1)
					time.Sleep(3 * time.Millisecond)
				}
			}()

			const clients, each = 16, 40
			var seen [2]atomic.Int64
			var failed atomic.Int64
			var wg sync.WaitGroup
			for c := 0; c < clients; c++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for i := 0; i < each; i++ {
						req, _ := http.NewRequest("GET", gate.URL+"/", nil)
						req.Host = "example.com"
						res, err := client.Do(req)
						if err != nil {
							failed.Add(1)
							t.Errorf("a request failed during a reload: %v", err)
							return
						}
						body, _ := io.ReadAll(res.Body)
						_ = res.Body.Close()
						switch {
						case res.StatusCode == 200 && string(body) == "a":
							seen[0].Add(1)
						case res.StatusCode == 200 && string(body) == "b":
							seen[1].Add(1)
						default:
							failed.Add(1)
							t.Errorf("a request during a reload answered %d %q", res.StatusCode, body)
							return
						}
					}
				}()
			}
			wg.Wait()
			close(stop)
			swapping.Wait()
			if got := seen[0].Load() + seen[1].Load(); got != clients*each || failed.Load() != 0 {
				t.Fatalf("%d of %d requests answered, %d failed", got, clients*each, failed.Load())
			}
			if seen[0].Load() == 0 || seen[1].Load() == 0 || swaps.Load() < 20 {
				t.Fatalf("the load did not cross a reload: a=%d b=%d swaps=%d", seen[0].Load(), seen[1].Load(), swaps.Load())
			}
		})
	}
}

// A request already with its upstream when the route moves, or is removed,
// finishes there; the next request takes the new table.
func TestARequestInFlightFinishesOnTheTableItStartedWith(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		_, _ = io.WriteString(w, "old")
	}))
	t.Cleanup(slow.Close)
	fresh := named(t, "new", 0)
	tbl := core.NewTable[http.Handler]()
	to(t, tbl, slow.URL)
	gate := front(t, tbl, false)

	get := func() (int, string, error) {
		req, _ := http.NewRequest("GET", gate.URL+"/", nil)
		req.Host = "example.com"
		res, err := gate.Client().Do(req)
		if err != nil {
			return 0, "", err
		}
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(body), nil
	}
	type answer struct {
		code int
		body string
		err  error
	}
	first := make(chan answer, 1)
	go func() {
		code, body, err := get()
		first <- answer{code, body, err}
	}()
	<-entered
	to(t, tbl, fresh.URL)
	if code, body, err := get(); err != nil || code != 200 || body != "new" {
		t.Fatalf("after the reload = %d %q %v; want the new upstream", code, body, err)
	}
	empty, err := Build(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	tbl.Swap(empty)
	if code, _, err := get(); err != nil || code != 404 {
		t.Fatalf("after the route is removed = %d %v; want 404", code, err)
	}
	close(release)
	if got := <-first; got.err != nil || got.code != 200 || got.body != "old" {
		t.Fatalf("the request in flight = %d %q %v; want it finished by the upstream it started with", got.code, got.body, got.err)
	}
}

// An Upgrade request becomes a two-way byte stream to the upstream, as a
// WebSocket needs, and stays one while the table changes under it.
func TestAnUpgradedConnectionIsATwoWayStream(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") || r.Header.Get("Sec-Websocket-Key") != "dGhlIHNhbXBsZSBub25jZQ==" {
			http.Error(w, "not an upgrade", 400)
			return
		}
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")
		_ = rw.Flush()
		line := bufio.NewScanner(rw)
		for line.Scan() { // the upstream speaks only when spoken to, then echoes
			if _, err := fmt.Fprintf(conn, "echo %s\n", line.Text()); err != nil {
				return
			}
		}
	}))
	t.Cleanup(up.Close)
	tbl := core.NewTable[http.Handler]()
	to(t, tbl, up.URL)
	gate := front(t, tbl, false)

	conn, err := net.Dial("tcp", gate.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = io.WriteString(conn, "GET /socket HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
	rd := bufio.NewReader(conn)
	res, err := http.ReadResponse(rd, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 101 || !strings.EqualFold(res.Header.Get("Upgrade"), "websocket") || res.Header.Get("Sec-Websocket-Accept") != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatalf("the upgrade answered %d %v; want 101 with the upstream's headers", res.StatusCode, res.Header)
	}
	say := func(s string) {
		t.Helper()
		if _, err := io.WriteString(conn, s+"\n"); err != nil {
			t.Fatal(err)
		}
		got, err := rd.ReadString('\n')
		if err != nil || got != "echo "+s+"\n" {
			t.Fatalf("sent %q, got %q %v", s, got, err)
		}
	}
	say("one")
	say("two")
	empty, err := Build(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	tbl.Swap(empty) // the route is removed: the open stream is not cut
	say("three")
}

// A large upload of unknown length reaches the upstream while the client is
// still sending (the gate does not hold it in memory), whole and unchanged.
func TestALargeUploadStreamsThrough(t *testing.T) {
	// Far more than the socket buffers and HTTP/2's windows between the two ends hold.
	const size = 24 << 20
	for _, h2 := range []bool{false, true} {
		t.Run(map[bool]string{false: "http1", true: "http2"}[h2], func(t *testing.T) {
			var got atomic.Int64
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.ContentLength != -1 {
					http.Error(w, "the upload came with a length", 400)
					return
				}
				sum := sha256.New()
				buf := make([]byte, 64<<10)
				for {
					n, err := r.Body.Read(buf)
					sum.Write(buf[:n])
					got.Add(int64(n))
					if err != nil {
						break
					}
				}
				_, _ = fmt.Fprintf(w, "%d %s", got.Load(), hex.EncodeToString(sum.Sum(nil)))
			}))
			t.Cleanup(up.Close)
			tbl := core.NewTable[http.Handler]()
			to(t, tbl, up.URL)
			gate := front(t, tbl, h2)

			pr, pw := io.Pipe()
			want := sha256.New()
			sent := make(chan struct{})
			go func() {
				defer close(sent)
				chunk := make([]byte, 1<<20)
				for i := range chunk {
					chunk[i] = byte(i * 31)
				}
				sent := 0
				write := func(n int) bool {
					for ; n > 0; n-- {
						chunk[0] = byte(sent >> 20) // every chunk differs
						want.Write(chunk)
						if _, err := pw.Write(chunk); err != nil {
							return false
						}
						sent += len(chunk)
					}
					return true
				}
				if !write(size / 2 >> 20) {
					return
				}
				// The second half is not sent until the upstream holds most of the first.
				deadline := time.Now().Add(20 * time.Second)
				for got.Load() < size/4 {
					if time.Now().After(deadline) {
						_ = pw.CloseWithError(fmt.Errorf("the upstream saw %d bytes of the first %d: the gate is holding the upload", got.Load(), size/2))
						return
					}
					time.Sleep(5 * time.Millisecond)
				}
				if write(size / 2 >> 20) {
					_ = pw.Close()
				}
			}()
			req, _ := http.NewRequest("POST", gate.URL+"/upload", pr)
			req.Host = "example.com"
			res, err := gate.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			body, _ := io.ReadAll(res.Body)
			_ = pr.Close() // an answer that came early stops the sender
			<-sent
			if wantBody := fmt.Sprintf("%d %s", size, hex.EncodeToString(want.Sum(nil))); res.StatusCode != 200 || string(body) != wantBody {
				t.Fatalf("the upload answered %d %q; want %q", res.StatusCode, body, wantBody)
			}
		})
	}
}

// A streamed answer (server-sent events) reaches the client as it is written,
// not when the upstream finishes.
func TestAStreamedAnswerArrivesAsItIsWritten(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(map[bool]string{false: "http1", true: "http2"}[h2], func(t *testing.T) {
			release := make(chan struct{})
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, "data: first\n\n")
				w.(http.Flusher).Flush()
				<-release
				_, _ = io.WriteString(w, "data: last\n\n")
			}))
			t.Cleanup(up.Close)
			t.Cleanup(func() {
				select {
				case <-release:
				default:
					close(release)
				}
			})
			tbl := core.NewTable[http.Handler]()
			to(t, tbl, up.URL)
			gate := front(t, tbl, h2)

			req, _ := http.NewRequest("GET", gate.URL+"/events", nil)
			req.Host = "example.com"
			res, err := gate.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			rd := bufio.NewReader(res.Body)
			first := make(chan string, 1)
			go func() {
				s, _ := rd.ReadString('\n')
				first <- s
			}()
			select {
			case s := <-first:
				if s != "data: first\n" {
					t.Fatalf("the first event = %q", s)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("the first event did not arrive while the upstream was still writing")
			}
			close(release)
			rest, _ := io.ReadAll(rd)
			if !strings.Contains(string(rest), "data: last\n") {
				t.Fatalf("the rest = %q", rest)
			}
		})
	}
}
