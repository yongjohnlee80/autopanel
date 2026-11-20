package gate

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"
)

// The HTTP server's own log: the internet's weather is dropped, anything else
// is logged at most once a second, cut to a bounded line, with a count of
// what was not shown.
func TestTheServersLogIsBoundedAndQuiet(t *testing.T) {
	var out bytes.Buffer
	l := &serverLog{log: slog.New(slog.NewTextHandler(&out, nil))}
	for _, weather := range []string{
		"http: TLS handshake error from 203.0.113.9:4000: EOF",
		"http2: server: error reading preface from client 203.0.113.9:4001: timeout",
		"http: URL query contains semicolon, which is no longer a supported separator",
	} {
		if n, err := l.Write([]byte(weather + "\n")); err != nil || n != len(weather)+1 {
			t.Fatalf("%q: %d, %v", weather, n, err)
		}
	}
	if out.Len() != 0 {
		t.Fatalf("weather was logged: %s", out.String())
	}
	long := "http: panic serving 203.0.113.9:4002: " + strings.Repeat("x", 4000)
	if _, err := l.Write([]byte(long)); err != nil {
		t.Fatal(err)
	}
	first := out.String()
	if !strings.Contains(first, "the HTTP server reported") || strings.Contains(first, strings.Repeat("x", 2100)) || !strings.Contains(first, "not_shown=0") {
		t.Fatalf("the first line: %s", first)
	}
	for range 3 {
		_, _ = l.Write([]byte("http: Accept error: too many open files"))
	}
	if out.String() != first {
		t.Fatalf("more than a line a second: %s", out.String())
	}
	l.mu.Lock()
	l.last = l.last.Add(-2 * time.Second)
	l.mu.Unlock()
	_, _ = l.Write([]byte("http: Accept error: too many open files"))
	if !strings.Contains(out.String(), "not_shown=3") {
		t.Fatalf("the count of lines not shown: %s", out.String())
	}
}

// serveUntil answers a server's own failure, and ends quietly when its
// context does.
func TestServeUntilEndsAsItsServerOrItsContextDoes(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_ = ln.Close() // a listener that fails at once
	for _, withTLS := range []bool{false, true} {
		if err := serveUntil(context.Background(), &http.Server{}, ln, withTLS); err == nil || errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("a server that failed (TLS %v): %v", withTLS, err)
		}
	}

	ln, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.NotFoundHandler()}
	done := make(chan error, 1)
	go func() { done <- serveUntil(context.Background(), srv, ln, false) }()
	time.Sleep(50 * time.Millisecond)
	_ = srv.Close()
	if err := <-done; err != nil {
		t.Fatalf("a server closed: %v", err)
	}

	ln, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done = make(chan error, 1)
	go func() { done <- serveUntil(ctx, &http.Server{Handler: http.NotFoundHandler()}, ln, false) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("a context that ended: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serveUntil outlived its context")
	}
}

// The runtime's memory, as the memory log line reports it: what it holds is
// at least the live heap, and what it holds beside the heap is not nothing.
func TestTheRuntimesMemoryIsRead(t *testing.T) {
	runtime.GC() // the live heap is the last collection's
	held, live, fixed := runtimeBytes()
	if live == 0 || fixed == 0 || held < live || held < fixed {
		t.Fatalf("held %d, live %d, fixed %d", held, live, fixed)
	}
}
