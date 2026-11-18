package mail

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// smtpServer answers each connection as serve says, on a loopback port.
func smtpServer(t *testing.T, serve func(c net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				serve(c)
			}()
		}
	}()
	return ln.Addr().String()
}

func closedPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// TestTheWayOutToPort25: the probe is satisfied by the first server that
// greets with 220 and says QUIT to it; one that cannot be reached, one that
// greets otherwise and one that never ends its line all count as no way out,
// and of the last no more than 512 bytes are read.
func TestTheWayOutToPort25(t *testing.T) {
	defer func(p []string) { smtpProbes = p }(smtpProbes)
	said := make(chan string, 1)
	good := smtpServer(t, func(c net.Conn) {
		_, _ = io.WriteString(c, "220 mx.example ESMTP\r\n")
		b := make([]byte, 16)
		n, _ := c.Read(b)
		said <- string(b[:n])
	})
	h := &Host{}
	ctx := context.Background()

	smtpProbes = []string{closedPort(t), good}
	if err := h.SMTPOut(ctx); err != nil {
		t.Fatalf("with one probe unreachable and the next greeting: %v", err)
	}
	if got := <-said; got != "QUIT\r\n" {
		t.Fatalf("the probe said %q to the server; want QUIT alone", got)
	}

	busy := smtpServer(t, func(c net.Conn) { _, _ = io.WriteString(c, "554 no service here\r\n") })
	smtpProbes = []string{closedPort(t), busy}
	if err := h.SMTPOut(ctx); err == nil || !strings.Contains(err.Error(), "554") {
		t.Fatalf("a server that greets with 554: %v", err)
	}

	sent := make(chan int, 1)
	endless := smtpServer(t, func(c net.Conn) {
		n, chunk := 0, []byte(strings.Repeat("x", 1024))
		_ = c.SetWriteDeadline(time.Now().Add(3 * time.Second))
		for {
			w, err := c.Write(chunk)
			n += w
			if err != nil {
				break
			}
		}
		sent <- n
	})
	smtpProbes = []string{endless}
	start := time.Now()
	if err := h.SMTPOut(ctx); err == nil {
		t.Fatal("a server that never ends its line counted as a way out")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("the probe read an endless line for %s; it should stop at 512 bytes", d)
	}
	<-sent // the server's writes failed once the probe hung up
}
