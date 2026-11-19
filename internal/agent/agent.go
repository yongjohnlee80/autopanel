// Package agent is the tunnel's far end: the program on a machine with no
// open port. It dials AutoPanel's gate on the HTTPS port, proves the key it
// was enrolled with, and serves the streams the gate opens, each to a target
// its own file names.
//
// The file is the only list of targets. The gate asks for a target by name;
// nothing it sends can add one, change an address or reach a port the file
// does not list.
//
// Decision: docs/decisions/forwards.md#tunnels
package agent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/yongjohnlee80/autopanel/internal/tunnel"
)

// DefaultStreams is the streams an agent serves at once unless its file says.
const DefaultStreams = 64

// Target is one service the agent reaches.
type Target struct {
	To string `yaml:"to" json:"to"` // host:port, as the agent's machine resolves it
}

// Options is an agent, ready to run.
type Options struct {
	// Server is the gate's host name, with a port when it is not 443. The
	// gate's certificate is checked for the name.
	Server string
	Key    ed25519.PrivateKey
	// Targets is the file's list, by name.
	Targets    map[string]Target
	MaxStreams int // 0: DefaultStreams
	Log        *slog.Logger

	// For tests: the address to dial in place of Server's, and the roots the
	// gate's certificate is checked against in place of the system's.
	DialAddr string
	Roots    *x509.CertPool
}

// ErrRefused is the gate refusing: an enrolment with a bad token, or a tunnel
// from a key it does not know.
var ErrRefused = errors.New("agent: the server refused")

// NewKey makes an agent's key.
func NewKey() (ed25519.PrivateKey, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	return key, err
}

// EncodeKey is key as the PEM the agent keeps in its key file.
func EncodeKey(key ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// DecodeKey reads a key file's contents.
func DecodeKey(b []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("agent: the key file holds no private key")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("agent: the key file's key does not parse: %w", err)
	}
	key, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("agent: the key file's key is not an Ed25519 key")
	}
	return key, nil
}

// certificate is the key as a certificate the handshake can present. It
// claims nothing: the gate knows the agent by the key inside, which the
// handshake proves the agent holds.
func certificate(key ed25519.PrivateKey) (tls.Certificate, error) {
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "autopanel-agent"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

// Fingerprint is the key's digest as people compare it: the form the panel
// lists beside the agent.
func Fingerprint(key ed25519.PrivateKey) (string, error) {
	cert, err := certificate(key)
	if err != nil {
		return "", err
	}
	raw, err := hex.DecodeString(tunnel.KeyDigest(cert.Leaf))
	if err != nil {
		return "", err
	}
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(raw), nil
}

// dial makes the TLS connection: the tunnel's protocol and no other, TLS 1.3,
// the gate's certificate checked for Server's name, and the agent's key
// presented.
func (o Options) dial(ctx context.Context) (*tls.Conn, error) {
	host, port, err := net.SplitHostPort(o.Server)
	if err != nil {
		host, port = o.Server, "443"
	}
	if host == "" {
		return nil, errors.New("agent: no server is named")
	}
	cert, err := certificate(o.Key)
	if err != nil {
		return nil, err
	}
	addr := net.JoinHostPort(host, port)
	if o.DialAddr != "" {
		addr = o.DialAddr
	}
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second},
		Config: &tls.Config{ServerName: host, RootCAs: o.Roots, MinVersion: tls.VersionTLS13,
			NextProtos: []string{tunnel.ALPN}, Certificates: []tls.Certificate{cert}}}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return c.(*tls.Conn), nil
}

// ask sends one HTTP/1.1 request on the connection and reads its answer's
// head. The reader is returned: bytes after the head may be in it.
func ask(ctx context.Context, c net.Conn, req *http.Request) (*http.Response, *bufio.Reader, error) {
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
		defer c.SetDeadline(time.Time{})
	}
	if err := req.Write(c); err != nil {
		return nil, nil, err
	}
	br := bufio.NewReader(c)
	res, err := http.ReadResponse(br, req)
	return res, br, err
}

// Enrol makes this key the agent the token names, and answers the agent's
// name. The token is good once: a second use, or a wrong one, is ErrRefused.
func Enrol(ctx context.Context, o Options, token string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	c, err := o.dial(ctx)
	if err != nil {
		return "", err
	}
	defer c.Close()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+o.Server+tunnel.EnrolPath, strings.NewReader(token))
	if err != nil {
		return "", err
	}
	res, _, err := ask(ctx, c, req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	switch {
	case res.StatusCode == http.StatusForbidden:
		return "", ErrRefused
	case res.StatusCode == http.StatusTooManyRequests:
		return "", errors.New("agent: too many enrolments from this address; wait a minute")
	case res.StatusCode != http.StatusOK:
		return "", fmt.Errorf("agent: the server answered %s", res.Status)
	}
	var out struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 4<<10)).Decode(&out); err != nil || out.Name == "" {
		return "", errors.New("agent: the server's answer names no agent")
	}
	return out.Name, nil
}

// Dialer is the agent's list as the tunnel uses it: a name the file has is
// dialled where the file says, and any other is refused. The names
// themselves are answered under tunnel.TargetsName.
func (o Options) Dialer() tunnel.Dialer {
	names := make([]string, 0, len(o.Targets))
	for n := range o.Targets {
		names = append(names, n)
	}
	sort.Strings(names)
	list, _ := json.Marshal(names)
	return func(ctx context.Context, name string) (net.Conn, error) {
		if name == tunnel.TargetsName {
			a, b := net.Pipe()
			go func() {
				_, _ = b.Write(list)
				_ = b.Close()
			}()
			return a, nil
		}
		t, ok := o.Targets[name]
		if !ok {
			o.log().Warn("agent: refused a target the file does not list", "target", name)
			return nil, errors.New("agent: no such target")
		}
		d := net.Dialer{Timeout: 10 * time.Second}
		c, err := d.DialContext(ctx, "tcp", t.To)
		if err != nil {
			o.log().Warn("agent: a target cannot be reached", "target", name, "err", err)
			return nil, err
		}
		o.log().Info("agent: stream", "target", name)
		return c, nil
	}
}

func (o Options) log() *slog.Logger {
	if o.Log != nil {
		return o.Log
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// Check refuses a list the agent cannot serve.
func (o Options) Check() error {
	for n, t := range o.Targets {
		if !tunnel.ValidTarget(n) {
			return fmt.Errorf("agent: %q is not a target's name: 1 to 32 lower-case letters, digits and hyphens, starting with a letter", n)
		}
		if _, _, err := net.SplitHostPort(t.To); err != nil {
			return fmt.Errorf("agent: target %s: %q is not host:port", n, t.To)
		}
	}
	if o.MaxStreams < 0 || o.MaxStreams > 1024 {
		return errors.New("agent: max_streams is 1 to 1024")
	}
	return nil
}

// connect holds one tunnel until it ends: it dials, asks for the tunnel, and
// serves the gate's streams. served is true once the gate had taken it.
func (o Options) connect(ctx context.Context) (served bool, err error) {
	dctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	c, err := o.dial(dctx)
	if err != nil {
		return false, err
	}
	defer c.Close()
	req, err := http.NewRequestWithContext(dctx, http.MethodGet, "https://"+o.Server+tunnel.ConnectPath, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", tunnel.ALPN)
	res, br, err := ask(dctx, c, req)
	if err != nil {
		return false, err
	}
	switch {
	case res.StatusCode == http.StatusForbidden:
		return false, ErrRefused
	case res.StatusCode != http.StatusSwitchingProtocols:
		return false, fmt.Errorf("agent: the server answered %s (is it AutoPanel, and new enough for tunnels?)", res.Status)
	}
	max := o.MaxStreams
	if max == 0 {
		max = DefaultStreams
	}
	o.log().Info("agent: the tunnel is up", "server", o.Server, "targets", len(o.Targets))
	var conn net.Conn = c
	if br.Buffered() > 0 { // the gate's first bytes came with its answer
		head, _ := br.Peek(br.Buffered())
		conn = &prefixed{Conn: c, r: io.MultiReader(bytes.NewReader(append([]byte(nil), head...)), c)}
	}
	return true, tunnel.Serve(ctx, conn, o.Dialer(), max)
}

// prefixed is a connection whose first bytes were already read.
type prefixed struct {
	net.Conn
	r io.Reader
}

func (p *prefixed) Read(b []byte) (int, error) { return p.r.Read(b) }

// Run holds the tunnel up until ctx ends, dialling again when it is lost: at
// once the first time, then after a wait that grows to a minute, never the
// same for two agents. A key the gate does not know is not an error to stop
// for: the agent may be enrolled again, or the gate may not have heard yet.
func Run(ctx context.Context, o Options) error {
	if err := o.Check(); err != nil {
		return err
	}
	wait := time.Second
	for ctx.Err() == nil {
		served, err := o.connect(ctx)
		if ctx.Err() != nil {
			break
		}
		if served {
			wait = time.Second
			o.log().Warn("agent: the tunnel ended; dialling again", "err", err)
		} else {
			o.log().Warn("agent: no tunnel; trying again", "err", err, "in", wait.Round(time.Second).String())
		}
		t := time.NewTimer(wait/2 + mrand.N(wait/2+1))
		select {
		case <-ctx.Done():
			t.Stop()
		case <-t.C:
		}
		if !served {
			if wait *= 2; wait > time.Minute {
				wait = time.Minute
			}
		}
	}
	return nil
}

// WriteKey writes a new key file, for its owner alone. A file already there
// is never replaced: its key is the agent's identity.
func WriteKey(path string, key ed25519.PrivateKey) error {
	b, err := EncodeKey(key)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	return f.Close()
}
