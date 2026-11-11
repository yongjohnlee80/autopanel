package app

import (
	"context"
	"crypto/x509"
	"net/http"
	"sync"
	"time"

	"github.com/yongjohnlee80/autopanel/core/gate"
	hostgate "github.com/yongjohnlee80/autopanel/host/gate"
	"github.com/yongjohnlee80/autopanel/internal/certs"
	"github.com/yongjohnlee80/autopanel/internal/module"
)

// THE LINK'S CORE SIDE — the five verbs the gate process may call. They are
// registered on the link socket only: the control socket never offers them,
// and the link socket offers nothing else. The gate has no passphrase, so the
// verbs are open; the kernel's record of the peer's user is what admits it.

// revision counts the routing table's changes, and wakes whoever waits for
// the next one.
type revision struct {
	mu sync.Mutex
	n  int64
	ch chan struct{} // closed at the next bump
}

// newRevision starts at start: the core's start time in seconds, so a gate
// that held a table from an earlier core rarely mistakes this one's revisions
// for its own (and it asks from 0 after a reconnect in any case). Seconds, not
// nanoseconds: a revision crosses the wire as a number, and one above 2^53
// would not come back the same.
func newRevision(start int64) *revision {
	return &revision{n: start, ch: make(chan struct{})}
}

func (r *revision) bump() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.n++
	close(r.ch)
	r.ch = make(chan struct{})
}

// waitNot returns the revision once it is not have, or ctx's error.
func (r *revision) waitNot(ctx context.Context, have int64) (int64, error) {
	for {
		r.mu.Lock()
		n, ch := r.n, r.ch
		r.mu.Unlock()
		if n != have {
			return n, nil
		}
		select {
		case <-ch:
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
}

// linkModule is link.*.
type linkModule struct {
	cfg    Config
	table  *gate.Table[http.Handler] // the core's own copy: it decides which names may have a certificate
	rev    *revision
	sw     *certSwitch
	counts *counters
}

func (m *linkModule) Name() string { return "link" }

func (m *linkModule) Errors() []module.PublicError {
	return []module.PublicError{
		{Err: certs.ErrUnknownHost, Code: -32190, Name: "link.unknown_host", Message: "no route names this host"},
	}
}

func (m *linkModule) Verbs() []module.Verb {
	return []module.Verb{
		module.Handle(module.Contract{Verb: hostgate.VerbHello, Since: 2, Open: true, Result: "{version, https, http, trusted}",
			Doc: "The gate's configuration: its two listen addresses and the proxies it trusts. Link socket only."}, m.hello),
		module.Handle(module.Contract{Verb: hostgate.VerbRoutes, Since: 2, Open: true, Param: "{after}", Result: "{rev, routes: [{id, host, path_prefix, upstream}]}",
			Doc: "The routing table and its revision. Answers at once when the revision is not after, and otherwise when the table next changes. Link socket only."}, m.routes),
		module.Handle(module.Contract{Verb: hostgate.VerbCert, Since: 2, Open: true, Param: "{name, alpn?}", Result: "{chain, key, not_after}",
			Doc: "The certificate and private key for a name a route holds, obtained first when there is none; with alpn, the TLS-ALPN-01 challenge certificate of an order in flight. Link socket only."}, m.cert),
		module.Handle(module.Contract{Verb: hostgate.VerbChallenge, Since: 2, Open: true, Param: "{host, path}", Result: "{handled, status, body}",
			Doc: "The answer to an ACME HTTP-01 request the gate received; handled is false when it is no challenge of this AutoPanel's. Link socket only."}, m.challenge),
		module.Handle(module.Contract{Verb: hostgate.VerbReport, Since: 2, Open: true, Param: "{https_requests, http_requests, pid, memory_bytes}",
			Doc: "The gate's request counts since it started, its process and its memory, for sys.metrics and sys.ports. Link socket only."}, m.report),
	}
}

func (m *linkModule) hello(context.Context, struct{}) (hostgate.Hello, error) {
	trusted := make([]string, 0, len(m.cfg.Trusted))
	for _, p := range m.cfg.Trusted {
		trusted = append(trusted, p.String())
	}
	return hostgate.Hello{Version: Version, HTTPS: m.cfg.HTTPSAddr, HTTP: m.cfg.HTTPAddr, Trusted: trusted}, nil
}

// routes holds the call open until the table is not the one the gate has: it
// is how a change reaches the gate without the core dialling it.
func (m *linkModule) routes(ctx context.Context, p hostgate.After) (hostgate.Routes, error) {
	rev, err := m.rev.waitNot(ctx, p.After)
	if err != nil {
		return hostgate.Routes{}, err
	}
	rs := m.table.Routes()
	out := hostgate.Routes{Rev: rev, Routes: make([]gate.RouteView, 0, len(rs))}
	for _, r := range rs {
		out.Routes = append(out.Routes, gate.RouteView{ID: int64(r.ID), Host: r.Host, PathPrefix: r.PathPrefix, Upstream: r.Upstream})
	}
	return out, nil
}

// cert hands the gate a private key. It crosses the link socket, which only
// the gate's user can open, and is never written anywhere on the way.
func (m *linkModule) cert(ctx context.Context, p hostgate.Name) (hostgate.Cert, error) {
	c, err := m.sw.cur.Load().For(ctx, p.Name, p.ALPN)
	if err != nil {
		return hostgate.Cert{}, err
	}
	key, err := x509.MarshalPKCS8PrivateKey(c.PrivateKey)
	if err != nil {
		return hostgate.Cert{}, err
	}
	return hostgate.Cert{Chain: c.Certificate, Key: key, NotAfter: c.Leaf.NotAfter.Unix()}, nil
}

func (m *linkModule) challenge(ctx context.Context, p hostgate.ChallengeAsk) (hostgate.ChallengeAnswer, error) {
	status, body, ok := m.sw.cur.Load().Challenge(ctx, p.Host, p.Path)
	return hostgate.ChallengeAnswer{Handled: ok, Status: status, Body: body}, nil
}

func (m *linkModule) report(_ context.Context, p hostgate.Report) (struct{}, error) {
	m.counts.https.Store(p.HTTPSRequests)
	m.counts.http.Store(p.HTTPRequests)
	m.counts.pid.Store(int64(p.PID))
	m.counts.memory.Store(p.MemoryBytes)
	m.counts.seen.Store(time.Now().UnixNano())
	return struct{}{}, nil
}
