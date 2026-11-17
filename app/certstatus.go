package app

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/yongjohnlee80/autopanel/internal/certs"
)

// CERTIFICATES' STATE — what the store holds for each name AutoPanel serves,
// when it expires, and how the last order for it ended. A read orders nothing.
//
// Decision: docs/decisions/certs.md#what-the-panel-shows

// CertRow is one name of certs.list.
type CertRow struct {
	Host      string `json:"host"`
	State     string `json:"state"`  // none, ok, due, expired, unknown
	Issuer    string `json:"issuer"` // the CA that issued the stored certificate
	NotBefore int64  `json:"not_before"`
	NotAfter  int64  `json:"not_after"`
	RenewFrom int64  `json:"renew_from"` // from then on, the next request for the name renews it
	Error     string `json:"error"`      // the last order's failure, or the read's
	FailedAt  int64  `json:"failed_at"`
}

// The states of a name's certificate.
const (
	certNone    = "none"    // none stored: the first HTTPS request for the name orders one
	certOK      = "ok"      // stored, and not yet due
	certDue     = "due"     // in its renewal window: the next request renews it
	certExpired = "expired" // past its end: the next request must order one first
	certUnknown = "unknown" // the store could not be read
)

// expiringWithin is how close to its end a certificate must be for Host
// checks to say so: well inside the renewal window, so a renewal that works
// never shows.
const expiringWithin = 7 * 24 * time.Hour

// failure is a name's last failed order.
type failure struct {
	err string
	at  time.Time
}

// certEvents keeps each name's last failed order, in memory, and writes each
// order's end to the audit log. A name that keeps failing is written once an
// hour, or when its error changes: a handshake can retry every few seconds.
type certEvents struct {
	audit func(ctx context.Context, actor, action, subject, detail string) error
	now   func() time.Time

	mu      sync.Mutex
	failed  map[string]failure
	written map[string]failure // the last failure put in the audit log, by name
}

func newCertEvents(audit func(ctx context.Context, actor, action, subject, detail string) error) *certEvents {
	return &certEvents{audit: audit, now: time.Now, failed: map[string]failure{}, written: map[string]failure{}}
}

// auditEvery is how often a name's unchanged failure is written again;
// auditWithin is how long one entry's write may take.
const (
	auditEvery  = time.Hour
	auditWithin = 5 * time.Second
)

// reset forgets every failure: they were another certificate service's.
func (e *certEvents) reset() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.failed, e.written = map[string]failure{}, map[string]failure{}
}

func (e *certEvents) on(ev certs.Event) {
	// The order's own context may be ending; and a store that is slow must
	// not hold the order, or the handshake behind it.
	ctx, cancel := context.WithTimeout(context.Background(), auditWithin)
	defer cancel()
	now := e.now()
	e.mu.Lock()
	if ev.Err == nil {
		delete(e.failed, ev.Name)
		delete(e.written, ev.Name)
		e.mu.Unlock()
		action := "certs.obtained"
		if ev.Renewal {
			action = "certs.renewed"
		}
		_ = e.audit(ctx, "autopanel", action, ev.Name, "ok")
		return
	}
	f := failure{err: oneLine(ev.Err.Error()), at: now}
	e.failed[ev.Name] = f
	last, seen := e.written[ev.Name]
	write := !seen || last.err != f.err || now.Sub(last.at) >= auditEvery
	if write {
		e.written[ev.Name] = f
	}
	e.mu.Unlock()
	if write {
		detail := "failed: " + f.err
		if ev.Renewal {
			detail = "renewal failed: " + f.err
		}
		_ = e.audit(ctx, "autopanel", "certs.failed", ev.Name, detail)
	}
}

func (e *certEvents) last(name string) (failure, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	f, ok := e.failed[name]
	return f, ok
}

// oneLine is an error's text on one line, cut to what a row shows.
func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 400 {
		s = s[:400] + "…"
	}
	return s
}

// names are the names that may have a certificate: every route's host, and
// the mail host.
func (s *certSwitch) names() []string {
	seen := map[string]bool{}
	var out []string
	add := func(h string) {
		if h != "" && !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	for _, r := range s.table.Routes() {
		add(r.Host)
	}
	if s.extra != nil {
		for _, h := range s.extra() {
			add(h)
		}
	}
	sort.Strings(out)
	return out
}

// rows reads each name's stored certificate.
func (s *certSwitch) rows(ctx context.Context) []CertRow {
	m, now := s.cur.Load(), time.Now()
	names := s.names()
	out := make([]CertRow, 0, len(names))
	for _, name := range names {
		c, ok, err := m.Stored(ctx, name)
		f, failed := s.events.last(name)
		out = append(out, certRow(name, c, ok, err, f, failed, now))
	}
	return out
}

// certRow is a name's row: what the store holds, and the last order that
// failed. A store that cannot be read says so itself: an older order's
// failure would hide the reason, and is left out.
func certRow(name string, c certs.Stored, ok bool, err error, f failure, failed bool, now time.Time) CertRow {
	row := CertRow{Host: name, State: certState(c, ok, err, now)}
	if ok {
		row.Issuer, row.NotBefore, row.NotAfter, row.RenewFrom = c.Issuer, c.NotBefore.Unix(), c.NotAfter.Unix(), c.RenewFrom.Unix()
	}
	switch {
	case err != nil:
		row.Error = oneLine(err.Error())
	case failed:
		row.Error, row.FailedAt = f.err, f.at.Unix()
	}
	return row
}

func certState(c certs.Stored, ok bool, err error, now time.Time) string {
	switch {
	case err != nil:
		return certUnknown
	case !ok:
		return certNone
	case !now.Before(c.NotAfter):
		return certExpired
	case !now.Before(c.RenewFrom):
		return certDue
	}
	return certOK
}

// list is certs.list.
func (m *certsModule) list(ctx context.Context, _ struct{}) ([]CertRow, error) {
	return m.sw.rows(ctx), nil
}

// certChecks are the host checks about certificates: one that has expired or
// is about to, and a name whose last order failed. Both name what to look at;
// Certs → Certificates has the reason.
//
// Decision: docs/decisions/certs.md#host-checks
func certChecks(rows []CertRow, now time.Time) []Check {
	var expiring, failing []string
	for _, r := range rows {
		switch {
		case r.State == certExpired:
			expiring = append(expiring, r.Host+" (expired)")
		case r.State == certDue && time.Unix(r.NotAfter, 0).Sub(now) < expiringWithin:
			expiring = append(expiring, r.Host+" ("+time.Unix(r.NotAfter, 0).UTC().Format("2006-01-02")+")")
		case r.FailedAt != 0:
			failing = append(failing, r.Host)
		}
	}
	var out []Check
	if len(expiring) > 0 {
		out = append(out, Check{ID: "cert-expiring", Severity: alert, Detail: strings.Join(expiring, ", ")})
	}
	if len(failing) > 0 {
		out = append(out, Check{ID: "cert-failing", Severity: notice, Detail: strings.Join(failing, ", ")})
	}
	return out
}
