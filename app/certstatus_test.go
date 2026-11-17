package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yongjohnlee80/autopanel/internal/certs"
)

func TestACertificatesState(t *testing.T) {
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c := certs.Stored{NotBefore: from, NotAfter: from.Add(90 * 24 * time.Hour), RenewFrom: from.Add(60 * 24 * time.Hour)}
	day := func(n int) time.Time { return from.Add(time.Duration(n) * 24 * time.Hour) }
	for _, tc := range []struct {
		name string
		ok   bool
		err  error
		now  time.Time
		want string
	}{
		{"none stored", false, nil, day(1), certNone},
		{"the store unread", false, errors.New("locked"), day(1), certUnknown},
		{"fresh", true, nil, day(59), certOK},
		{"the window opens", true, nil, day(60), certDue},
		{"its last day", true, nil, day(89), certDue},
		{"at its end", true, nil, day(90), certExpired},
	} {
		if got := certState(c, tc.ok, tc.err, tc.now); got != tc.want {
			t.Errorf("%s: %s; want %s", tc.name, got, tc.want)
		}
	}
}

type auditLine struct{ actor, action, subject, detail string }

func TestOrdersAreAuditedAndARepeatedFailureOnceAnHour(t *testing.T) {
	var lines []auditLine
	e := newCertEvents(func(_ context.Context, actor, action, subject, detail string) error {
		lines = append(lines, auditLine{actor, action, subject, detail})
		return nil
	})
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	e.now = func() time.Time { return now }
	refused := errors.New("429 too many\n  certificates")

	e.on(certs.Event{Name: "a.example.com"})
	e.on(certs.Event{Name: "a.example.com", Renewal: true})
	for i := 0; i < 5; i++ { // a handshake retries every few seconds
		e.on(certs.Event{Name: "b.example.com", Err: refused})
		now = now.Add(10 * time.Second)
	}
	want := []auditLine{
		{"autopanel", "certs.obtained", "a.example.com", "ok"},
		{"autopanel", "certs.renewed", "a.example.com", "ok"},
		{"autopanel", "certs.failed", "b.example.com", "failed: 429 too many certificates"},
	}
	if len(lines) != len(want) {
		t.Fatalf("audit = %+v; want %d lines", lines, len(want))
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("audit line %d = %+v; want %+v", i, lines[i], want[i])
		}
	}
	if f, ok := e.last("b.example.com"); !ok || f.err != "429 too many certificates" || !f.at.Equal(now.Add(-10*time.Second)) {
		t.Errorf("the last failure = %+v, %v; want the newest", f, ok)
	}

	e.on(certs.Event{Name: "b.example.com", Renewal: true, Err: errors.New("no route to host")}) // another reason: written
	now = now.Add(auditEvery)
	e.on(certs.Event{Name: "b.example.com", Renewal: true, Err: errors.New("no route to host")}) // an hour on: written again
	if len(lines) != 5 || lines[3].detail != "renewal failed: no route to host" || lines[4] != lines[3] {
		t.Fatalf("after a new reason and an hour = %+v", lines[3:])
	}

	e.on(certs.Event{Name: "b.example.com", Renewal: true}) // it works again: the failure is forgotten
	if _, ok := e.last("b.example.com"); ok {
		t.Error("a name whose order succeeded still shows its old failure")
	}
	e.on(certs.Event{Name: "b.example.com", Err: errors.New("no route to host")})
	if len(lines) != 7 || lines[5].action != "certs.renewed" || lines[6].action != "certs.failed" {
		t.Fatalf("a failure after a success is written at once: %+v", lines[5:])
	}
}

func TestCertificateChecks(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	in := func(d time.Duration) int64 { return now.Add(d).Unix() }
	rows := []CertRow{
		{Host: "ok.example.com", State: certOK, NotAfter: in(60 * 24 * time.Hour)},
		{Host: "due.example.com", State: certDue, NotAfter: in(20 * 24 * time.Hour)},                            // renewing in time: not said
		{Host: "late.example.com", State: certDue, NotAfter: in(6 * 24 * time.Hour), FailedAt: 1, Error: "429"}, // said once, as expiring
		{Host: "gone.example.com", State: certExpired, NotAfter: in(-time.Hour)},
		{Host: "new.example.com", State: certNone, FailedAt: 1, Error: "no such host"},
		{Host: "idle.example.com", State: certNone}, // never asked for: nothing to say
	}
	got := certChecks(rows, now)
	if len(got) != 2 {
		t.Fatalf("checks = %+v; want two", got)
	}
	if got[0] != (Check{ID: "cert-expiring", Severity: alert, Detail: "late.example.com (2026-03-07), gone.example.com (expired)"}) {
		t.Errorf("expiring = %+v", got[0])
	}
	if got[1] != (Check{ID: "cert-failing", Severity: notice, Detail: "new.example.com"}) {
		t.Errorf("failing = %+v", got[1])
	}
	if got := certChecks(rows[:2], now); len(got) != 0 {
		t.Errorf("healthy certificates = %+v; want no check", got)
	}
}
