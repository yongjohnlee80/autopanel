package app

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	coretunnel "github.com/yongjohnlee80/autopanel/core/tunnel"
	hostgate "github.com/yongjohnlee80/autopanel/host/gate"
	"github.com/yongjohnlee80/autopanel/internal/module"
)

// agentRows is the agents' store in memory, with the real one's rule for an
// enrolment: the token once, the key for one agent.
type agentRows struct {
	mu   sync.Mutex
	rows []coretunnel.Agent
}

func (s *agentRows) All(context.Context) ([]coretunnel.Agent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]coretunnel.Agent(nil), s.rows...), nil
}

func (s *agentRows) Add(_ context.Context, a coretunnel.Agent) (coretunnel.Agent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a.ID = int64(len(s.rows) + 1)
	s.rows = append(s.rows, a)
	return a, nil
}

func (s *agentRows) Enrol(_ context.Context, id, hash, key, from string, now int64) (coretunnel.Agent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, a := range s.rows {
		if a.Key == "" && a.TokenID == id && a.TokenHash == hash && a.TokenExpires > now {
			a.Key, a.EnrolledFrom, a.EnrolledAt, a.TokenID, a.TokenHash = key, from, now, "", ""
			s.rows[i] = a
			return a, nil
		}
	}
	return coretunnel.Agent{}, coretunnel.ErrBadToken
}

func (s *agentRows) Remove(_ context.Context, id int64) (coretunnel.Agent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, a := range s.rows {
		if a.ID == id {
			s.rows = append(s.rows[:i], s.rows[i+1:]...)
			return a, nil
		}
	}
	return coretunnel.Agent{}, coretunnel.ErrNotFound
}

// verb calls one of the module's verbs as the control socket would.
func verb(ctx context.Context, m *coretunnel.Module, name string, param, out any) error {
	for _, v := range m.Verbs() {
		if v.Contract.Verb == name {
			res, err := v.Call(ctx, []any{param})
			if err != nil {
				return err
			}
			return module.Decode(res, out)
		}
	}
	return errors.New("no verb " + name)
}

func addAgent(ctx context.Context, m *coretunnel.Module, name string) (coretunnel.Added, error) {
	var out coretunnel.Added
	return out, verb(ctx, m, "gate.tunnel.agent.add", coretunnel.Name{Name: name}, &out)
}

func removeAgent(ctx context.Context, m *coretunnel.Module, id int64) error {
	var out coretunnel.View
	return verb(ctx, m, "gate.tunnel.agent.remove", coretunnel.Ref{ID: id}, &out)
}

// TestTheGateHearsOfAKeyWhenItAppearsAndWhenItGoes: link.agents answers the
// enrolled keys, holds a call open while nothing changes, and wakes it for an
// enrolment through link.enrol and for a removal; a refused enrolment wakes
// nobody and is the declared error.
func TestTheGateHearsOfAKeyWhenItAppearsAndWhenItGoes(t *testing.T) {
	ctx := context.Background()
	rev := newRevision(100)
	m := coretunnel.NewModule(&agentRows{}, func(context.Context) error { rev.bump(); return nil }, nil)
	l := tunnelLink{m: m, rev: rev}
	first, err := l.agents(ctx, hostgate.After{})
	if err != nil || len(first.Agents) != 0 || first.Rev != 100 {
		t.Fatalf("link.agents = %+v, %v", first, err)
	}
	woke := make(chan hostgate.Agents, 1)
	go func() {
		a, _ := l.agents(ctx, hostgate.After{After: first.Rev})
		woke <- a
	}()

	added, err := addAgent(ctx, m, "nas")
	if err != nil {
		t.Fatal(err)
	}
	key := strings.Repeat("a1", 32)
	if _, err := l.enrol(ctx, hostgate.EnrolAsk{Token: "ape_nope", Key: key, Client: "203.0.113.9"}); !errors.Is(err, coretunnel.ErrBadToken) {
		t.Fatalf("a wrong token over the link: %v", err)
	}
	select {
	case a := <-woke:
		t.Fatalf("the gate was woken with no key changed: %+v", a)
	case <-time.After(200 * time.Millisecond):
	}
	got, err := l.enrol(ctx, hostgate.EnrolAsk{Token: added.Token, Key: key, Client: "203.0.113.9"})
	if err != nil || got.Name != "nas" {
		t.Fatalf("link.enrol = %+v, %v", got, err)
	}
	var now hostgate.Agents
	select {
	case now = <-woke:
	case <-time.After(5 * time.Second):
		t.Fatal("the gate was not told of the new key")
	}
	if len(now.Agents) != 1 || now.Agents[0] != (hostgate.AgentKey{Name: "nas", Key: key}) {
		t.Fatalf("link.agents after the enrolment = %+v", now)
	}
	if err := removeAgent(ctx, m, added.Agent.ID); err != nil {
		t.Fatal(err)
	}
	after, err := l.agents(ctx, hostgate.After{After: now.Rev})
	if err != nil || len(after.Agents) != 0 {
		t.Fatalf("link.agents after the removal = %+v, %v", after, err)
	}
	// The refusal is one the link declares, so the gate reads it as the
	// core's answer and not as a lost link.
	var declared bool
	for _, e := range l.Errors() {
		declared = declared || errors.Is(e.Err, coretunnel.ErrBadToken)
	}
	if !declared {
		t.Fatal("the link does not declare a refused enrolment")
	}
}

// TestTheGatesWordAboutTunnelsIsKeptShort: the list shows what the gate last
// reported, bounded and with only names that are names, and nothing once the
// gate has gone quiet.
func TestTheGatesWordAboutTunnelsIsKeptShort(t *testing.T) {
	c := &counters{}
	if c.tunnelStatus() != nil {
		t.Fatal("tunnels with no report")
	}
	r := hostgate.Report{}
	for i := range 40 {
		ts := hostgate.TunnelState{Name: "a" + strings.Repeat("x", i%20), Since: 5, From: strings.Repeat("9", 200), Streams: 2}
		for j := range 100 {
			ts.Targets = append(ts.Targets, "t"+strings.Repeat("y", j%30))
		}
		ts.Targets = append(ts.Targets, "127.0.0.1:22", "Bad Name", "")
		r.Tunnels = append(r.Tunnels, ts)
	}
	c.probe.Store(&r)
	c.seen.Store(time.Now().UnixNano())
	st := c.tunnelStatus()
	if len(st) == 0 || len(st) > maxTunnelStates {
		t.Fatalf("%d tunnels kept", len(st))
	}
	for name, s := range st {
		if !s.Connected || s.Streams != 2 || len(s.From) > 64 || len(s.Targets) > maxTunnelTargets {
			t.Fatalf("%s = %+v", name, s)
		}
		for _, tg := range s.Targets {
			if strings.ContainsAny(tg, ".: ") || tg == "" {
				t.Fatalf("a target that is no name was kept: %q", tg)
			}
		}
	}
	c.seen.Store(time.Now().Add(-10 * time.Minute).UnixNano())
	if c.tunnelStatus() != nil {
		t.Fatal("a gate that has gone quiet still has tunnels")
	}
}
