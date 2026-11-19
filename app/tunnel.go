package app

import (
	"context"
	"time"

	coretunnel "github.com/yongjohnlee80/autopanel/core/tunnel"
	hostgate "github.com/yongjohnlee80/autopanel/host/gate"
	"github.com/yongjohnlee80/autopanel/internal/module"
	"github.com/yongjohnlee80/autopanel/internal/tunnel"
)

// TUNNELS, WIRED — the agents' record (core/tunnel) joined to the gate, which
// holds their tunnels. The gate learns the enrolled keys over the link, as it
// learns the routes; an enrolment it received comes back over the link for
// the core to decide; and what it reports of each tunnel is what the panel
// lists.
//
// Decision: docs/decisions/forwards.md#tunnels

// The most of the gate's word about tunnels the core keeps, whatever it sent.
const (
	maxTunnelStates  = coretunnel.MaxAgents
	maxTunnelTargets = 64
)

// tunnelLink is the link's verbs for tunnels. Like the link's others they are
// open: the kernel's record of the peer's user is what admits the gate.
type tunnelLink struct {
	m   *coretunnel.Module
	rev *revision
}

func (tunnelLink) Name() string { return "link" } // another module of the link socket

func (tunnelLink) Errors() []module.PublicError {
	return []module.PublicError{
		{Err: coretunnel.ErrBadToken, Code: -32274, Name: "gate.tunnel.bad_token", Message: "the enrolment was refused"},
	}
}

func (l tunnelLink) Verbs() []module.Verb {
	return []module.Verb{
		module.Handle(module.Contract{Verb: hostgate.VerbAgents, Since: 10, Open: true, Param: "{after}", Result: "{rev, agents: [{name, key}]}",
			Doc: "The enrolled tunnel agents: each one's name and the SHA-256 of its public key. Answers at once when the revision is not after, and otherwise when they next change. Link socket only."}, l.agents),
		module.Handle(module.Contract{Verb: hostgate.VerbEnrol, Since: 10, Open: true, Param: "{token, key, client}", Result: "{name}",
			Doc: "An enrolment the gate received: the token offered, the digest of the key the handshake proved, and the address it came from. The token is spent if it is good. Link socket only."}, l.enrol),
	}
}

// agents holds the call open until the keys are not the ones the gate has.
func (l tunnelLink) agents(ctx context.Context, p hostgate.After) (hostgate.Agents, error) {
	rev, err := l.rev.waitNot(ctx, p.After)
	if err != nil {
		return hostgate.Agents{}, err
	}
	keys, err := l.m.Keys(ctx)
	if err != nil {
		return hostgate.Agents{}, err
	}
	out := hostgate.Agents{Rev: rev, Agents: make([]hostgate.AgentKey, 0, len(keys))}
	for _, k := range keys {
		out.Agents = append(out.Agents, hostgate.AgentKey{Name: k.Name, Key: k.Key})
	}
	return out, nil
}

func (l tunnelLink) enrol(ctx context.Context, p hostgate.EnrolAsk) (hostgate.Enrolled, error) {
	name, err := l.m.Enrol(ctx, p.Token, p.Key, p.Client)
	return hostgate.Enrolled{Name: name}, err
}

// tunnelStatus is each agent's tunnel as the gate last reported it: nothing
// once the gate has gone quiet, since a tunnel is the gate's to hold. The
// gate's word is kept short and its names are checked, whatever it sent.
func (c *counters) tunnelStatus() map[string]coretunnel.Status {
	r := c.probe.Load()
	seen := c.seen.Load()
	if r == nil || seen == 0 || time.Since(time.Unix(0, seen)) > gateQuiet() {
		return nil
	}
	states := r.Tunnels
	if len(states) > maxTunnelStates {
		states = states[:maxTunnelStates]
	}
	out := make(map[string]coretunnel.Status, len(states))
	for _, s := range states {
		st := coretunnel.Status{Connected: true, Since: s.Since, From: s.From, Streams: s.Streams}
		if len(st.From) > 64 {
			st.From = st.From[:64]
		}
		for _, t := range s.Targets {
			if tunnel.ValidTarget(t) && len(st.Targets) < maxTunnelTargets {
				st.Targets = append(st.Targets, t)
			}
		}
		out[s.Name] = st
	}
	return out
}
