package gate

import (
	"fmt"
	"sort"
	"sync/atomic"
)

// Table is the live routing table. Readers load one immutable snapshot per
// request and never lock; a change builds a whole new snapshot and swaps it in,
// so a request in flight finishes on the snapshot it loaded (rationale §R9).
//
// H is what the host serves a route with (an http.Handler for the data plane);
// core never sees the transport.
type Table[H any] struct {
	cur atomic.Pointer[snapshot[H]]
}

type entry[H any] struct {
	route   Route
	handler H
}

type snapshot[H any] struct {
	byHost map[string][]entry[H] // each host's routes, longest prefix first
}

// NewTable returns an empty table: every lookup misses until the first Swap.
func NewTable[H any]() *Table[H] {
	t := &Table[H]{}
	t.cur.Store(&snapshot[H]{byHost: map[string][]entry[H]{}})
	return t
}

// Build makes the snapshot for routes, building each route's handler with
// handlerFor. It fails, and changes nothing, if a route is not canonical or a
// handler can't be built: the live table is never half-updated.
func Build[H any](routes []Route, handlerFor func(Route) (H, error)) (*Snapshot[H], error) {
	s := &snapshot[H]{byHost: make(map[string][]entry[H], len(routes))}
	for _, r := range routes {
		n, err := r.Normalize()
		if err != nil || n != r {
			return nil, fmt.Errorf("gate: route %d (%s%s) is not canonical: %v", r.ID, r.Host, r.PathPrefix, err)
		}
		h, err := handlerFor(r)
		if err != nil {
			return nil, fmt.Errorf("gate: route %d: %w", r.ID, err)
		}
		s.byHost[r.Host] = append(s.byHost[r.Host], entry[H]{route: r, handler: h})
	}
	for _, es := range s.byHost {
		sort.Slice(es, func(i, j int) bool { return len(es[i].route.PathPrefix) > len(es[j].route.PathPrefix) })
	}
	return &Snapshot[H]{s: s}, nil
}

// Snapshot is a built table, ready to swap in.
type Snapshot[H any] struct{ s *snapshot[H] }

// Swap makes snap the live table.
func (t *Table[H]) Swap(snap *Snapshot[H]) { t.cur.Store(snap.s) }

// Match finds the route for a canonical host and a request path: the longest
// prefix that matches on a segment boundary.
func (t *Table[H]) Match(host, path string) (Route, H, bool) {
	for _, e := range t.cur.Load().byHost[host] {
		if e.route.matches(path) {
			return e.route, e.handler, true
		}
	}
	var zero H
	return Route{}, zero, false
}

// Holds reports whether any route names host. The certificate module asks this
// before ordering a certificate, so a stranger's SNI can't make AutoPanel order one.
func (t *Table[H]) Holds(host string) bool {
	_, ok := t.cur.Load().byHost[host]
	return ok
}

// Routes lists the live routes, by host then longest prefix first.
func (t *Table[H]) Routes() []Route {
	s := t.cur.Load()
	hosts := make([]string, 0, len(s.byHost))
	for h := range s.byHost {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	var out []Route
	for _, h := range hosts {
		for _, e := range s.byHost[h] {
			out = append(out, e.route)
		}
	}
	return out
}
