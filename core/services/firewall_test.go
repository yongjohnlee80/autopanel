package services

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"

	corefw "github.com/yongjohnlee80/autopanel/core/firewall"
)

// fakeFirewall records what an owner asked of the firewall.
type fakeFirewall struct {
	calls []string
	fail  error
}

func wantKeys(ws []corefw.Want) []string {
	out := []string{}
	for _, w := range ws {
		out = append(out, w.Key())
	}
	return out
}

func (f *fakeFirewall) Review(_ context.Context, owner string, wants []corefw.Want) ([]corefw.PortState, error) {
	var out []corefw.PortState
	for _, w := range wants {
		out = append(out, corefw.PortState{Want: w, Key: w.Key(), Verdict: "blocked", Needs: true, Managed: true})
	}
	return out, nil
}

func (f *fakeFirewall) Open(_ context.Context, owner string, wants []corefw.Want) error {
	f.calls = append(f.calls, "open "+owner+" "+join(wantKeys(wants)))
	return f.fail
}

func (f *fakeFirewall) Close(_ context.Context, owner string, wants []corefw.Want) error {
	what := "all"
	if wants != nil {
		what = join(wantKeys(wants))
	}
	f.calls = append(f.calls, "close "+owner+" "+what)
	return f.fail
}

func join(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out
}

const public = `services:
  relay:
    image: example.com/web:1
    ports: ["3478:3478/udp", "192.0.2.1:8008:80", "127.0.0.1:9000:9000", "49152-49160:49152-49160/udp"]
`

// TestAStackOpensWhatItChoseAndClosesWhatItDrops: the review lists the public
// ports with the firewall's view (a loopback one is not there; an address-bound
// one keeps its address); an apply opens only its own ports, last; a later
// apply that drops one closes it; a removal closes the rest first.
func TestAStackOpensWhatItChoseAndClosesWhatItDrops(t *testing.T) {
	f := setup(t)
	fw := &fakeFirewall{}
	f.m.SetFirewall(fw)
	ctx := context.Background()
	f.h.defs["relay"] = map[string]string{"compose.yaml": public}
	r, err := f.m.check(ctx, Ref{Name: "relay"})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, s := range r.Firewall {
		got = append(got, s.Key)
	}
	want := []string{"udp/3478", "tcp/192.0.2.1:8008", "udp/49152-49160"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("the review's ports = %v; want %v", got, want)
	}
	relay := corefw.Want{Proto: "udp", From: 3478, To: 3478}
	bound := corefw.Want{Proto: "tcp", From: 8008, To: 8008, Addr: netip.MustParseAddr("192.0.2.1")}
	loop := corefw.Want{Proto: "tcp", From: 9000, To: 9000}
	if _, err := f.m.add(ctx, Accept{Name: "relay", Accept: r.SHA256, Open: []corefw.Want{relay, loop}}); !errors.Is(err, ErrNotOwnPort) {
		t.Fatalf("opening a loopback port = %v; want ErrNotOwnPort", err)
	}
	if len(fw.calls) != 0 || len(f.s.all) != 0 {
		t.Fatalf("a refused apply did something: %q, %d rows", fw.calls, len(f.s.all))
	}
	if _, err := f.m.add(ctx, Accept{Name: "relay", Accept: r.SHA256, Open: []corefw.Want{relay, bound}}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fw.calls, []string{"open stack:relay udp/3478,tcp/192.0.2.1:8008"}) {
		t.Fatalf("calls = %q", fw.calls)
	}
	if got := wantKeys(f.s.all["relay"].Applied.Open); !reflect.DeepEqual(got, []string{"udp/3478", "tcp/192.0.2.1:8008"}) {
		t.Fatalf("the applied plan keeps %v", got)
	}

	fw.calls = nil
	if _, err := f.m.applyVerb(ctx, Accept{Name: "relay", Accept: f.accept("relay"), Open: []corefw.Want{relay}}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fw.calls, []string{"close stack:relay tcp/192.0.2.1:8008", "open stack:relay udp/3478"}) {
		t.Fatalf("an apply that drops a port: %q", fw.calls)
	}

	// A close the guard refuses stops the removal before anything goes.
	fw.calls, fw.fail = nil, corefw.ErrLockout
	if _, err := f.m.remove(ctx, Remove{Name: "relay"}); !errors.Is(err, corefw.ErrLockout) || f.s.all["relay"].State == Removing {
		t.Fatalf("a refused close: %v, state %s", err, f.s.all["relay"].State)
	}
	fw.fail = nil
	if _, err := f.m.remove(ctx, Remove{Name: "relay"}); err != nil {
		t.Fatal(err)
	}
	if fw.calls[len(fw.calls)-1] != "close stack:relay all" || len(f.s.all) != 0 {
		t.Fatalf("the removal: %q, rows %d", fw.calls, len(f.s.all))
	}
}

// TestAnOpeningThatFailsLeavesTheApplyToFinish: the apply stops at the
// firewall, unrecorded; asking again finishes it.
func TestAnOpeningThatFailsLeavesTheApplyToFinish(t *testing.T) {
	f := setup(t)
	fw := &fakeFirewall{fail: corefw.ErrNotApplied}
	f.m.SetFirewall(fw)
	ctx := context.Background()
	f.h.defs["relay"] = map[string]string{"compose.yaml": public}
	open := []corefw.Want{{Proto: "udp", From: 3478, To: 3478}}
	if _, err := f.m.add(ctx, Accept{Name: "relay", Accept: f.accept("relay"), Open: open}); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("err = %v; want ErrIncomplete", err)
	}
	if len(f.s.all["relay"].Applied.Units) != 0 || f.s.all["relay"].Pending == nil || f.s.all["relay"].Pending.Step != "firewall" {
		t.Fatalf("after the failure: %+v", f.s.all["relay"])
	}
	fw.fail = nil
	if _, err := f.m.applyVerb(ctx, Accept{Name: "relay", Accept: f.accept("relay"), Open: open}); err != nil {
		t.Fatal(err)
	}
	if f.s.all["relay"].Pending != nil || len(f.s.all["relay"].Applied.Open) != 1 {
		t.Fatalf("after the retry: %+v", f.s.all["relay"])
	}
}

// ownedBy is a guard that owns one stack.
type ownedBy struct{ name string }

func (g ownedBy) Owns(name string) bool                          { return name == g.name }
func (ownedBy) Review(context.Context, string, []byte) []Finding { return nil }
func (ownedBy) Reserved() []Claim                                { return nil }
func (ownedBy) Mask(_ string, lines []string) []string           { return lines }

// TestAnOwnedStackIsRemovedOnlyByItsOwner (T2): services.remove refuses it;
// its owner's RemoveOwned removes it.
func TestAnOwnedStackIsRemovedOnlyByItsOwner(t *testing.T) {
	f := setup(t)
	f.add("site")
	f.m.SetGuard(ownedBy{"site"})
	ctx := context.Background()
	if _, err := f.m.remove(ctx, Remove{Name: "site"}); !errors.Is(err, ErrReserved) || len(f.s.all) != 1 {
		t.Fatalf("services.remove of an owned stack = %v, rows %d", err, len(f.s.all))
	}
	if err := f.m.RemoveOwned(ctx, "site", false); err != nil || len(f.s.all) != 0 {
		t.Fatalf("RemoveOwned = %v, rows %d", err, len(f.s.all))
	}
}
