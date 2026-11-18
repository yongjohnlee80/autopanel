package app

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"testing"

	corefw "github.com/yongjohnlee80/autopanel/core/firewall"
	"github.com/yongjohnlee80/autopanel/core/forward"
	"github.com/yongjohnlee80/autopanel/core/mail"
	"github.com/yongjohnlee80/autopanel/core/services"
	hostgate "github.com/yongjohnlee80/autopanel/host/gate"
	"github.com/yongjohnlee80/autopanel/internal/sysinfo"
)

type someForwards struct {
	forward.Store
	fs []forward.Forward
}

func (s someForwards) All(context.Context) ([]forward.Forward, error) { return s.fs, nil }

type noStacks struct{ services.Store }

func (noStacks) All(context.Context) ([]services.Service, error) { return nil, nil }

type noRows struct{ corefw.Store }

func (noRows) FirewallRows(context.Context) ([]corefw.Row, error) { return nil, nil }

// TestWhichAddressesAreThisHosts: loopback and an interface's address are the
// host's own; another machine's is not; an interface list that cannot be read
// makes every address the host's, the stricter answer.
func TestWhichAddressesAreThisHosts(t *testing.T) {
	defer func(f func() ([]net.Addr, error)) { interfaceAddrs = f }(interfaceAddrs)
	interfaceAddrs = func() ([]net.Addr, error) {
		return []net.Addr{&net.IPNet{IP: net.ParseIP("203.0.113.5"), Mask: net.CIDRMask(24, 32)}, &net.IPNet{IP: net.ParseIP("2001:db8::5"), Mask: net.CIDRMask(64, 128)}}, nil
	}
	h := forwardHost{}
	for addr, want := range map[string]bool{"127.0.0.1": true, "127.9.9.9": true, "::1": true, "203.0.113.5": true, "::ffff:203.0.113.5": true,
		"2001:db8::5": true, "203.0.113.6": false, "10.0.0.5": false, "2001:db8::6": false} {
		if got := h.Local(netip.MustParseAddr(addr)); got != want {
			t.Errorf("%s is this host's: %v; want %v", addr, got, want)
		}
	}
	interfaceAddrs = func() ([]net.Addr, error) { return nil, errors.New("no netlink") }
	if !h.Local(netip.MustParseAddr("10.0.0.5")) {
		t.Error("with the interfaces unread, an address was taken for another machine's")
	}
}

// TestThePortsAutoPanelHoldsItself: the gate's two and mail's four are public
// ports no forward may take; mail's loopback and management ports are ones no
// forward may lead to, whether or not mail is set up.
func TestThePortsAutoPanelHoldsItself(t *testing.T) {
	r := forwardReserved(Config{HTTPAddr: ":80", HTTPSAddr: "0.0.0.0:8443"})()
	for _, p := range []int{80, 8443, 25, 465, 587, 993} {
		if r.Public[p] == "" {
			t.Errorf("public port %d is not reserved", p)
		}
	}
	for _, p := range append(mail.LoopbackPorts(), mail.ManagePort) {
		if r.Inner[p] != "mail" {
			t.Errorf("inner port %d is not reserved", p)
		}
	}
	if len(r.Public) != 6 || len(r.Inner) != 5 {
		t.Errorf("reserved: %d public, %d inner", len(r.Public), len(r.Inner))
	}
}

// TestTheGateIsSentMailsStreamsAndTheForwards: both travel on link.streams,
// under one limit: mail's, and the same one when mail is off; a set that did
// not change wakes nobody.
func TestTheGateIsSentMailsStreamsAndTheForwards(t *testing.T) {
	tbl := newStreamTable(100)
	ctx := context.Background()
	fm := forward.NewModule(someForwards{fs: []forward.Forward{{ID: 1, Name: "game", Proto: "tcp", From: 25565, To: 25566, Target: "127.0.0.1:26000", Allow: []string{"203.0.113.0/24"}}}}, nil, nil, nil)
	send := forwardStreams(fm, tbl)
	if err := send(ctx); err != nil {
		t.Fatal(err)
	}
	s, err := tbl.wait(ctx, 100)
	if err != nil || s.Total != mail.TotalConnections || len(s.Streams) != 2 {
		t.Fatalf("forwards alone: %+v, %v", s, err)
	}
	want := hostgate.Stream{Name: "forward:game", Listen: ":25566", To: "127.0.0.1:26001", IdleSecs: forward.DefaultIdle, PerClient: forward.DefaultClient,
		Share: forward.Connections, Plain: true, Allow: "203.0.113.0/24"}
	if s.Streams[1] != want {
		t.Fatalf("a forward's second port as a stream:\n got %+v\nwant %+v", s.Streams[1], want)
	}
	rev := s.Rev
	if err := send(ctx); err != nil {
		t.Fatal(err)
	}
	tbl.mu.Lock()
	n := tbl.rev.n
	tbl.mu.Unlock()
	if n != rev {
		t.Fatal("the same forwards sent again woke the gate")
	}
	switchStreams(tbl)(true)
	s, _ = tbl.wait(ctx, rev)
	if len(s.Streams) != len(mail.Ports)+2 || s.Total != mail.TotalConnections || s.Streams[0].Name != "smtp" || s.Streams[0].Plain {
		t.Fatalf("with mail on: %d streams, total %d, first %+v", len(s.Streams), s.Total, s.Streams[0])
	}
	switchStreams(tbl)(false)
	s, _ = tbl.wait(ctx, s.Rev)
	if len(s.Streams) != 2 || s.Total != mail.TotalConnections {
		t.Fatalf("with mail off again: %d streams, total %d", len(s.Streams), s.Total)
	}
}

// TestAForwardsPortInTheFirewall: a forward's port the firewall blocks is a
// host check, and the plan to turn the firewall on names a forward's port as
// that forward's.
func TestAForwardsPortInTheFirewall(t *testing.T) {
	ctx := context.Background()
	fs := someForwards{fs: []forward.Forward{
		{ID: 1, Name: "game", Proto: "tcp", From: 25565, To: 25565, Target: "127.0.0.1:26000"},
		{ID: 2, Name: "range", Proto: "tcp", From: 6000, To: 6009, Target: "10.0.0.5:7000"},
	}}
	off := func(context.Context) bool { return false }
	checks := ownerChecks(off, noStacks{}, fs, noRows{})
	deny := sysinfo.Firewall{Manager: "ufw", Active: true, Default: "deny", Limits: []string{}}
	got := checks(ctx, deny)
	if len(got) != 1 || got[0].ID != "forward-port-blocked" || got[0].Severity != alert || got[0].Detail != "game tcp/25565, range tcp/6000-6009" {
		t.Fatalf("with the firewall denying: %+v", got)
	}
	if got := checks(ctx, sysinfo.Firewall{Manager: "ufw", Active: false, Limits: []string{}}); len(got) != 0 {
		t.Fatalf("with the firewall off: %+v", got)
	}
	uses := firewallUses(Config{HTTPAddr: ":80", HTTPSAddr: ":443"}, off, noStacks{}, fs)(ctx)
	if u := uses["tcp/25565"]; !reflect.DeepEqual(u, corefw.Use{Name: "forward game", Owner: "forward:game"}) {
		t.Fatalf("the plan's use of a forward's port: %+v", u)
	}
	if _, ok := uses["tcp/6000"]; ok {
		t.Fatal("a range was named port by port in the plan")
	}
}
