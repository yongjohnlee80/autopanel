package forward

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	corefw "github.com/yongjohnlee80/autopanel/core/firewall"
)

type memStore struct {
	fs         []Forward
	next       int64
	failUpdate error
}

func (m *memStore) All(context.Context) ([]Forward, error) {
	out := slices.Clone(m.fs)
	slices.SortFunc(out, func(a, b Forward) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

func (m *memStore) Add(_ context.Context, f Forward) (Forward, error) {
	m.next++
	f.ID = m.next
	m.fs = append(m.fs, f)
	return f, nil
}

func (m *memStore) Update(_ context.Context, f Forward) (Forward, error) {
	if m.failUpdate != nil {
		return Forward{}, m.failUpdate
	}
	for i := range m.fs {
		if m.fs[i].ID == f.ID {
			f.Name = m.fs[i].Name
			m.fs[i] = f
			return f, nil
		}
	}
	return Forward{}, ErrNotFound
}

func (m *memStore) Remove(_ context.Context, id int64) (Forward, error) {
	for i, f := range m.fs {
		if f.ID == id {
			m.fs = slices.Delete(m.fs, i, i+1)
			return f, nil
		}
	}
	return Forward{}, ErrNotFound
}

// fakeHost is a host whose SSH is on 22 and 2200, with a web server on 8080
// and the gate on 80 and 443; its own addresses are loopback and 203.0.113.5.
type fakeHost struct {
	listeners  []Listener
	ssh        []int
	incomplete bool
	err        error
}

func newFakeHost() *fakeHost {
	return &fakeHost{ssh: []int{22, 2200}, listeners: []Listener{{"tcp", 22, "sshd"}, {"tcp", 2200, "sshd"}, {"tcp", 80, "autopanel"}, {"tcp", 443, "autopanel"}, {"tcp", 8080, "nginx"}, {"udp", 53, "systemd-resolved"}}}
}

func (h *fakeHost) Listeners(context.Context) ([]Listener, error) { return h.listeners, h.err }
func (h *fakeHost) SSHPorts(context.Context) ([]int, bool, error) {
	return h.ssh, !h.incomplete, h.err
}
func (h *fakeHost) Local(a netip.Addr) bool {
	return a.IsLoopback() || a == netip.MustParseAddr("203.0.113.5")
}

type fakeFirewall struct {
	opened, closed []string // "owner key"
	openErr        error
	needs          bool
}

func (f *fakeFirewall) Review(_ context.Context, _ string, wants []corefw.Want) ([]corefw.PortState, error) {
	var out []corefw.PortState
	for _, w := range wants {
		out = append(out, corefw.PortState{Want: w, Key: w.Key(), Verdict: "blocked", Needs: f.needs, Managed: true})
	}
	return out, nil
}

func (f *fakeFirewall) Open(_ context.Context, owner string, wants []corefw.Want) error {
	if f.openErr != nil {
		return f.openErr
	}
	for _, w := range wants {
		f.opened = append(f.opened, owner+" "+w.Key())
	}
	return nil
}

func (f *fakeFirewall) Close(_ context.Context, owner string, wants []corefw.Want) error {
	if wants == nil {
		f.closed = append(f.closed, owner+" all")
	}
	for _, w := range wants {
		f.closed = append(f.closed, owner+" "+w.Key())
	}
	return nil
}

type fixture struct {
	m       *Module
	st      *memStore
	host    *fakeHost
	fw      *fakeFirewall
	reloads int
}

func newFixture() *fixture {
	f := &fixture{st: &memStore{}, host: newFakeHost(), fw: &fakeFirewall{needs: true}}
	f.m = NewModule(f.st, f.host, func() Reserved {
		return Reserved{Public: map[int]string{80: "the gate", 443: "the gate", 25: "mail", 465: "mail", 587: "mail", 993: "mail"},
			Inner: map[int]string{10025: "mail", 10465: "mail", 10587: "mail", 10993: "mail", 18480: "mail"}}
	}, func(context.Context) error { f.reloads++; return nil })
	f.m.SetFirewall(f.fw)
	return f
}

// add reviews and applies s, as the panel does.
func (f *fixture) add(t *testing.T, s Spec, open bool) (View, error) {
	t.Helper()
	ctx := context.Background()
	r, err := f.m.check(ctx, s)
	if err != nil {
		return View{}, err
	}
	return f.m.add(ctx, Apply{Spec: s, Accept: r.SHA256, Open: open})
}

// TestAForwardsShape: what a forward may be, read from the request alone.
func TestAForwardsShape(t *testing.T) {
	ok := Spec{Name: "game", From: 25565, Target: "127.0.0.1:25566"}
	f, err := Normalize(ok)
	if err != nil || f.Proto != "tcp" || f.To != 25565 || f.Target != "127.0.0.1:25566" || f.Ports() != 1 || f.Owner() != "forward:game" {
		t.Fatalf("a plain forward: %+v, %v", f, err)
	}
	f, err = Normalize(Spec{Name: "r", From: 6000, To: 6009, Target: "[::ffff:10.0.0.5]:7000", Allow: []string{"203.0.113.77/24", "2001:db8::1/32"}})
	if err != nil || f.Target != "10.0.0.5:7000" || f.Ports() != 10 || strings.Join(f.Allow, " ") != "2001:db8::/32 203.0.113.0/24" {
		t.Fatalf("a range with sources: %+v, %v", f, err)
	}
	for _, target := range []string{"127.0.0.1:1", "10.0.0.5:22", "192.168.1.9:8080", "203.0.113.9:443", "223.255.255.254:1", "[::1]:8080", "[fd00::5]:22", "[2001:db8::5]:443", "[3fff::1]:1"} {
		s := ok
		s.Target = target
		if _, err := Normalize(s); err != nil {
			t.Errorf("the target %s: %v; want it taken", target, err)
		}
	}
	with := func(change func(*Spec)) Spec { s := ok; change(&s); return s }
	for what, c := range map[string]struct {
		s    Spec
		want error
	}{
		"no name":                 {with(func(s *Spec) { s.Name = "" }), ErrBadName},
		"a name in capitals":      {with(func(s *Spec) { s.Name = "Game" }), ErrBadName},
		"a name that is a path":   {with(func(s *Spec) { s.Name = "a/b" }), ErrBadName},
		"a name starting 0":       {with(func(s *Spec) { s.Name = "0day" }), ErrBadName},
		"a long name":             {with(func(s *Spec) { s.Name = strings.Repeat("a", 33) }), ErrBadName},
		"udp with a header":       {with(func(s *Spec) { s.Proto, s.Proxy = "udp", true }), ErrBadProto},
		"another protocol":        {with(func(s *Spec) { s.Proto = "sctp" }), ErrBadProto},
		"port 0":                  {with(func(s *Spec) { s.From = 0 }), ErrBadPorts},
		"a port past the last":    {with(func(s *Spec) { s.From = 65536 }), ErrBadPorts},
		"a range that runs back":  {with(func(s *Spec) { s.From, s.To = 2000, 1000 }), ErrBadPorts},
		"a range of 101":          {with(func(s *Spec) { s.From, s.To = 2000, 2100 }), ErrBadPorts},
		"a host name":             {with(func(s *Spec) { s.Target = "db.internal:5432" }), ErrBadTarget},
		"localhost":               {with(func(s *Spec) { s.Target = "localhost:5432" }), ErrBadTarget},
		"no port":                 {with(func(s *Spec) { s.Target = "127.0.0.1" }), ErrBadTarget},
		"port 0 at the target":    {with(func(s *Spec) { s.Target = "127.0.0.1:0" }), ErrBadTarget},
		"the unspecified address": {with(func(s *Spec) { s.Target = "0.0.0.0:80" }), ErrBadTarget},
		"the IPv6 unspecified":    {with(func(s *Spec) { s.Target = "[::]:80" }), ErrBadTarget},
		"a multicast address":     {with(func(s *Spec) { s.Target = "224.0.0.1:80" }), ErrBadTarget},
		"broadcast":               {with(func(s *Spec) { s.Target = "255.255.255.255:80" }), ErrBadTarget},
		"cloud metadata":          {with(func(s *Spec) { s.Target = "169.254.169.254:80" }), ErrBadTarget},
		"IPv6 link-local":         {with(func(s *Spec) { s.Target = "[fe80::1]:80" }), ErrBadTarget},
		"this network, 0.0.0.1":   {with(func(s *Spec) { s.Target = "0.0.0.1:22" }), ErrBadTarget},
		"this network, 0.1.2.3":   {with(func(s *Spec) { s.Target = "0.1.2.3:10025" }), ErrBadTarget},
		"the reserved range":      {with(func(s *Spec) { s.Target = "240.0.0.1:80" }), ErrBadTarget},
		"an IPv4-compatible IPv6": {with(func(s *Spec) { s.Target = "[::127.0.0.1]:80" }), ErrBadTarget},
		"a NAT64 address":         {with(func(s *Spec) { s.Target = "[64:ff9b::7f00:1]:80" }), ErrBadTarget},
		"a documentation prefix":  {with(func(s *Spec) { s.Target = "[100::1]:80" }), ErrBadTarget},
		"a range past the last":   {with(func(s *Spec) { s.From, s.To, s.Target = 6000, 6009, "127.0.0.1:65530" }), ErrBadTarget},
		"a source that is a name": {with(func(s *Spec) { s.Allow = []string{"office"} }), ErrBadAllow},
		"too many sources":        {with(func(s *Spec) { s.Allow = slices.Repeat([]string{"10.0.0.0/8"}, 17) }), ErrBadAllow},
		"a negative limit":        {with(func(s *Spec) { s.PerClient = -1 }), ErrBadLimits},
		"an idle time of a week":  {with(func(s *Spec) { s.IdleSecs = 7 * 24 * 3600 }), ErrBadLimits},
	} {
		if _, err := Normalize(c.s); !errors.Is(err, c.want) {
			t.Errorf("%s: %v; want %v", what, err, c.want)
		}
	}
}

// TestAForwardNeverTakesWhatIsHeld: SSH's port above all, then the gate's and
// mail's, a port another program listens on, and another forward's.
func TestAForwardNeverTakesWhatIsHeld(t *testing.T) {
	f := newFixture()
	if _, err := f.add(t, Spec{Name: "first", From: 7000, To: 7009, Target: "127.0.0.1:17000"}, false); err != nil {
		t.Fatal(err)
	}
	for what, c := range map[string]struct {
		s    Spec
		want error
		says string
	}{
		"SSH's port":                {Spec{Name: "a", From: 22, Target: "10.0.0.5:22"}, ErrSSH, "tcp/22 is SSH's"},
		"SSH's other port":          {Spec{Name: "a", From: 2200, Target: "10.0.0.5:22"}, ErrSSH, "tcp/2200"},
		"a range over SSH's port":   {Spec{Name: "a", From: 2150, To: 2249, Target: "10.0.0.5:3000"}, ErrSSH, "tcp/2200"},
		"the gate's port":           {Spec{Name: "a", From: 443, Target: "10.0.0.5:443"}, ErrPortTaken, "tcp/443 is the gate's"},
		"mail's port":               {Spec{Name: "a", From: 993, Target: "10.0.0.5:993"}, ErrPortTaken, "mail's"},
		"another program's port":    {Spec{Name: "a", From: 8080, Target: "10.0.0.5:80"}, ErrPortTaken, "nginx listens on tcp/8080"},
		"another forward's port":    {Spec{Name: "a", From: 7005, Target: "10.0.0.5:80"}, ErrPortTaken, "the forward first holds tcp/7005"},
		"a range into another's":    {Spec{Name: "a", From: 6990, To: 7000, Target: "10.0.0.5:80"}, ErrPortTaken, "first"},
		"another forward's name":    {Spec{Name: "first", From: 9000, Target: "10.0.0.5:80"}, ErrDuplicate, ""},
		"this host's SSH":           {Spec{Name: "a", From: 2222, Target: "127.0.0.1:22"}, ErrSSH, "tcp/22 on this host is SSH"},
		"this host's SSH, low port": {Spec{Name: "a", From: 222, Target: "203.0.113.5:2200"}, ErrSSH, "this host"},
		"a range onto SSH":          {Spec{Name: "a", From: 9000, To: 9010, Target: "127.0.0.1:15"}, ErrSSH, "tcp/22"},
		"mail's inner port":         {Spec{Name: "a", From: 2525, Target: "127.0.0.1:10025"}, ErrInner, "tcp/10025 is mail's"},
		"mail's management port":    {Spec{Name: "a", From: 9000, Target: "[::1]:18480"}, ErrInner, "18480"},
		"the gate's own port":       {Spec{Name: "a", From: 9000, Target: "127.0.0.1:443"}, ErrLoop, "tcp/443"},
		"itself":                    {Spec{Name: "a", From: 9000, Target: "127.0.0.1:9000"}, ErrLoop, "own public port"},
		"another forward, a loop":   {Spec{Name: "a", From: 9000, Target: "203.0.113.5:7003"}, ErrLoop, "the forward first"},
	} {
		_, err := f.m.check(context.Background(), c.s)
		if !errors.Is(err, c.want) || !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s: %v; want %v naming %q", what, err, c.want, c.says)
		}
	}
	// The same ports on another machine are that machine's business.
	for what, s := range map[string]Spec{
		"another machine's SSH":      {Name: "nas-ssh", From: 2222, Target: "10.0.0.5:22"},
		"another machine's port 443": {Name: "b", From: 9443, Target: "10.0.0.5:443"},
		"another machine's 10025":    {Name: "c", From: 9025, Target: "10.0.0.5:10025"},
	} {
		if _, err := f.m.check(context.Background(), s); err != nil {
			t.Errorf("%s: %v; want it allowed", what, err)
		}
	}
	if len(f.st.fs) != 1 || f.reloads != 1 {
		t.Fatalf("a refused forward changed something: %d stored, %d reloads", len(f.st.fs), f.reloads)
	}
}

// TestNothingChangesWhenTheHostCannotBeRead: with SSH's ports not all
// explained, or the listeners unread, no forward is judged safe.
func TestNothingChangesWhenTheHostCannotBeRead(t *testing.T) {
	s := Spec{Name: "game", From: 25565, Target: "127.0.0.1:25566"}
	f := newFixture()
	f.host.incomplete = true
	if _, err := f.add(t, s, true); !errors.Is(err, ErrUnknown) {
		t.Fatalf("with an SSH listener unexplained: %v", err)
	}
	f = newFixture()
	f.host.err = errors.New("ss: not found")
	if _, err := f.add(t, s, true); !errors.Is(err, ErrUnknown) {
		t.Fatalf("with the listeners unread: %v", err)
	}
	if len(f.st.fs) != 0 || len(f.fw.opened) != 0 {
		t.Fatal("something changed on a host that could not be read")
	}
}

// TestAForwardIsAppliedAsReviewed: the review's digest is needed to add; a
// host that changed since refuses; the firewall rule is the forward's own,
// opened with it, moved with its ports and closed with it; a firewall that
// will not open the port leaves nothing behind.
func TestAForwardIsAppliedAsReviewed(t *testing.T) {
	f := newFixture()
	ctx := context.Background()
	s := Spec{Name: "game", From: 25565, Target: "127.0.0.1:25566", Allow: []string{"203.0.113.0/24"}}
	r, err := f.m.check(ctx, s)
	if err != nil || len(r.Ports) != 1 || r.Ports[0].Key != "tcp/25565" || !r.Ports[0].Needs || len(r.SHA256) != 64 {
		t.Fatalf("the review: %+v, %v", r, err)
	}
	if len(f.st.fs) != 0 || f.reloads != 0 || len(f.fw.opened) != 0 {
		t.Fatal("a review changed something")
	}
	if _, err := f.m.add(ctx, Apply{Spec: s, Accept: "not the review"}); !errors.Is(err, ErrChanged) {
		t.Fatalf("an add without the review's digest: %v", err)
	}
	f.fw.needs = false // the firewall changed between the review and the apply
	if _, err := f.m.add(ctx, Apply{Spec: s, Accept: r.SHA256, Open: true}); !errors.Is(err, ErrChanged) {
		t.Fatalf("an add after the firewall changed: %v", err)
	}
	f.fw.needs = true
	other := s
	other.Target = "127.0.0.1:1"
	if _, err := f.m.add(ctx, Apply{Spec: other, Accept: r.SHA256}); !errors.Is(err, ErrChanged) {
		t.Fatalf("another forward under the first one's review: %v", err)
	}

	// A firewall that refuses: the forward is not added.
	f.fw.openErr = errors.New("ufw: could not")
	if _, err := f.m.add(ctx, Apply{Spec: s, Accept: r.SHA256, Open: true}); err == nil || len(f.st.fs) != 0 || f.reloads != 0 {
		t.Fatalf("a forward whose port could not be opened: %v, %d stored", err, len(f.st.fs))
	}
	f.fw.openErr = nil

	v, err := f.m.add(ctx, Apply{Spec: s, Accept: r.SHA256, Open: true})
	if err != nil || v.ID == 0 || v.Proto != "tcp" || v.To != 25565 || f.reloads != 1 {
		t.Fatalf("the add: %+v, %v", v, err)
	}
	if got := strings.Join(f.fw.opened, ";"); got != "forward:game tcp/25565" {
		t.Fatalf("opened: %s", got)
	}
	list, _ := f.m.list(ctx, struct{}{})
	if len(list) != 1 || list[0].Name != "game" || list[0].Allow[0] != "203.0.113.0/24" {
		t.Fatalf("the list: %+v", list)
	}

	// Moved to another port: reviewed again, the new port opened, the old closed.
	moved := Spec{ID: v.ID, Name: "game", From: 25570, Target: "127.0.0.1:25566"}
	r2, err := f.m.check(ctx, moved)
	if err != nil {
		t.Fatalf("reviewing an update of itself: %v", err)
	}
	if _, err := f.m.update(ctx, Apply{Spec: moved, Accept: r2.SHA256, Open: true}); err != nil {
		t.Fatal(err)
	}
	// (The first "all" is the clean-up after the firewall refused, above.)
	if got := strings.Join(f.fw.opened, ";") + " | " + strings.Join(f.fw.closed, ";"); got != "forward:game tcp/25565;forward:game tcp/25570 | forward:game all;forward:game tcp/25565" {
		t.Fatalf("after the move: %s", got)
	}
	// A store that fails the update: the port just opened for it is closed again,
	// the gate is told nothing, and the old port's rule stays.
	f.st.failUpdate = errors.New("the store is gone")
	again := Spec{ID: v.ID, Name: "game", From: 25580, Target: "127.0.0.1:25566"}
	r3, _ := f.m.check(ctx, again)
	reloads, closed := f.reloads, len(f.fw.closed)
	if _, err := f.m.update(ctx, Apply{Spec: again, Accept: r3.SHA256, Open: true}); err == nil {
		t.Fatal("an update the store refused was reported done")
	}
	if f.reloads != reloads || len(f.fw.closed) != closed+1 || f.fw.closed[closed] != "forward:game tcp/25580" {
		t.Fatalf("after a failed update: %d reloads more, closed %v", f.reloads-reloads, f.fw.closed[closed:])
	}
	f.st.failUpdate = nil
	f.fw.opened, f.fw.closed = f.fw.opened[:2], f.fw.closed[:closed]

	// A forward keeps its name, and one that is gone cannot be updated.
	renamed := Spec{ID: v.ID, Name: "other", From: 25570, Target: "127.0.0.1:25566"}
	if _, err := f.m.check(ctx, renamed); !errors.Is(err, ErrBadName) {
		t.Fatalf("an update that renames: %v", err)
	}
	if _, err := f.m.check(ctx, Spec{ID: 99, Name: "gone", From: 1, Target: "10.0.0.1:1"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an update of a forward that is not there: %v", err)
	}
	// Updating in place, its own port is its own, though the gate listens on it now.
	f.host.listeners = append(f.host.listeners, Listener{"tcp", 25570, "autopanel"})
	same := Spec{ID: v.ID, Name: "game", From: 25570, Target: "127.0.0.1:25567"}
	if _, err := f.m.check(ctx, same); err != nil {
		t.Fatalf("an update that keeps its port: %v", err)
	}

	// Removed: the port stops being forwarded, then its rule is closed.
	if _, err := f.m.remove(ctx, Ref{ID: v.ID}); err != nil {
		t.Fatal(err)
	}
	if len(f.st.fs) != 0 || f.fw.closed[len(f.fw.closed)-1] != "forward:game all" || f.reloads != 3 {
		t.Fatalf("after the removal: %d stored, closed %v, %d reloads", len(f.st.fs), f.fw.closed, f.reloads)
	}
	if _, err := f.m.remove(ctx, Ref{ID: v.ID}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("removing it twice: %v", err)
	}
	// Added without open, the firewall is left as it is.
	n := len(f.fw.opened)
	if _, err := f.add(t, s, false); err != nil || len(f.fw.opened) != n {
		t.Fatalf("an add that does not open: %v, opened %v", err, f.fw.opened)
	}
}

// TestTheForwardsAreBounded: sixteen forwards, and 128 public ports over them
// all; every forward has a share of the 64 connections, never fewer than four.
func TestTheForwardsAreBounded(t *testing.T) {
	f := newFixture()
	for i := range MaxForwards {
		s := Spec{Name: "f" + string(rune('a'+i)), From: 20000 + i*10, To: 20000 + i*10 + 7, Target: "10.0.0.5:1000"}
		if _, err := f.add(t, s, false); err != nil {
			t.Fatalf("forward %d: %v", i+1, err)
		}
	}
	if _, err := f.add(t, Spec{Name: "one-more", From: 30000, Target: "10.0.0.5:1"}, false); !errors.Is(err, ErrTooMany) {
		t.Fatalf("a seventeenth forward: %v", err)
	}
	streams, err := f.m.Streams(context.Background())
	if err != nil || len(streams) != MaxForwards*8 {
		t.Fatalf("%d streams, %v; want a stream a public port", len(streams), err)
	}
	total := 0
	seen := map[string]bool{}
	for _, s := range streams {
		if !seen[s.Name] {
			seen[s.Name] = true
			total += s.Share
		}
		if s.Share < minShare || !s.Plain || s.IdleSecs != DefaultIdle || s.PerClient != DefaultClient {
			t.Fatalf("a stream: %+v", s)
		}
	}
	if total > Connections {
		t.Fatalf("the forwards' shares add up to %d; the most is %d", total, Connections)
	}
	// 128 public ports: two forwards of 100 are too many.
	g := newFixture()
	if _, err := g.add(t, Spec{Name: "wide", From: 20000, To: 20099, Target: "10.0.0.5:1000"}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := g.add(t, Spec{Name: "wider", From: 21000, To: 21099, Target: "10.0.0.5:2000"}, false); !errors.Is(err, ErrTooMany) {
		t.Fatalf("200 public ports: %v", err)
	}
	// A range's ports keep their order at the target; with a header and sources, the stream says so.
	one := StreamsOf([]Forward{{Name: "r", Proto: "tcp", From: 6000, To: 6002, Target: "10.0.0.5:7000", Proxy: true, Allow: []string{"10.0.0.0/8", "192.0.2.0/24"}, PerClient: 3, IdleSecs: 60}})
	if len(one) != 3 || one[2].Listen != ":6002" || one[2].To != "10.0.0.5:7002" || one[0].Plain || one[0].Allow != "10.0.0.0/8 192.0.2.0/24" ||
		one[0].Share != Connections || one[0].PerClient != 3 || one[0].IdleSecs != 60 || one[0].Name != "forward:r" {
		t.Fatalf("a range as streams: %+v", one)
	}
	if StreamsOf(nil) != nil {
		t.Fatal("no forwards made streams")
	}
}

// TestAUDPForward: SSH, the gate and mail hold TCP ports, so a UDP forward on
// the same number takes nothing of theirs; it is held to the UDP ports other
// programs and other UDP forwards hold, and to no loop. A TCP and a UDP
// forward may share a number.
func TestAUDPForward(t *testing.T) {
	f := newFixture()
	ctx := context.Background()
	if _, err := f.add(t, Spec{Name: "dns", Proto: "udp", From: 5353, Target: "10.0.0.5:53"}, true); err != nil {
		t.Fatal(err)
	}
	if got := f.fw.opened; len(got) != 1 || got[0] != "forward:dns udp/5353" {
		t.Fatalf("the rule opened: %v", got)
	}
	for what, s := range map[string]Spec{
		"the number SSH has on TCP":      {Name: "a", Proto: "udp", From: 22, Target: "10.0.0.5:22"},
		"the number the gate has on TCP": {Name: "a", Proto: "udp", From: 443, Target: "10.0.0.5:443"},
		"a TCP forward on dns's number":  {Name: "a", From: 5353, Target: "10.0.0.5:53"},
		"a UDP port on this host":        {Name: "a", Proto: "udp", From: 9000, Target: "127.0.0.1:10025"},
	} {
		if _, err := f.m.check(ctx, s); err != nil {
			t.Errorf("%s: %v; want it allowed", what, err)
		}
	}
	for what, c := range map[string]struct {
		s    Spec
		want error
		says string
	}{
		"a UDP port another program holds": {Spec{Name: "a", Proto: "udp", From: 53, Target: "10.0.0.5:53"}, ErrPortTaken, "systemd-resolved listens on udp/53"},
		"another UDP forward's port":       {Spec{Name: "a", Proto: "udp", From: 5353, Target: "10.0.0.6:53"}, ErrPortTaken, "the forward dns holds udp/5353"},
		"itself":                           {Spec{Name: "a", Proto: "udp", From: 9000, Target: "127.0.0.1:9000"}, ErrLoop, "udp/9000"},
		"another UDP forward, a loop":      {Spec{Name: "a", Proto: "udp", From: 9000, Target: "203.0.113.5:5353"}, ErrLoop, "the forward dns"},
	} {
		if _, err := f.m.check(ctx, c.s); !errors.Is(err, c.want) || !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s: %v; want %v naming %q", what, err, c.want, c.says)
		}
	}
	// As streams: a UDP forward has no share of the TCP connections and takes
	// none from the TCP forwards; its limits are the gate's unless it sets them.
	ss := StreamsOf([]Forward{
		{Name: "dns", Proto: "udp", From: 5353, To: 5354, Target: "10.0.0.5:53", PerClient: 4, IdleSecs: 30, Allow: []string{"10.0.0.0/8"}},
		{Name: "game", Proto: "tcp", From: 25565, To: 25565, Target: "127.0.0.1:26000"},
	})
	if len(ss) != 3 {
		t.Fatalf("%d streams", len(ss))
	}
	u, tc := ss[1], ss[2]
	if u.Proto != "udp" || u.Listen != ":5354" || u.To != "10.0.0.5:54" || u.Share != 0 || u.Plain || u.PerClient != 4 || u.IdleSecs != 30 || u.Allow != "10.0.0.0/8" {
		t.Fatalf("a UDP forward's second port as a stream: %+v", u)
	}
	if tc.Proto != "tcp" || tc.Share != Connections || !tc.Plain {
		t.Fatalf("the TCP forward beside it: %+v", tc)
	}
	if d := StreamsOf([]Forward{{Name: "d", Proto: "udp", From: 1, To: 1, Target: "10.0.0.5:1"}}); d[0].PerClient != 0 || d[0].IdleSecs != 0 {
		t.Fatalf("a UDP forward with no limits of its own: %+v; want the gate's defaults", d[0])
	}
}
