package sysinfo

import (
	"strings"
	"testing"
	"time"
)

func TestTheHostsCountersAreParsed(t *testing.T) {
	dev := `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 1000 10 0 0 0 0 0 0 1000 10 0 0 0 0 0 0
  eth0: 5000 50 1 0 0 0 0 0 7000 70 2 0 0 0 0 0
br-d37a: 300 3 0 0 0 0 0 0 400 4 0 0 0 0 0 0
`
	got := ParseNetDev(strings.NewReader(dev))
	if len(got) != 2 || got[0].Name != "br-d37a" || got[1] != (Iface{Name: "eth0", RxBytes: 5000, RxPackets: 50, RxErrors: 1, TxBytes: 7000, TxPackets: 70, TxErrors: 2}) {
		t.Errorf("ParseNetDev = %+v; want every interface but lo, by name", got)
	}
	cpu, n := ParseCPUStat(strings.NewReader("cpu  100 0 50 800 50 0 0 0 7 0\ncpu0 50 0 25 400 25 0 0 0 0 0\ncpu1 50 0 25 400 25 0 0 0 0 0\nintr 1\n"))
	if cpu != (CPUTime{Total: 1000, Idle: 850}) || n != 2 {
		t.Errorf("ParseCPUStat = %+v, %d", cpu, n)
	}
	if total, free := ParseSwap(strings.NewReader("MemTotal: 1 kB\nSwapTotal: 3072 kB\nSwapFree: 1024 kB\n")); total != 3<<20 || free != 1<<20 {
		t.Errorf("ParseSwap = %d, %d", total, free)
	}
}

func TestASamplerAnswersRatesSinceTheLastRead(t *testing.T) {
	at := time.Unix(1000, 0)
	reads := []struct {
		cpu CPUTime
		net []Iface
	}{
		{CPUTime{Total: 1000, Idle: 900}, []Iface{{Name: "eth0", RxBytes: 1000, TxBytes: 500}}},
		{CPUTime{Total: 2000, Idle: 1650}, []Iface{{Name: "eth0", RxBytes: 21000, TxBytes: 2500}, {Name: "wg0", RxBytes: 9}}},
		{CPUTime{Total: 3000, Idle: 2650}, []Iface{{Name: "eth0", RxBytes: 100, TxBytes: 2600}}}, // a counter that went back
	}
	i := 0
	s := &Sampler{now: func() time.Time { return at }, read: func() (CPUTime, int, []Iface, uint64, uint64, int64) {
		r := reads[i]
		i++
		return r.cpu, 2, r.net, 0, 0, 77
	}}
	first := s.Read()
	if first.CPUPercent != -1 || first.Network[0].RxPerSec != 0 || first.Seconds != 0 || first.Uptime != 77 {
		t.Errorf("the first read = %+v; want no rates yet", first)
	}
	at = at.Add(10 * time.Second)
	second := s.Read()
	if second.CPUPercent != 25 || second.Network[0].RxPerSec != 2000 || second.Network[0].TxPerSec != 200 || second.Network[1].RxPerSec != 0 {
		t.Errorf("the second read = %+v; want 25%% busy, 2000 B/s in and 200 out on eth0, no rate yet for wg0", second)
	}
	at = at.Add(10 * time.Second)
	if third := s.Read(); third.Network[0].RxPerSec != 0 || third.Network[0].TxPerSec != 10 {
		t.Errorf("the third read = %+v; a counter that went back is no traffic", third)
	}
}
