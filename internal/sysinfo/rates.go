package sysinfo

import (
	"bufio"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RATES. The host's counters only grow: what the panel shows per second is the
// difference between two reads. Sampler keeps the last read and answers each
// new one with the rates since it.

// Iface is one network interface's counters, as /proc/net/dev keeps them.
type Iface struct {
	Name      string `json:"name"`
	RxBytes   uint64 `json:"rx_bytes"`
	TxBytes   uint64 `json:"tx_bytes"`
	RxPackets uint64 `json:"rx_packets"`
	TxPackets uint64 `json:"tx_packets"`
	RxErrors  uint64 `json:"rx_errors"`
	TxErrors  uint64 `json:"tx_errors"`
}

// ParseNetDev reads /proc/net/dev: every interface but the loopback, by name.
func ParseNetDev(r io.Reader) []Iface {
	var out []Iface
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		name, rest, ok := strings.Cut(sc.Text(), ":")
		name = strings.TrimSpace(name)
		if !ok || name == "lo" || strings.Contains(name, "|") {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 16 {
			continue
		}
		n := func(i int) uint64 { v, _ := strconv.ParseUint(f[i], 10, 64); return v }
		out = append(out, Iface{Name: processName(name), RxBytes: n(0), RxPackets: n(1), RxErrors: n(2),
			TxBytes: n(8), TxPackets: n(9), TxErrors: n(10)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// CPUTime is /proc/stat's first line: the time all processors spent, and of it
// the time they spent idle (idle and waiting for input or output), in ticks.
type CPUTime struct{ Total, Idle uint64 }

// ParseCPUStat reads the "cpu" line of /proc/stat, and counts the processors.
func ParseCPUStat(r io.Reader) (CPUTime, int) {
	var t CPUTime
	cpus := 0
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 {
			continue
		}
		switch {
		case f[0] == "cpu":
			for i, s := range f[1:] {
				if i >= 8 { // guest time is counted inside user time already
					break
				}
				v, _ := strconv.ParseUint(s, 10, 64)
				t.Total += v
				if i == 3 || i == 4 { // idle, iowait
					t.Idle += v
				}
			}
		case strings.HasPrefix(f[0], "cpu"):
			cpus++
		}
	}
	return t, cpus
}

// ParseSwap reads /proc/meminfo's SwapTotal and SwapFree, in bytes.
func ParseSwap(r io.Reader) (total, free uint64) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 {
			continue
		}
		kb, err := strconv.ParseUint(f[1], 10, 64)
		if err != nil {
			continue
		}
		switch f[0] {
		case "SwapTotal:":
			total = kb << 10
		case "SwapFree:":
			free = kb << 10
		}
	}
	return total, free
}

// IfaceRate is an interface's counters and its rates since the last read.
type IfaceRate struct {
	Iface
	RxPerSec uint64 `json:"rx_per_sec"` // bytes; 0 on the first read
	TxPerSec uint64 `json:"tx_per_sec"`
}

// Sample is one read of the host's activity.
type Sample struct {
	CPUPercent float64     `json:"cpu_percent"` // all processors, since the last read; -1 on the first
	CPUs       int         `json:"cpus"`
	SwapTotal  uint64      `json:"swap_total"`
	SwapFree   uint64      `json:"swap_free"`
	Uptime     int64       `json:"uptime"` // the host's, in seconds
	Network    []IfaceRate `json:"network"`
	Seconds    float64     `json:"seconds"` // since the last read; 0 on the first
}

// Sampler answers each read with the rates since the one before. Safe for
// concurrent use.
type Sampler struct {
	mu   sync.Mutex
	at   time.Time
	cpu  CPUTime
	net  map[string]Iface
	read func() (CPUTime, int, []Iface, uint64, uint64, int64)
	now  func() time.Time
}

// rate is how much a counter grew per second; a counter that went back (an
// interface reset) counts as not having grown.
func rate(now, before uint64, secs float64) uint64 {
	if now < before || secs <= 0 {
		return 0
	}
	return uint64(float64(now-before) / secs)
}

// Read takes a sample.
func (s *Sampler) Read() Sample {
	cpu, cpus, ifaces, swapTotal, swapFree, uptime := s.read()
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	out := Sample{CPUs: cpus, SwapTotal: swapTotal, SwapFree: swapFree, Uptime: uptime, CPUPercent: -1, Network: []IfaceRate{}}
	first := s.at.IsZero()
	if !first {
		out.Seconds = now.Sub(s.at).Seconds()
		if dt := cpu.Total - s.cpu.Total; cpu.Total > s.cpu.Total && cpu.Idle >= s.cpu.Idle {
			busy := dt - (cpu.Idle - s.cpu.Idle)
			out.CPUPercent = float64(busy) * 100 / float64(dt)
		}
	}
	prev := s.net
	s.net = make(map[string]Iface, len(ifaces))
	for _, i := range ifaces {
		r := IfaceRate{Iface: i}
		if p, ok := prev[i.Name]; ok {
			r.RxPerSec, r.TxPerSec = rate(i.RxBytes, p.RxBytes, out.Seconds), rate(i.TxBytes, p.TxBytes, out.Seconds)
		}
		out.Network = append(out.Network, r)
		s.net[i.Name] = i
	}
	s.at, s.cpu = now, cpu
	return out
}
