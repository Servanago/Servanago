package web

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
)

func TestParseMeminfoReadsMemSwapAndAvailability(t *testing.T) {
	sample := `MemTotal:        8000000 kB
MemFree:         2000000 kB
MemAvailable:    4000000 kB
Buffers:          200000 kB
SwapTotal:       2000000 kB
SwapFree:        1500000 kB
HugePages_Total:       0
`
	mem, swap := parseMeminfo([]byte(sample))
	if mem.Total != 8_000_000*1024 || mem.Used != 4_000_000*1024 {
		t.Errorf("mem: %+v", mem)
	}
	if swap.Total != 2_000_000*1024 || swap.Used != 500_000*1024 || swap.Pct != 25 {
		t.Errorf("swap: %+v", swap)
	}
}

func TestParseMeminfoWithoutSwapReadsZero(t *testing.T) {
	_, swap := parseMeminfo([]byte("MemTotal: 8000000 kB\nMemAvailable: 4000000 kB\n"))
	if swap.Total != 0 || swap.Used != 0 {
		t.Errorf("swap: %+v", swap)
	}
}

func TestParseMeminfoIgnoresLinesWithoutValues(t *testing.T) {
	mem, _ := parseMeminfo([]byte("MemAvailable:\nMemTotal: not-a-number\n"))
	if mem.Total != 0 {
		t.Errorf("mem: %+v", mem)
	}
}

func TestParseLoadavg(t *testing.T) {
	l1, l5, l15 := parseLoadavg([]byte("0.52 0.58 0.59 1/469 12345\n"))
	if l1 < 0.51 || l1 > 0.53 || l5 < 0.57 || l5 > 0.59 || l15 != 0.59 {
		t.Errorf("load: %v %v %v", l1, l5, l15)
	}
	l1, l5, l15 = parseLoadavg([]byte("truncated"))
	if l1 != 0 || l5 != 0 || l15 != 0 {
		t.Errorf("want zeros: %v %v %v", l1, l5, l15)
	}
}

func TestCPUBusySamplesTwoSnapshots(t *testing.T) {
	// Between the snapshots 500 jiffies pass, 300 of them idle (200 -> 500): 40% busy.
	a := []byte("cpu  100 0 100 200 0 0 0 0 0 0\n")
	b := []byte("cpu  200 0 200 500 0 0 0 0 0 0\n")
	if got := cpuBusy(a, b); got != 40 {
		t.Errorf("cpu busy: got %d, want 40", got)
	}
	// The second snapshot is not newer: no division by zero, no negative percent.
	if got := cpuBusy(b, a); got != 0 {
		t.Errorf("reversed sample: %d", got)
	}
	if got := cpuBusy(nil, b); got != 0 {
		t.Errorf("empty before: %d", got)
	}
}

func TestHostStatsDataDedupesRootsWithDataDir(t *testing.T) {
	dir := t.TempDir()
	procRead = func(path string) ([]byte, error) {
		switch path {
		case "/proc/meminfo":
			return []byte("MemTotal: 8000000 kB\nMemAvailable: 4000000 kB\n"), nil
		case "/proc/loadavg":
			return []byte("0.10 0.10 0.10 1/1 1\n"), nil
		case "/proc/stat":
			return []byte("cpu  100 0 100 200 0 0\n"), nil
		}
		return nil, os.ErrNotExist
	}
	defer func() { procRead = os.ReadFile }()
	st := hostStatsData(context.Background(), dir, []string{dir, dir + "/missing"})
	if st.Err != "" {
		t.Fatal(st.Err)
	}
	n := len(st.Disks)
	if n != 1 || st.Disks[0].Path != dir {
		// One filesystem backs both paths; the missing root is skipped.
		t.Errorf("disks: %+v", st.Disks)
	}
	if st.Mem.Pct != 50 || st.SwapOn {
		t.Errorf("mem %+v swap %+v", st.Mem, st.Swap)
	}
	if st.CPU != 0 { // an unsampled cpu line pair reads 0, not a garbage percent
		t.Errorf("cpu: %d", st.CPU)
	}
}

func TestHostStatsDataDimsWhenProcIsUnreadable(t *testing.T) {
	procRead = func(path string) ([]byte, error) { return nil, os.ErrPermission }
	defer func() { procRead = os.ReadFile }()
	st := hostStatsData(context.Background(), "/nonexistent", nil)
	if st.Err == "" {
		t.Error("want Err on a failed meminfo read")
	}
}

func TestHostStatsStripRendersComplete(t *testing.T) {
	s := newServer(t, "pw")
	c := sessionCookie(t, login(s, "pw", nil, ""))
	s.hostSamples = func(context.Context) hostStats {
		return hostStats{
			Mem:    statPair{Total: 8 << 30, Used: 4 << 30, Pct: 50},
			SwapOn: true, Swap: statPair{Total: 2 << 30, Used: 1 << 30, Pct: 50},
			CPU: 12, Load1: 0.5, Load5: 0.4, Load15: 0.3,
			Disks: []diskStat{{Path: "/", Total: 100 << 30, Used: 25 << 30, Pct: 25}},
		}
	}
	// The dashboard top carries the strip and finishes rendering.
	w := s.do(req{method: "GET", path: "/", cookies: []*http.Cookie{c}})
	page := w.Body.String()
	for _, want := range []string{"Memory", "Swap", "CPU", "Disk", "id=\"hoststats\"", "every 30s", "load 0.50"} {
		if !strings.Contains(page, want) {
			t.Errorf("dashboard lacks %q", want)
		}
	}
	if !strings.Contains(page, "</html>") {
		t.Error("dashboard truncated")
	}
	// The polled partial returns the same strip alone.
	w = s.do(req{method: "GET", path: "/hoststats", cookies: []*http.Cookie{c}})
	part := w.Body.String()
	if !strings.Contains(part, "statstrip") || !strings.Contains(part, "(25%)") || !strings.Contains(part, `value="50"`) {
		t.Errorf("partial, code %d, hdrs %v: %s", w.Code, w.Header(), part)
	}
	// Swap off renders "no swap", not a zero meter.
	s.hostSamples = func(context.Context) hostStats {
		return hostStats{Mem: statPair{Total: 8 << 30, Used: 4 << 30, Pct: 50},
			Disks: []diskStat{{Path: "/", Total: 100 << 30, Used: 25 << 30, Pct: 25}}}
	}
	w = s.do(req{method: "GET", path: "/hoststats", cookies: []*http.Cookie{c}})
	if !strings.Contains(w.Body.String(), "no swap") {
		t.Errorf("swap-off text: %s", w.Body.String())
	}
}

func TestHostStatsStripDimsWhenSamplesFail(t *testing.T) {
	s := newServer(t, "pw")
	c := sessionCookie(t, login(s, "pw", nil, ""))
	s.hostSamples = func(context.Context) hostStats { return hostStats{Err: "stats unavailable"} }
	w := s.do(req{method: "GET", path: "/hoststats", cookies: []*http.Cookie{c}})
	if !strings.Contains(w.Body.String(), "stats unavailable") || !strings.Contains(w.Body.String(), "statstrip") {
		t.Errorf("dim strip: %s", w.Body.String())
	}
}
