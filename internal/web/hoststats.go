package web

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// hoststats.go: the dashboard's server stats strip (memory, swap, CPU, disk). The panel user
// reads /proc and statfs directly; nothing here needs root or the helper. Sizes are bytes;
// the template renders them with humanBytes.

type statPair struct {
	Total, Used int64
	Pct         int // 0..100; 0 when the size is unknown
}

type diskStat struct {
	Path        string
	Total, Used int64
	Pct         int
}

type hostStats struct {
	Mem, Swap            statPair
	SwapOn               bool // false: the template shows "no swap" instead of a zeroed meter
	CPU                  int  // busy percent, sampled over cpuSampleWindow
	Load1, Load5, Load15 float64
	Disks                []diskStat
	Err                  string // reads failed; the strip renders dim with this message
}

// cpuSampleWindow is the two-snapshot window the CPU percent is measured over.
const cpuSampleWindow = time.Second

// procRead is the seam tests use instead of the real /proc.
var procRead = os.ReadFile

func pairPct(total, used int64) int {
	if total <= 0 || used < 0 {
		return 0
	}
	return int(100 * used / total)
}

// parseMeminfo reads MemTotal/MemAvailable/SwapTotal/SwapFree out of meminfo content.
// Values are kB in the file, bytes here.
func parseMeminfo(b []byte) (mem, swap statPair) {
	sum := map[string]int64{}
	for _, line := range strings.Split(string(b), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		fields := strings.Fields(value)
		if len(fields) == 0 {
			continue
		}
		n, err := strconv.ParseInt(fields[0], 10, 64)
		if err != nil {
			continue
		}
		sum[key] = n * 1024
	}
	mem.Total = sum["MemTotal"]
	mem.Used = sum["MemTotal"] - sum["MemAvailable"]
	mem.Pct = pairPct(mem.Total, mem.Used)
	swap.Total = sum["SwapTotal"]
	swap.Used = sum["SwapTotal"] - sum["SwapFree"]
	swap.Pct = pairPct(swap.Total, swap.Used)
	return mem, swap
}

// parseLoadavg returns the 1, 5 and 15 minute load averages.
func parseLoadavg(b []byte) (l1, l5, l15 float64) {
	fs := strings.Fields(string(b))
	if len(fs) < 3 {
		return 0, 0, 0
	}
	var f [3]float64
	for i := 0; i < 3; i++ {
		f[i], _ = strconv.ParseFloat(fs[i], 64)
	}
	return f[0], f[1], f[2]
}

// cpuBusy is the busy percentage between the first "cpu" lines of two /proc/stat snapshots.
// A snapshot reads user nice system idle iowait ... in jiffies; busy = total - idle - iowait.
func cpuBusy(a, b []byte) int {
	snapshot := func(b []byte) (idle, total float64, ok bool) {
		line, _, _ := bytes.Cut(b, []byte("\n"))
		fs := strings.Fields(string(line))
		if len(fs) < 5 || fs[0] != "cpu" {
			return 0, 0, false
		}
		for i, f := range fs[1:] {
			n, err := strconv.ParseFloat(f, 64)
			if err != nil {
				return 0, 0, false
			}
			total += n
			if i == 3 || i == 4 { // iowait, idle
				idle += n
			}
		}
		return idle, total, true
	}
	i0, t0, ok0 := snapshot(a)
	i1, t1, ok1 := snapshot(b)
	if !ok0 || !ok1 || t1 <= t0 {
		return 0
	}
	total := t1 - t0
	idle := i1 - i0
	return int((100 * (total - idle)) / total)
}

// statdev is the device id backing path (0 when it cannot be statted; no real filesystem
// reports 0), used to skip several paths on one filesystem.
func statdev(path string) uint64 {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return 0
	}
	return st.Dev
}

func statdisk(path string) (diskStat, error) {
	var fs syscall.Statfs_t
	if err := syscall.Statfs(path, &fs); err != nil {
		return diskStat{}, err
	}
	st := diskStat{
		Path:  path,
		Total: int64(fs.Bsize) * int64(fs.Blocks),
		Used:  int64(fs.Bsize) * (int64(fs.Blocks) - int64(fs.Bavail)), // what df reports; reserved blocks aside
	}
	st.Pct = pairPct(st.Total, st.Used)
	return st, nil
}

// hostStatsData samples the running host once. roots are site paths whose distinct
// filesystems are reported after dataDir's; a path that cannot be statted is skipped — its
// own site row already flags the problem.
func hostStatsData(ctx context.Context, dataDir string, roots []string) hostStats {
	st := hostStats{}
	memRaw, err := procRead("/proc/meminfo")
	if err != nil {
		st.Err = "stats unavailable"
		return st
	}
	avgRaw, err := procRead("/proc/loadavg")
	if err != nil {
		st.Err = "stats unavailable"
		return st
	}
	st.Mem, st.Swap = parseMeminfo(memRaw)
	st.SwapOn = st.Swap.Total > 0
	st.Load1, st.Load5, st.Load15 = parseLoadavg(avgRaw)
	if a, err := procRead("/proc/stat"); err == nil {
		select {
		case <-ctx.Done():
			return st
		case <-time.After(cpuSampleWindow):
		}
		if b, err := procRead("/proc/stat"); err == nil {
			st.CPU = cpuBusy(a, b)
		}
	}
	seen := map[uint64]bool{}
	for _, p := range append([]string{dataDir}, roots...) {
		dev := statdev(p)
		if dev == 0 || seen[dev] {
			continue
		}
		seen[dev] = true
		if ds, err := statdisk(p); err == nil {
			st.Disks = append(st.Disks, ds)
		}
	}
	sort.Slice(st.Disks, func(i, j int) bool { return st.Disks[i].Path < st.Disks[j].Path })
	return st
}

// realHostStats samples /proc and the filesystems backing DATA_DIR and the static roots.
func (s *Server) realHostStats(ctx context.Context) hostStats {
	sites, err := s.deps.Store.ListSites(ctx)
	if err != nil {
		return hostStats{Err: "stats unavailable"}
	}
	var roots []string
	for _, site := range sites {
		if site.StaticRoot != "" {
			roots = append(roots, site.StaticRoot)
		}
	}
	return hostStatsData(ctx, s.deps.Cfg.DataDir, roots)
}

// hostStatsPanel renders just the strip; the dashboard polls it every 30s.
func (s *Server) hostStatsPanel(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.pages["dashboard"].ExecuteTemplate(w, "hoststats", s.hostSamples(r.Context())); err != nil {
		slog.Error("render hoststats", "error", err)
	}
}
