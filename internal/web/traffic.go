package web

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/servanago/servanago/internal/guard"
	"github.com/servanago/servanago/internal/store"
	"github.com/servanago/servanago/internal/trafficdb"
)

func init() {
	helpFuncs["spark"] = sparkline
	helpFuncs["pct"] = func(part, total uint64) string {
		if total == 0 {
			return "0"
		}
		return strconv.FormatFloat(float64(part)*100/float64(total), 'f', 1, 64)
	}
	helpFuncs["ms"] = func(v float64) string {
		if v >= 1000 {
			return strconv.FormatFloat(v/1000, 'f', 1, 64) + " s"
		}
		return strconv.FormatFloat(v, 'f', 0, 64) + " ms"
	}
	helpFuncs["bar"] = statusBar
	helpFuncs["ubytes"] = func(n uint64) string { return humanBytes(int64(n)) }
}

// sparkline is a server-rendered inline SVG of the series: no script, light and dark through currentColor.
func sparkline(vals []uint64) template.HTML {
	const w, h = 240.0, 40.0
	var max uint64 = 1
	for _, v := range vals {
		if v > max {
			max = v
		}
	}
	var pts strings.Builder
	for i, v := range vals {
		x := 0.0
		if len(vals) > 1 {
			x = w * float64(i) / float64(len(vals)-1)
		}
		fmt.Fprintf(&pts, "%.1f,%.1f ", x, h-2-(h-4)*float64(v)/float64(max))
	}
	return template.HTML(fmt.Sprintf(`<svg class="spark" viewBox="0 0 %.0f %.0f" width="%.0f" height="%.0f" role="img" aria-label="Requests over time, peak %d per interval"><polyline fill="none" stroke="currentColor" stroke-width="1.5" points="%s"/></svg>`, w, h, w, h, max, pts.String())) // #nosec: numbers only
}

// statusBar is the 2xx/3xx/4xx/5xx split as one inline SVG bar.
func statusBar(s guard.Stats) template.HTML {
	total := float64(s.S2 + s.S3 + s.S4 + s.S5)
	if total == 0 {
		return template.HTML(`<svg class="bar" viewBox="0 0 100 8" width="240" height="12" role="img" aria-label="No requests"><rect width="100" height="8" fill="currentColor" opacity=".12"/></svg>`)
	}
	var b strings.Builder
	b.WriteString(`<svg class="bar" viewBox="0 0 100 8" width="240" height="12" role="img" aria-label="Status classes">`)
	x := 0.0
	for _, seg := range []struct {
		n     uint64
		color string
	}{{s.S2, "var(--sg-ok, #0d9b49)"}, {s.S3, "var(--sg-info, #3b82f6)"}, {s.S4, "var(--sg-warn, #d97706)"}, {s.S5, "var(--sg-bad, #dc2626)"}} {
		w := float64(seg.n) * 100 / total
		fmt.Fprintf(&b, `<rect x="%.2f" width="%.2f" height="8" fill="%s"/>`, x, w, seg.color)
		x += w
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String()) // #nosec: numbers and fixed colors only
}

type trafficRange struct {
	Key, Label string
	Dur        time.Duration
}

var trafficRanges = []trafficRange{{"live", "Live", 0}, {"1h", "1 hour", time.Hour}, {"24h", "24 hours", 24 * time.Hour}, {"7d", "7 days", 7 * 24 * time.Hour}, {"90d", "90 days", 90 * 24 * time.Hour}}

type siteOpt struct{ Slug, Name string }

type trafficData struct {
	Sites       []siteOpt
	Site, Range string
	Ranges      []trafficRange
	Snap        trafficSnap
	Rows        []trafficdb.Row
	Filter      trafficFilter
	Degraded    bool
}

type trafficFilter struct{ Client, Outcome, Path, Status string }

type trafficSnap struct {
	Site, Range string
	Live        bool
	Stats       guard.Stats
	Series      []uint64
	Bans        int
	Queue       guard.QueueStats
	QueueOn     bool
	UnderAttack bool
	Dropped     uint64
	NoData      bool
}

func (s *Server) trafficSites(r *http.Request) []siteOpt {
	var out []siteOpt
	if all, err := s.deps.Store.ListSites(r.Context()); err == nil {
		for _, x := range all {
			out = append(out, siteOpt{x.Slug, x.Hostnames[0]})
		}
	}
	return out
}

func rangeOf(key string) trafficRange {
	for _, x := range trafficRanges {
		if x.Key == key {
			return x
		}
	}
	return trafficRanges[0]
}

func (s *Server) snapshot(ctx context.Context, slug, rangeKey string) trafficSnap {
	rg := rangeOf(rangeKey)
	sn := trafficSnap{Site: slug, Range: rg.Key, Live: rg.Dur == 0}
	g := s.deps.Guard
	if g == nil {
		sn.NoData = true
		return sn
	}
	sn.Bans = g.ActiveCount()
	if slug != "" {
		sn.Queue = g.QueueStats(slug)
		sn.UnderAttack = g.AutoActive(slug)
		if rt, err := s.siteBySlug(ctx, slug); err == nil && rt.Guard != nil {
			sn.QueueOn = rt.Guard.QOn
			sn.UnderAttack = sn.UnderAttack || rt.Guard.UAMode == "on"
		}
	}
	sn.Dropped = g.LogDropped()
	if sn.Live {
		sn.Stats = g.Live(slug, 60)
		sn.Series = g.Series(slug, 60, 15) // 15 minutes in 15-second bins
		return sn
	}
	if s.deps.Traffic == nil {
		sn.NoData = true
		return sn
	}
	from := time.Now().Add(-rg.Dur).Unix() / 60
	rs, err := s.deps.Traffic.RollupsSince(ctx, slug, slug == "", from)
	if err != nil {
		sn.NoData = true
		return sn
	}
	sn.Stats = guard.Aggregate(rs, int(rg.Dur/time.Second))
	bins := make([]uint64, 60)
	for _, x := range rs {
		i := int((x.Minute - from) * 60 / int64(rg.Dur/time.Minute))
		if i >= 0 && i < 60 {
			bins[i] += uint64(x.Req)
		}
	}
	sn.Series = bins
	return sn
}

func (s *Server) siteBySlug(ctx context.Context, slug string) (store.Site, error) {
	all, err := s.deps.Store.ListSites(ctx)
	if err != nil {
		return store.Site{}, err
	}
	for _, x := range all {
		if x.Slug == slug {
			return x, nil
		}
	}
	return store.Site{}, fmt.Errorf("no site %q", slug)
}

func filterOf(r *http.Request) (trafficdb.Filter, trafficFilter) {
	q := r.URL.Query()
	tf := trafficFilter{Client: strings.TrimSpace(q.Get("client")), Outcome: q.Get("outcome"), Path: strings.TrimSpace(q.Get("path")), Status: q.Get("status")}
	f := trafficdb.Filter{Site: q.Get("site"), Client: tf.Client, Outcome: tf.Outcome, Path: tf.Path, ErrOnly: q.Get("errs") != ""}
	if n, err := strconv.Atoi(tf.Status); err == nil && n >= 100 && n < 600 {
		f.Status = n
	}
	if rg := rangeOf(q.Get("range")); rg.Dur > 0 {
		f.Since = time.Now().Add(-rg.Dur).Unix()
	}
	return f, tf
}

func (s *Server) trafficPage(w http.ResponseWriter, r *http.Request) {
	f, tf := filterOf(r)
	rg := rangeOf(r.URL.Query().Get("range"))
	d := trafficData{Sites: s.trafficSites(r), Site: f.Site, Range: rg.Key, Ranges: trafficRanges, Filter: tf, Degraded: s.deps.Traffic == nil}
	d.Snap = s.snapshot(r.Context(), f.Site, rg.Key)
	f.Limit = 100
	if s.deps.Traffic != nil {
		d.Rows, _ = s.deps.Traffic.List(r.Context(), f)
	}
	s.render(w, "traffic", http.StatusOK, page{Title: "Traffic", Nav: "traffic", Data: d})
}

// trafficSnapshot is the polled fragment: counters, percentiles and sparkline, no page chrome.
func (s *Server) trafficSnapshot(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	sn := s.snapshot(r.Context(), q.Get("site"), q.Get("range"))
	var b bytes.Buffer
	if err := s.pages["traffic"].ExecuteTemplate(&b, "trafficsnap", sn); err != nil {
		fail(w, http.StatusInternalServerError, "The snapshot failed to render; the error is in the ServanaGo log.")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = b.WriteTo(w)
}

func (s *Server) trafficRows(w http.ResponseWriter, r *http.Request) {
	f, _ := filterOf(r)
	f.Limit = 100
	var rows []trafficdb.Row
	if s.deps.Traffic != nil {
		rows, _ = s.deps.Traffic.List(r.Context(), f)
	}
	var b bytes.Buffer
	if err := s.pages["traffic"].ExecuteTemplate(&b, "trafficrows", rows); err != nil {
		fail(w, http.StatusInternalServerError, "The rows failed to render; the error is in the ServanaGo log.")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = b.WriteTo(w)
}

// trafficExport streams the filtered log as CSV (or JSON lines with format=json), at most 100,000 rows.
func (s *Server) trafficExport(w http.ResponseWriter, r *http.Request) {
	if s.deps.Traffic == nil {
		fail(w, http.StatusServiceUnavailable, "The request log is unavailable (traffic.db could not be opened).")
		return
	}
	f, _ := filterOf(r)
	f.Limit = 100000
	rows, err := s.deps.Traffic.List(r.Context(), f)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	if r.URL.Query().Get("format") == "json" {
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Content-Disposition", `attachment; filename="requests.jsonl"`)
		enc := json.NewEncoder(w)
		for _, x := range rows {
			_ = enc.Encode(rowOut(x))
		}
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="requests.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"time", "site", "host", "client", "method", "path", "status", "ms", "bytes", "outcome", "user_agent", "referrer", "error"})
	for _, x := range rows {
		_ = cw.Write([]string{time.Unix(x.TS, 0).UTC().Format(time.RFC3339), x.Site, x.Host, x.Client, x.Method, csvSafe(x.Path), strconv.Itoa(x.Status),
			strconv.Itoa(x.MS), strconv.Itoa(x.Bytes), x.Outcome, csvSafe(x.UA), x.Ref, csvSafe(x.Err)})
	}
	cw.Flush()
}

// csvSafe neutralizes spreadsheet formula injection: a cell that starts with =, +, - or @ gets a leading quote.
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

type requestOut struct {
	Time    string `json:"time"`
	Site    string `json:"site"`
	Host    string `json:"host"`
	Client  string `json:"client"`
	Method  string `json:"method"`
	Path    string `json:"path"`
	Status  int    `json:"status"`
	MS      int    `json:"ms"`
	Bytes   int    `json:"bytes"`
	Outcome string `json:"outcome"`
	UA      string `json:"user_agent,omitempty"`
	Ref     string `json:"referrer,omitempty"`
	Err     string `json:"error,omitempty"`
}

func rowOut(x trafficdb.Row) requestOut {
	return requestOut{time.Unix(x.TS, 0).UTC().Format(time.RFC3339), x.Site, x.Host, x.Client, x.Method, x.Path, x.Status, x.MS, x.Bytes, x.Outcome, x.UA, x.Ref, x.Err}
}

func init() { helpFuncs["list"] = func(v ...string) []string { return v } }
