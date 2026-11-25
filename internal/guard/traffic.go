package guard

import (
	"context"
	"encoding/json"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/servanago/servanago/internal/trafficdb"
)

// Outcomes a layer reports through the request variable sg_outcome.
const (
	OutPass        = "pass"
	OutBlocked     = "blocked"
	OutBanned      = "banned"
	OutChallenged  = "challenged"
	OutQueued      = "queued"
	OutPayment     = "payment"
	OutRateLimited = "ratelimited"
	OutUnknownHost = "unknown_host"
)

// OutcomeVar is the Caddy request variable the layers set.
const OutcomeVar = "sg_outcome"

// Record is one finished request as the observer sees it.
type Record struct {
	Site, Host, Client, Method, Path, UA, Ref, Err, Outcome string
	Status, Bytes                                           int
	Dur                                                     time.Duration
}

// latBounds are the upper edges, in ms, of the first 19 latency buckets; the 20th is everything above.
var latBounds = [19]int{1, 2, 3, 5, 8, 12, 20, 30, 50, 80, 120, 200, 300, 500, 800, 1200, 2000, 5000, 10000}

const nBuckets = 20

func bucketOf(ms int) int {
	return sort.SearchInts(latBounds[:], ms) // first bound >= ms; len = overflow bucket
}

type counters struct {
	req, s2, s3, s4, s5                       atomic.Uint64
	blocked, challenged, queued, banned, paid atomic.Uint64
	ratelimited, unknown, bytes               atomic.Uint64
	lat                                       [nBuckets]atomic.Uint64
}

// snap is a cumulative reading of counters.
type snap struct {
	ts                                        int64
	req, s2, s3, s4, s5                       uint64
	blocked, challenged, queued, banned, paid uint64
	ratelimited, unknown, bytes               uint64
	lat                                       [nBuckets]uint64
}

func (c *counters) load(ts int64) snap {
	x := snap{ts: ts, req: c.req.Load(), s2: c.s2.Load(), s3: c.s3.Load(), s4: c.s4.Load(), s5: c.s5.Load(),
		blocked: c.blocked.Load(), challenged: c.challenged.Load(), queued: c.queued.Load(), banned: c.banned.Load(), paid: c.paid.Load(),
		ratelimited: c.ratelimited.Load(), unknown: c.unknown.Load(), bytes: c.bytes.Load()}
	for i := range x.lat {
		x.lat[i] = c.lat[i].Load()
	}
	return x
}

func (a snap) sub(b snap) snap {
	d := snap{ts: a.ts, req: a.req - b.req, s2: a.s2 - b.s2, s3: a.s3 - b.s3, s4: a.s4 - b.s4, s5: a.s5 - b.s5,
		blocked: a.blocked - b.blocked, challenged: a.challenged - b.challenged, queued: a.queued - b.queued, banned: a.banned - b.banned, paid: a.paid - b.paid,
		ratelimited: a.ratelimited - b.ratelimited, unknown: a.unknown - b.unknown, bytes: a.bytes - b.bytes}
	for i := range d.lat {
		d.lat[i] = a.lat[i] - b.lat[i]
	}
	return d
}

type siteState struct {
	slug      string
	c         counters
	cfg       atomic.Pointer[SiteCfg]
	auto      atomic.Int64 // under-attack auto mode runs until this unix time
	autoWasOn atomic.Bool
	room      *room

	mu         sync.Mutex
	ring       []snap // one per second, newest last, at most ringLen
	minuteBase snap
	minute     int64
}

const ringLen = 900 // 15 minutes

func (s *Service) site(slug string) *siteState {
	if v, ok := s.sites.Load(slug); ok {
		return v.(*siteState)
	}
	v, _ := s.sites.LoadOrStore(slug, &siteState{slug: slug, room: newRoom()})
	return v.(*siteState)
}

// Register records the site's provision-time settings. Safe to call on every apply.
func (s *Service) Register(c SiteCfg) { s.site(c.Slug).cfg.Store(&c) }

// Observe records one request: counters, the ban feed and the request log. It never blocks.
func (s *Service) Observe(r Record, client clientRef) {
	st := s.site(r.Site)
	c := &st.c
	c.req.Add(1)
	switch r.Status / 100 {
	case 2:
		c.s2.Add(1)
	case 3:
		c.s3.Add(1)
	case 4:
		c.s4.Add(1)
	case 5:
		c.s5.Add(1)
	}
	switch r.Outcome {
	case OutBlocked:
		c.blocked.Add(1)
	case OutChallenged:
		c.challenged.Add(1)
	case OutQueued:
		c.queued.Add(1)
	case OutBanned:
		c.banned.Add(1)
	case OutPayment:
		c.paid.Add(1)
	case OutRateLimited:
		c.ratelimited.Add(1)
	case OutUnknownHost:
		c.unknown.Add(1)
	}
	if r.Bytes > 0 {
		c.bytes.Add(uint64(r.Bytes))
	}
	c.lat[bucketOf(int(r.Dur.Milliseconds()))].Add(1)

	if cfg := st.cfg.Load(); cfg != nil && client.ok {
		if (cfg.BanOn || (cfg.UnknownHost && s.cfg().UnknownHost)) && !inPrefixes(cfg.Allow, client.addr) && countsForBan(r.Outcome) {
			s.Feed(client.addr, r.Site, r.Status)
		}
	}
	if s.db.Load() == nil {
		return
	}
	select {
	case s.logCh <- trafficdb.Row{TS: s.now().Unix(), Site: r.Site, Host: r.Host, Client: r.Client, Method: r.Method, Path: r.Path,
		Status: r.Status, MS: int(r.Dur.Milliseconds()), Bytes: r.Bytes, Outcome: r.Outcome, UA: r.UA, Ref: r.Ref, Err: r.Err}:
	default:
		s.logDropped.Add(1)
	}
}

// countsForBan: answers the guard layers themselves give, and the WAF's own rate-limit 429, never count toward a ban.
func countsForBan(outcome string) bool {
	switch outcome {
	case OutBanned, OutChallenged, OutQueued, OutPayment, OutRateLimited:
		return false
	}
	return true
}

// LogDropped is the number of log rows dropped because the writer fell behind.
func (s *Service) LogDropped() uint64 { return s.logDropped.Load() }

// Tick is the one-second heartbeat: ring snapshot, minute rollup, under-attack evaluation, queue admission.
func (s *Service) Tick(now time.Time) {
	var rollups []trafficdb.Rollup
	s.sites.Range(func(_, v any) bool {
		st := v.(*siteState)
		cur := st.c.load(now.Unix())
		st.mu.Lock()
		st.ring = append(st.ring, cur)
		if len(st.ring) > ringLen {
			st.ring = st.ring[len(st.ring)-ringLen:]
		}
		min := now.Unix() / 60
		if st.minute == 0 {
			st.minute, st.minuteBase = min, cur
		} else if min != st.minute {
			if d := cur.sub(st.minuteBase); d.req > 0 {
				rollups = append(rollups, rollupOf(st.slug, st.minute, d))
			}
			st.minute, st.minuteBase = min, cur
		}
		st.mu.Unlock()
		s.evaluate(st, now)
		st.room.admit(now)
		return true
	})
	if db := s.db.Load(); db != nil && len(rollups) > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := db.PutRollups(ctx, rollups); err != nil {
			slog.Warn("traffic rollup write failed", "error", err)
		}
	}
}

func rollupOf(slug string, minute int64, d snap) trafficdb.Rollup {
	lat, _ := json.Marshal(d.lat[:])
	return trafficdb.Rollup{Site: slug, Minute: minute, Req: int64(d.req), S2: int64(d.s2), S3: int64(d.s3), S4: int64(d.s4), S5: int64(d.s5),
		Blocked: int64(d.blocked), Challenged: int64(d.challenged), Queued: int64(d.queued), Banned: int64(d.banned), Paid: int64(d.paid),
		RateLimited: int64(d.ratelimited), UnknownHost: int64(d.unknown), BytesOut: int64(d.bytes), Lat: string(lat)}
}

// Run drives Tick every second, flushes the request log every 2 s and prunes hourly, until ctx ends.
func (s *Service) Run(ctx context.Context) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var batch []trafficdb.Row
	var lastFlush, lastPrune, lastSweep time.Time
	for {
		select {
		case <-ctx.Done():
			s.flush(batch)
			s.Flush()
			return
		case row := <-s.logCh:
			batch = append(batch, row)
			if len(batch) >= 500 {
				s.flush(batch)
				batch = batch[:0]
			}
		case now := <-tick.C:
			s.Tick(now)
			if now.Sub(lastFlush) >= 2*time.Second && len(batch) > 0 {
				s.flush(batch)
				batch, lastFlush = batch[:0], now
			}
			if now.Sub(lastSweep) >= 30*time.Second {
				s.sweepBans(now)
				lastSweep = now
			}
			if now.Sub(lastPrune) >= time.Hour {
				s.prune(now)
				lastPrune = now
			}
		}
	}
}

func (s *Service) flush(rows []trafficdb.Row) {
	db := s.db.Load()
	if db == nil || len(rows) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.InsertLog(ctx, rows); err != nil {
		slog.Warn("request log write failed", "error", err)
	}
}

func (s *Service) prune(now time.Time) {
	cfg := s.pruneDays.Load()
	if cfg == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if db := s.db.Load(); db != nil {
		if err := db.Prune(ctx, now, cfg[0], cfg[1], 200000); err != nil {
			slog.Warn("traffic prune failed", "error", err)
		}
	}
	if s.bans != nil {
		if err := s.bans.PruneBans(ctx, now.Add(-7*24*time.Hour).Unix()); err != nil {
			slog.Warn("ban prune failed", "error", err)
		}
	}
}

// SetRetention sets the log and rollup retention in days (the settings form's values).
func (s *Service) SetRetention(logDays, rollupDays int) {
	s.pruneDays.Store(&[2]int{logDays, rollupDays})
}

// Stats is a summed window of counters.
type Stats struct {
	Window                                    int // seconds
	Req, S2, S3, S4, S5                       uint64
	Blocked, Challenged, Queued, Banned, Paid uint64
	RateLimited, Unknown, Bytes               uint64
	RPS                                       float64
	P50, P95, P99                             float64 // ms
	lat                                       [nBuckets]uint64
}

func (st *Stats) add(d snap) {
	st.Req += d.req
	st.S2 += d.s2
	st.S3 += d.s3
	st.S4 += d.s4
	st.S5 += d.s5
	st.Blocked += d.blocked
	st.Challenged += d.challenged
	st.Queued += d.queued
	st.Banned += d.banned
	st.Paid += d.paid
	st.RateLimited += d.ratelimited
	st.Unknown += d.unknown
	st.Bytes += d.bytes
	for i := range st.lat {
		st.lat[i] += d.lat[i]
	}
}

func (st *Stats) finish() {
	if st.Window > 0 {
		st.RPS = float64(st.Req) / float64(st.Window)
	}
	st.P50, st.P95, st.P99 = percentile(st.lat, .50), percentile(st.lat, .95), percentile(st.lat, .99)
}

// percentile reads a quantile out of the bucket counts with linear interpolation inside the bucket.
func percentile(b [nBuckets]uint64, q float64) float64 {
	var total uint64
	for _, n := range b {
		total += n
	}
	if total == 0 {
		return 0
	}
	target := q * float64(total)
	var cum float64
	for i, n := range b {
		if n == 0 {
			continue
		}
		if cum+float64(n) >= target {
			lo := 0.0
			if i > 0 {
				lo = float64(latBounds[i-1])
			}
			hi := lo * 2
			if i < len(latBounds) {
				hi = float64(latBounds[i])
			} else if hi == 0 {
				hi = 20000
			}
			return lo + (hi-lo)*(target-cum)/float64(n)
		}
		cum += float64(n)
	}
	return float64(latBounds[len(latBounds)-1])
}

// Live sums the last `seconds` seconds (at most 15 minutes) of one site, or of every site when slug is "".
func (s *Service) Live(slug string, seconds int) Stats {
	if seconds < 1 {
		seconds = 1
	}
	if seconds > ringLen-1 {
		seconds = ringLen - 1
	}
	out := Stats{Window: seconds}
	s.sites.Range(func(_, v any) bool {
		st := v.(*siteState)
		if slug != "" && st.slug != slug {
			return true
		}
		cur := st.c.load(s.now().Unix())
		st.mu.Lock()
		base := snap{}
		if n := len(st.ring); n > seconds {
			base = st.ring[n-1-seconds]
		}
		st.mu.Unlock()
		out.add(cur.sub(base))
		return true
	})
	out.finish()
	return out
}

// Series is the request count per bin over the last bins*binSeconds seconds, oldest first (sparkline data).
func (s *Service) Series(slug string, bins, binSeconds int) []uint64 {
	out := make([]uint64, bins)
	s.sites.Range(func(_, v any) bool {
		st := v.(*siteState)
		if slug != "" && st.slug != slug {
			return true
		}
		st.mu.Lock()
		defer st.mu.Unlock()
		n := len(st.ring)
		for b := 0; b < bins; b++ {
			hiIdx, loIdx := n-1-(bins-1-b)*binSeconds, n-1-(bins-b)*binSeconds
			if hiIdx < 0 || hiIdx >= n {
				continue
			}
			lo := uint64(0)
			if loIdx >= 0 {
				lo = st.ring[loIdx].req
			}
			out[b] += st.ring[hiIdx].req - lo
		}
		return true
	})
	return out
}

// Sites lists the slugs the service has seen.
func (s *Service) Sites() []string {
	var out []string
	s.sites.Range(func(k, _ any) bool { out = append(out, k.(string)); return true })
	sort.Strings(out)
	return out
}

// Aggregate sums stored rollups into Stats; window is the range length in seconds.
func Aggregate(rs []trafficdb.Rollup, window int) Stats {
	st := Stats{Window: window}
	for _, r := range rs {
		d := snap{req: uint64(r.Req), s2: uint64(r.S2), s3: uint64(r.S3), s4: uint64(r.S4), s5: uint64(r.S5), blocked: uint64(r.Blocked),
			challenged: uint64(r.Challenged), queued: uint64(r.Queued), banned: uint64(r.Banned), paid: uint64(r.Paid),
			ratelimited: uint64(r.RateLimited), unknown: uint64(r.UnknownHost), bytes: uint64(r.BytesOut)}
		var lat []uint64
		if json.Unmarshal([]byte(r.Lat), &lat) == nil {
			for i := 0; i < len(lat) && i < nBuckets; i++ {
				d.lat[i] = lat[i]
			}
		}
		st.add(d)
	}
	st.finish()
	return st
}

// Flush writes every queued request-log row now (Run does it every two seconds; shutdown and tests call it).
func (s *Service) Flush() {
	var batch []trafficdb.Row
	for {
		select {
		case row := <-s.logCh:
			batch = append(batch, row)
			continue
		default:
		}
		break
	}
	s.flush(batch)
}
