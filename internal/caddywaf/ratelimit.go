package caddywaf

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RateLimit is the site's per-IP rate limit as rendered into the waf handler JSON:
//
//	{"rate_limit":{"requests":120,"window_ms":300000,"paths":["/login"]}}
type RateLimit struct {
	Requests int64    `json:"requests"`
	WindowMS int64    `json:"window_ms"`
	Paths    []string `json:"paths,omitempty"`
}

// maxRateEntries bounds the key table so a flood of unique addresses cannot grow the
// map without bound; past it, expired keys drop first and then untracked keys are admitted
// without counting.
const maxRateEntries = 1_000_000

type rateEntry struct {
	// count carries the request count of the window that started at start.
	count int64
	start time.Time
	// limitedAt is set once an address exceeded the limit this window, so the UI can
	// show which clients were refused (the per-IP window table of the mock).
	limitedAt time.Time
}

// rateLimiter counts requests per client IP (per scoped path) over one fixed window.
// ponytail: fixed window, in-process, no cross-server state — matches the panel's
// one-process Caddy.
type rateLimiter struct {
	mu       sync.Mutex
	requests int64
	window   time.Duration
	paths    []string // empty = the whole site; otherwise path prefixes
	entries  map[string]*rateEntry
}

func newRateLimiter(cfg RateLimit) *rateLimiter {
	return &rateLimiter{
		requests: cfg.Requests,
		window:   time.Duration(cfg.WindowMS) * time.Millisecond,
		paths:    cfg.Paths,
		entries:  make(map[string]*rateEntry),
	}
}

// allow records one request and reports whether it passes, with the wait for the
// window to reset when it does not. The budget is per client IP: the path scope only
// narrows what gets counted, so one address cannot spread its budget across child paths.
func (rl *rateLimiter) allow(ip, path string) (ok bool, wait time.Duration, limitedTime time.Time) {
	if len(rl.paths) > 0 && !rl.pathMatches(path) {
		return true, 0, time.Time{} // outside the scope: not counted, not limited
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()

	e, tracked := rl.entries[ip]
	if tracked && now.Sub(e.start) >= rl.window {
		e.count, e.start, e.limitedAt = 0, now, time.Time{} // window reset, same key
	}
	if !tracked {
		// Bound the table: drop expired keys first; past the cap still, admit
		// without tracking (the address is not limited by this instance).
		if len(rl.entries) >= maxRateEntries {
			rl.pruneExpired(now)
		}
		if len(rl.entries) >= maxRateEntries {
			return true, 0, time.Time{}
		}
		e = &rateEntry{start: now}
		rl.entries[ip] = e
	}

	e.count++
	if e.count > rl.requests {
		e.limitedAt = now
		return false, rl.window - now.Sub(e.start), e.limitedAt
	}
	return true, 0, time.Time{}
}

func (rl *rateLimiter) pathMatches(path string) bool {
	for _, p := range rl.paths {
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}

func (rl *rateLimiter) pruneExpired(now time.Time) {
	for k, e := range rl.entries {
		if now.Sub(e.start) >= rl.window {
			delete(rl.entries, k)
		}
	}
}

// snapshot returns the client IPs of the current window with their counts, so the tab's
// per-address table can show who is at the limit.
func (rl *rateLimiter) snapshot(now time.Time) []RateEntrySnapshot {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	out := make([]RateEntrySnapshot, 0, len(rl.entries))
	for ip, e := range rl.entries {
		if now.Sub(e.start) >= rl.window {
			continue // expired: not part of the current window
		}
		out = append(out, RateEntrySnapshot{IP: ip, Count: e.count, Limited: e.count > rl.requests, LimitedAt: e.limitedAt})
	}
	return out
}

// RateEntrySnapshot is one row of the rate limit state panel.
type RateEntrySnapshot struct {
	IP        string    `json:"ip"`
	Count     int64     `json:"count"`
	Limited   bool      `json:"limited"`
	LimitedAt time.Time `json:"limited_at,omitempty"`
}

// ServeRateLimit answers 429 for an over-the-limit request; the body matches the mock.
func (m *Middleware) serveRateLimit(w http.ResponseWriter, r *http.Request) bool {
	if m.limiter == nil {
		return false
	}
	ip, _ := clientAddress(r)
	ok, wait, _ := m.limiter.allow(ip, r.URL.Path)
	if ok {
		return false
	}
	retry := int(wait.Seconds() + 0.5)
	if retry < 1 {
		retry = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(retry))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusTooManyRequests)
	_, _ = w.Write([]byte("Too many requests. Wait the window out and try again.\n"))
	return true
}
