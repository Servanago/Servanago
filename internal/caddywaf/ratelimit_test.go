// SPDX-License-Identifier: Apache-2.0

package caddywaf

import (
	"testing"
	"time"
)

func newTestLimiter(requests int64, window time.Duration, paths ...string) *rateLimiter {
	return newRateLimiter(RateLimit{Requests: requests, WindowMS: window.Milliseconds(), Paths: paths})
}

func TestRateLimiterBlocksOverTheWindow(t *testing.T) {
	rl := newTestLimiter(2, 100*time.Millisecond)
	for i := 0; i < 2; i++ {
		if ok, _, _ := rl.allow("203.0.113.1", "/"); !ok {
			t.Fatalf("request %d refused early", i+1)
		}
	}
	ok, wait, _ := rl.allow("203.0.113.1", "/")
	if ok {
		t.Fatal("third request not limited")
	}
	if wait <= 0 || wait > 100*time.Millisecond {
		t.Errorf("wait %v outside the window", wait)
	}
	// another address is unaffected
	if ok, _, _ := rl.allow("203.0.113.2", "/"); !ok {
		t.Error("second address limited alongside the first")
	}
	// the window passes and the counter resets
	time.Sleep(120 * time.Millisecond)
	if ok, _, _ := rl.allow("203.0.113.1", "/"); !ok {
		t.Error("request refused after the window reset")
	}
}

func TestRateLimiterPathScope(t *testing.T) {
	rl := newTestLimiter(1, 100*time.Millisecond, "/login")
	if ok, _, _ := rl.allow("203.0.113.1", "/login"); !ok {
		t.Fatal("first login refused")
	}
	if ok, _, _ := rl.allow("203.0.113.1", "/login"); ok {
		t.Error("second login allowed within the window")
	}
	if ok, _, _ := rl.allow("203.0.113.1", "/"); !ok {
		t.Error("the whole site was limited; scope is the named prefixes only")
	}
	if ok, _, _ := rl.allow("203.0.113.1", "/login/2fa"); ok {
		t.Error("a child of a scoped path escaped the limit")
	}
}

func TestRateLimiterSnapshotMarksLimited(t *testing.T) {
	rl := newTestLimiter(1, time.Minute)
	_, _, _ = rl.allow("203.0.113.9", "/")
	if ok, _, _ := rl.allow("203.0.113.71", "/"); !ok {
		t.Fatal("first request of the limit address refused")
	}
	_, _, limitedAt := rl.allow("203.0.113.71", "/")
	rows := rl.snapshot(time.Now())
	if len(rows) != 2 {
		t.Fatalf("snapshot rows %d", len(rows))
	}
	byIP := map[string]RateEntrySnapshot{}
	for _, r := range rows {
		byIP[r.IP] = r
	}
	if byIP["203.0.113.71"].Count != 2 || !byIP["203.0.113.71"].Limited || byIP["203.0.113.71"].LimitedAt != limitedAt {
		t.Errorf("limited client wrong: %+v", byIP["203.0.113.71"])
	}
	if byIP["203.0.113.9"].Limited {
		t.Errorf("clean client marked limited: %+v", byIP["203.0.113.9"])
	}
}

// The table must stay bounded when a flood of unique addresses walks the site.
func TestRateLimiterBoundsTheTable(t *testing.T) {
	rl := newTestLimiter(10, time.Minute)
	for i := 0; i < 1_050_000; i++ {
		rl.allow("10.0."+string(rune('a'+i%26)), "/x") // keys capped by pruneExpired, not unbounded
		if len(rl.entries) > maxRateEntries+1 {
			t.Fatalf("entry table grew past the cap: %d", len(rl.entries))
		}
	}
}
