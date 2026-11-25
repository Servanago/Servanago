package guard

import (
	"context"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/servanago/servanago/internal/store"
)

type fakeBans struct {
	mu   sync.Mutex
	rows map[string]store.Ban
}

func (f *fakeBans) UpsertBan(_ context.Context, b store.Ban) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.rows == nil {
		f.rows = map[string]store.Ban{}
	}
	f.rows[b.Client] = b
	return nil
}
func (f *fakeBans) DeleteBan(_ context.Context, c string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.rows, c)
	return nil
}
func (f *fakeBans) ListBans(context.Context, int64) ([]store.Ban, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []store.Ban
	for _, b := range f.rows {
		out = append(out, b)
	}
	return out, nil
}
func (f *fakeBans) PruneBans(context.Context, int64) error { return nil }

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newSvc(t *testing.T) (*Service, *clock) {
	t.Helper()
	s := New("test-secret-key-test-secret-key-0123", &fakeBans{})
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	s.Now = c.now
	return s, c
}

func TestBanTripsAtThresholdAndEscalates(t *testing.T) {
	s, c := newSvc(t)
	var alerts []Event
	s.OnAlert = func(e Event) { alerts = append(alerts, e) }
	a := netip.MustParseAddr("203.0.113.9")
	for i := 0; i < 19; i++ {
		s.Feed(a, "site", 403)
	}
	if s.Banned(Key(a)) {
		t.Fatal("banned below the threshold")
	}
	s.Feed(a, "site", 403)
	if !s.Banned(Key(a)) {
		t.Fatal("not banned at the threshold")
	}
	if len(alerts) != 1 || alerts[0].Kind != "ban" {
		t.Errorf("alerts %+v", alerts)
	}
	c.t = c.t.Add(16 * time.Minute) // level 1 (15 min) expired
	if s.Banned(Key(a)) {
		t.Fatal("ban outlived its 15 minutes")
	}
	for i := 0; i < 20; i++ {
		s.Feed(a, "site", 401)
	}
	v, _ := s.active.Load(Key(a))
	if v.(banInfo).level != 2 || v.(banInfo).until-c.t.Unix() != 3600 {
		t.Errorf("second ban should be level 2 for an hour: %+v", v)
	}
}

func TestBanIgnoresOtherCodesExemptAndRateLimited(t *testing.T) {
	s, _ := newSvc(t)
	a := netip.MustParseAddr("203.0.113.10")
	for i := 0; i < 50; i++ {
		s.Feed(a, "site", 404) // not in the default code list
	}
	if s.Banned(Key(a)) {
		t.Error("404 counted")
	}
	s.SetSettings(store.GuardSettings{BanCodes: "403", BanThreshold: 2, BanWindowS: 60, BanExempt: "198.51.100.0/24"})
	ex := netip.MustParseAddr("198.51.100.7")
	for i := 0; i < 5; i++ {
		s.Feed(ex, "site", 403)
	}
	if s.Banned(Key(ex)) {
		t.Error("exempt address banned")
	}
	// the observer filter: guard answers and the WAF's own 429 never count
	s.site("site").cfg.Store(&SiteCfg{Slug: "site", BanOn: true})
	b := netip.MustParseAddr("203.0.113.11")
	for i := 0; i < 5; i++ {
		s.Observe(Record{Site: "site", Status: 403, Outcome: OutChallenged}, ClientRef(b, true))
	}
	if s.Banned(Key(b)) {
		t.Error("a challenge page counted toward a ban")
	}
	for i := 0; i < 2; i++ {
		s.Observe(Record{Site: "site", Status: 403, Outcome: OutPass}, ClientRef(b, true))
	}
	if !s.Banned(Key(b)) {
		t.Error("real 403s did not ban")
	}
	// a Cloudflare node or private peer is never judged
	p := netip.MustParseAddr("10.0.0.1")
	for i := 0; i < 5; i++ {
		s.Observe(Record{Site: "site", Status: 403, Outcome: OutPass}, ClientRef(p, false))
	}
	if s.Banned(Key(p)) {
		t.Error("unjudgeable peer banned")
	}
}

func TestKeyIPv6IsSlash64AndParseClient(t *testing.T) {
	if got := Key(netip.MustParseAddr("2001:db8:1:2:aaaa:bbbb:cccc:dddd")); got != "2001:db8:1:2::/64" {
		t.Errorf("key %q", got)
	}
	if k, err := ParseClient("2001:db8:1:2::/64"); err != nil || k != "2001:db8:1:2::/64" {
		t.Errorf("parse /64: %q %v", k, err)
	}
	if _, err := ParseClient("10.0.0.0/8"); err == nil {
		t.Error("a /8 was accepted as a client")
	}
	s, _ := newSvc(t)
	if _, err := s.Ban("203.0.113.5", "", "admin", "x", 0); err == nil {
		t.Error("a manual ban without a duration")
	}
	if _, err := s.Ban("203.0.113.5", "", "admin", "x", time.Hour); err != nil || !s.Banned("203.0.113.5") {
		t.Error("manual ban failed")
	}
	_ = s.Unban("203.0.113.5")
	if s.Banned("203.0.113.5") {
		t.Error("unban failed")
	}
}

func solve(salt string, bits int) string {
	for n := 0; ; n++ {
		if leadingZeroBits(sum(salt+strconv.Itoa(n))) >= bits {
			return strconv.Itoa(n)
		}
	}
}

func TestPuzzleVerifyRejectsTamperAndExpiry(t *testing.T) {
	s, c := newSvc(t)
	p := s.NewPuzzle("site", "1.2.3.4", 10)
	n := solve(p.Salt, p.Bits)
	if err := s.CheckPuzzle("site", "1.2.3.4", p, n); err != nil {
		t.Fatalf("valid solution rejected: %v", err)
	}
	if s.CheckPuzzle("site", "1.2.3.4", p, "0") == nil && leadingZeroBits(sum(p.Salt+"0")) < p.Bits {
		t.Error("wrong counter accepted")
	}
	if s.CheckPuzzle("other", "1.2.3.4", p, n) == nil {
		t.Error("a puzzle for one site solved another")
	}
	if s.CheckPuzzle("site", "9.9.9.9", p, n) == nil {
		t.Error("a puzzle for one client solved another")
	}
	weak := p
	weak.Bits = 1
	if s.CheckPuzzle("site", "1.2.3.4", weak, n) == nil {
		t.Error("lowered difficulty accepted")
	}
	c.t = c.t.Add(3 * time.Minute)
	if s.CheckPuzzle("site", "1.2.3.4", p, n) == nil {
		t.Error("expired puzzle accepted")
	}
}

func TestChallengeRoundTripAndPass(t *testing.T) {
	s, _ := newSvc(t)
	cfg := ChallengeCfg{Slug: "site", Forced: true, Kind: "pow", Difficulty: "low", TTLMin: 5}
	// no cookie: 403 page
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/secret?x=1", nil)
	if !s.Challenge(rec, req, cfg, "1.2.3.4", netip.Addr{}, false) || rec.Code != 403 || rec.Header().Get("X-ServanaGo-Challenge") != "pow" {
		t.Fatalf("challenge page: %d %v", rec.Code, rec.Header())
	}
	// panel paths and ACME pass
	for _, p := range []string{"/.well-known/acme-challenge/x", "/__servanago/queue/status"} {
		if s.Challenge(httptest.NewRecorder(), httptest.NewRequest("GET", p, nil), cfg, "1.2.3.4", netip.Addr{}, false) {
			t.Errorf("%s was challenged", p)
		}
	}
	// solve and post; use a low-bit puzzle for speed
	p := s.NewPuzzle("site", "1.2.3.4", 10)
	form := "salt=" + p.Salt + "&bits=10&ts=" + strconv.FormatInt(p.TS, 10) + "&sig=" + p.Sig + "&counter=" + solve(p.Salt, 10) + "&return=//evil.example"
	post := httptest.NewRequest("POST", ChallengePath, strings.NewReader(form))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	if !s.Challenge(rec, post, cfg, "1.2.3.4", netip.Addr{}, false) || rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" {
		t.Fatalf("solve: %d %q (open redirect must collapse to /)", rec.Code, rec.Header().Get("Location"))
	}
	cookie := rec.Result().Cookies()[0]
	again := httptest.NewRequest("GET", "/secret", nil)
	again.AddCookie(cookie)
	if s.Challenge(httptest.NewRecorder(), again, cfg, "1.2.3.4", netip.Addr{}, false) {
		t.Error("a valid pass was challenged again")
	}
	other := httptest.NewRequest("GET", "/secret", nil)
	other.AddCookie(cookie)
	if !s.Challenge(httptest.NewRecorder(), other, cfg, "5.6.7.8", netip.Addr{}, false) {
		t.Error("a pass cookie worked from another address")
	}
	// the allowlist skips the challenge
	cfg.Allow = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
	if s.Challenge(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil), cfg, "203.0.113.4", netip.MustParseAddr("203.0.113.4"), true) {
		t.Error("allowlisted address challenged")
	}
	// off: nothing happens
	cfg = ChallengeCfg{Slug: "site", Auto: true}
	if s.Challenge(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil), cfg, "1.2.3.4", netip.Addr{}, false) {
		t.Error("auto mode challenged while calm")
	}
}

func TestSafeReturn(t *testing.T) {
	for in, want := range map[string]string{"/a?b=1": "/a?b=1", "//evil": "/", "https://evil": "/", "/\\evil": "/", "": "/", "/ok\r\nX: y": "/"} {
		if got := SafeReturn(in); got != want {
			t.Errorf("SafeReturn(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAutoUnderAttackSwitchesOnAndOff(t *testing.T) {
	s, c := newSvc(t)
	var ev []Event
	s.OnAlert = func(e Event) { ev = append(ev, e) }
	st := s.site("s")
	s.Register(SiteCfg{Slug: "s", AutoRPS: 10, AutoCooldown: time.Minute})
	for i := 0; i < 12; i++ { // calm warm-up so the ring has history
		s.Tick(c.t)
		c.t = c.t.Add(time.Second)
	}
	if s.AutoActive("s") {
		t.Fatal("active while calm")
	}
	for i := 0; i < 12; i++ {
		for j := 0; j < 20; j++ { // 20 req/s
			st.c.req.Add(1)
		}
		s.Tick(c.t)
		c.t = c.t.Add(time.Second)
	}
	if !s.AutoActive("s") || len(ev) != 1 || ev[0].Kind != "underattack" {
		t.Fatalf("auto not on: active=%v events=%v", s.AutoActive("s"), ev)
	}
	for i := 0; i < 90; i++ { // quiet: cooldown expires
		s.Tick(c.t)
		c.t = c.t.Add(time.Second)
	}
	if s.AutoActive("s") || len(ev) != 2 {
		t.Errorf("auto not off: active=%v events=%d", s.AutoActive("s"), len(ev))
	}
}

func TestLiveStatsAndPercentiles(t *testing.T) {
	s, c := newSvc(t)
	for i := 0; i < 5; i++ {
		s.Tick(c.t)
		c.t = c.t.Add(time.Second)
	}
	for i := 0; i < 100; i++ {
		ms := 10
		if i >= 95 {
			ms = 1000
		}
		st := 200
		if i%10 == 0 {
			st = 503
		}
		s.Observe(Record{Site: "x", Status: st, Dur: time.Duration(ms) * time.Millisecond, Outcome: OutPass, Bytes: 10}, ClientRef(netip.Addr{}, false))
	}
	s.Tick(c.t)
	got := s.Live("x", 10)
	if got.Req != 100 || got.S5 != 10 || got.S2 != 90 || got.Bytes != 1000 {
		t.Errorf("counts %+v", got)
	}
	if got.P50 < 5 || got.P50 > 12 || got.P99 < 800 {
		t.Errorf("percentiles p50=%v p99=%v", got.P50, got.P99)
	}
	if all := s.Live("", 10); all.Req != 100 {
		t.Errorf("all sites: %d", all.Req)
	}
	if series := s.Series("x", 5, 1); len(series) != 5 {
		t.Errorf("series %v", series)
	}
}

func TestQueueAdmitsInOrderAndTokenHoldersAreNeverBlocked(t *testing.T) {
	s, c := newSvc(t)
	cfg := QueueCfg{Slug: "q", Capacity: 2, ActiveTTL: 300, MaxQueue: 2}
	visit := func(cookies ...*http.Cookie) (*httptest.ResponseRecorder, bool) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Accept", "text/html")
		for _, ck := range cookies {
			req.AddCookie(ck)
		}
		return rec, s.Queue(rec, req, cfg, netip.Addr{}, false)
	}
	enter := func() []*http.Cookie {
		rec, handled := visit() // first visit: cookie + redirect, no server state
		if !handled || rec.Code != http.StatusFound || s.QueueStats("q").Active+s.QueueStats("q").Waiting != 0 {
			t.Fatalf("first visit: %d %+v", rec.Code, s.QueueStats("q"))
		}
		return rec.Result().Cookies()
	}
	a, b, d, e, f := enter(), enter(), enter(), enter(), enter()
	if _, h := visit(a...); h {
		t.Error("first visitor should be admitted")
	}
	if _, h := visit(b...); h {
		t.Error("second visitor should be admitted")
	}
	if rec, h := visit(d...); !h || rec.Code != 503 || !strings.Contains(rec.Body.String(), "in line") {
		t.Errorf("third visitor should wait: %d", rec.Code)
	}
	if _, h := visit(e...); !h {
		t.Error("fourth visitor should wait")
	}
	if rec, h := visit(f...); !h || !strings.Contains(rec.Body.String(), "busy") {
		t.Errorf("fifth visitor hits the queue limit: %d %q", rec.Code, rec.Body.String())
	}
	if st := s.QueueStats("q"); st.Active != 2 || st.Waiting != 2 {
		t.Fatalf("stats %+v", st)
	}
	// capacity frees: expire both actives, the head of the line is admitted first
	c.t = c.t.Add(10 * time.Minute)
	s.site("q").room.mu.Lock()
	for _, sid := range s.site("q").room.queue {
		s.site("q").room.seen[sid] = c.t.Unix()
	}
	s.site("q").room.mu.Unlock()
	s.Tick(c.t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", QueueStatus, nil)
	for _, ck := range d {
		req.AddCookie(ck)
	}
	s.Queue(rec, req, cfg, netip.Addr{}, false)
	if !strings.Contains(rec.Body.String(), `"admitted":true`) {
		t.Errorf("head of line not admitted: %s", rec.Body.String())
	}
	// an admit cookie keeps working without a room slot (restart safety): a fresh room still lets the holder in
	adm := rec.Result().Cookies()
	s2, _ := newSvc(t)
	s2.Now = s.Now
	s2.master = s.master
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "/", nil)
	for _, ck := range adm {
		req2.AddCookie(ck)
	}
	if s2.Queue(rec2, req2, cfg, netip.Addr{}, false) {
		t.Error("a token holder was queued after a restart")
	}
	// emergency release
	s.ReleaseQueue("q", time.Minute)
	if _, h := visit(); h {
		t.Error("released site still queues")
	}
}

func TestPriceToUnitsAndWallet(t *testing.T) {
	for in, want := range map[string]string{"0.001": "1000", "1": "1000000", "12.5": "12500000", "0.000001": "1"} {
		if got, err := PriceToUnits(in); err != nil || got != want {
			t.Errorf("PriceToUnits(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "0", "0.0000001", "-1", "1e3", "abc", "1.2.3", "12345678901234567890", " "} {
		if _, err := PriceToUnits(bad); err == nil {
			t.Errorf("PriceToUnits(%q) accepted", bad)
		}
	}
	if !ValidWallet("0x"+strings.Repeat("a", 40)) || ValidWallet("0x12") || ValidWallet(strings.Repeat("a", 42)) {
		t.Error("wallet validation")
	}
}

func sum(s string) [32]byte { return sha256.Sum256([]byte(s)) }

func FuzzCheckPuzzle(f *testing.F) {
	f.Add("salt", 16, int64(1_700_000_000), "sig", "123")
	f.Add("", -1, int64(0), "", "")
	f.Fuzz(func(t *testing.T, salt string, bits int, ts int64, sig, counter string) {
		s := New("fuzz-secret-key-fuzz-secret-key-0123", nil)
		s.Now = func() time.Time { return time.Unix(1_700_000_000, 0) }
		if s.CheckPuzzle("site", "1.2.3.4", Puzzle{Salt: salt, Bits: bits, TS: ts, Sig: sig}, counter) == nil {
			t.Fatalf("a forged puzzle verified: %q %d %d %q %q", salt, bits, ts, sig, counter)
		}
	})
}
