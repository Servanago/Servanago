package web

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/servanago/servanago/internal/alerts"
	"github.com/servanago/servanago/internal/config"
	"github.com/servanago/servanago/internal/guard"
	"github.com/servanago/servanago/internal/secretbox"
	"github.com/servanago/servanago/internal/store"
	"github.com/servanago/servanago/internal/trafficdb"
)

const guardKey = "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk"

// guardServer is an installed server with a live guard service and a traffic.db.
func guardServer(t *testing.T) (*Server, *guard.Service) {
	t.Helper()
	s, _ := siteServer(t)
	s.deps.Cfg.SecretKey, s.deps.Cfg.MCPToken = guardKey, mcpToken
	g := guard.New(guardKey, s.deps.Store)
	db, err := trafficdb.Open(filepath.Join(t.TempDir(), "traffic.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	g.UseDB(db)
	s.deps.Guard, s.deps.Traffic = g, db
	return s, g
}

func addProxy(t *testing.T, s *Server, host string) store.Site {
	t.Helper()
	x, err := s.deps.Store.CreateSite(context.Background(), store.Site{Kind: "proxy", Hostnames: []string{host}, Scheme: "http", UpstreamHost: "127.0.0.1", UpstreamPort: 9000, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	return x
}

func TestTrafficPagesRenderAndExportFilters(t *testing.T) {
	s, g := guardServer(t)
	x := addProxy(t, s, "t.example.com")
	now := time.Now()
	g.Now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		g.Observe(guard.Record{Site: x.Slug, Host: "t.example.com", Client: "203.0.113.5", Method: "GET", Path: "/ok", Status: 200, Outcome: "pass", Dur: 5 * time.Millisecond}, guard.ClientRef(netip.Addr{}, false))
	}
	g.Observe(guard.Record{Site: x.Slug, Host: "t.example.com", Client: "198.51.100.1", Method: "GET", Path: "=cmd|calc", Status: 502, Outcome: "pass", Err: "dial tcp: refused", Dur: time.Millisecond}, guard.ClientRef(netip.Addr{}, false))
	g.Tick(now)
	g.Tick(now.Add(time.Second))
	g.Flush()

	w := s.do(req{path: "/traffic"})
	body := w.Body.String()
	if w.Code != 200 || !strings.Contains(body, "</table>") || !strings.Contains(body, "Last minute") || !strings.Contains(body, "<svg") {
		t.Fatalf("traffic page: %d, complete=%v", w.Code, strings.Contains(body, "</table>"))
	}
	if !strings.Contains(body, `hx-trigger="every 2s"`) {
		t.Error("the live view must poll")
	}
	snap := s.do(req{path: "/traffic/snapshot?site=" + x.Slug}).Body.String()
	if strings.Contains(snap, "<html") || !strings.Contains(snap, "<strong>4</strong> requests") {
		t.Errorf("snapshot fragment: %q", snap)
	}
	if h := s.do(req{path: "/traffic?range=1h"}); h.Code != 200 || strings.Contains(h.Body.String(), `hx-trigger="every 2s"`) {
		t.Errorf("a history range must not poll: %d", h.Code)
	}
	csvOut := s.do(req{path: "/traffic/export?status=502"}).Body.String()
	if !strings.Contains(csvOut, "time,site,host,client") || !strings.Contains(csvOut, "'=cmd|calc") || strings.Contains(csvOut, "/ok") {
		t.Errorf("export must honor the filter and neutralize formulas:\n%s", csvOut)
	}
	if rows := s.do(req{path: "/traffic/rows?outcome=banned"}).Body.String(); !strings.Contains(rows, "No requests match") {
		t.Errorf("rows fragment: %q", rows)
	}
}

func TestTrafficPageWithNoGuardOrLogStillRenders(t *testing.T) {
	s := newServer(t, "")
	for _, p := range []string{"/traffic", "/traffic/snapshot", "/traffic/rows", "/bans", "/alerts"} {
		if w := s.do(req{path: p}); w.Code != 200 {
			t.Errorf("%s: %d", p, w.Code)
		}
	}
	if w := s.do(req{path: "/traffic/export"}); w.Code != http.StatusServiceUnavailable {
		t.Errorf("export without traffic.db: %d", w.Code)
	}
}

func TestBansCreateRefusesOwnAddressAndUnban(t *testing.T) {
	s, g := guardServer(t)
	post := func(path string, kv ...string) *httptest.ResponseRecorder {
		return s.do(req{method: "POST", path: path, body: form(kv...).Encode(), hdr: htmxPost})
	}
	if w := post("/bans", "client", "127.0.0.1", "hours", "1"); w.Code != 422 || !strings.Contains(w.Body.String(), "your own address") {
		t.Errorf("own address: %d %s", w.Code, w.Body)
	}
	if w := post("/bans", "client", "10.0.0.0/8", "hours", "1"); w.Code != 422 {
		t.Errorf("a /8 ban: %d", w.Code)
	}
	if w := post("/bans", "client", "203.0.113.9", "hours", "0"); w.Code != 422 {
		t.Errorf("zero hours: %d", w.Code)
	}
	if w := post("/bans", "client", "203.0.113.9", "hours", "2", "reason", "scanner"); w.Code != 204 {
		t.Fatalf("ban: %d %s", w.Code, w.Body)
	}
	if !g.Banned("203.0.113.9") {
		t.Fatal("not banned in the registry")
	}
	page := s.do(req{path: "/bans"}).Body.String()
	if !strings.Contains(page, "203.0.113.9") || !strings.Contains(page, "scanner") || !strings.Contains(page, "</table>") {
		t.Errorf("bans page: %s", page)
	}
	if w := post("/bans/delete", "client", "203.0.113.9"); w.Code != 204 || g.Banned("203.0.113.9") {
		t.Errorf("unban: %d", w.Code)
	}
	rows, _ := s.deps.Store.ListAudit(context.Background(), 20)
	if !hasAudit(rows, "ban.create") || !hasAudit(rows, "ban.delete") {
		t.Errorf("audit rows %v", rows)
	}
}

func TestAlertDestinationsLifecycleAndTestSend(t *testing.T) {
	s, _ := guardServer(t)
	post := func(path string, kv ...string) *httptest.ResponseRecorder {
		return s.do(req{method: "POST", path: path, body: form(kv...).Encode(), hdr: htmxPost})
	}
	if w := post("/alerts", "name", "bad", "kind", "ntfy", "target", "http://ntfy.example.com/x"); w.Code != 422 {
		t.Errorf("http ntfy accepted: %d", w.Code)
	}
	if w := post("/alerts", "name", "hook", "kind", "webhook", "target", "https://hooks.example.com/x"); w.Code != 422 {
		t.Errorf("webhook without a signing secret: %d", w.Code)
	}
	if w := post("/alerts", "name", "phone", "kind", "pushover", "target", "ukey", "secret", "apptoken"); w.Code != 204 {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	ds, _ := s.deps.Store.ListAlertDests(context.Background())
	if len(ds) != 1 || ds[0].Events != "underattack x402" || strings.Contains(string(ds[0].Target), "ukey") {
		t.Fatalf("stored: %+v (pushover defaults to the loud events, and the target is sealed)", ds)
	}
	if w := post("/alerts", "name", "phone", "kind", "ntfy", "target", "https://n.example.com/t"); w.Code != 422 {
		t.Errorf("duplicate name: %d", w.Code)
	}
	page := s.do(req{path: "/alerts"}).Body.String()
	if !strings.Contains(page, "phone") || strings.Contains(page, "ukey") || strings.Contains(page, "apptoken") {
		t.Errorf("alerts page leaks or lacks: %s", page)
	}

	// a test send reaches the destination and records the outcome on the row
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Title")
		if r.URL.Path == "/fail" {
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()
	s.deps.Alerts = &alerts.Sender{AllowLocal: true}
	mk := func(name, path string) store.AlertDest {
		tgt, _ := secretbox.Seal(guardKey, []byte(srv.URL+path))
		d, err := s.deps.Store.CreateAlertDest(context.Background(), store.AlertDest{Name: name, Kind: "ntfy", Target: tgt, Events: "scan", Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	ok, bad := mk("ok", "/topic"), mk("bad", "/fail")
	if w := post("/alerts/" + strconv.FormatInt(ok.ID, 10) + "/test"); w.Code != 200 || got != "ServanaGo test" {
		t.Errorf("test send: %d %q title=%q", w.Code, w.Body, got)
	}
	if w := post("/alerts/" + strconv.FormatInt(bad.ID, 10) + "/test"); w.Code != 502 {
		t.Errorf("failing send: %d", w.Code)
	}
	if d, _ := s.deps.Store.GetAlertDest(context.Background(), bad.ID); !strings.Contains(d.LastError, "500") {
		t.Errorf("the failure must be recorded on the row: %q", d.LastError)
	}
	// scan hits are routed to destinations that listen for them
	got = ""
	s.fireAlert(context.Background(), alerts.Event{Kind: "scan", Title: "ServanaGo: virus found", Text: "x"})
	if got != "ServanaGo: virus found" {
		t.Errorf("scan event not delivered: %q", got)
	}
	if w := post("/alerts/" + strconv.FormatInt(ok.ID, 10) + "/toggle"); w.Code != 204 {
		t.Errorf("toggle: %d", w.Code)
	}
	if d, _ := s.deps.Store.GetAlertDest(context.Background(), ok.ID); d.Enabled {
		t.Error("still enabled")
	}
	if w := post("/alerts/" + strconv.FormatInt(ok.ID, 10) + "/delete"); w.Code != 204 {
		t.Errorf("delete: %d", w.Code)
	}
}

func TestProtectionTabSavesValidatesAndRenders(t *testing.T) {
	s, g := guardServer(t)
	x := addProxy(t, s, "p.example.com")
	id := strconv.FormatInt(x.ID, 10)
	w := s.do(req{path: "/sites/" + id + "/protection"})
	body := w.Body.String()
	if w.Code != 200 || !strings.Contains(body, ">Save protection</button>") || !strings.Contains(body, "</form>") || !strings.Contains(body, "Turn under-attack mode on") {
		t.Fatalf("tab: %d complete=%v", w.Code, strings.Contains(body, ">Save protection</button>"))
	}
	save := func(kv ...string) *httptest.ResponseRecorder {
		return s.do(req{method: "POST", path: "/sites/" + id + "/protection", body: form(kv...).Encode(), hdr: htmxPost})
	}
	for name, kv := range map[string][]string{
		"auto without a trigger": {"ua_mode", "auto", "ua_auto_rps", "0"},
		"turnstile unconfigured": {"ua_mode", "on", "ch_kind", "turnstile"},
		"bad difficulty":         {"ch_difficulty", "extreme"},
		"queue out of range":     {"q_capacity", "0"},
		"bad backend":            {"backends", "not-a-host-port"},
		"bad paywall price":      {"x402_routes", "/api/ abc all request"},
		"bad paywall path":       {"x402_routes", "/a/../b 0.1 all request"},
		"paywall mode":           {"x402_routes", "/api/ 0.1 maybe request"},
	} {
		if w := save(kv...); w.Code != 422 {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
	}
	if w := save("ban_on", "on", "ua_mode", "auto", "ua_auto_rps", "50", "q_on", "on", "q_capacity", "7",
		"backends", "10.0.0.2:9000\n10.0.0.3:9000", "x402_routes", "/api/ 0.001 bots token 600\n/vip/ 1 all request"); w.Code != 200 {
		t.Fatalf("save: %d %s", w.Code, w.Body)
	}
	got, _ := s.deps.Store.GetSite(context.Background(), x.ID)
	if !got.Guard.BanOn || got.Guard.UAMode != "auto" || got.Guard.UAAutoRPS != 50 || !got.Guard.QOn || got.Guard.QCapacity != 7 ||
		got.Guard.Backends != "10.0.0.2:9000\n10.0.0.3:9000" || len(got.X402) != 2 {
		t.Fatalf("stored protection: %+v %+v", got.Guard, got.X402)
	}
	// the main form (no protect marker) leaves it alone
	f := siteForm("hostnames", "p.example.com", "upstream_port", "9100")
	if w := s.do(req{method: "PUT", path: "/sites/" + id, body: f.Encode(), hdr: htmxPost}); w.Code != 200 {
		t.Fatalf("main save: %d %s", w.Code, w.Body)
	}
	if after, _ := s.deps.Store.GetSite(context.Background(), x.ID); !after.Guard.BanOn || len(after.X402) != 2 || after.UpstreamPort != 9100 {
		t.Errorf("the site form wiped the protection set: %+v", after.Guard)
	}
	// under-attack on/off and the queue release valve
	post := func(path string, kv ...string) *httptest.ResponseRecorder {
		return s.do(req{method: "POST", path: path, body: form(kv...).Encode(), hdr: htmxPost})
	}
	if w := post("/sites/"+id+"/underattack", "mode", "on"); w.Code != 204 {
		t.Fatalf("under-attack on: %d %s", w.Code, w.Body)
	}
	if on, _ := s.deps.Store.GetSite(context.Background(), x.ID); on.Guard.UAMode != "on" {
		t.Error("mode not stored")
	}
	if w := post("/sites/"+id+"/underattack", "mode", "off"); w.Code != 204 {
		t.Fatalf("off: %d", w.Code)
	}
	if w := post("/sites/" + id + "/queue/release"); w.Code != 204 || g.QueueStats(x.Slug).ReleasedUntil == 0 {
		t.Errorf("release: %d", w.Code)
	}
	rows, _ := s.deps.Store.ListAudit(context.Background(), 30)
	if !hasAudit(rows, "site.protection") || !hasAudit(rows, "site.underattack") || !hasAudit(rows, "queue.release") {
		t.Errorf("audit rows %v", rows)
	}
}

func TestPageSiteThroughTheForm(t *testing.T) {
	s, _ := guardServer(t)
	post := func(kv ...string) (int, string) {
		v := siteForm("kind", "page", "hostnames", "parked.example.com", "page_status", "503", "page_title", "Back soon", "page_message", "Maintenance")
		v.Del("upstream_host")
		v.Del("upstream_port")
		for i := 0; i < len(kv); i += 2 {
			v.Set(kv[i], kv[i+1])
		}
		return postSite(s, v)
	}
	if c, b := post("page_status", "301", "page_target", "https://parked.example.com/"); c != 422 || !strings.Contains(b, "loop") {
		t.Errorf("a redirect to itself: %d %s", c, b)
	}
	if c, b := post("page_status", "301", "page_target", "ftp://x.example.org"); c != 422 {
		t.Errorf("a non-http target: %d %s", c, b)
	}
	if c, b := post("page_status", "503", "page_target", "https://x.example.org"); c != 422 {
		t.Errorf("a target on a status page: %d %s", c, b)
	}
	if c, b := post("page_html", strings.Repeat("x", 70000)); c != 422 {
		t.Errorf("a 70 KB page: %d %.80s", c, b)
	}
	if c, b := post(); c != 204 {
		t.Fatalf("create: %d %s", c, b)
	}
	ss, _ := s.deps.Store.ListSites(context.Background())
	if len(ss) != 1 || ss[0].Kind != "page" || ss[0].Page.Title != "Back soon" || ss[0].Page.Status != 503 || ss[0].StaticRoot != "" || ss[0].UpstreamHost != "" {
		t.Fatalf("stored: %+v", ss)
	}
	id := strconv.FormatInt(ss[0].ID, 10)
	edit := s.do(req{path: "/sites/" + id}).Body.String()
	if !strings.Contains(edit, `name="page_status"`) || !strings.Contains(edit, ">Save</button>") || !strings.Contains(edit, "</form>") {
		t.Error("the edit page is truncated or lacks the page fields")
	}
	// convert to a redirect through the edit form
	v := siteForm("kind", "page", "hostnames", "parked.example.com", "page_status", "302", "page_target", "https://elsewhere.example.org", "page_keep_path", "on")
	v.Del("upstream_host")
	v.Del("upstream_port")
	if w := s.do(req{method: "PUT", path: "/sites/" + id, body: v.Encode(), hdr: htmxPost}); w.Code != 200 {
		t.Fatalf("update: %d %s", w.Code, w.Body)
	}
	if got, _ := s.deps.Store.GetSite(context.Background(), ss[0].ID); !got.Page.IsRedirect() || !got.Page.KeepPath {
		t.Errorf("redirect not stored: %+v", got.Page)
	}
}

func TestSettingsGuardTabSavesAndReloadsTheService(t *testing.T) {
	s, g := guardServer(t)
	page := s.do(req{path: "/settings/guard"}).Body.String()
	if !strings.Contains(page, "<h2>Protection</h2>") || !strings.Contains(page, `name="ban_threshold"`) || !strings.Contains(page, "</form>") {
		t.Fatal("guard tab missing or truncated")
	}
	post := func(kv ...string) *httptest.ResponseRecorder {
		return s.do(req{method: "POST", path: "/settings/guard", body: form(kv...).Encode(), hdr: htmxPost})
	}
	base := []string{"ban_codes", "403 429", "ban_threshold", "5", "ban_window_s", "30", "ban_steps_min", "5 10", "log_days", "3", "rollup_days", "30",
		"x402_network", "eip155:84532", "x402_facilitator", "https://x402.org/facilitator", "x402_pay_to", "0x" + strings.Repeat("ab", 20)}
	with := func(kv ...string) []string { return append(append([]string{}, base...), kv...) }
	for name, kv := range map[string][]string{
		"bad code":         with("ban_codes", "abc"),
		"threshold":        with("ban_threshold", "1"),
		"empty steps":      with("ban_steps_min", ""),
		"bad exempt":       with("ban_exempt", "not a cidr"),
		"http facilitator": with("x402_facilitator", "http://x402.example.com"),
		"bad wallet":       with("x402_pay_to", "0x12"),
		"bad network":      with("x402_network", "eip155:1"),
	} {
		if w := post(kv...); w.Code != 422 {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
	}
	if w := post(with("x402_api_key", "facilitator-secret")...); w.Code != 204 {
		t.Fatalf("save: %d %s", w.Code, w.Body)
	}
	got, _ := s.deps.Store.GetGuardSettings(context.Background())
	if got.BanThreshold != 5 || got.BanCodes != "403 429" || got.X402Network != "eip155:84532" || len(got.X402APIKey) == 0 || strings.Contains(string(got.X402APIKey), "facilitator-secret") {
		t.Fatalf("stored: %+v", got)
	}
	// the running service picked the rules up: 5 responses of 403 now ban
	a := netip.MustParseAddr("203.0.113.77")
	for i := 0; i < 5; i++ {
		g.Feed(a, "x", 403)
	}
	if !g.Banned(guard.Key(a)) {
		t.Error("the saved ban rules are not live")
	}
	if page := s.do(req{path: "/settings/guard"}).Body.String(); strings.Contains(page, "facilitator-secret") || !strings.Contains(page, "set; leave blank to keep") {
		t.Error("the facilitator key must be write-only")
	}
}

func TestCheckConnectionNamesTheFailingStage(t *testing.T) {
	s := newServer(t, "")
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	closedAddr := closed.Addr().String()
	closed.Close()
	host, port, _ := net.SplitHostPort(ln.Addr().String())
	post := func(kv ...string) string {
		w := s.do(req{method: "POST", path: "/sites/check", body: form(kv...).Encode(), hdr: htmxPost})
		return w.Body.String()
	}
	if out := post("upstream_host", host, "upstream_port", port); !strings.Contains(out, "reachable") {
		t.Errorf("open port: %s", out)
	}
	ch, cp, _ := net.SplitHostPort(closedAddr)
	if out := post("upstream_host", ch, "upstream_port", cp); !strings.Contains(out, "TCP connection") {
		t.Errorf("closed port: %s", out)
	}
	if out := post("upstream_host", "no-such-host.invalid", "upstream_port", "80"); !strings.Contains(out, "DNS lookup") {
		t.Errorf("unknown name: %s", out)
	}
	if out := post("upstream_host", host, "upstream_port", port, "scheme", "https"); !strings.Contains(out, "TLS handshake") {
		t.Errorf("plain port as https: %s", out)
	}
	if out := post("upstream_host", host, "upstream_port", port, "backends", closedAddr); !strings.Contains(out, closedAddr) || !strings.Contains(out, "reachable") {
		t.Errorf("extra backends are checked too: %s", out)
	}
}

func TestMCPGuardToolsAndFieldsSurviveUpdates(t *testing.T) {
	s, g := guardServer(t)
	sess := mcpSession(t, s, mcpToken)
	var made changed
	if err := call(t, sess, "create_site", map[string]any{"kind": "proxy", "scheme": "http", "upstream_host": "192.168.1.20", "upstream_port": 9200,
		"hostnames": []string{"m.example.com"}, "ban_on": true, "backends": "10.0.0.2:9200", "x402_routes": "/api/ 0.001 bots token 600", "queue_on": true, "queue_capacity": 9}, &made); err != nil || made.ID == 0 {
		t.Fatalf("create_site: %+v %v", made, err)
	}
	// an update that never mentions protection keeps all of it
	if err := call(t, sess, "update_site", map[string]any{"id": made.ID, "notes": "touched"}, nil); err != nil {
		t.Fatal(err)
	}
	v := getSite(t, sess, made.ID)
	if v.Protection == nil || !v.Protection.BanOn || !v.Protection.QueueOn || v.Protection.QueueCapacity != 9 || len(v.Protection.Backends) != 1 || len(v.Protection.X402Routes) != 1 {
		t.Fatalf("update_site dropped the protection set: %+v", v.Protection)
	}
	if err := call(t, sess, "update_site", map[string]any{"id": made.ID, "backends": ""}, nil); err != nil {
		t.Fatal(err)
	}
	if v := getSite(t, sess, made.ID); len(v.Protection.Backends) != 0 || !v.Protection.BanOn {
		t.Errorf("clearing one field must not touch the others: %+v", v.Protection)
	}
	if err := call(t, sess, "set_under_attack", map[string]any{"id": made.ID, "mode": "on"}, nil); err != nil {
		t.Fatal(err)
	}
	if v := getSite(t, sess, made.ID); v.Protection.UnderAttack != "on" {
		t.Errorf("under-attack: %+v", v.Protection)
	}
	if err := call(t, sess, "set_queue_release", map[string]any{"id": made.ID}, nil); err != nil {
		t.Fatal(err)
	}
	// bans
	if err := call(t, sess, "create_ban", map[string]any{"client": "203.0.113.50", "hours": 1, "reason": "test"}, nil); err != nil {
		t.Fatal(err)
	}
	var bans struct{ Bans []banOut }
	if err := call(t, sess, "list_bans", nil, &bans); err != nil || len(bans.Bans) != 1 || !bans.Bans[0].Active || !g.Banned("203.0.113.50") {
		t.Fatalf("list_bans: %+v %v", bans, err)
	}
	if err := call(t, sess, "delete_ban", map[string]any{"client": "203.0.113.50"}, nil); err != nil || g.Banned("203.0.113.50") {
		t.Errorf("delete_ban: %v", err)
	}
	// alert destinations: secrets never come back
	if err := call(t, sess, "create_alert_destination", map[string]any{"name": "hook", "kind": "webhook", "target": "https://hooks.example.com/abc", "secret": "sign-key", "events": []string{"ban"}}, nil); err != nil {
		t.Fatal(err)
	}
	var ds struct{ Destinations []destOut }
	if err := call(t, sess, "list_alert_destinations", nil, &ds); err != nil || len(ds.Destinations) != 1 || ds.Destinations[0].Events[0] != "ban" {
		t.Fatalf("list_alert_destinations: %+v %v", ds, err)
	}
	if err := call(t, sess, "delete_alert_destination", map[string]any{"id": ds.Destinations[0].ID}, nil); err != nil {
		t.Fatal(err)
	}
	// traffic and the upstream check
	var tr trafficOut
	if err := call(t, sess, "get_traffic", map[string]any{"range": "live"}, &tr); err != nil {
		t.Fatal(err)
	}
	var chk checkOut
	if err := call(t, sess, "run_upstream_check", map[string]any{"address": "127.0.0.1:1"}, &chk); err != nil || chk.OK || chk.Stage != "TCP connection" {
		t.Errorf("run_upstream_check: %+v %v", chk, err)
	}
	var reqs struct{ Requests []requestOut }
	if err := call(t, sess, "list_requests", map[string]any{"limit": 5}, &reqs); err != nil {
		t.Errorf("list_requests: %v", err)
	}
}

func TestEveryPageKindIsHandled(t *testing.T) {
	// the kinds the migration CHECK allows must each be accepted by the form parser
	for _, k := range []string{"proxy", "static", "node", "php", "frankenphp", "fastcgi", "cgi", "page"} {
		v := siteForm("kind", k)
		if _, _, err := parseSiteFor(v, config.Config{}, ""); err != nil && strings.Contains(err.Error(), "must be proxy, static") {
			t.Errorf("kind %q is not a known kind: %v", k, err)
		}
	}
}

// Every kind the migration's CHECK allows must be a kind the form parser knows.
func TestEveryKindInTheSchemaIsParsed(t *testing.T) {
	b, err := os.ReadFile("../store/migrations/013_guard.sql")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`kind\s+TEXT NOT NULL DEFAULT 'proxy' CHECK \(kind IN \(([^)]*)\)`).FindSubmatch(b)
	if m == nil {
		t.Fatal("kind CHECK not found")
	}
	kinds := regexp.MustCompile(`'(\w+)'`).FindAllSubmatch(m[1], -1)
	if len(kinds) < 8 {
		t.Fatalf("parsed %d kinds", len(kinds))
	}
	for _, k := range kinds {
		if _, _, err := parseSiteFor(siteForm("kind", string(k[1])), config.Config{}, ""); err != nil && strings.Contains(err.Error(), "must be proxy, static") {
			t.Errorf("schema kind %q is unknown to the form parser", k[1])
		}
	}
}
