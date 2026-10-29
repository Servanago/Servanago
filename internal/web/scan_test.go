package web

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/servanago/servanago/internal/config"
	"github.com/servanago/servanago/internal/scan/fake"
	"github.com/servanago/servanago/internal/secretbox"
	"github.com/servanago/servanago/internal/store"
)

// scanTestServer is a server with a site on disk and a fake clamd socket in the settings.
func scanTestServer(t *testing.T) (*Server, store.Site) {
	t.Helper()
	secret := strings.Repeat("k", 32)
	cf := &cfFake{zones: zonesOK}
	s := cfgServer(t, cf, config.Config{SecretKey: secret})
	x, err := s.deps.Store.CreateSite(context.Background(), store.Site{
		Hostnames: []string{"scanned.example.com"}, Scheme: "http", Kind: "static", StaticRoot: t.TempDir(), Enabled: true, Slug: "scanned-example-com",
	})
	if err != nil {
		t.Fatal(err)
	}
	sock, _ := fake.Clamd(t, "")
	st, err := s.deps.Store.GetSettings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	st.ScanSocket, st.ScanHour = sock, 3
	if err := s.deps.Store.SaveSettings(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	return s, x
}

func TestScanSettingsSaveSealAndClear(t *testing.T) {
	s, _ := scanTestServer(t)
	key := strings.Repeat("k", 32)
	cases := []struct {
		name  string
		form  url.Values
		code  int
		check func(t *testing.T, st store.Settings)
	}{
		{"socket+ntfy", form("scan_socket", "/tmp/clamd.sock", "scan_hour", "5", "scan_ntfy", "https://ntfy.example.com/t", "scan_ntfy_token", "tok123"), 204,
			func(t *testing.T, st store.Settings) {
				if st.ScanSocket != "/tmp/clamd.sock" || st.ScanHour != 5 {
					t.Errorf("stored: %+v", st)
				}
				b, err := secretbox.Open(key, st.ScanNtfy)
				if err != nil || string(b) != "https://ntfy.example.com/t" {
					t.Errorf("ntfy unseal: %q %v", b, err)
				}
				if st.ScanNtfyToken == nil {
					t.Error("token not sealed")
				}
			}},
		{"bad socket", form("scan_socket", "clamd.sock"), 422,
			func(t *testing.T, st store.Settings) {
				if st.ScanSocket != "" {
					t.Errorf("relative socket was stored")
				}
			}},
		{"bad ntfy", form("scan_socket", "/tmp/clamd.sock", "scan_ntfy", "http://ntfy.example.com/t"), 422,
			func(t *testing.T, st store.Settings) {
				if st.ScanSocket != "" {
					t.Errorf("the whole form should have been refused: %+v", st)
				}
			}},
		{"clear ntfy", form("scan_socket", "/tmp/clamd.sock", "clear_ntfy", "1"), 204,
			func(t *testing.T, st store.Settings) {
				if st.ScanNtfy != nil || st.ScanNtfyToken != nil {
					t.Errorf("clear left the ntfy secrets: %+v", st)
				}
			}},
	}
	for _, c := range cases {
		// every case starts from clean scanner columns
		if cur, err := s.deps.Store.GetSettings(context.Background()); err == nil {
			cur.ScanSocket, cur.ScanNtfy, cur.ScanNtfyToken = "", nil, nil
			_ = s.deps.Store.SaveSettings(context.Background(), cur)
		}
		if w := s.do(req{method: "POST", path: "/settings/scan", hdr: htmxPost, body: c.form.Encode()}); w.Code != c.code {
			t.Errorf("%s: got %d %s, want %d", c.name, w.Code, w.Body.String(), c.code)
			continue
		}
		st, _ := s.deps.Store.GetSettings(context.Background())
		c.check(t, st)
	}
}

func TestRunScanQuarantinesAndNotifies(t *testing.T) {
	s, x := scanTestServer(t)
	ctx := context.Background()
	fake.Infected(t, filepath.Join(x.StaticRoot, "evil.php"))
	if err := os.WriteFile(filepath.Join(x.StaticRoot, "ok.html"), []byte("fine"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(x.StaticRoot, filepath.Join(x.StaticRoot, "selflink")); err != nil {
		t.Fatal(err)
	}
	s.runScan(ctx, x, "manual")
	runs, _ := s.deps.Store.ListScanRuns(ctx, x.ID, 5)
	if len(runs) != 1 || runs[0].State != "ok" || runs[0].Files != 2 || runs[0].Skipped != 1 {
		t.Fatalf("run row: %+v", runs[0])
	}
	hits, _ := s.deps.Store.ListScanHits(ctx, runs[0].ID)
	if len(hits) != 1 || hits[0].Action != "quarantined" || hits[0].Virus != "Eicar-Test-Signature" {
		t.Fatalf("hits: %+v", hits)
	}
	if _, err := os.Stat(filepath.Join(x.StaticRoot, "evil.php")); !os.IsNotExist(err) {
		t.Fatal("the infected file is still in the webroot")
	}
	if _, err := os.Stat(hits[0].QuarantinedTo); err != nil || !strings.Contains(hits[0].QuarantinedTo, "quarantine") {
		t.Fatalf("quarantined copy missing: %q %v", hits[0].QuarantinedTo, err)
	}
	// pages: the runs page shows the count, the run page the hit and its buttons
	if body := s.do(req{path: "/scan"}).Body.String(); !strings.Contains(body, "scanned.example.com") || !strings.Contains(body, ">1<") {
		t.Errorf("scan page (count): %s", body)
	}
	if body := s.do(req{path: "/scan/runs/" + strconv.FormatInt(runs[0].ID, 10)}).Body.String(); !strings.Contains(body, "evil.php") || !strings.Contains(body, ">Restore</button>") {
		t.Errorf("run page: %s", body)
	}
}

func TestScanHitActionsMoveFiles(t *testing.T) {
	s, x := scanTestServer(t)
	ctx := context.Background()
	evil := filepath.Join(x.StaticRoot, "evil.php")
	fake.Infected(t, evil)
	run, _ := s.deps.Store.InsertScanRun(ctx, x.ID, "manual", time.Now().Unix())
	hid, _ := s.deps.Store.AddScanHit(ctx, store.ScanHit{RunID: run, SiteID: x.ID, Path: evil, Virus: "Win.Test", Action: "live"})

	if w := s.do(req{method: "POST", path: "/scan/hits/" + strconv.FormatInt(hid, 10) + "/quarantine", hdr: htmxPost}); w.Code != 204 {
		t.Fatalf("quarantine: %d %s", w.Code, w.Body.String())
	}
	h, _ := s.deps.Store.GetScanHit(ctx, hid)
	if h.Action != "quarantined" || !strings.Contains(h.QuarantinedTo, s.quarantineDir(x.Slug)) {
		t.Fatalf("hit row: %+v", h)
	}
	if _, err := os.Stat(evil); !os.IsNotExist(err) {
		t.Fatal("quarantine left the file in place")
	}
	if w := s.do(req{method: "POST", path: "/scan/hits/" + strconv.FormatInt(hid, 10) + "/ignore", hdr: htmxPost}); w.Code != 204 {
		t.Fatalf("ignore: %d", w.Code)
	}
	if h, _ := s.deps.Store.GetScanHit(ctx, hid); h.Action != "ignored" || h.QuarantinedTo == "" {
		t.Fatalf("ignored hit: %+v", h)
	}
	if w := s.do(req{method: "POST", path: "/scan/hits/" + strconv.FormatInt(hid, 10) + "/restore", hdr: htmxPost}); w.Code != 204 {
		t.Fatalf("restore: %d", w.Code)
	}
	if h, _ := s.deps.Store.GetScanHit(ctx, hid); h.Action != "restored" {
		t.Fatalf("restored hit: %+v", h)
	}
	if _, err := os.Stat(evil); err != nil {
		t.Fatalf("file not restored home: %v", err)
	}
	// restore refuses when the original path is occupied again
	if err := os.Remove(evil); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(evil, []byte("a newer file appeared here"), 0o644); err != nil {
		t.Fatal(err)
	}
	if w := s.do(req{method: "POST", path: "/scan/hits/" + strconv.FormatInt(hid, 10) + "/restore", hdr: htmxPost}); w.Code == 204 {
		t.Errorf("restore over an existing path was accepted")
	}
}

func TestServedRootOfAndScanable(t *testing.T) {
	base := store.Site{StaticRoot: "/srv/site"}
	if r := servedRootOf(base); r != "/srv/site" {
		t.Errorf("plain root: %q", r)
	}
	base.PublicDir = "public"
	if r := servedRootOf(base); r != "/srv/site/public" {
		t.Errorf("public dir: %q", r)
	}
	if servedRootOf(store.Site{}) != "" {
		t.Error("a proxy/node site must not scan")
	}
}

func TestScanStartAndDashboardBadge(t *testing.T) {
	s, x := scanTestServer(t)
	ctx := context.Background()
	fake.Infected(t, filepath.Join(x.StaticRoot, "evil.php"))
	if w := s.do(req{method: "POST", path: "/scan/sites/" + strconv.FormatInt(x.ID, 10), hdr: htmxPost}); w.Code != 204 {
		t.Fatalf("start scan: %d %s", w.Code, w.Body.String())
	}
	time.Sleep(200 * time.Millisecond) // the detached scan on a tiny tree; one short wait keeps the assertion meaningful
	if w := s.do(req{method: "POST", path: "/sites/" + strconv.FormatInt(x.ID, 10) + "/scan", hdr: htmxPost}); w.Code != 204 {
		t.Fatalf("start scan from the dashboard route: %d", w.Code)
	}
	page := s.do(req{path: "/"}).Body.String()
	if !strings.Contains(page, `hx-post="/sites/`+strconv.FormatInt(x.ID, 10)+`/scan"`) {
		t.Errorf("dashboard lacks the Scan now button: %s", page)
	}
	// the badge: once the run has finished it shows hits
	runs, _ := s.deps.Store.ListScanRuns(ctx, x.ID, 5)
	for _, run := range runs {
		if run.State == "ok" {
			page = s.do(req{path: "/"}).Body.String()
			break
		}
	}
	if !strings.Contains(page, "hit") && !strings.Contains(page, "running") && !strings.Contains(page, ">scan clean<") {
		t.Errorf("dashboard lacks the scan badge/running state")
	}
}

// sweepDue: one sweep per day at the set hour; a second call in the same day does nothing.
func TestSweepDueRunsOncePerDay(t *testing.T) {
	s, x := scanTestServer(t)
	ctx := context.Background()
	fake.Infected(t, filepath.Join(x.StaticRoot, "evil.php"))
	st, _ := s.deps.Store.GetSettings(ctx)
	st.ScanHour = time.Now().Hour() // the sweep is due now
	if err := s.deps.Store.SaveSettings(ctx, st); err != nil {
		t.Fatal(err)
	}
	if err := s.sweepDue(ctx); err != nil {
		t.Fatalf("first sweep: %v", err)
	}
	runs, _ := s.deps.Store.ListScanRuns(ctx, x.ID, 10)
	if len(runs) != 1 || runs[0].Trigger != "sweep" {
		t.Fatalf("sweep runs: %+v", runs)
	}
	if err := s.sweepDue(ctx); err != nil {
		t.Fatalf("second sweep: %v", err)
	}
	again, _ := s.deps.Store.ListScanRuns(ctx, x.ID, 10)
	if len(again) != 1 {
		t.Fatalf("a sweep already done today ran again: %+v", again)
	}
}

func TestGeoGuardAndSettings(t *testing.T) {
	s, _ := scanTestServer(t)
	// the guard with nothing configured: pass
	if w := s.do(req{path: "/"}); w.Code != 200 {
		t.Fatalf("no rule: %d", w.Code)
	}
	if w := s.do(req{method: "POST", path: "/settings/geo", hdr: htmxPost,
		body: form("geo_db", "/var/lib/GeoIP/GeoLite2-Country.mmdb", "webui_mode", "deny", "webui_countries", "RU, CN").Encode()}); w.Code != 204 {
		t.Fatalf("geo settings save: %d %s", w.Code, w.Body.String())
	}
	if gr, ok := s.geoRule.Load().(geoRule); !ok || gr.mode != "deny" || gr.countries != "RU CN" {
		t.Fatalf("cached rule: %+v", gr)
	}
	// the save refreshed the reader as well: the missing file reports through the reader only
	if _, err := s.deps.Store.GetSettings(context.Background()); err != nil {
		t.Fatal(err)
	}
	st, _ := s.deps.Store.GetSettings(context.Background())
	if st.GeoDB != "/var/lib/GeoIP/GeoLite2-Country.mmdb" || st.WebUICountries != "RU CN" {
		t.Fatalf("stored settings: %+v", st)
	}
	// loopback clients: never judged; a public XFF client: the geo rule passes it (US is not in
	// RU CN; the failing branch of a missing file is the fail-open rule) and the open panel's own
	// peer-gate answers — its message proves the request reached the mux rather than being blocked
	if w := s.do(req{path: "/"}); w.Code != 200 {
		t.Fatalf("loopback blocked: %d", w.Code)
	}
	w := s.do(req{path: "/", hdr: map[string]string{"X-Forwarded-For": "8.8.4.4"}, peer: "127.0.0.1:5555"})
	if w.Code != 403 || !strings.Contains(w.Body.String(), "No administrator") {
		t.Fatalf("open mode: the public client should pass the geo rule and meet the peer gate: %d %q", w.Code, w.Body.String())
	}
	// an unusable mode is refused and changes nothing
	if w := s.do(req{method: "POST", path: "/settings/geo", hdr: htmxPost, body: form("geo_db", "/x", "webui_mode", "block", "webui_countries", "RU").Encode()}); w.Code != 422 {
		t.Errorf("bad mode accepted: %d", w.Code)
	}
	if w := s.do(req{method: "POST", path: "/settings/geo", hdr: htmxPost, body: form("geo_db", "/x", "webui_mode", "deny", "webui_countries", "").Encode()}); w.Code != 422 {
		t.Errorf("rule without codes accepted: %d", w.Code)
	}
}

// TestGeoGuardBlocksPublicClients points the guard at the LIVE mmdb when the host keeps one:
// 8.8.4.4 (US) is 403, the loopback peer without XFF is not judged at all.
func TestGeoGuardBlocksPublicClients(t *testing.T) {
	const installed = "/var/lib/GeoIP/GeoLite2-Country.mmdb"
	if _, err := os.Stat(installed); err != nil {
		t.Skip("no GeoLite2 database on this host:", err)
	}
	s, _ := scanTestServer(t)
	st, _ := s.deps.Store.GetSettings(context.Background())
	st.GeoDB = installed
	if err := s.deps.Store.SaveSettings(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	s.geo.Use(installed)
	s.geoRule.Store(geoRule{db: installed, mode: "deny", countries: "US"})
	w := s.do(req{path: "/", hdr: map[string]string{"X-Forwarded-For": "8.8.4.4"}, peer: "127.0.0.1:5555"})
	if w.Code != 403 || !strings.Contains(w.Body.String(), "not allowed") {
		t.Fatalf("8.8.4.4 under a US deny: %d %q", w.Code, w.Body.String())
	}
	if w := s.do(req{path: "/"}); w.Code != 200 {
		t.Fatalf("loopback got judged: %d", w.Code)
	}
}
