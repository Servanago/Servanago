package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/servanago/servanago/internal/backup"
	"github.com/servanago/servanago/internal/config"
	"github.com/servanago/servanago/internal/helper"
	"github.com/servanago/servanago/internal/secretbox"
	"github.com/servanago/servanago/internal/store"
)

const backupKey = "0123456789abcdef0123456789abcdef-web-test"
const goodPass = "a long enough archive passphrase"

type backupHost struct {
	mu    sync.Mutex
	calls []helper.Spec
	names []string
	fail  string // when set, backup-start answers with this error
}

func (h *backupHost) act(name string) helper.Action {
	return func(r helper.Request) helper.Response {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.calls = append(h.calls, r.Vals)
		h.names = append(h.names, name)
		if name == "backup-start" && h.fail != "" {
			return helper.Response{Error: h.fail}
		}
		return helper.Response{OK: true}
	}
}

func (h *backupHost) log() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []string
	for i, n := range h.names {
		c := h.calls[i]
		out = append(out, fmt.Sprintf("%s scope=%s slug=%s archive=%s files=%v dumps=%v actor=%s enabled=%v", n, c.Scope, c.Slug, c.Archive, c.RestoreFiles, c.RestoreDumps, c.Actor, c.Enabled))
	}
	return strings.Join(out, "|")
}

type bt struct {
	s       *Server
	host    *backupHost
	cookies []*http.Cookie
	dir     string
}

func backupServer(t *testing.T) *bt {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	host := &backupHost{}
	ln, err := net.Listen("unix", filepath.Join(t.TempDir(), "h.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go helper.Serve(ln, func(helper.Peer) bool { return true }, map[string]helper.Action{
		helper.ActionBackupEnable:  host.act("backup-enable"),
		helper.ActionBackupStart:   host.act("backup-start"),
		helper.ActionBackupRestore: host.act("backup-restore"),
		helper.ActionBackupStatus: func(helper.Request) helper.Response {
			return helper.Response{OK: true, Status: &helper.StatusData{ActiveState: "inactive"}}
		},
	})
	s := New(Deps{Cfg: config.Config{AdminPassword: "pw", SecretKey: backupKey, DataDir: t.TempDir()}, Store: st, Apply: txApplier{st}, HelperSocket: ln.Addr().String()})
	w := login(s, "pw", nil, "")
	if w.Code != 204 {
		t.Fatalf("login %d %s", w.Code, w.Body)
	}
	return &bt{s: s, host: host, cookies: cookiesOf(t, w), dir: filepath.Join(t.TempDir(), "backups")}
}

func (b *bt) post(path string, kv ...string) *httptest.ResponseRecorder {
	v := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		v.Set(kv[i], kv[i+1]) // a later pair overrides an earlier one (settings() puts its defaults first)
	}
	return b.s.do(req{method: "POST", path: path, body: v.Encode(), hdr: htmxPost, cookies: b.cookies})
}

func (b *bt) get(path string) *httptest.ResponseRecorder {
	return b.s.do(req{path: path, cookies: b.cookies})
}

func (b *bt) settings(kv ...string) *httptest.ResponseRecorder {
	base := []string{"enabled", "on", "panel", "on", "dir", b.dir, "sched", "daily@03:00", "keep", "7", "keep_weekly", "4", "passphrase", goodPass, "password", "pw"}
	return b.post("/backups/settings", append(base, kv...)...)
}

func (b *bt) site(t *testing.T, host string) store.Site {
	t.Helper()
	site, err := b.s.deps.Store.CreateSite(context.Background(), store.Site{Kind: "static", Hostnames: []string{host}, StaticRoot: t.TempDir(), Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	return site
}

func TestBackupsPageRendersCompleteWithAndWithoutSites(t *testing.T) {
	b := backupServer(t)
	check := func(label string) {
		w := b.get("/backups")
		body := w.Body.String()
		if w.Code != 200 || !strings.Contains(body, ">Save</button>") || !strings.Contains(body, "Recent runs") || strings.Count(body, "<form") != strings.Count(body, "</form>") {
			t.Fatalf("%s: %d truncated or unbalanced page", label, w.Code)
		}
	}
	check("empty")
	site := b.site(t, "shop.example.com")
	_ = b.s.deps.Store.AddProfile(context.Background(), store.BackupProfile{SiteID: site.ID, Name: "db", Engine: "sqlite", Path: "a.sqlite"})
	_ = b.s.deps.Store.AddVolume(context.Background(), site.ID, "vol1")
	check("with a site, a dump and a volume")
	if body := b.get("/backups").Body.String(); !strings.Contains(body, "shop.example.com") || !strings.Contains(body, "a.sqlite") || !strings.Contains(body, "vol1") {
		t.Error("site, dump or volume missing from the page")
	}
}

func TestSaveSettingsSealsSecretsAndInstallsTheTimer(t *testing.T) {
	b := backupServer(t)
	if w := b.settings("ntfy", "https://ntfy.example.com/topic-secret"); w.Code != 204 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	set, _ := b.s.deps.Store.GetBackupSettings(context.Background())
	if !set.Enabled || set.Dir != b.dir || set.Keep != 7 || set.Pass == nil || strings.Contains(string(set.Pass), goodPass) {
		t.Fatalf("saved %+v", set)
	}
	if p, err := secretbox.Open(backupKey, set.Pass); err != nil || string(p) != goodPass {
		t.Errorf("passphrase did not round trip: %q %v", p, err)
	}
	if u, err := secretbox.Open(backupKey, set.Ntfy); err != nil || !strings.Contains(string(u), "topic-secret") || strings.Contains(string(set.Ntfy), "topic-secret") {
		t.Errorf("ntfy not sealed: %v", err)
	}
	if got := b.host.log(); !strings.Contains(got, "backup-enable") || !strings.Contains(got, "enabled=true") {
		t.Errorf("helper calls: %s", got)
	}
	// a second save without the secrets keeps them
	if w := b.settings("passphrase", "", "ntfy", ""); w.Code != 204 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if again, _ := b.s.deps.Store.GetBackupSettings(context.Background()); string(again.Pass) != string(set.Pass) || string(again.Ntfy) != string(set.Ntfy) {
		t.Error("a blank passphrase or ntfy field must keep the stored value")
	}
	if rows, _ := b.s.deps.Store.ListAudit(context.Background(), 20); !hasAudit(rows, "backup.passphrase") || !hasAudit(rows, "backup.settings") {
		t.Errorf("audit rows %v", rows)
	}
}

func hasAudit(rows []store.AuditEntry, action string) bool {
	for _, r := range rows {
		if r.Action == action {
			return true
		}
	}
	return false
}

func TestSaveSettingsRejections(t *testing.T) {
	for _, tc := range []struct {
		name string
		kv   []string
		want string
		code int
	}{
		{"short passphrase", []string{"passphrase", "short"}, "at least 20", 422},
		{"bad schedule", []string{"sched", "every day"}, "must be hourly", 422},
		{"denied folder", []string{"dir", "/etc/backups"}, "Backup folder", 422},
		{"relative folder", []string{"dir", "backups"}, "absolute", 422},
		{"keep out of range", []string{"keep", "0"}, "Keep the newest", 422},
		{"ntfy over http", []string{"ntfy", "http://ntfy.example.com/x"}, "https", 422},
		{"wrong password", []string{"password", "nope"}, "Wrong password", 401},
		{"no password", []string{"password", ""}, "Wrong password", 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := backupServer(t) // one server per case: wrong passwords are throttled per address
			w := b.settings(tc.kv...)
			if w.Code != tc.code || !strings.Contains(w.Body.String(), tc.want) {
				t.Fatalf("%d %q, want %d mentioning %q", w.Code, w.Body, tc.code, tc.want)
			}
			if set, _ := b.s.deps.Store.GetBackupSettings(context.Background()); set.Enabled || set.Pass != nil {
				t.Errorf("a refused save changed the settings: %+v", set)
			}
			if b.host.log() != "" {
				t.Errorf("a refused save called the helper: %s", b.host.log())
			}
		})
	}
}

func TestEnableNeedsAPassphrase(t *testing.T) {
	b := backupServer(t)
	if w := b.settings("passphrase", ""); w.Code != 422 || !strings.Contains(w.Body.String(), "passphrase before") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

func TestProfilesAndVolumes(t *testing.T) {
	b := backupServer(t)
	site := b.site(t, "shop.example.com")
	id := fmt.Sprint(site.ID)
	ok := b.post("/backups/sites/"+id+"/profiles", "name", "billing", "engine", "mariadb", "container", "billing-mariadb-1", "db", "billing", "user", "root", "secret", "dbpw-plain")
	if ok.Code != 204 {
		t.Fatalf("%d %s", ok.Code, ok.Body)
	}
	ps, _ := b.s.deps.Store.ListProfiles(context.Background(), site.ID)
	if len(ps) != 1 || ps[0].Secret == nil || strings.Contains(string(ps[0].Secret), "dbpw-plain") {
		t.Fatalf("profile %+v", ps)
	}
	if p, err := secretbox.Open(backupKey, ps[0].Secret); err != nil || string(p) != "dbpw-plain" {
		t.Errorf("secret did not round trip: %v", err)
	}
	for _, tc := range []struct {
		name, want string
		kv         []string
	}{
		{"dup", "already used", []string{"name", "billing", "engine", "sqlite", "path", "a.db"}},
		{"injection in db", "database and user", []string{"name", "x", "engine", "postgres", "container", "c", "db", "-evil", "user", "u"}},
		{"traversal", "clean relative", []string{"name", "y", "engine", "sqlite", "path", "../../etc/passwd"}},
		{"bad engine", "engine", []string{"name", "z", "engine", "redis"}},
	} {
		if w := b.post("/backups/sites/"+id+"/profiles", tc.kv...); w.Code < 400 || !strings.Contains(w.Body.String(), tc.want) {
			t.Errorf("%s: %d %s, want an error mentioning %q", tc.name, w.Code, w.Body, tc.want)
		}
	}
	if w := b.post("/backups/sites/"+id+"/profiles/delete", "name", "billing"); w.Code != 204 {
		t.Fatalf("%d", w.Code)
	}
	if ps, _ := b.s.deps.Store.ListProfiles(context.Background(), site.ID); len(ps) != 0 {
		t.Error("profile not removed")
	}
	if w := b.post("/backups/sites/"+id+"/volumes", "volume", "app_data"); w.Code != 204 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if w := b.post("/backups/sites/"+id+"/volumes", "volume", "../../etc"); w.Code != 422 {
		t.Errorf("a path-like volume name was accepted: %d", w.Code)
	}
	if v, _ := b.s.deps.Store.ListVolumes(context.Background(), site.ID); len(v) != 1 || v[0] != "app_data" {
		t.Errorf("volumes %v", v)
	}
	if w := b.post("/backups/sites/"+id, "on", "on", "sched", "hourly", "keep", "2"); w.Code != 204 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if sb, _ := b.s.deps.Store.GetSiteBackup(context.Background(), site.ID); !sb.On || sb.Sched != "hourly" || sb.Keep != 2 {
		t.Errorf("site backup %+v", sb)
	}
	if w := b.post("/backups/sites/"+id, "on", "on", "sched", "nonsense"); w.Code != 422 {
		t.Errorf("a bad schedule was accepted: %d", w.Code)
	}
}

func TestRunNowCallsTheHelperWithTheActor(t *testing.T) {
	b := backupServer(t)
	site := b.site(t, "shop.example.com")
	if w := b.post("/backups/run", "scope", "site", "site", fmt.Sprint(site.ID)); w.Code != 204 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if got := b.host.log(); !strings.Contains(got, "backup-start scope=site slug="+site.Slug) || !strings.Contains(got, "actor=admin") {
		t.Errorf("helper calls: %s", got)
	}
	b.host.fail = "a backup job is already running"
	if w := b.post("/backups/run", "scope", "all"); w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "already running") {
		t.Errorf("%d %s", w.Code, w.Body)
	}
	if w := b.post("/backups/run", "scope", "everything"); w.Code != 400 {
		t.Errorf("%d", w.Code)
	}
}

// archiveFor writes a real encrypted archive for a scope into the backup folder.
func (b *bt) archiveFor(t *testing.T, scope string) string {
	t.Helper()
	set := store.BackupSettings{}
	if s, err := b.s.deps.Store.GetBackupSettings(context.Background()); err == nil {
		set = s
	}
	dir := set.Dir
	if dir == "" || dir == "/var/backups/servanago" {
		dir = b.dir
	}
	name, _, err := backup.Create(backup.CreateOpts{Dir: dir, Scratch: t.TempDir(), Pass: goodPass},
		backup.Manifest{Scope: scope, RunID: "r1", Started: time.Now().UTC().Truncate(time.Second)},
		func(bl *backup.Builder) error {
			return bl.AddReader("dumps/a.sql", "dump", strings.NewReader("select 1"))
		})
	if err != nil {
		t.Fatal(err)
	}
	return name
}

func TestDownloadNeedsThePasswordAndIsSingleUse(t *testing.T) {
	b := backupServer(t)
	if w := b.settings(); w.Code != 204 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	name := b.archiveFor(t, "panel")
	want, _ := os.ReadFile(filepath.Join(b.dir, "panel", name))

	if w := b.post("/backups/download", "scope", "panel", "name", "../../etc/passwd", "password", "pw"); w.Code != 404 {
		t.Errorf("traversal: %d", w.Code)
	}
	if w := b.post("/backups/download", "scope", "panel", "name", name, "password", "wrong"); w.Code != 401 || strings.Contains(w.Header().Get("HX-Redirect"), "/backups/file/") {
		t.Fatalf("a wrong password got a link: %d %v", w.Code, w.Header())
	}
	w := b.post("/backups/download", "scope", "panel", "name", name, "password", "pw")
	link := w.Header().Get("HX-Redirect")
	if w.Code != 204 || !strings.HasPrefix(link, "/backups/file/") {
		t.Fatalf("%d %v", w.Code, w.Header())
	}
	got := b.get(link)
	if got.Code != 200 || got.Body.String() != string(want) || !strings.Contains(got.Header().Get("Content-Disposition"), name) {
		t.Fatalf("download %d, %d bytes (want %d), %v", got.Code, got.Body.Len(), len(want), got.Header())
	}
	if again := b.get(link); again.Code != http.StatusGone {
		t.Errorf("a second use of the link: %d", again.Code)
	}
	if noSession := b.s.do(req{path: link}); noSession.Code == 200 {
		t.Error("the link worked without a session")
	}
}

func TestRestoreRules(t *testing.T) {
	b := backupServer(t)
	if w := b.settings(); w.Code != 204 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	site := b.site(t, "shop.example.com")
	other := b.site(t, "blog.example.com")
	mine, theirs := b.archiveFor(t, site.Slug), b.archiveFor(t, other.Slug)
	id := fmt.Sprint(site.ID)
	for _, tc := range []struct {
		name string
		kv   []string
		code int
		want string
	}{
		{"another site's archive", []string{"site", id, "name", theirs, "files", "on", "sure", site.Slug, "password", "pw"}, 404, "not an archive"},
		{"nothing chosen", []string{"site", id, "name", mine, "sure", site.Slug, "password", "pw"}, 422, "Tick files"},
		{"no confirmation word", []string{"site", id, "name", mine, "files", "on", "password", "pw"}, 422, "Type the site"},
		{"wrong password", []string{"site", id, "name", mine, "files", "on", "sure", site.Slug, "password", "bad"}, 401, "Wrong password"},
	} {
		if w := b.post("/backups/restore", tc.kv...); w.Code != tc.code || !strings.Contains(w.Body.String(), tc.want) {
			t.Errorf("%s: %d %s, want %d mentioning %q", tc.name, w.Code, w.Body, tc.code, tc.want)
		}
	}
	if strings.Contains(b.host.log(), "backup-restore") {
		t.Fatalf("a refused restore reached the helper: %s", b.host.log())
	}
	if w := b.post("/backups/restore", "site", id, "name", mine, "files", "on", "sure", site.Slug, "password", "pw"); w.Code != 204 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if got := b.host.log(); !strings.Contains(got, "backup-restore scope= slug="+site.Slug+" archive="+mine+" files=true dumps=false actor=admin") {
		t.Errorf("helper calls: %s", got)
	}
}

func writeRun(t *testing.T, dir string, r backup.Result) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, ".runs"), 0o755); err != nil {
		t.Fatal(err)
	}
	bs, _ := json.Marshal(r)
	if err := os.WriteFile(filepath.Join(dir, ".runs", fmt.Sprintf("%d-%s.json", r.Finished, r.RunID)), bs, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestIngestRecordsRunsAuditsOnceAndRaisesTheBanner(t *testing.T) {
	b := backupServer(t)
	if w := b.settings(); w.Code != 204 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	site := b.site(t, "shop.example.com")
	if err := b.s.deps.Store.SaveSiteBackup(context.Background(), site.ID, store.SiteBackup{On: true}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	writeRun(t, b.dir, backup.Result{RunID: "a1", Scope: "panel", Trigger: "schedule", Status: "ok", Archive: "panel-x", Bytes: 2048, Started: now - 5, Finished: now - 4})
	writeRun(t, b.dir, backup.Result{RunID: "b2", Scope: site.Slug, Trigger: "restore", Status: "failed", Error: "container db is not running", Actor: "brian", Started: now - 3, Finished: now - 2})
	writeRun(t, b.dir, backup.Result{RunID: "c3", Scope: site.Slug, Trigger: "schedule", Status: "failed", Error: "disk full", Started: now - 1, Finished: now})
	ctx := context.Background()
	b.s.ingestBackups(ctx)
	b.s.ingestBackups(ctx) // the files stay on disk until the job ages them out: no duplicates
	runs, _ := b.s.deps.Store.ListRuns(ctx, "", 10)
	if len(runs) != 3 {
		t.Fatalf("runs %+v", runs)
	}
	rows, _ := b.s.deps.Store.ListAudit(ctx, 50)
	var okRows, restoreRows int
	for _, r := range rows {
		switch r.Action {
		case "backup.ok":
			okRows++
			if r.Actor != "system" {
				t.Errorf("actor %q", r.Actor)
			}
		case "restore.failed":
			restoreRows++
			if r.Actor != "brian" || !strings.Contains(r.Target, "not running") {
				t.Errorf("restore row %+v", r)
			}
		}
	}
	if okRows != 1 || restoreRows != 1 {
		t.Errorf("audit rows ok=%d restore=%d, want 1 each", okRows, restoreRows)
	}
	if w := b.get("/backups"); !strings.Contains(w.Body.String(), "Backup problem") || !strings.Contains(w.Body.String(), "failed: disk full") {
		t.Error("the failed backup did not raise the banner")
	}
}

func TestStaleScopes(t *testing.T) {
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	set := store.BackupSettings{Sched: "daily@03:00"}
	h := func(n int) int64 { return now.Add(-time.Duration(n) * time.Hour).Unix() }
	run := func(status string, ago int) store.BackupRun { return store.BackupRun{Status: status, Finished: h(ago)} }
	for _, tc := range []struct {
		name   string
		scopes map[string]string
		last   map[string]store.BackupRun
		ok     map[string]int64
		want   string
	}{
		{"never ran: not stale yet", map[string]string{"panel": ""}, nil, nil, ""},
		{"fresh success", map[string]string{"panel": ""}, map[string]store.BackupRun{"panel": run("ok", 3)}, map[string]int64{"panel": h(3)}, ""},
		{"daily success 47h ago is fine", map[string]string{"panel": ""}, map[string]store.BackupRun{"panel": run("ok", 47)}, map[string]int64{"panel": h(47)}, ""},
		{"daily success 49h ago is stale", map[string]string{"panel": ""}, map[string]store.BackupRun{"panel": run("ok", 49)}, map[string]int64{"panel": h(49)}, "panel has no recent"},
		{"hourly override goes stale in 3h", map[string]string{"shop": "hourly"}, map[string]store.BackupRun{"shop": run("ok", 3)}, map[string]int64{"shop": h(3)}, "shop has no recent"},
		{"latest run failed", map[string]string{"panel": ""}, map[string]store.BackupRun{"panel": {Status: "failed", Error: "disk full", Finished: h(1)}}, map[string]int64{"panel": h(30)}, "panel failed: disk full"},
	} {
		got := strings.Join(staleScopes(now, set, tc.scopes, tc.last, tc.ok), ";")
		if (tc.want == "") != (got == "") || !strings.Contains(got, tc.want) {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}
