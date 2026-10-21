package web

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/servanago/servanago/internal/config"
	"github.com/servanago/servanago/internal/helper"
	"github.com/servanago/servanago/internal/phpbuild"
	"github.com/servanago/servanago/internal/runtimes"
	"github.com/servanago/servanago/internal/store"
)

//go:embed testdata/active.php.json
var activeFeed []byte

const (
	bin8427 = "/opt/servanago/php/8.4.27-1/sbin/php-fpm"
	bin8426 = "/opt/servanago/php/8.4.26-1/sbin/php-fpm"
)

// phpExec: a host with two ServanaGo builds of PHP 8.4 and the distro's php-fpm 8.2.
type phpExec struct{ builds []string }

func (phpExec) LookPath(string) (string, error) { return "", errors.New("none") }
func (phpExec) LookupPath(string) (string, error) {
	return "", errors.New("none")
}
func (phpExec) Run(context.Context, string, ...string) ([]byte, error) {
	return nil, errors.New("none")
}
func (e phpExec) Glob(p string) ([]string, error) {
	switch p {
	case runtimes.PHPRoot + "/*-*/sbin/php-fpm":
		return e.builds, nil
	case "/usr/sbin/php-fpm*":
		return []string{"/usr/sbin/php-fpm8.2"}, nil
	}
	return nil, nil
}

// phpHost is a fake helper that records every call and can be told to misbehave.
type phpHost struct {
	mu        sync.Mutex
	calls     []string
	installs  []helper.Spec
	unitState map[string]string // slug -> active state a unit-status reports
	phase     string            // php-status phase
	phaseVer  string
	buildErr  string
	installed chan string
}

func (h *phpHost) rec(format string, a ...any) {
	h.mu.Lock()
	h.calls = append(h.calls, fmt.Sprintf(format, a...))
	h.mu.Unlock()
}

func (h *phpHost) log() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return strings.Join(h.calls, "|")
}

func (h *phpHost) actions() map[string]helper.Action {
	ok := func(name string) helper.Action {
		return func(r helper.Request) helper.Response {
			h.rec("%s %s %s", name, r.Vals.Slug, r.Vals.User)
			return helper.Response{OK: true}
		}
	}
	return map[string]helper.Action{
		helper.ActionUserAdd:    ok("user-add"),
		helper.ActionUnitRemove: ok("unit-remove"),
		helper.ActionUnitStart:  ok("unit-start"),
		helper.ActionUnitStop:   ok("unit-stop"),
		helper.ActionUnitInstall: func(r helper.Request) helper.Response {
			h.mu.Lock()
			h.installs = append(h.installs, r.Vals)
			h.mu.Unlock()
			h.rec("unit-install %s %s", r.Vals.Slug, filepath.Base(filepath.Dir(filepath.Dir(r.Vals.FPMBin))))
			return helper.Response{OK: true}
		},
		helper.ActionUnitStatus: func(r helper.Request) helper.Response {
			h.mu.Lock()
			st := h.unitState[r.Vals.Slug]
			h.mu.Unlock()
			if st == "" {
				st = "active"
			}
			return helper.Response{OK: true, Status: &helper.StatusData{ActiveState: st, SubState: "running"}}
		},
		helper.ActionPHPBuild: func(r helper.Request) helper.Response {
			h.rec("php-build %s", r.Vals.PHPVersion)
			if h.buildErr != "" {
				return helper.Response{Error: h.buildErr}
			}
			return helper.Response{OK: true}
		},
		helper.ActionPHPStatus: func(helper.Request) helper.Response {
			h.mu.Lock()
			defer h.mu.Unlock()
			return helper.Response{OK: true, Build: &phpbuild.State{Phase: h.phase, Version: h.phaseVer}, Logs: []string{"make: Entering <b>directory"}}
		},
		helper.ActionPHPInstall: func(r helper.Request) helper.Response {
			h.rec("php-install %s", r.Vals.PHPVersion)
			if h.installed != nil {
				h.installed <- r.Vals.PHPVersion
			}
			return helper.Response{OK: true}
		},
		helper.ActionPHPPrune: func(r helper.Request) helper.Response {
			h.rec("php-prune %s", r.Vals.Build)
			return helper.Response{OK: true}
		},
		helper.ActionPHPUserDefault: func(r helper.Request) helper.Response {
			h.rec("php-user-default %s %s", r.Vals.User, r.Vals.PHPVersion)
			return helper.Response{OK: true}
		},
		helper.ActionComposer: func(helper.Request) helper.Response { h.rec("composer-install"); return helper.Response{OK: true} },
	}
}

func phpServer(t *testing.T, builds ...string) (*Server, *phpHost) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	host := &phpHost{unitState: map[string]string{}, phase: phpbuild.PhaseIdle}
	ln, err := net.Listen("unix", filepath.Join(t.TempDir(), "h.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go helper.Serve(ln, func(helper.Peer) bool { return true }, host.actions())
	if len(builds) == 0 {
		builds = []string{bin8426, bin8427}
	}
	s := New(Deps{Cfg: config.Config{DataDir: t.TempDir(), Host: "panel.example.com"}, Store: st, Apply: txApplier{st}, HelperSocket: ln.Addr().String(),
		Exec: phpExec{builds: builds}, HTTPGet: func(context.Context, string) ([]byte, error) { return activeFeed, nil }})
	s.phpSettle, s.phpPoll = 0, time.Millisecond
	s.healthGet = func(context.Context, string, string) (int, error) { return 200, nil }
	return s, host
}

func (h *phpHost) set(slug, state string) {
	h.mu.Lock()
	h.unitState[slug] = state
	h.mu.Unlock()
}

func addPHPSite(t *testing.T, s *Server, host, label, health string) store.Site {
	t.Helper()
	site, err := s.deps.Store.CreateSite(context.Background(), store.Site{Hostnames: []string{host}, Kind: "php", StaticRoot: "/srv/" + host,
		FPMVersion: label, PHPHealthPath: health, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	return site
}

func post(s *Server, path string, kv ...string) (code int, body, redirect string) {
	w := s.do(req{method: "POST", path: path, body: form(kv...).Encode(), hdr: htmxPost})
	return w.Code, w.Body.String(), w.Header().Get("HX-Redirect")
}

func TestPHPPage(t *testing.T) {
	s, _ := phpServer(t)
	addPHPSite(t, s, "a.example.com", "8.4", "")
	w := s.do(req{method: "GET", path: "/php"})
	body := w.Body.String()
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, body)
	}
	for _, want := range []string{"8.4.27-1", "8.4.26-1", "newest 8.4", "a.example.com", "Check now", "Command-line PHP"} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q", want)
		}
	}
	if strings.Contains(body, "<b>directory") { // journal text is the app's own output: only ever escaped
		t.Error("build log rendered unescaped")
	}
}

func TestPHPBuildRefusals(t *testing.T) {
	s, host := phpServer(t)
	tests := []struct{ name, version, want string }{
		{"not a version", "8.4", "must look like"},
		{"injection", "8.4.27;id", "must look like"},
		{"end of life branch", "8.1.30", "no longer gets security fixes"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, body, _ := post(s, "/php/builds", "version", tt.version)
			if code != 422 || !strings.Contains(body, tt.want) {
				t.Fatalf("%d %q, want 422 mentioning %q", code, body, tt.want)
			}
		})
	}
	if strings.Contains(host.log(), "php-build") {
		t.Errorf("the helper was asked to build: %s", host.log())
	}
	host.buildErr = "build tools missing: cmake. Install them once with: sudo apt install cmake"
	code, body, _ := post(s, "/php/builds", "version", "8.4.27")
	if code != 422 || !strings.Contains(body, "sudo apt install cmake") {
		t.Errorf("a helper refusal must reach the admin: %d %q", code, body)
	}
}

func TestPHPBuildInstallsWhenBuilt(t *testing.T) {
	s, host := phpServer(t)
	host.installed = make(chan string, 1)
	host.phase, host.phaseVer = phpbuild.PhaseBuilt, "8.4.28"
	code, _, redirect := post(s, "/php/builds", "version", "8.4.28")
	if code != 204 || redirect != "/php" {
		t.Fatalf("%d redirect %q", code, redirect)
	}
	select {
	case v := <-host.installed:
		if v != "8.4.28" {
			t.Errorf("installed %q", v)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("the finished build was never installed; calls: %s", host.log())
	}
}

func TestPHPSwitchMovesFollowingSites(t *testing.T) {
	s, host := phpServer(t)
	addPHPSite(t, s, "a.example.com", "8.4", "")
	addPHPSite(t, s, "b.example.com", "8.4", "")
	addPHPSite(t, s, "pinned.example.com", "8.4.26-1", "") // an exact pin stays where it is
	addPHPSite(t, s, "distro.example.com", "8.2", "")
	code, body, _ := post(s, "/php/switch", "branch", "8.4")
	if code != 200 || !strings.Contains(body, "Switched 2 site(s)") {
		t.Fatalf("%d %q", code, body)
	}
	log := host.log()
	if strings.Count(log, "unit-install") != 2 || !strings.Contains(log, "8.4.27-1") || strings.Contains(log, "8.4.26-1") {
		t.Errorf("calls: %s", log)
	}
}

func TestPHPSwitchRevertsAndStops(t *testing.T) {
	s, host := phpServer(t)
	a := addPHPSite(t, s, "a.example.com", "8.4", "")
	b := addPHPSite(t, s, "b.example.com", "8.4", "")
	host.set(a.Slug, "failed")
	_, body, _ := post(s, "/php/switch", "branch", "8.4")
	if !strings.Contains(body, "put back on 8.4.26-1") || !strings.Contains(body, "left alone") {
		t.Errorf("message: %q", body)
	}
	log := host.log()
	// a: new build, then the previous one. b is never touched.
	if !(strings.Contains(log, "unit-install "+a.Slug+" 8.4.27-1") && strings.Contains(log, "unit-install "+a.Slug+" 8.4.26-1")) {
		t.Errorf("no revert: %s", log)
	}
	if strings.Contains(log, "unit-install "+b.Slug) {
		t.Errorf("the loop went on after a failure: %s", log)
	}
	rows, _ := s.deps.Store.ListAudit(context.Background(), 20)
	got := ""
	for _, r := range rows {
		got += r.Action + " "
	}
	if !strings.Contains(got, "php.switch.reverted") {
		t.Errorf("audit: %s", got)
	}
}

func TestPHPSwitchHealthPath(t *testing.T) {
	s, host := phpServer(t)
	addPHPSite(t, s, "a.example.com", "8.4", "/healthz")
	var asked string
	s.healthGet = func(_ context.Context, h, p string) (int, error) { asked = h + p; return 503, nil }
	_, body, _ := post(s, "/php/switch", "branch", "8.4")
	if asked != "a.example.com/healthz" || !strings.Contains(body, "answered 503") || !strings.Contains(body, "put back") {
		t.Errorf("asked %q, message %q", asked, body)
	}
	if !strings.Contains(host.log(), "8.4.26-1") {
		t.Errorf("not reverted: %s", host.log())
	}
	s.healthGet = func(context.Context, string, string) (int, error) { return 0, errors.New("connection refused") }
	if _, body, _ := post(s, "/php/switch", "branch", "8.4"); !strings.Contains(body, "connection refused") {
		t.Errorf("a failing request must fail the switch: %q", body)
	}
}

func TestPHPSwitchWithoutAnEarlierBuild(t *testing.T) {
	s, host := phpServer(t, bin8427)
	addPHPSite(t, s, "a.example.com", "8.4", "")
	host.set(s.mustSlug(t, "a.example.com"), "failed")
	_, body, _ := post(s, "/php/switch", "branch", "8.4")
	if !strings.Contains(body, "no earlier PHP 8.4 build") {
		t.Errorf("message: %q", body)
	}
}

func (s *Server) mustSlug(t *testing.T, host string) string {
	t.Helper()
	sites, _ := s.deps.Store.ListSites(context.Background())
	for _, x := range sites {
		if x.Hostnames[0] == host {
			return x.Slug
		}
	}
	t.Fatalf("no site %s", host)
	return ""
}

func TestPHPSwitchRejectsBadBranch(t *testing.T) {
	s, _ := phpServer(t)
	for _, b := range []string{"", "8", "8.4.27", "../x", "8.4;id"} {
		if code, _, _ := post(s, "/php/switch", "branch", b); code != 422 {
			t.Errorf("branch %q: %d", b, code)
		}
	}
	if _, body, _ := post(s, "/php/switch", "branch", "7.4"); !strings.Contains(body, "no PHP 7.4 build") {
		t.Errorf("unknown branch: %q", body)
	}
}

func TestPHPPrune(t *testing.T) {
	s, host := phpServer(t)
	addPHPSite(t, s, "pinned.example.com", "8.4.26-1", "")
	if err := s.deps.Store.SetPHPUserDefault(context.Background(), "brian", "8.4.27-1"); err != nil {
		t.Fatal(err)
	}
	for label, want := range map[string]string{"8.4.26-1": "pinned by pinned.example.com", "8.4.27-1": "the default PHP of brian"} {
		code, body, _ := post(s, "/php/builds/"+label+"/delete")
		if code != 409 || !strings.Contains(body, want) {
			t.Errorf("%s: %d %q, want 409 %q", label, code, body, want)
		}
	}
	if code, _, _ := post(s, "/php/builds/8.9.9-9/delete"); code != 404 {
		t.Errorf("unknown build: %d", code)
	}
	if code, _, _ := post(s, "/php/builds/..%2Fetc/delete"); code == 204 {
		t.Error("traversal accepted")
	}
	if strings.Contains(host.log(), "php-prune") {
		t.Errorf("a build in use was pruned: %s", host.log())
	}
	// Free the older one: nothing pins it and the branch has another build.
	if err := s.deps.Store.DeletePHPUserDefault(context.Background(), "brian"); err != nil {
		t.Fatal(err)
	}
	sites, _ := s.deps.Store.ListSites(context.Background())
	sites[0].FPMVersion = "8.4"
	if err := s.deps.Store.UpdateSite(context.Background(), sites[0]); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := post(s, "/php/builds/8.4.26-1/delete"); code != 204 || !strings.Contains(host.log(), "php-prune") {
		t.Errorf("prune of a free build: %d %s", code, host.log())
	}
}

func TestPHPPruneKeepsTheOnlyBuildOfAFollowedBranch(t *testing.T) {
	s, host := phpServer(t, bin8427)
	addPHPSite(t, s, "a.example.com", "8.4", "")
	code, body, _ := post(s, "/php/builds/8.4.27-1/delete")
	if code != 409 || !strings.Contains(body, "the only build of PHP 8.4") || strings.Contains(host.log(), "php-prune") {
		t.Errorf("%d %q %s", code, body, host.log())
	}
}

func TestPHPDefault(t *testing.T) {
	passwd := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(passwd, []byte("root:x:0:0::/root:/bin/bash\nbrian:x:1000:1000::/home/brian:/bin/bash\nsg-blog:x:998:998::/srv:/usr/sbin/nologin\nsvc:x:1001:1001::/x:/bin/false\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := passwdFile
	passwdFile = passwd
	t.Cleanup(func() { passwdFile = old })
	s, host := phpServer(t)
	if code, _, redirect := post(s, "/php/defaults", "user", "brian", "version", "8.4"); code != 204 || redirect != "/php" {
		t.Fatalf("set: %d", code)
	}
	if got, _ := s.deps.Store.PHPUserDefaults(context.Background()); len(got) != 1 || got[0] != (store.PHPUserDefault{Username: "brian", Version: "8.4"}) {
		t.Errorf("stored %+v", got)
	}
	if !strings.Contains(host.log(), "php-user-default brian 8.4") {
		t.Errorf("helper: %s", host.log())
	}
	tests := []struct{ name, user, version, want string }{
		{"root", "root", "8.4", "not a login user"},
		{"system user", "sg-blog", "8.4", "not a login user"},
		{"no shell", "svc", "8.4", "not a login user"},
		{"unknown", "ghost", "8.4", "not a login user"},
		{"label injection", "brian", "8.4;id", "not a PHP branch"},
		{"distro php", "brian", "8.2", "not a ServanaGo PHP build"},
		{"pruned build", "brian", "8.4.20-1", "not a ServanaGo PHP build"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, body, _ := post(s, "/php/defaults", "user", tt.user, "version", tt.version)
			if code != 422 || !strings.Contains(body, tt.want) {
				t.Fatalf("%d %q, want 422 %q", code, body, tt.want)
			}
		})
	}
	if code, _, _ := post(s, "/php/defaults", "user", "brian", "version", ""); code != 204 {
		t.Fatalf("clear: %d", code)
	}
	if got, _ := s.deps.Store.PHPUserDefaults(context.Background()); len(got) != 0 {
		t.Errorf("after clear: %+v", got)
	}
}

func TestReconcilePHPWritesStoredDefaultsAgain(t *testing.T) {
	s, host := phpServer(t)
	_ = s.deps.Store.SetPHPUserDefault(context.Background(), "brian", "8.4")
	s.ReconcilePHP(context.Background())
	if !strings.Contains(host.log(), "php-user-default brian 8.4") {
		t.Errorf("calls: %s", host.log())
	}
}

func TestPHPSiteFormExtensionsAndHealthPath(t *testing.T) {
	s, host := phpServer(t)
	root := t.TempDir()
	f := form("kind", "php", "static_root", root, "hostnames", "blog.example.com", "fpm_version", "8.4", "php_health_path", "/healthz", "enabled", "on")
	f["php_ext"] = []string{"curl", "mbstring", "mbstring"} // a repeated checkbox value, as a browser sends it
	w := s.do(req{method: "POST", path: "/sites", hdr: htmxPost, body: f.Encode()})
	if w.Code != 204 {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	sites, _ := s.deps.Store.ListSites(context.Background())
	if len(sites) != 1 || sites[0].PHPExtensions != "mbstring curl" || sites[0].PHPHealthPath != "/healthz" || sites[0].FPMVersion != "8.4" {
		t.Fatalf("stored %+v", sites)
	}
	host.mu.Lock()
	spec := host.installs[0]
	host.mu.Unlock()
	if strings.Join(spec.Extensions, " ") != "mbstring curl" || spec.FPMBin != bin8427 || spec.FPMVersion != "8.4" {
		t.Errorf("helper spec %+v", spec)
	}
	// An unknown extension and a bad health path are refused, and say why.
	for _, tt := range []struct {
		kv   []string
		want string
	}{
		{[]string{"php_ext", "evil"}, "not one of the available"},
		{[]string{"php_health_path", "healthz"}, "absolute path"},
		{[]string{"php_health_path", "//evil.example/x"}, "absolute path"},
		{[]string{"php_health_path", "/a b"}, "absolute path"},
	} {
		kv := append([]string{"kind", "php", "static_root", root, "hostnames", "c.example.com", "fpm_version", "8.4"}, tt.kv...)
		w := s.do(req{method: "POST", path: "/sites", hdr: htmxPost, body: form(kv...).Encode()})
		if w.Code != 422 || !strings.Contains(w.Body.String(), tt.want) {
			t.Errorf("%v: %d %q, want 422 %q", tt.kv, w.Code, w.Body, tt.want)
		}
	}
}

// The MCP update path re-posts formOf's form: a php site's extensions and health path must survive it.
func TestFormOfKeepsPHPFields(t *testing.T) {
	s, _ := phpServer(t)
	root := t.TempDir()
	site, err := s.deps.Store.CreateSite(context.Background(), store.Site{Hostnames: []string{"a.example.com"}, Kind: "php", StaticRoot: root,
		FPMVersion: "8.4", PHPExtensions: "mbstring curl", PHPHealthPath: "/healthz", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	in, err := parseSite(s.formOf(context.Background(), site), s.deps.Cfg)
	if err != nil {
		t.Fatal(err)
	}
	if in.PHPExtensions != "mbstring curl" || in.PHPHealthPath != "/healthz" {
		t.Errorf("lost on a round trip: %+v", in)
	}
}

// A pinned build that was pruned still lets its site be saved: the label falls back to its branch.
func TestPHPSitePinnedToAPrunedBuildFallsBack(t *testing.T) {
	s, host := phpServer(t)
	site := addPHPSite(t, s, "a.example.com", "8.4.20-1", "")
	if err := s.applyRuntime(context.Background(), site, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(host.log(), "unit-install "+site.Slug+" 8.4.27-1") {
		t.Errorf("fell back to %s", host.log())
	}
}

func TestParsePHPFeed(t *testing.T) {
	got, err := parsePHPFeed(activeFeed)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 || got["8.4"].Version != "8.4.27" || !got["8.4"].Security {
		t.Errorf("feed: %+v", got)
	}
	for _, bad := range []string{`{}`, `not json`, `{"8":{"8.4":{"version":"9.9.9"}}}`, `{"8":{"8.4":{"version":"8.4.x"}}}`, `{"8":{"../x":{"version":"8.4.27"}}}`} {
		if _, err := parsePHPFeed([]byte(bad)); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestPendingUpdates(t *testing.T) {
	latest := map[string]phpRelease{"8.4": {Version: "8.4.27", Security: true}, "8.3": {Version: "8.3.36"}, "8.5": {Version: "8.5.12"}}
	installed := []runtimes.PHPVersion{
		{Version: "8.4.26-1", Source: true}, {Version: "8.4.9-2", Source: true}, {Version: "8.3.36-1", Source: true},
		{Version: "8.2", Path: "/usr/sbin/php-fpm8.2"}, {Version: "8.4", Source: true},
	}
	got := pendingUpdates(latest, installed)
	if len(got) != 1 || got[0] != (phpUpdate{Branch: "8.4", Version: "8.4.27", Security: true}) {
		t.Errorf("pending %+v", got) // 8.3 is current, 8.5 has no build, the distro 8.2 is not ours to update
	}
}

func TestPHPCheckMailsOnlyWhenTheSetChanges(t *testing.T) {
	s, _ := phpServer(t, bin8426)
	if err := s.deps.Store.SaveSettings(context.Background(), store.Settings{SMTPHost: "mail", SMTPPort: 587, MailFrom: "ops@example.com"}); err != nil {
		t.Fatal(err)
	}
	var sent []string
	s.sendMail = func(from, to, subject, body string) error { sent = append(sent, to+"|"+body); return nil }
	for i := 0; i < 2; i++ {
		if err := s.runPHPCheck(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if len(sent) != 1 || !strings.HasPrefix(sent[0], "ops@example.com|") || !strings.Contains(sent[0], "8.4.27") || !strings.Contains(sent[0], "security release") {
		t.Errorf("mail: %q", sent)
	}
	// A failed mail is retried at the next check.
	s2, _ := phpServer(t, bin8426)
	_ = s2.deps.Store.SaveSettings(context.Background(), store.Settings{SMTPHost: "mail", SMTPPort: 587, MailFrom: "ops@example.com"})
	calls := 0
	s2.sendMail = func(string, string, string, string) error { calls++; return errors.New("smtp down") }
	_ = s2.runPHPCheck(context.Background())
	_ = s2.runPHPCheck(context.Background())
	if calls != 2 {
		t.Errorf("a failed mail must be retried, got %d attempts", calls)
	}
	// The result is kept and the page shows it.
	w := s.do(req{method: "GET", path: "/php"})
	if !strings.Contains(w.Body.String(), "New PHP releases") || !strings.Contains(w.Body.String(), "security release") {
		t.Error("the update is not on the page")
	}
}

func TestPHPCheckFailureKeepsThePreviousResult(t *testing.T) {
	s, _ := phpServer(t, bin8426)
	if err := s.runPHPCheck(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.deps.HTTPGet = func(context.Context, string) ([]byte, error) { return nil, errors.New("offline") }
	if err := s.runPHPCheck(context.Background()); err == nil || !strings.Contains(err.Error(), "offline") {
		t.Fatalf("err %v", err)
	}
	if res, at := s.loadCheck(context.Background()); at == 0 || res.Latest["8.4"].Version != "8.4.27" {
		t.Errorf("the earlier result was lost: %+v %d", res, at)
	}
}

func TestParseHealthPath(t *testing.T) {
	for in, want := range map[string]string{"": "", " /healthz ": "/healthz", "/a/b?x=1": "/a/b?x=1"} {
		if got, err := parseHealthPath(in); err != nil || got != want {
			t.Errorf("%q: %q, %v", in, got, err)
		}
	}
	for _, in := range []string{"healthz", "//x", "/a b", "/a\nb", "/a#b", "http://x/y", "/" + strings.Repeat("a", 200), `/a\b`} {
		if _, err := parseHealthPath(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestPHPJobPanelEscapesAndRefreshesWhenDone(t *testing.T) {
	s, host := phpServer(t)
	host.phase, host.phaseVer = phpbuild.PhaseBuilding, "8.4.28"
	w := s.do(req{method: "GET", path: "/php/job"})
	if !strings.Contains(w.Body.String(), `hx-get="/php/job"`) || w.Header().Get("HX-Refresh") != "" || strings.Contains(w.Body.String(), "<b>directory") {
		t.Errorf("active panel: %s %v", w.Body, w.Header())
	}
	host.phase = phpbuild.PhaseBuilt
	if w := s.do(req{method: "GET", path: "/php/job"}); w.Header().Get("HX-Refresh") != "true" || strings.Contains(w.Body.String(), "hx-get") {
		t.Errorf("finished panel: %s %v", w.Body, w.Header())
	}
}

func TestPHPComposer(t *testing.T) {
	s, host := phpServer(t)
	if code, _, _ := post(s, "/php/composer"); code != 204 || !strings.Contains(host.log(), "composer-install") {
		t.Errorf("composer: %d %s", code, host.log())
	}
}

// Sensitive PHP actions re-authenticate the signed-in admin like the Users page does.
func TestPHPActionsAskForThePassword(t *testing.T) {
	for _, path := range []string{"/php/builds", "/php/builds/install", "/php/switch", "/php/defaults", "/php/composer", "/php/builds/8.4.27-1/delete"} {
		s := newServer(t, "pw") // the sign-in throttle allows 5 wrong passwords per address: one server per path
		s.deps.Exec = phpExec{builds: []string{bin8427}}
		s.deps.HelperSocket = filepath.Join(t.TempDir(), "none.sock")
		ck := cookiesOf(t, login(s, "pw", nil, ""))
		f := url.Values{"version": {"8.4.27"}, "branch": {"8.4"}, "password": {"wrong"}}
		if w := postForm(s, path, f, ck); w.Code != 401 {
			t.Errorf("%s with a wrong password: %d %s", path, w.Code, w.Body)
		}
	}
}
