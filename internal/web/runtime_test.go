package web

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/servanago/servanago/internal/config"
	"github.com/servanago/servanago/internal/helper"
	"github.com/servanago/servanago/internal/store"
)

// fakeHost fakes a host with node and one php-fpm, and records every helper call.
type fakeHost struct {
	mu    sync.Mutex
	calls []string // "action slug kind"
}

func (f *fakeHost) record(name string) helper.Action {
	return func(r helper.Request) helper.Response {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls = append(f.calls, name+" "+r.Vals.Slug+" "+r.Vals.Kind)
		return helper.Response{OK: true}
	}
}

func (f *fakeHost) log() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.calls, "|")
}

// runtimeExec is the runtime detector's view of the fake host: node 20 and php-fpm 8.2.
type runtimeExec struct{ noFranken, noFCGI bool }

func (runtimeExec) LookupPath(string) (string, error) { return "/usr/bin/node", nil }
func (runtimeExec) Run(context.Context, string, ...string) ([]byte, error) {
	return []byte("v20.11.0\n"), nil
}
func (e runtimeExec) Glob(p string) ([]string, error) {
	switch {
	case p == "/usr/sbin/php-fpm*":
		return []string{"/usr/sbin/php-fpm8.2"}, nil
	case p == "/usr/bin/frankenphp" && !e.noFranken, p == "/usr/sbin/fcgiwrap" && !e.noFCGI:
		return []string{p}, nil
	}
	return nil, nil
}

func runtimeServer(t *testing.T) (*Server, *fakeHost) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	host := &fakeHost{}
	ln, err := net.Listen("unix", filepath.Join(t.TempDir(), "h.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go helper.Serve(ln, func(helper.Peer) bool { return true }, map[string]helper.Action{
		helper.ActionUserAdd:     host.record("user-add"),
		helper.ActionUserRemove:  host.record("user-remove"),
		helper.ActionUnitInstall: host.record("unit-install"),
		helper.ActionUnitRemove:  host.record("unit-remove"),
		helper.ActionUnitStart:   host.record("unit-start"),
		helper.ActionUnitStop:    host.record("unit-stop"),
		helper.ActionUnitStatus: func(helper.Request) helper.Response {
			return helper.Response{OK: true, Status: &helper.StatusData{ActiveState: "active", SubState: "running", PID: "4242"}}
		},
		helper.ActionUnitLogs: func(helper.Request) helper.Response {
			return helper.Response{OK: true, Logs: []string{"listening on 3000", `<script>alert("x")</script>`}}
		},
	})
	cfg := config.Config{DataDir: t.TempDir(), Host: "panel.example.com"}
	s := New(Deps{Cfg: cfg, Store: st, Apply: txApplier{st}, HelperSocket: ln.Addr().String(), Exec: runtimeExec{}})
	return s, host
}

func nodeForm(root string, kv ...string) []string {
	return append([]string{"kind", "node", "static_root", root, "hostnames", "app.example.com", "port", "3000",
		"start_command", "node server.js", "enabled", "on"}, kv...)
}

func phpForm(root string, kv ...string) []string {
	return append([]string{"kind", "php", "static_root", root, "hostnames", "blog.example.com", "fpm_version", "8.2", "enabled", "on"}, kv...)
}

func TestCreateNodeSite(t *testing.T) {
	s, host := runtimeServer(t)
	root := t.TempDir()
	w := s.do(req{method: "POST", path: "/sites", body: form(nodeForm(root, "install_command", "npm ci", "build_command", "npm run build")...).Encode(), hdr: htmxPost})
	if w.Code != 204 {
		t.Fatalf("create: %d %q", w.Code, w.Body.String())
	}
	rs, _ := s.deps.Store.ListSites(context.Background())
	if len(rs) != 1 {
		t.Fatalf("%+v", rs)
	}
	got := rs[0]
	resolved, _ := filepath.EvalSymlinks(root)
	if got.Kind != "node" || got.StaticRoot != resolved || got.UpstreamHost != "127.0.0.1" || got.UpstreamPort != 3000 ||
		got.StartCommand != "node server.js" || got.InstallCommand != "npm ci" || got.BuildCommand != "npm run build" || got.FPMVersion != "" {
		t.Fatalf("node site stored wrong: %+v", got)
	}
	want := "user-add " + got.Slug + " |unit-install " + got.Slug + " node|unit-start " + got.Slug + " "
	if host.log() != want {
		t.Errorf("helper calls\n got %q\nwant %q", host.log(), want)
	}
}

func TestCreatePHPSite(t *testing.T) {
	s, host := runtimeServer(t)
	w := s.do(req{method: "POST", path: "/sites", body: form(phpForm(t.TempDir())...).Encode(), hdr: htmxPost})
	if w.Code != 204 {
		t.Fatalf("create: %d %q", w.Code, w.Body.String())
	}
	rs, _ := s.deps.Store.ListSites(context.Background())
	if len(rs) != 1 || rs[0].Kind != "php" || rs[0].FPMVersion != "8.2" || rs[0].UpstreamHost != "" || rs[0].StartCommand != "" {
		t.Fatalf("php site stored wrong: %+v", rs)
	}
	slug := rs[0].Slug
	if want := "user-add " + slug + " |unit-install " + slug + " php|unit-start " + slug + " "; host.log() != want {
		t.Errorf("helper calls\n got %q\nwant %q", host.log(), want)
	}
}

func TestRuntimeSiteRejections(t *testing.T) {
	s, host := runtimeServer(t)
	root := t.TempDir()
	// A real, readable folder the helper would still refuse: whitespace splits a ReadWritePaths= list.
	spaced := filepath.Join(t.TempDir(), "my site")
	if err := os.Mkdir(spaced, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, kv := range map[string][]string{
		"node low port":            nodeForm(root, "port", "80"),
		"node no start":            nodeForm(root, "start_command", ""),
		"node overlong start":      nodeForm(root, "start_command", strings.Repeat("a", 2001)),
		"node missing folder":      nodeForm("/does/not/exist"),
		"node start line break":    nodeForm(root, "start_command", "node a\nUser=root"),
		"node folder with space":   nodeForm(spaced),
		"php folder with space":    phpForm(spaced),
		"php version not detected": phpForm(root, "fpm_version", "7.4"),
		"php no version":           phpForm(root, "fpm_version", ""),
	} {
		t.Run(name, func(t *testing.T) {
			if w := s.do(req{method: "POST", path: "/sites", body: form(kv...).Encode(), hdr: htmxPost}); w.Code != 422 {
				t.Fatalf("status %d %q", w.Code, w.Body.String())
			}
		})
	}
	if rs, _ := s.deps.Store.ListSites(context.Background()); len(rs) != 0 {
		t.Errorf("rejected forms left sites: %+v", rs)
	}
	if host.log() != "" {
		t.Errorf("rejected forms reached the helper: %q", host.log())
	}
}

// Two node apps cannot listen on the same loopback port: the second would fail to bind and its hostname
// would quietly serve the first app. Other kinds on that port number are unaffected.
func TestNodePortMustBeUnique(t *testing.T) {
	s, _ := runtimeServer(t)
	root := t.TempDir()
	if w := s.do(req{method: "POST", path: "/sites", body: form(nodeForm(root)...).Encode(), hdr: htmxPost}); w.Code != 204 {
		t.Fatalf("first node site: %d %q", w.Code, w.Body.String())
	}
	second := nodeForm(root, "hostnames", "other.example.com") // same port 3000
	w := s.do(req{method: "POST", path: "/sites", body: form(second...).Encode(), hdr: htmxPost})
	if w.Code != 409 || !strings.Contains(w.Body.String(), "3000") {
		t.Fatalf("duplicate port: %d %q", w.Code, w.Body.String())
	}
	if rs, _ := s.deps.Store.ListSites(context.Background()); len(rs) != 1 {
		t.Fatalf("duplicate-port site was saved: %+v", rs)
	}
	// A different port is fine; so is a proxy site that points at port 3000 elsewhere.
	if w := s.do(req{method: "POST", path: "/sites", body: form(nodeForm(root, "hostnames", "other.example.com", "port", "3001")...).Encode(), hdr: htmxPost}); w.Code != 204 {
		t.Fatalf("second node site on 3001: %d %q", w.Code, w.Body.String())
	}
	proxy := []string{"hostnames", "proxy.example.com", "scheme", "http", "upstream_host", "192.168.1.20", "upstream_port", "3000", "enabled", "on"}
	if w := s.do(req{method: "POST", path: "/sites", body: form(proxy...).Encode(), hdr: htmxPost}); w.Code != 204 {
		t.Fatalf("proxy site on port 3000: %d %q", w.Code, w.Body.String())
	}
	// Editing a node site keeps its own port without tripping the check against itself.
	rs, _ := s.deps.Store.ListSites(context.Background())
	var first store.Site
	for _, x := range rs {
		if x.Kind == "node" && x.UpstreamPort == 3000 {
			first = x
		}
	}
	edit := nodeForm(root, "hostnames", first.Hostnames[0], "start_command", "node app.js")
	if w := s.do(req{method: "PUT", path: "/sites/" + strconv.FormatInt(first.ID, 10), body: form(edit...).Encode(), hdr: htmxPost}); w.Code != 200 {
		t.Fatalf("edit keeping its own port: %d %q", w.Code, w.Body.String())
	}
}

func TestRuntimeSiteLifecycle(t *testing.T) {
	s, host := runtimeServer(t)
	w := s.do(req{method: "POST", path: "/sites", body: form(nodeForm(t.TempDir())...).Encode(), hdr: htmxPost})
	if w.Code != 204 {
		t.Fatalf("create: %d %q", w.Code, w.Body.String())
	}
	rs, _ := s.deps.Store.ListSites(context.Background())
	site := rs[0]
	host.mu.Lock()
	host.calls = nil
	host.mu.Unlock()

	// Toggle off: the unit is reinstalled and stopped, never left running behind a disabled route.
	if w := s.do(req{method: "POST", path: "/sites/" + strconv.FormatInt(site.ID, 10) + "/toggle", hdr: htmxPost}); w.Code != 204 {
		t.Fatalf("toggle: %d %q", w.Code, w.Body.String())
	}
	if !strings.HasSuffix(host.log(), "unit-stop "+site.Slug+" ") {
		t.Errorf("toggle off did not stop the unit: %q", host.log())
	}

	// Delete: unit then user, both torn down.
	host.mu.Lock()
	host.calls = nil
	host.mu.Unlock()
	if w := s.do(req{method: "DELETE", path: "/sites/" + strconv.FormatInt(site.ID, 10), hdr: htmxPost}); w.Code != 204 {
		t.Fatalf("delete: %d %q", w.Code, w.Body.String())
	}
	if want := "unit-remove " + site.Slug + " |user-remove " + site.Slug + " "; host.log() != want {
		t.Errorf("delete helper calls\n got %q\nwant %q", host.log(), want)
	}
}

// The edit page of a node or php site shows the unit's state and the tail of its journal. The journal is
// the app's own output, so it must be escaped; a proxy or static site shows no service panel at all.
func TestServicePanel(t *testing.T) {
	s, _ := runtimeServer(t)
	if w := s.do(req{method: "POST", path: "/sites", body: form(nodeForm(t.TempDir())...).Encode(), hdr: htmxPost}); w.Code != 204 {
		t.Fatalf("create: %d %q", w.Code, w.Body.String())
	}
	rs, _ := s.deps.Store.ListSites(context.Background())
	page := s.do(req{path: "/sites/" + strconv.FormatInt(rs[0].ID, 10)}).Body.String()
	for _, want := range []string{`id="service"`, "active (running)", "4242", "listening on 3000", "&lt;script&gt;alert(&#34;x&#34;)&lt;/script&gt;"} {
		if !strings.Contains(page, want) {
			t.Errorf("service panel missing %q", want)
		}
	}
	if strings.Contains(page, `<script>alert("x")`) {
		t.Error("journal text was not escaped")
	}

	// A dead helper: the page still renders, with a note instead of the panel body.
	s.deps.HelperSocket = filepath.Join(t.TempDir(), "absent.sock")
	page = s.do(req{path: "/sites/" + strconv.FormatInt(rs[0].ID, 10)}).Body.String()
	if !strings.Contains(page, `id="service"`) || !strings.Contains(page, "helper") {
		t.Errorf("no helper-unavailable note:\n%s", page)
	}

	// Proxy sites have no unit.
	s2, _ := runtimeServer(t)
	proxy := []string{"hostnames", "p.example.com", "scheme", "http", "upstream_host", "192.168.1.20", "upstream_port", "9000", "enabled", "on"}
	s2.do(req{method: "POST", path: "/sites", body: form(proxy...).Encode(), hdr: htmxPost})
	prs, _ := s2.deps.Store.ListSites(context.Background())
	if page := s2.do(req{path: "/sites/" + strconv.FormatInt(prs[0].ID, 10)}).Body.String(); strings.Contains(page, `id="service"`) {
		t.Error("proxy site shows a service panel")
	}
}

// A dead helper must not lose the site: it is saved, and the failure is a notice, not an error page.
func TestRuntimeSiteSurvivesHelperFailure(t *testing.T) {
	s, _ := runtimeServer(t)
	s.deps.HelperSocket = filepath.Join(t.TempDir(), "absent.sock")
	w := s.do(req{method: "POST", path: "/sites", body: form(nodeForm(t.TempDir())...).Encode(), hdr: htmxPost})
	if w.Code != 204 {
		t.Fatalf("create with dead helper: %d %q", w.Code, w.Body.String())
	}
	if rs, _ := s.deps.Store.ListSites(context.Background()); len(rs) != 1 {
		t.Fatalf("site lost: %+v", rs)
	}
	if body := s.do(req{path: "/"}).Body.String(); !strings.Contains(body, "runtime setup failed") {
		t.Errorf("no failure notice on the next page: %s", body)
	}
}

func frankenForm(root string, kv ...string) []string {
	return append([]string{"kind", "frankenphp", "static_root", root, "hostnames", "shop.example.com", "port", "8100", "enabled", "on"}, kv...)
}

func TestCreateFrankenPHPSite(t *testing.T) {
	s, host := runtimeServer(t)
	root := t.TempDir()
	w := s.do(req{method: "POST", path: "/sites", body: form(frankenForm(root)...).Encode(), hdr: htmxPost})
	if w.Code != 204 {
		t.Fatalf("create: %d %q", w.Code, w.Body.String())
	}
	rs, _ := s.deps.Store.ListSites(context.Background())
	if len(rs) != 1 {
		t.Fatalf("%+v", rs)
	}
	got := rs[0]
	if got.Kind != "frankenphp" || got.UpstreamHost != "127.0.0.1" || got.UpstreamPort != 8100 || got.StartCommand != "" || got.FPMVersion != "" || !got.HasUpstream() {
		t.Fatalf("frankenphp site stored wrong: %+v", got)
	}
	if want := "user-add " + got.Slug + " |unit-install " + got.Slug + " frankenphp|unit-start " + got.Slug + " "; host.log() != want {
		t.Errorf("helper calls\n got %q\nwant %q", host.log(), want)
	}
}

func TestFrankenPHPRejections(t *testing.T) {
	s, host := runtimeServer(t)
	root := t.TempDir()
	if w := s.do(req{method: "POST", path: "/sites", body: form(nodeForm(root)...).Encode(), hdr: htmxPost}); w.Code != 204 {
		t.Fatalf("node site: %d %q", w.Code, w.Body.String())
	}
	host.mu.Lock()
	host.calls = nil
	host.mu.Unlock()
	// Node and FrankenPHP share one loopback port space.
	if w := s.do(req{method: "POST", path: "/sites", body: form(frankenForm(root, "port", "3000")...).Encode(), hdr: htmxPost}); w.Code != 409 || !strings.Contains(w.Body.String(), "3000") {
		t.Fatalf("port shared with a node site: %d %q", w.Code, w.Body.String())
	}
	if w := s.do(req{method: "POST", path: "/sites", body: form(frankenForm(root, "port", "80")...).Encode(), hdr: htmxPost}); w.Code != 422 {
		t.Fatalf("low port: %d %q", w.Code, w.Body.String())
	}
	s.deps.Exec = runtimeExec{noFranken: true}
	if w := s.do(req{method: "POST", path: "/sites", body: form(frankenForm(root)...).Encode(), hdr: htmxPost}); w.Code != 422 || !strings.Contains(w.Body.String(), "not installed") {
		t.Fatalf("frankenphp missing: %d %q", w.Code, w.Body.String())
	}
	if rs, _ := s.deps.Store.ListSites(context.Background()); len(rs) != 1 {
		t.Errorf("rejected forms left sites: %+v", rs)
	}
	if host.log() != "" {
		t.Errorf("rejected forms reached the helper: %q", host.log())
	}
}

func fastcgiForm(root, addr string, kv ...string) []string {
	return append([]string{"kind", "fastcgi", "static_root", root, "hostnames", "legacy.example.com", "fcgi_addr", addr, "enabled", "on"}, kv...)
}

func TestFastCGISites(t *testing.T) {
	s, host := runtimeServer(t)
	root := t.TempDir()
	for i, tt := range []struct {
		addr, host string
		port       int
	}{{"/run/myapp/fcgi.sock", "/run/myapp/fcgi.sock", 0}, {"10.0.0.5:9000", "10.0.0.5", 9000}} {
		name := []string{"a.example.com", "b.example.com"}[i]
		if w := s.do(req{method: "POST", path: "/sites", body: form(fastcgiForm(root, tt.addr, "hostnames", name)...).Encode(), hdr: htmxPost}); w.Code != 204 {
			t.Fatalf("create %s: %d %q", tt.addr, w.Code, w.Body.String())
		}
		rs, _ := s.deps.Store.ListSites(context.Background())
		got := rs[i]
		if got.Kind != "fastcgi" || got.UpstreamHost != tt.host || got.UpstreamPort != tt.port || got.HasUpstream() || got.IsRuntime() {
			t.Errorf("fastcgi %s stored wrong: %+v", tt.addr, got)
		}
	}
	if host.log() != "" { // ServanaGo supervises nothing for this kind
		t.Errorf("fastcgi reached the helper: %q", host.log())
	}
	for name, addr := range map[string]string{
		"relative path": "run/app.sock", "traversal": "/run/../etc/x.sock", "space in path": "/run/my app.sock",
		"no port": "10.0.0.5", "port zero": "10.0.0.5:0", "port too big": "10.0.0.5:70000", "bad host": "bad host:9000", "empty": "",
	} {
		t.Run(name, func(t *testing.T) {
			if w := s.do(req{method: "POST", path: "/sites", body: form(fastcgiForm(root, addr, "hostnames", "c.example.com")...).Encode(), hdr: htmxPost}); w.Code != 422 {
				t.Fatalf("%q accepted: %d %q", addr, w.Code, w.Body.String())
			}
		})
	}
}

func TestCreateCGISite(t *testing.T) {
	s, host := runtimeServer(t)
	root := t.TempDir()
	form := form("kind", "cgi", "static_root", root, "hostnames", "cgi.example.com", "enabled", "on")
	if w := s.do(req{method: "POST", path: "/sites", body: form.Encode(), hdr: htmxPost}); w.Code != 204 {
		t.Fatalf("create: %d %q", w.Code, w.Body.String())
	}
	rs, _ := s.deps.Store.ListSites(context.Background())
	if len(rs) != 1 || rs[0].Kind != "cgi" || rs[0].UpstreamHost != "" || !rs[0].IsRuntime() {
		t.Fatalf("cgi site stored wrong: %+v", rs)
	}
	slug := rs[0].Slug
	if want := "user-add " + slug + " |unit-install " + slug + " cgi|unit-start " + slug + " "; host.log() != want {
		t.Errorf("helper calls\n got %q\nwant %q", host.log(), want)
	}
	s.deps.Exec = runtimeExec{noFCGI: true}
	form.Set("hostnames", "other.example.com")
	if w := s.do(req{method: "POST", path: "/sites", body: form.Encode(), hdr: htmxPost}); w.Code != 422 || !strings.Contains(w.Body.String(), "fcgiwrap") {
		t.Fatalf("fcgiwrap missing: %d %q", w.Code, w.Body.String())
	}
}
