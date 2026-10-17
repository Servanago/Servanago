package web

import (
	"context"
	"net"
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
type runtimeExec struct{}

func (runtimeExec) LookupPath(string) (string, error) { return "/usr/bin/node", nil }
func (runtimeExec) Run(context.Context, string, ...string) ([]byte, error) {
	return []byte("v20.11.0\n"), nil
}
func (runtimeExec) Glob(p string) ([]string, error) {
	if p == "/usr/sbin/php-fpm*" {
		return []string{"/usr/sbin/php-fpm8.2"}, nil
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
	for name, kv := range map[string][]string{
		"node low port":            nodeForm(root, "port", "80"),
		"node no start":            nodeForm(root, "start_command", ""),
		"node overlong start":      nodeForm(root, "start_command", strings.Repeat("a", 2001)),
		"node missing folder":      nodeForm("/does/not/exist"),
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
