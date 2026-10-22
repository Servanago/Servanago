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

// userHost is a fake helper that records every call with its spec and knows which users exist.
type userHost struct {
	mu    sync.Mutex
	calls []string
	specs map[string][]helper.Spec
	users map[string]helper.UserData
}

func (h *userHost) log() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return strings.Join(h.calls, "|")
}

func (h *userHost) last(action string) helper.Spec {
	h.mu.Lock()
	defer h.mu.Unlock()
	if s := h.specs[action]; len(s) > 0 {
		return s[len(s)-1]
	}
	return helper.Spec{}
}

func (h *userHost) act(name string, f func(helper.Request) helper.Response) helper.Action {
	return func(r helper.Request) helper.Response {
		h.mu.Lock()
		h.calls = append(h.calls, name)
		h.specs[name] = append(h.specs[name], r.Vals)
		h.mu.Unlock()
		return f(r)
	}
}

func userServer(t *testing.T) (*Server, *userHost) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	h := &userHost{specs: map[string][]helper.Spec{}, users: map[string]helper.UserData{}}
	ok := func(helper.Request) helper.Response { return helper.Response{OK: true} }
	ln, err := net.Listen("unix", filepath.Join(t.TempDir(), "h.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go helper.Serve(ln, func(helper.Peer) bool { return true }, map[string]helper.Action{
		helper.ActionPing: func(helper.Request) helper.Response { return helper.Response{OK: true} },
		helper.ActionUserCheck: h.act("user-check", func(r helper.Request) helper.Response {
			h.mu.Lock()
			u := h.users[r.Vals.User]
			h.mu.Unlock()
			return helper.Response{OK: true, User: &u}
		}),
		helper.ActionUserAdd: h.act("user-add", func(r helper.Request) helper.Response {
			if r.Vals.User == "" {
				return helper.Response{OK: true}
			}
			h.mu.Lock()
			u := h.users[r.Vals.User]
			h.mu.Unlock()
			if !u.Exists {
				u = helper.UserData{Exists: true, Home: r.Vals.Home, Group: r.Vals.User, Login: r.Vals.Shell}
			}
			return helper.Response{OK: true, User: &u}
		}),
		helper.ActionUserRemove:     h.act("user-remove", ok),
		helper.ActionUnitInstall:    h.act("unit-install", ok),
		helper.ActionUnitRemove:     h.act("unit-remove", ok),
		helper.ActionUnitStart:      h.act("unit-start", ok),
		helper.ActionUnitStop:       h.act("unit-stop", ok),
		helper.ActionPHPUserDefault: h.act("php-user-default", ok),
		helper.ActionUnitStatus: func(helper.Request) helper.Response {
			return helper.Response{OK: true, Status: &helper.StatusData{ActiveState: "active", SubState: "running"}}
		},
		helper.ActionUnitLogs: func(helper.Request) helper.Response { return helper.Response{OK: true} },
	})
	cfg := config.Config{DataDir: t.TempDir(), Host: "panel.example.com"}
	return New(Deps{Cfg: cfg, Store: st, Apply: txApplier{st}, HelperSocket: ln.Addr().String(), Exec: runtimeExec{}}), h
}

func postUserSite(s *Server, kv ...string) (int, string) {
	w := s.do(req{method: "POST", path: "/sites", body: form(kv...).Encode(), hdr: htmxPost})
	return w.Code, w.Body.String()
}

func onlySite(t *testing.T, s *Server) store.Site {
	t.Helper()
	rs, _ := s.deps.Store.ListSites(context.Background())
	if len(rs) != 1 {
		t.Fatalf("want one site, have %+v", rs)
	}
	return rs[0]
}

func TestCreatePHPSiteWithANewUser(t *testing.T) {
	s, h := userServer(t)
	code, body := postUserSite(s, "kind", "php", "hostnames", "luckyedward.com", "fpm_version", "8.2", "enabled", "on",
		"user_mode", "create", "public_dir", "public", "shell_login", "on")
	if code != 204 {
		t.Fatalf("create: %d %q", code, body)
	}
	got := onlySite(t, s)
	if got.SiteUser != "luckyedward.com" || got.StaticRoot != "/home/luckyedward.com/public_html" || got.PublicDir != "public" {
		t.Fatalf("stored wrong: %+v", got)
	}
	if want := "user-check|user-add|unit-install|php-user-default|unit-start"; h.log() != want {
		t.Errorf("helper calls\n got %q\nwant %q", h.log(), want)
	}
	add := h.last("user-add")
	if add.User != "luckyedward.com" || add.Home != "/home/luckyedward.com" || add.Root != got.StaticRoot || add.Public != "public" || !add.Shell {
		t.Errorf("user-add spec %+v", add)
	}
	if inst := h.last("unit-install"); inst.User != "luckyedward.com" || inst.Public != "public" || inst.Kind != "php" {
		t.Errorf("unit-install spec %+v", inst)
	}
	if d := h.last("php-user-default"); d.User != "luckyedward.com" || d.PHPVersion != "8.2" || d.Slug != got.Slug {
		t.Errorf("php-user-default spec %+v", d)
	}
}

func TestNoLoginShellLeavesThePHPDefaultAlone(t *testing.T) {
	s, h := userServer(t)
	if code, body := postUserSite(s, "kind", "php", "hostnames", "luckyedward.com", "fpm_version", "8.2", "enabled", "on", "user_mode", "create"); code != 204 {
		t.Fatalf("%d %q", code, body)
	}
	if strings.Contains(h.log(), "php-user-default") {
		t.Errorf("a nologin user has no command line: %s", h.log())
	}
	if h.last("user-add").Shell {
		t.Error("the shell was not asked for")
	}
}

func TestCreateStaticSiteWithAUserIsServedByAUnit(t *testing.T) {
	s, h := userServer(t)
	if code, body := postUserSite(s, "kind", "static", "hostnames", "docs.example.com", "enabled", "on", "user_mode", "create"); code != 204 {
		t.Fatalf("%d %q", code, body)
	}
	got := onlySite(t, s)
	if got.SiteUser != "docs.example.com" || !got.IsRuntime() {
		t.Fatalf("%+v", got)
	}
	if inst := h.last("unit-install"); inst.Kind != "static" || inst.User != "docs.example.com" {
		t.Errorf("unit-install spec %+v", inst)
	}
}

func TestExistingUserSite(t *testing.T) {
	s, h := userServer(t)
	h.users["bob"] = helper.UserData{Exists: true, Home: "/home/bob", Group: "bob", Login: true}
	if code, body := postUserSite(s, "kind", "node", "hostnames", "bob.example.com", "port", "3000", "start_command", "node a.js", "enabled", "on",
		"user_mode", "existing", "site_user", "bob", "static_root", "/home/bob/app"); code != 204 {
		t.Fatalf("%d %q", code, body)
	}
	if got := onlySite(t, s); got.SiteUser != "bob" || got.StaticRoot != "/home/bob/app" {
		t.Errorf("%+v", got)
	}
	if add := h.last("user-add"); add.User != "bob" || add.Home != "" {
		t.Errorf("an existing user is checked, not created: %+v", add)
	}
}

func TestUserSiteRejections(t *testing.T) {
	base := func(kv ...string) []string {
		return append([]string{"kind", "php", "hostnames", "luckyedward.com", "fpm_version", "8.2", "enabled", "on"}, kv...)
	}
	bob := map[string]helper.UserData{"bob": {Exists: true, Home: "/home/bob"}}
	tests := []struct {
		name   string
		kv     []string
		users  map[string]helper.UserData
		status int
		want   string
	}{
		{"digit start needs a typed name", base("hostnames", "123.example.com", "user_mode", "create"), nil, 422, "start with a letter"},
		{"existing user missing", base("user_mode", "existing", "site_user", "ghost", "static_root", "/home/ghost/x"), nil, 422, "does not exist"},
		{"existing needs a name", base("user_mode", "existing", "static_root", "/home/bob/x"), nil, 422, "user"},
		{"create over an existing user", base("user_mode", "create", "site_user", "bob"), bob, 422, "already exists"},
		{"folder outside the home", base("user_mode", "existing", "site_user", "bob", "static_root", "/srv/other"), bob, 422, "inside"},
		{"bad typed name", base("user_mode", "create", "site_user", "Bad Name"), nil, 422, "user"},
		{"bad public folder", base("user_mode", "create", "public_dir", "../x"), nil, 422, "public"},
		{"public folder on node", []string{"kind", "node", "hostnames", "n.example.com", "port", "3000", "start_command", "x", "static_root", t.TempDir(), "public_dir", "public"}, nil, 422, "public"},
		{"home outside /home", base("user_mode", "create", "user_home", "/etc/x"), nil, 422, "home"},
		{"unknown mode", base("user_mode", "root"), nil, 422, "user_mode"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, h := userServer(t)
			for k, v := range tt.users {
				h.users[k] = v
			}
			code, body := postUserSite(s, tt.kv...)
			if code != tt.status || !strings.Contains(body, tt.want) {
				t.Fatalf("%d %q, want %d mentioning %q", code, body, tt.status, tt.want)
			}
			if rs, _ := s.deps.Store.ListSites(context.Background()); len(rs) != 0 {
				t.Errorf("a rejected form saved %+v", rs)
			}
			if strings.Contains(h.log(), "user-add") || strings.Contains(h.log(), "unit-install") {
				t.Errorf("a rejected form changed the host: %s", h.log())
			}
		})
	}
}

func TestOneSitePerUser(t *testing.T) {
	s, h := userServer(t)
	h.users["bob"] = helper.UserData{Exists: true, Home: "/home/bob", Group: "bob", Login: true}
	one := []string{"kind", "php", "fpm_version", "8.2", "enabled", "on", "user_mode", "existing", "site_user", "bob", "static_root", "/home/bob/one"}
	if code, body := postUserSite(s, append(one, "hostnames", "one.example.com")...); code != 204 {
		t.Fatalf("first: %d %q", code, body)
	}
	code, body := postUserSite(s, append(one, "hostnames", "two.example.com")...)
	if code != 409 || !strings.Contains(body, "bob") {
		t.Fatalf("second site for the same user: %d %q", code, body)
	}
}

func TestUserSiteEditKeepsItsUser(t *testing.T) {
	s, h := userServer(t)
	if code, body := postUserSite(s, "kind", "php", "hostnames", "luckyedward.com", "fpm_version", "8.2", "enabled", "on", "user_mode", "create", "shell_login", "on"); code != 204 {
		t.Fatalf("%d %q", code, body)
	}
	site := onlySite(t, s)
	h.mu.Lock()
	h.users["luckyedward.com"] = helper.UserData{Exists: true, Home: "/home/luckyedward.com", Group: "luckyedward.com", Login: true}
	h.mu.Unlock()
	// The edit form posts no user fields (the user cannot change); the site keeps it and the host is checked again.
	edit := []string{"kind", "php", "hostnames", "luckyedward.com", "fpm_version", "8.2", "enabled", "on", "static_root", site.StaticRoot, "public_dir", "web"}
	w := s.do(req{method: "PUT", path: "/sites/" + strconv.FormatInt(site.ID, 10), body: form(edit...).Encode(), hdr: htmxPost})
	if w.Code != 200 {
		t.Fatalf("edit: %d %q", w.Code, w.Body.String())
	}
	got := onlySite(t, s)
	if got.SiteUser != "luckyedward.com" || got.PublicDir != "web" {
		t.Errorf("%+v", got)
	}
	if inst := h.last("unit-install"); inst.User != "luckyedward.com" || inst.Public != "web" {
		t.Errorf("unit-install spec %+v", inst)
	}
}

// Deleting a site stops its unit and clears the command line php, but the user stays for the admin to remove.
func TestDeleteUserSiteKeepsTheUser(t *testing.T) {
	s, h := userServer(t)
	if code, body := postUserSite(s, "kind", "php", "hostnames", "luckyedward.com", "fpm_version", "8.2", "enabled", "on", "user_mode", "create", "shell_login", "on"); code != 204 {
		t.Fatalf("%d %q", code, body)
	}
	site := onlySite(t, s)
	h.mu.Lock()
	h.calls = nil
	h.mu.Unlock()
	w := s.do(req{method: "DELETE", path: "/sites/" + strconv.FormatInt(site.ID, 10), hdr: htmxPost})
	if w.Code != 204 {
		t.Fatalf("delete: %d %q", w.Code, w.Body.String())
	}
	if strings.Contains(h.log(), "user-remove") || !strings.Contains(h.log(), "unit-remove") || !strings.Contains(h.log(), "php-user-default") {
		t.Errorf("delete calls: %s", h.log())
	}
	if d := h.last("php-user-default"); d.User != "luckyedward.com" || d.PHPVersion != "" {
		t.Errorf("the command line php was not cleared: %+v", d)
	}
}

// A generated-user site is removed with its user, as before.
func TestDeleteGeneratedUserSiteRemovesTheUser(t *testing.T) {
	s, h := userServer(t)
	if code, body := postUserSite(s, "kind", "php", "hostnames", "blog.example.com", "fpm_version", "8.2", "enabled", "on", "static_root", t.TempDir()); code != 204 {
		t.Fatalf("%d %q", code, body)
	}
	site := onlySite(t, s)
	if w := s.do(req{method: "DELETE", path: "/sites/" + strconv.FormatInt(site.ID, 10), hdr: htmxPost}); w.Code != 204 {
		t.Fatalf("delete: %d", w.Code)
	}
	if !strings.Contains(h.log(), "user-remove") || strings.Contains(h.log(), "php-user-default") {
		t.Errorf("delete calls: %s", h.log())
	}
}

// The form offers the user choice only when the helper can act on it, and preselects "create" for a new site.
func TestFormOffersUsersOnlyWithAHelper(t *testing.T) {
	s, _ := userServer(t)
	body := s.do(req{path: "/sites/new"}).Body.String()
	if !strings.Contains(body, `name="user_mode"`) || !strings.Contains(body, `value="create" checked`) {
		t.Errorf("with a helper the form lacks the user choice:\n%s", body)
	}
	bare := newServer(t, "pw")
	bare.deps.HelperSocket = filepath.Join(t.TempDir(), "none.sock")
	ck := cookiesOf(t, login(bare, "pw", nil, ""))
	w := bare.do(req{path: "/sites/new", cookies: ck})
	if strings.Contains(w.Body.String(), `name="user_mode"`) {
		t.Error("without a helper the form must not offer a user")
	}
}
