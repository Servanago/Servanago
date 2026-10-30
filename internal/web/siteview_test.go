package web

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/servanago/servanago/internal/config"
	"github.com/servanago/servanago/internal/store"
)

// siteTabsAll is the tab rail of the site view, settings first (it lives on /sites/{id} itself).
var siteTabsAll = []string{"settings", "dns", "ssl", "scan", "backups", "mail", "snippets", "runtime", "gate", "routes", "countries"}

// signedIn makes a server with one static site full of facts and returns the admin's cookies.
func signedIn(t *testing.T) (*Server, int64, []*http.Cookie) {
	return signedWith(t, store.Site{
		Hostnames:   []string{"tabs.example.com", "www.tabs.example.com"},
		Kind:        "static",
		StaticRoot:  "/srv/www/tabs",
		Enabled:     true,
		ExtraRoutes: "/api=127.0.0.1:3011\n/old=127.0.0.1:3012",
		CountryMode: "deny",
		Countries:   "RU IR",
		GateMode:    "open",
		Notes:       "note body",
	})
}

// signedWith makes a server with Apply wired and an arbitrary site signed in as the admin.
func signedWith(t *testing.T, rt store.Site) (*Server, int64, []*http.Cookie) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cfg := config.Config{AdminPassword: "pw", SecretKey: strings.Repeat("k", 32)}
	s := New(Deps{Cfg: cfg, Store: st, Apply: txApplier{st}})
	w := s.do(req{method: "POST", path: "/login", body: url.Values{"username": {"admin"}, "password": {"pw"}}.Encode(),
		hdr: map[string]string{"HX-Request": "true", "Origin": "https://servanago.example.com", "X-Forwarded-Proto": "https"}})
	if w.Code != 204 {
		t.Fatalf("login: %d", w.Code)
	}
	got, err := s.deps.Store.CreateSite(context.Background(), rt)
	if err != nil {
		t.Fatal(err)
	}
	return s, got.ID, cookiesOf(t, w)
}

// wantTab asserts each tab path renders its panel.
func TestSiteTabsRender(t *testing.T) {
	s, id, ck := signedIn(t)
	want := map[string]string{
		"dns":       "panel-dns", // without Cloudflare the tab explains itself
		"ssl":       "panel-ssl",
		"scan":      "panel-scan",
		"backups":   "panel-backups",
		"mail":      "panel-mail",
		"snippets":  "panel-snippets",
		"runtime":   "panel-runtime",
		"gate":      "panel-gate",
		"routes":    "127.0.0.1:3011",
		"countries": "RU, IR",
	}
	for _, tab := range siteTabsAll {
		if tab == "settings" {
			continue
		}
		w := s.do(req{path: fmt.Sprintf("/sites/%d/%s", id, tab), cookies: ck})
		if w.Code != 200 {
			t.Errorf("%s: %d", tab, w.Code)
			continue
		}
		if !strings.Contains(w.Body.String(), "panel-"+tab) {
			t.Errorf("%s: panel marker missing:\n%s", tab, w.Body.String())
		}
		if mark := want[tab]; mark != "" && !strings.Contains(w.Body.String(), mark) {
			t.Errorf("%s: marker %q missing", tab, mark)
		}
	}
}

// TestSiteEditorHasTheRail keeps the full editor on /sites/{id} with the tabs above it.
func TestSiteEditorHasTheRail(t *testing.T) {
	s, id, ck := signedIn(t)
	body := s.do(req{path: fmt.Sprintf("/sites/%d", id), cookies: ck}).Body.String()
	for _, tab := range siteTabsAll {
		if !strings.Contains(body, `href="/sites/`+fmt.Sprint(id)+`/`+tab+`"`) {
			t.Errorf("settings page: no link to %s", tab)
		}
	}
	for _, mark := range []string{"Save</button>", "</form>", "panel-settings"} {
		if !strings.Contains(body, mark) {
			t.Errorf("settings page: %q missing", mark)
		}
	}
}

func TestSiteTabUnknownOrMissingFails(t *testing.T) {
	s, id, ck := signedIn(t)
	for _, path := range []string{"/sites/" + fmt.Sprint(id) + "/nope", "/sites/999/dns", "/sites/0x/dns", "/sites/new/dns"} {
		if w := s.do(req{path: path, cookies: ck}); w.Code != http.StatusNotFound {
			t.Errorf("%s: got %d", path, w.Code)
		}
	}
}

// TestBackRedirectOfActions only changes redirect targets: with back the row lands on the calling tab.
func TestBackRedirectOfActions(t *testing.T) {
	s, id, ck := signedIn(t)

	w := s.do(req{method: "POST", path: fmt.Sprintf("/sites/%d/gate/grants", id), cookies: ck,
		hdr: htmxPost, body: url.Values{"rule": {"alice@example.com"}, "back": {"/sites/" + fmt.Sprint(id) + "/gate"}}.Encode()})
	if got := w.Header().Get("HX-Redirect"); got != "/sites/"+fmt.Sprint(id)+"/gate" {
		t.Errorf("grant add back redirect: %q", got)
	}
	w = s.do(req{method: "POST", path: fmt.Sprintf("/sites/%d/gate/grants", id), cookies: ck,
		hdr: htmxPost, body: url.Values{"rule": {"bob@example.com"}}.Encode()})
	if got := w.Header().Get("HX-Redirect"); got != fmt.Sprintf("/sites/%d", id) {
		t.Errorf("grant add default redirect: %q", got)
	}

	w = s.do(req{method: "POST", path: fmt.Sprintf("/backups/sites/%d", id), cookies: ck,
		hdr: htmxPost, body: url.Values{"on": {"1"}, "back": {"/sites/" + fmt.Sprint(id) + "/backups"}}.Encode()})
	if got := w.Header().Get("HX-Redirect"); got != "/sites/"+fmt.Sprint(id)+"/backups" {
		t.Errorf("backup save back redirect: %q", got)
	}
	if _, err := s.deps.Store.GetSiteBackup(context.Background(), id); err != nil {
		t.Errorf("backup row: %v", err)
	}
	w = s.do(req{method: "POST", path: fmt.Sprintf("/backups/sites/%d", id), cookies: ck,
		hdr: htmxPost, body: url.Values{"s sched": {"on"}}.Encode()})
	if got := w.Header().Get("HX-Redirect"); got != "/backups" {
		t.Errorf("backup save default redirect: %q", got)
	}
}

// The moved access and gate sections are saved from their tabs; the editor's PUT must not clear
// what its form no longer carries.

func TestPutPreservesAccessSections(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "keep"), 0o755); err != nil {
		t.Fatal(err)
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte("keep pw"), bcrypt.MinCost)
	s, id, _ := signedWith(t, store.Site{
		Hostnames: []string{"keep.example.com"}, Kind: "static", StaticRoot: filepath.Join(root, "keep"), Enabled: true,
		Allowlist: "192.168.0.0/16",
		BasicUser: "ops", BasicHash: string(hash),
		GateFrom: "keep@example.com", GateProvider: "smtp", GateSMTPHost: "smtp.example.com",
		Notes: "kept",
	})
	ck := cookiesOf(t, login(s, "pw", map[string]string{"X-Forwarded-Proto": "https"}, ""))
	w := s.do(req{method: "PUT", path: fmt.Sprintf("/sites/%d", id), cookies: ck, hdr: htmxPost,
		body: url.Values{"hostnames": {"keep.example.com"}, "kind": {"static"}, "static_root": {filepath.Join(root, "keep")},
			"enabled": {"1"}, "user_mode": {""}, "site_user": {""}, "public_dir": {""}}.Encode()})
	if w.Code != 200 {
		t.Fatalf("PUT: %d %s", w.Code, w.Body.String())
	}
	rt, err := s.deps.Store.GetSite(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if rt.Allowlist != "192.168.0.0/16" || rt.BasicUser != "ops" {
		t.Errorf("access moved but reset: allowlist=%q user=%q", rt.Allowlist, rt.BasicUser)
	}
	if rt.GateFrom != "keep@example.com" || rt.GateProvider != "smtp" || rt.GateMode != "" {
		t.Errorf("gate moved but reset: mode=%q from=%q", rt.GateMode, rt.GateFrom)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(rt.BasicHash), []byte("keep pw")); err != nil {
		t.Errorf("basic hash not preserved: %v (user %q)", err, rt.BasicUser)
	}
}

func TestGateScopedSave(t *testing.T) {
	cf := &cfFake{zones: zonesOK}
	s := cfgServer(t, cf, config.Config{AdminPassword: "pw", SecretKey: strings.Repeat("k", 32)})
	w := login(s, "pw", map[string]string{"X-Forwarded-Proto": "https"}, "")
	ck := cookiesOf(t, w)
	if w.Code != 204 {
		t.Fatalf("login: %d", w.Code)
	}
	rt, err := s.deps.Store.CreateSite(context.Background(), store.Site{Hostnames: []string{"g.example.com"}, Kind: "static", StaticRoot: "/srv/www/g"})
	if err != nil {
		t.Fatal(err)
	}
	id := rt.ID
	// unknown mode is refused in place
	w2 := s.do(req{method: "POST", path: fmt.Sprintf("/sites/%d/gate", id), cookies: ck, hdr: htmxPost,
		body: url.Values{"gate_mode": {"pigeon"}}.Encode()})
	if w2.Code != http.StatusUnprocessableEntity {
		t.Fatalf("bad mode: %d %s", w2.Code, w2.Body.String())
	}
	// a valid save keeps the mode and mail block
	w2 = s.do(req{method: "POST", path: fmt.Sprintf("/sites/%d/gate", id), cookies: ck, hdr: htmxPost,
		body: url.Values{"gate_mode": {"acl"}, "gate_provider": {"smtp"}, "gate_from": {"gate@example.com"},
			"gate_smtp_host": {"smtp.example.com"}, "gate_smtp_port": {"2525"}}.Encode()})
	if w2.Code != 200 {
		t.Fatalf("acl save: %d %s", w2.Code, w2.Body.String())
	}
	cur, _ := s.deps.Store.GetSite(context.Background(), id)
	if cur.GateMode != "acl" || cur.GateFrom != "gate@example.com" || cur.GateSMTPPort != 2525 {
		t.Errorf("scoped gate save: %+v", cur)
	}
	// acl on a site without a mail provider is refused
	rt2, err := s.deps.Store.CreateSite(context.Background(), store.Site{Hostnames: []string{"g2.example.com"}, Kind: "static", StaticRoot: "/srv/www/g2"})
	if err != nil {
		t.Fatal(err)
	}
	w2 = s.do(req{method: "POST", path: fmt.Sprintf("/sites/%d/gate", rt2.ID), cookies: ck, hdr: htmxPost,
		body: url.Values{"gate_mode": {"acl"}, "gate_provider": {""}}.Encode()})
	if w2.Code != http.StatusUnprocessableEntity {
		t.Errorf("acl without provider: %d %s", w2.Code, w2.Body.String())
	}
}

func TestAccessScopedSave(t *testing.T) {
	s, id, ck := signedWith(t, store.Site{Hostnames: []string{"acc.example.com"}, Kind: "static", StaticRoot: "/srv/www/acc"})
	w := s.do(req{method: "POST", path: fmt.Sprintf("/sites/%d/access", id), cookies: ck, hdr: htmxPost,
		body: url.Values{"allowlist": {"10.0.0.1 \n 10.0.0.0/24"}, "basic_user": {"ops"}, "basic_password": {"s3cret"}}.Encode()})
	if w.Code != 200 {
		t.Fatalf("access save: %d %s", w.Code, w.Body.String())
	}
	rt, _ := s.deps.Store.GetSite(context.Background(), id)
	if rt.Allowlist != "10.0.0.1/32\n10.0.0.0/24" {
		t.Errorf("allowlist: %q", rt.Allowlist)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(rt.BasicHash), []byte("s3cret")); err != nil {
		t.Errorf("basic hash: %v", err)
	}
	// a bad CIDR is refused in place
	w = s.do(req{method: "POST", path: fmt.Sprintf("/sites/%d/access", id), cookies: ck, hdr: htmxPost,
		body: url.Values{"allowlist": {"not-an-ip"}}.Encode()})
	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("bad cidr: %d", w.Code)
	}
}

func TestMailScopedSave(t *testing.T) {
	s, id, ck := signedWith(t, store.Site{Hostnames: []string{"m.example.com"}, Kind: "static", StaticRoot: "/srv/www/m"})
	w := s.do(req{method: "POST", path: fmt.Sprintf("/sites/%d/mail", id), cookies: ck, hdr: htmxPost,
		body: url.Values{"gate_provider": {"smtp"}, "gate_from": {"mail@m.example.com"},
			"gate_smtp_host": {"smtp.example.com"}, "gate_smtp_port": {"587"}, "gate_secret": {"postal-horse"}}.Encode()})
	if w.Code != 200 {
		t.Fatalf("mail save: %d %s", w.Code, w.Body.String())
	}
	rt, _ := s.deps.Store.GetSite(context.Background(), id)
	if rt.GateProvider != "smtp" || rt.GateSMTPHost != "smtp.example.com" || rt.GateSecret == nil {
		t.Fatalf("mail block: %+v", rt)
	}
	// a blank secret keeps the stored one
	w = s.do(req{method: "POST", path: fmt.Sprintf("/sites/%d/mail", id), cookies: ck, hdr: htmxPost,
		body: url.Values{"gate_provider": {"smtp"}, "gate_from": {"mail@m.example.com"}, "gate_smtp_host": {"smtp.example.com"}}.Encode()})
	if w.Code != 200 {
		t.Fatalf("mail re-save: %d", w.Code)
	}
	rt2, _ := s.deps.Store.GetSite(context.Background(), id)
	if string(rt2.GateSecret) == "" || string(rt.GateSecret) != string(rt2.GateSecret) {
		t.Error("stored secret not kept across a blank-password save")
	}
}

// The last four sections: snippets, routes (+ tuning), countries, per-site DNS record IPs.

func TestSnippetsScopedSave(t *testing.T) {
	s, id, ck := signedWith(t, store.Site{Hostnames: []string{"snp.example.com"}, Kind: "static", StaticRoot: "/srv/www/snp"})
	ctx := context.Background()
	if _, err := s.deps.Store.CreateSnippet(ctx, "sec-headers", "header X-A 1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.deps.Store.CreateSnippet(ctx, "rate-limit", "rate_limit 1/m"); err != nil {
		t.Fatal(err)
	}
	w := s.do(req{method: "POST", path: fmt.Sprintf("/sites/%d/snippets", id), cookies: ck, hdr: htmxPost,
		body: url.Values{"snippets": {"sec-headers", "rate-limit", ""}}.Encode()})
	if w.Code != 200 {
		t.Fatalf("attach: %d %s", w.Code, w.Body.String())
	}
	rt, _ := s.deps.Store.GetSite(ctx, id)
	if len(rt.Snippets) != 2 || rt.Snippets[0] != "rate-limit" || rt.Snippets[1] != "sec-headers" {
		t.Fatalf("attached: %v", rt.Snippets)
	}
	// an unknown name is refused, nothing changes
	w = s.do(req{method: "POST", path: fmt.Sprintf("/sites/%d/snippets", id), cookies: ck, hdr: htmxPost,
		body: url.Values{"snippets": {"ghost"}}.Encode()})
	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("unknown snippet: %d %s", w.Code, w.Body.String())
	}
	if cur, _ := s.deps.Store.GetSite(ctx, id); len(cur.Snippets) != 2 {
		t.Errorf("unknown snippet changed the rows: %v", cur.Snippets)
	}
	// detaching everything clears (the form always carries the empty sentinel)
	w = s.do(req{method: "POST", path: fmt.Sprintf("/sites/%d/snippets", id), cookies: ck, hdr: htmxPost,
		body: url.Values{"snippets": {""}}.Encode()})
	if w.Code != 200 {
		t.Fatalf("detach: %d", w.Code)
	}
	if rt, _ = s.deps.Store.GetSite(ctx, id); len(rt.Snippets) != 0 {
		t.Errorf("still attached: %v", rt.Snippets)
	}
}

func TestRoutesScopedSave(t *testing.T) {
	s, id, ck := signedWith(t, store.Site{Hostnames: []string{"rte.example.com"}, Kind: "static", StaticRoot: "/srv/www/rte"})
	w := s.do(req{method: "POST", path: fmt.Sprintf("/sites/%d/routes", id), cookies: ck, hdr: htmxPost,
		body: url.Values{"extra_routes": {"/api=127.0.0.1:3011"}, "stream": {"on"}, "max_body": {"2GB"}, "tls_skip_verify": {"on"}}.Encode()})
	if w.Code != 200 {
		t.Fatalf("routes save: %d %s", w.Code, w.Body.String())
	}
	rt, _ := s.deps.Store.GetSite(context.Background(), id)
	if rt.ExtraRoutes != "/api=127.0.0.1:3011" || rt.Stream != true || rt.MaxBody != 2<<30 {
		t.Fatalf("routes: %q %v %d", rt.ExtraRoutes, rt.Stream, rt.MaxBody)
	}
	w = s.do(req{method: "POST", path: fmt.Sprintf("/sites/%d/routes", id), cookies: ck, hdr: htmxPost,
		body: url.Values{"extra_routes": {"/api=nonsense"}}.Encode()})
	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("bad route: %d %s", w.Code, w.Body.String())
	}
}

func TestGeoScopedSave(t *testing.T) {
	s, id, ck := signedWith(t, store.Site{Hostnames: []string{"geo.example.com"}, Kind: "static", StaticRoot: "/srv/www/geo"})
	w := s.do(req{method: "POST", path: fmt.Sprintf("/sites/%d/geo", id), cookies: ck, hdr: htmxPost,
		body: url.Values{"country_mode": {"deny"}, "countries": {"RU, IR"}}.Encode()})
	if w.Code != 200 {
		t.Fatalf("geo save: %d %s", w.Code, w.Body.String())
	}
	rt, _ := s.deps.Store.GetSite(context.Background(), id)
	if rt.CountryMode != "deny" || rt.Countries != "RU IR" {
		t.Fatalf("geo: %q %q", rt.CountryMode, rt.Countries)
	}
	w = s.do(req{method: "POST", path: fmt.Sprintf("/sites/%d/geo", id), cookies: ck, hdr: htmxPost,
		body: url.Values{"country_mode": {"deny"}, "countries": {"USA"}}.Encode()})
	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("bad code: %d %s", w.Code, w.Body.String())
	}
}

func TestDNSIpScopedSave(t *testing.T) {
	s, id, ck := signedWith(t, store.Site{Hostnames: []string{"ip.example.com"}, Kind: "static", StaticRoot: "/srv/www/ip"})
	w := s.do(req{method: "POST", path: fmt.Sprintf("/sites/%d/dns-ip", id), cookies: ck, hdr: htmxPost,
		body: url.Values{"record_ip": {"192.168.1.9"}, "record_ip6": {"2001:db8::9"}}.Encode()})
	if w.Code != 200 {
		t.Fatalf("dns-ip save: %d %s", w.Code, w.Body.String())
	}
	rt, _ := s.deps.Store.GetSite(context.Background(), id)
	if rt.RecordIP != "192.168.1.9" || rt.RecordIP6 != "2001:db8::9" {
		t.Fatalf("record ips: %q %q", rt.RecordIP, rt.RecordIP6)
	}
	w = s.do(req{method: "POST", path: fmt.Sprintf("/sites/%d/dns-ip", id), cookies: ck, hdr: htmxPost,
		body: url.Values{"record_ip": {"999.1.1.1"}}.Encode()})
	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("bad ip: %d %s", w.Code, w.Body.String())
	}
}
