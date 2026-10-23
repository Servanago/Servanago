package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/servanago/servanago/internal/config"
	"github.com/servanago/servanago/internal/store"
)

// gateSettings is the settings row the gate tests need: mail ready.
func gateSettings() store.Settings {
	return store.Settings{SMTPHost: "127.0.0.1", SMTPPort: 28097, SMTPUser: "u",
		SMTPPass: []byte{1}, MailFrom: "access@example.com", UpdatedAt: "2026-10-15T10:00:00Z"}
}

// gateCfg is config with the admin password and session key the gate needs.
func gateCfg() config.Config {
	return config.Config{AdminPassword: "pw", SecretKey: "e2e-secret-key-0123456789abcdef-e2e"}
}

// gateServer is domainServer's wiring with gate settings and the gate's config.
func gateServer(t *testing.T) *Server {
	cf := &cfFake{zones: zonesOK}
	s := cfgServer(t, cf, gateCfg())
	if err := s.deps.Store.SaveSettings(context.Background(), gateSettings()); err != nil {
		t.Fatal(err)
	}
	return s
}

// gateMail is the form block of a site with its own SMTP provider.
var gateMail = []string{"gate_provider", "smtp", "gate_from", "access@example.com", "gate_smtp_host", "127.0.0.1", "gate_smtp_port", "28097"}

func TestParseGate(t *testing.T) {
	ctx := context.Background()
	v := url.Values{"gate_acl": {"alice@example.com\n@dev.example"}}
	s := gateServer(t)
	ready := store.Site{GateMode: "acl", GateProvider: "smtp", GateFrom: "access@example.com", GateSMTPHost: "127.0.0.1"}
	gs, err := s.parseGate(ctx, ready, v)
	if err != nil || len(gs) != 2 || gs[0].Mode != "email" || gs[1].Mode != "domain" {
		t.Fatalf("acl: %v %v", gs, err)
	}
	// An edit page has no gate_acl field: the stored rows are left alone (nil), never cleared.
	if gs, err = s.parseGate(ctx, ready, url.Values{}); err != nil || gs != nil {
		t.Fatalf("acl without rows field: %v %v", gs, err)
	}
	open := ready
	open.GateMode = "open"
	if gs, err = s.parseGate(ctx, open, url.Values{}); err != nil || gs == nil || len(gs) != 0 {
		t.Fatalf("open: %v %v", gs, err)
	}
	if gs, err = s.parseGate(ctx, store.Site{GateMode: ""}, v); err != nil || len(gs) != 0 {
		t.Fatalf("none: %v %v", gs, err)
	}
	// This site has no mail provider: refused, even though the global Settings mail works.
	if _, err := s.parseGate(ctx, store.Site{GateMode: "acl"}, v); err == nil || !strings.Contains(err.Error(), "mail provider") {
		t.Fatalf("provider refusal: %v", err)
	}
	// Postmark needs its token, not a host.
	if _, err := s.parseGate(ctx, store.Site{GateMode: "acl", GateProvider: "postmark", GateFrom: "a@x.test"}, v); err == nil {
		t.Fatal("postmark without a token accepted")
	}
	// No secret key: saving a gated site is refused naming it.
	s2 := newServer(t, "pw")
	if _, err := s2.parseGate(ctx, ready, v); err == nil || !strings.Contains(err.Error(), "SECRET_KEY") {
		t.Fatalf("secret-key refusal: %v", err)
	}
	// No Cloudflare: the ml host cannot get its records.
	s3 := newServer(t, "pw")
	s3.deps.Cfg = config.Config{SecretKey: "e2e-secret-key-0123456789abcdef-e2e"}
	if _, err := s3.parseGate(ctx, ready, v); err == nil || !strings.Contains(err.Error(), "Cloudflare") {
		t.Fatalf("cloudflare refusal: %v", err)
	}
}

// TestSettingsPageEndToEnd covers the page render, bad saves, a good save, sealing and clearing.
func TestSettingsPageEndToEnd(t *testing.T) {
	s := gateServer(t) // settings row already prefilled
	c := sessionCookie(t, login(s, "pw", nil, ""))
	post := func(srv *Server, ck *http.Cookie, kv url.Values) *httptest.ResponseRecorder {
		return srv.do(req{method: "POST", path: "/settings/smtp", body: kv.Encode(), hdr: htmxPost, cookies: []*http.Cookie{ck}})
	}

	w := s.do(req{path: "/settings", cookies: []*http.Cookie{c}})
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Email delivery") || !strings.Contains(w.Body.String(), `value="28097"`) {
		t.Fatalf("settings page: %d %s", w.Code, w.Body.String())
	}
	if w = post(s, c, url.Values{"smtp_host": {"mail.x"}, "mail_from": {"not-an-email"}}); w.Code != 422 {
		t.Fatalf("bad from: %d %s", w.Code, w.Body.String())
	}
	if w = post(s, c, url.Values{"smtp_host": {"mail.x"}}); w.Code != 422 { // host without sender
		t.Fatalf("half config: %d", w.Code)
	}
	if w = post(s, c, url.Values{"smtp_host": {"mail.x"}, "smtp_port": {"587"}, "mail_from": {"access@x.io"}}); w.Code != 204 {
		t.Fatalf("save: %d %s", w.Code, w.Body.String())
	}
	if set, err := s.deps.Store.GetSettings(context.Background()); err != nil || !set.MailReady() || set.SMTPHost != "mail.x" {
		t.Fatalf("persisted: %+v %v", set, err)
	}

	// A password needs the secret key to seal it.
	noKey := cfgServer(t, &cfFake{zones: zonesOK}, config.Config{AdminPassword: "pw"})
	cNK := sessionCookie(t, login(noKey, "pw", nil, ""))
	w = post(noKey, cNK, url.Values{"smtp_host": {"mail.x"}, "mail_from": {"a@x.io"}, "smtp_pass": {"hunter2"}})
	if w.Code != 422 || !strings.Contains(w.Body.String(), "SECRET_KEY") {
		t.Fatalf("pass without key: %d %s", w.Code, w.Body.String())
	}
	// With the key it is stored sealed, shown as set, and a blank password keeps it.
	if w = post(s, c, url.Values{"smtp_host": {"mail.x"}, "mail_from": {"a@x.io"}, "smtp_pass": {"hunter2"}}); w.Code != 204 {
		t.Fatalf("sealed save: %d %s", w.Code, w.Body.String())
	}
	set, _ := s.deps.Store.GetSettings(context.Background())
	if set.SMTPPass == nil || strings.Contains(string(set.SMTPPass), "hunter2") {
		t.Fatalf("pass not sealed: %q", set.SMTPPass)
	}
	sealed := string(set.SMTPPass)
	if w = post(s, c, url.Values{"smtp_host": {"mail.x"}, "mail_from": {"a@x.io"}}); w.Code != 204 {
		t.Fatalf("keep save: %d", w.Code)
	}
	if set, _ = s.deps.Store.GetSettings(context.Background()); string(set.SMTPPass) != sealed {
		t.Fatal("blank password did not keep the stored one")
	}
	if w = s.do(req{path: "/settings", cookies: []*http.Cookie{c}}); !strings.Contains(w.Body.String(), "leave blank to keep") {
		t.Fatal("password-set state not shown")
	}

	// Clearing host and sender stops delivery and drops the password.
	if w = post(s, c, url.Values{}); w.Code != 204 {
		t.Fatalf("clear: %d", w.Code)
	}
	if set, _ = s.deps.Store.GetSettings(context.Background()); set.MailReady() || set.SMTPPass != nil {
		t.Fatalf("not cleared: %+v", set)
	}
}

func TestRouteFormShowsGateSection(t *testing.T) {
	s := gateServer(t)
	if _, err := s.deps.Store.CreateDomain(context.Background(), store.Domain{Name: "gateui.example.net", DefaultIP: "192.168.1.5", CertMode: "wildcard"}); err != nil {
		t.Fatal(err)
	}
	c := sessionCookie(t, login(s, "pw", nil, ""))
	w := s.do(req{path: "/sites/new", cookies: []*http.Cookie{c}})
	if !strings.Contains(w.Body.String(), "gate_mode") || !strings.Contains(w.Body.String(), "Magic-link access") {
		t.Fatalf("gate section missing from the site form:\n%s", w.Body.String())
	}
	// Mail unconfigured: the section stays visible but its controls are off, with a pointer to Settings.
	s2 := newServer(t, "pw")
	if _, err := s2.deps.Store.CreateDomain(context.Background(), store.Domain{Name: "gateui2.example.net", DefaultIP: "192.168.1.6", CertMode: "wildcard"}); err != nil {
		t.Fatal(err)
	}
	c2 := sessionCookie(t, login(s2, "pw", nil, ""))
	for _, path := range []string{"/sites/new", "/sites/new"} {
		w2 := s2.do(req{path: path, cookies: []*http.Cookie{c2}})
		if strings.Contains(w2.Body.String(), "gate_mode") {
			t.Fatalf("%s: controls rendered while mail is unconfigured", path)
		}
		if !strings.Contains(w2.Body.String(), "needs Cloudflare") {
			t.Fatalf("%s: disabled note missing: %s", path, w2.Body.String())
		}
	}
	// The quick Add-site form carries the controls too once mail works.
	if w3 := s.do(req{path: "/sites/new", cookies: []*http.Cookie{c}}); !strings.Contains(w3.Body.String(), "gate_mode") {
		t.Fatal("quick Add site form lacks the gate section")
	}
}

func TestCreateGatedRouteAndSecurityListing(t *testing.T) {
	s := gateServer(t) // Apply = txApplier, DNS = cftest fake, auth = "pw"
	if _, err := s.deps.Store.CreateDomain(context.Background(), store.Domain{Name: "example.com", DefaultIP: "192.168.1.5", CertMode: "wildcard"}); err != nil {
		t.Fatal(err)
	}
	c := sessionCookie(t, login(s, "pw", nil, ""))
	w := s.do(req{method: "POST", path: "/sites",
		body: form(append([]string{"enabled", "on", "gate_mode", "acl", "gate_acl", "alice@example.com\n@dev.example"}, gateMail...)...).Encode(),
		hdr:  htmxPost, cookies: []*http.Cookie{c}})
	if w.Code != 204 {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	rs, err := s.deps.Store.ListSites(context.Background())
	if err != nil || len(rs) != 1 || rs[0].GateMode != "acl" {
		t.Fatalf("site: %+v %v", rs, err)
	}
	gs, _ := s.deps.Store.Grants(context.Background(), rs[0].ID)
	if len(gs) != 2 {
		t.Fatalf("grants saved: %+v", gs)
	}

	// The Security page lists a session once one exists, and revoke kills it.
	if err := s.deps.Store.UpsertIdentity(context.Background(), "alice@example.com", "n1", "hash1", "2026-10-15T10:00:00Z", 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	w = s.do(req{path: "/security", cookies: []*http.Cookie{c}})
	if !strings.Contains(w.Body.String(), "alice@example.com") || !strings.Contains(w.Body.String(), "Site access sessions") {
		t.Fatalf("security page: %s", w.Body.String())
	}
	w2 := s.do(req{method: "POST", path: "/security/gate/revoke", body: "email=alice@example.com", hdr: htmxPost, cookies: []*http.Cookie{c}})
	if w2.Code != 204 {
		t.Fatalf("revoke: %d %s", w2.Code, w2.Body.String())
	}
	if gs, _ := s.deps.Store.GateIdentities(context.Background()); len(gs) != 0 {
		t.Fatalf("identity survived revoke: %+v", gs)
	}
}
