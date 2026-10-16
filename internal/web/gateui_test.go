package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/servanago/servanago/internal/config"
	"github.com/servanago/servanago/internal/store"
)

// gateCfg is config with everything the gate needs.
func gateCfg() config.Config {
	return config.Config{AdminPassword: "pw", SMTPHost: "127.0.0.1", SMTPPort: 587,
		MailFrom: "access@example.com", SecretKey: "e2e-secret-key-0123456789abcdef-e2e"}
}

// gateServer is domainServer with the gate's config; it reuses the cftest-backed deps.
func gateServer(t *testing.T) *Server {
	cf := &cfFake{zones: zonesOK}
	return cfgServer(t, cf, gateCfg())
}

func TestParseGate(t *testing.T) {
	v := url.Values{"gate_acl": {"alice@example.com\n@dev.example"}}
	s := gateServer(t)
	gs, err := s.parseGate(store.Route{GateMode: "acl"}, v)
	if err != nil || len(gs) != 2 || gs[0].Mode != "email" || gs[1].Mode != "domain" {
		t.Fatalf("acl: %v %v", gs, err)
	}
	if gs, err = s.parseGate(store.Route{GateMode: "open"}, url.Values{}); err != nil || len(gs) != 0 {
		t.Fatalf("open: %v %v", gs, err)
	}
	if gs, err = s.parseGate(store.Route{GateMode: ""}, v); err != nil || len(gs) != 0 {
		t.Fatalf("none: %v %v", gs, err)
	}
	// Without the secret key or mail, saving a gated route is refused with a plain-language error.
	s2 := newServer(t, "pw")
	s2.deps.Cfg = config.Config{SMTPHost: "127.0.0.1", MailFrom: "access@example.com"}
	if _, err := s2.parseGate(store.Route{GateMode: "acl"}, v); err == nil || !strings.Contains(err.Error(), "SECRET_KEY") {
		t.Fatalf("secret-key refusal: %v", err)
	}
	s3 := newServer(t, "pw")
	s3.deps.Cfg = config.Config{SecretKey: "e2e-secret-key-0123456789abcdef-e2e"}
	if _, err := s3.parseGate(store.Route{GateMode: "acl"}, v); err == nil || !strings.Contains(err.Error(), "SMTP") {
		t.Fatalf("smtp refusal: %v", err)
	}
}

func TestRouteFormShowsGateSection(t *testing.T) {
	s := gateServer(t)
	if _, err := s.deps.Store.CreateDomain(context.Background(), store.Domain{Name: "gateui.example.net", DefaultIP: "192.168.1.5", CertMode: "wildcard"}); err != nil {
		t.Fatal(err)
	}
	c := sessionCookie(t, login(s, "pw", nil, ""))
	w := s.do(req{path: "/routes/new", cookies: []*http.Cookie{c}})
	if !strings.Contains(w.Body.String(), "gate_mode") || !strings.Contains(w.Body.String(), "Magic-link access") {
		t.Fatalf("gate section missing from the route form:\n%s", w.Body.String())
	}
	// Without email delivery: no section, and the hint explains what to set.
	s2 := newServer(t, "pw")
	c2 := sessionCookie(t, login(s2, "pw", nil, ""))
	w2 := s2.do(req{path: "/routes/new", cookies: []*http.Cookie{c2}})
	if strings.Contains(w2.Body.String(), "gate_mode") {
		t.Fatal("gate section shown without email delivery")
	}
	if !strings.Contains(w2.Body.String(), "No domains yet") {
		t.Fatalf("unexpected page: %s", w2.Body.String())
	}
}

func TestCreateGatedRouteAndSecurityListing(t *testing.T) {
	s := gateServer(t) // Apply = txApplier, DNS = cftest fake, auth = "pw"
	if _, err := s.deps.Store.CreateDomain(context.Background(), store.Domain{Name: "example.com", DefaultIP: "192.168.1.5", CertMode: "wildcard"}); err != nil {
		t.Fatal(err)
	}
	c := sessionCookie(t, login(s, "pw", nil, ""))
	w := s.do(req{method: "POST", path: "/routes",
		body: form("enabled", "on", "gate_mode", "acl", "gate_acl", "alice@example.com\n@dev.example").Encode(),
		hdr:  htmxPost, cookies: []*http.Cookie{c}})
	if w.Code != 204 {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	rs, err := s.deps.Store.ListRoutes(context.Background())
	if err != nil || len(rs) != 1 || rs[0].GateMode != "acl" {
		t.Fatalf("route: %+v %v", rs, err)
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
