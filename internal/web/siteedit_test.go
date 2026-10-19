package web

import (
	"time"

	"context"
	"github.com/servanago/servanago/internal/config"
	"github.com/servanago/servanago/internal/probe"
	"net/url"
	"strings"
	"testing"

	"github.com/servanago/servanago/internal/store"
)

func form(kv ...string) url.Values {
	v := url.Values{"hostnames": {"sonarr.example.com"}, "scheme": {"http"}, "upstream_host": {"192.168.1.20"}, "upstream_port": {"8989"}}
	for i := 0; i < len(kv); i += 2 {
		v.Set(kv[i], kv[i+1])
	}
	return v
}

func TestParseRoute(t *testing.T) {
	tests := []struct {
		name   string
		v      url.Values
		errHas string
	}{
		{"valid", form(), ""},
		{"hostname upstream with underscore", form("upstream_host", "sonarr_1"), ""},
		{"ipv6 upstream", form("upstream_host", "fd00::5"), ""},
		{"uppercase hostname is lowercased", form("hostnames", "Sonarr.Example.com"), ""},
		{"several hostnames", form("hostnames", "a.example.com\nb.example.org, c.example.net"), ""},
		{"empty hostnames", form("hostnames", ""), "hostname"},
		{"single label", form("hostnames", "sonarr"), "hostname"},
		{"ip literal", form("hostnames", "10.0.0.1"), "hostname"},
		{"local suffix", form("hostnames", "nas.local"), "hostname"},
		{"unknown kind", form("kind", "php"), "kind"},
		{"static without a folder", form("kind", "static"), "static folder"},
		{"bad scheme", form("scheme", "ftp"), "scheme"},
		{"empty host", form("upstream_host", ""), "upstream host"},
		{"host with slash", form("upstream_host", "a/b"), "upstream host"},
		{"host with space", form("upstream_host", "a b"), "upstream host"},
		{"host with port", form("upstream_host", "a:80"), "upstream host"},
		{"port zero", form("upstream_port", "0"), "port"},
		{"port too big", form("upstream_port", "65536"), "port"},
		{"port text", form("upstream_port", "http"), "port"},
		{"record ip private", form("record_ip", "100.64.1.2"), ""},
		{"record ip public", form("record_ip", "8.8.8.8"), ""},
		{"record ip loopback", form("record_ip", "127.0.0.1"), "record IP"},
		{"record ip garbage", form("record_ip", "nope"), "record IP"},
		{"extra routes", form("extra_routes", "/cryptpad_websocket=127.0.0.1:3303"), ""},
		{"extra routes socket and trash", form("extra_routes", "\n\n/api=/run/api.sock\nbadline\n"), "extra routes"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := parseSite(tt.v, config.Config{})
			if tt.errHas == "" {
				if err != nil || len(r.Hostnames) == 0 {
					t.Fatalf("%+v %v", r, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.errHas) {
				t.Fatalf("want error containing %q, got %v", tt.errHas, err)
			}
		})
	}
}

func TestParseRouteRecordIP(t *testing.T) {
	r, _ := parseSite(form("record_ip", " 192.168.1.9 "), config.Config{})
	if r.RecordIP != "192.168.1.9" {
		t.Errorf("%q", r.RecordIP)
	}
	if r, _ := parseSite(form(), config.Config{}); r.RecordIP != "" {
		t.Errorf("blank must stay blank (domain default): %q", r.RecordIP)
	}
}

func TestParseRouteExtraRoutes(t *testing.T) {
	r, err := parseSite(form("extra_routes", "  /cryptpad_websocket=127.0.0.1:3303\n\n"), config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if want := "/cryptpad_websocket=127.0.0.1:3303"; r.ExtraRoutes != want {
		t.Errorf("ExtraRoutes = %q, want the normalized %q", r.ExtraRoutes, want)
	}
}

func TestParseRouteFlags(t *testing.T) {
	r, err := parseSite(form("tls_skip_verify", "on", "enabled", "on"), config.Config{})
	if err != nil || !r.TLSSkipVerify || !r.Enabled {
		t.Fatalf("%+v %v", r, err)
	}
	r, _ = parseSite(form(), config.Config{})
	if r.TLSSkipVerify || r.Enabled {
		t.Fatalf("unchecked boxes must be false: %+v", r)
	}
}

func routeServer(t *testing.T) (*Server, store.Domain) {
	t.Helper()
	s := domainServer(t, &cfFake{zones: zonesOK})
	d, err := s.deps.Store.CreateDomain(context.Background(), store.Domain{Name: "example.com", ZoneID: "z", DefaultIP: "10.0.0.1", CertMode: "wildcard"})
	if err != nil {
		t.Fatal(err)
	}
	return s, d
}

func TestRouteLifecycle(t *testing.T) {
	s, _ := routeServer(t)
	s.deps.Cfg.HostIP = "192.168.25.165" // a hostname with no managed domain asks Cloudflare for its zone
	ctx := context.Background()
	v := form("enabled", "on")

	w := s.do(req{method: "POST", path: "/sites", body: v.Encode(), hdr: htmxPost})
	if w.Code != 204 || w.Header().Get("HX-Redirect") != "/" {
		t.Fatalf("create: %d %q", w.Code, w.Body.String())
	}
	rs, _ := s.deps.Store.ListSites(ctx)
	if len(rs) != 1 || rs[0].Hostnames[0] != "sonarr.example.com" || rs[0].UpstreamPort != 8989 || !rs[0].Enabled {
		t.Fatalf("%+v", rs)
	}

	if w := s.do(req{method: "POST", path: "/sites", body: v.Encode(), hdr: htmxPost}); w.Code != 409 {
		t.Errorf("duplicate hostname: %d %q", w.Code, w.Body.String())
	}
	// A hostname under no managed domain is fine: it is served without one.
	if w := s.do(req{method: "POST", path: "/sites", body: form("hostnames", "tv.other.test").Encode(), hdr: htmxPost}); w.Code != 204 {
		t.Errorf("hostname with no domain: %d %q", w.Code, w.Body.String())
	}
	if w := s.do(req{method: "POST", path: "/sites", body: form("upstream_port", "0").Encode(), hdr: htmxPost}); w.Code != 422 {
		t.Errorf("bad port: %d", w.Code)
	}

	// pages
	if body := s.do(req{path: "/"}).Body.String(); !strings.Contains(body, "sonarr.example.com") || !strings.Contains(body, "192.168.1.20:8989") {
		t.Errorf("dashboard missing site: %s", body)
	}
	if body := s.do(req{path: "/sites/new"}).Body.String(); !strings.Contains(body, "example.com") {
		t.Errorf("new page missing domains")
	}
	id := itoa(rs[0].ID)
	if body := s.do(req{path: "/sites/" + id}).Body.String(); !strings.Contains(body, "192.168.1.20") {
		t.Errorf("edit page missing values")
	}

	// edit (domain and subdomain stay; upstream changes; checkbox unchecked disables)
	e := form("upstream_host", "10.1.1.1", "upstream_port", "9000")
	if w := s.do(req{method: "PUT", path: "/sites/" + id, body: e.Encode(), hdr: htmxPost}); w.Code != 200 {
		t.Fatalf("update: %d %q", w.Code, w.Body.String())
	}
	got, _ := s.deps.Store.GetSite(ctx, rs[0].ID)
	if got.UpstreamHost != "10.1.1.1" || got.UpstreamPort != 9000 || got.Enabled {
		t.Errorf("%+v", got)
	}

	if w := s.do(req{method: "DELETE", path: "/sites/" + id, hdr: htmxPost}); w.Code != 204 {
		t.Fatalf("delete: %d", w.Code)
	}
	if rs, _ := s.deps.Store.ListSites(ctx); len(rs) != 1 || rs[0].Hostnames[0] != "tv.other.test" {
		t.Errorf("only the domain-less site should remain: %+v", rs)
	}
}

func TestRouteCannotShadowUIHost(t *testing.T) {
	s, _ := routeServer(t)
	s.deps.Cfg.Host = "sonarr.example.com"
	w := s.do(req{method: "POST", path: "/sites", body: form().Encode(), hdr: htmxPost})
	if w.Code != 422 || !strings.Contains(w.Body.String(), "sonarr.example.com") {
		t.Fatalf("create: %d %q", w.Code, w.Body.String())
	}
	if rs, _ := s.deps.Store.ListSites(context.Background()); len(rs) != 0 {
		t.Fatalf("stored: %+v", rs)
	}
	// renaming an existing site onto the UI host is rejected too
	other := form("hostnames", "radarr.example.com")
	if w := s.do(req{method: "POST", path: "/sites", body: other.Encode(), hdr: htmxPost}); w.Code != 204 {
		t.Fatalf("setup: %d", w.Code)
	}
	rs, _ := s.deps.Store.ListSites(context.Background())
	if w := s.do(req{method: "PUT", path: "/sites/" + itoa(rs[0].ID), body: form().Encode(), hdr: htmxPost}); w.Code != 422 {
		t.Fatalf("rename onto UI host: %d", w.Code)
	}
}

func TestCertExpiringSoon(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	issued := func(d time.Duration) probe.CertStatus {
		return probe.CertStatus{State: probe.StateIssued, NotAfter: now.Add(d)}
	}
	for name, tt := range map[string]struct {
		cs   probe.CertStatus
		want bool
	}{
		"plenty of time":    {issued(60 * 24 * time.Hour), false},
		"just outside":      {issued(21*24*time.Hour + time.Hour), false},
		"inside the window": {issued(20 * 24 * time.Hour), true},
		"about to expire":   {issued(time.Hour), true},
		"pending":           {probe.CertStatus{State: probe.StatePending}, false},
		"error":             {probe.CertStatus{State: probe.StateError}, false},
	} {
		if got := certExpiringSoon(tt.cs, now); got != tt.want {
			t.Errorf("%s: got %v want %v", name, got, tt.want)
		}
	}
}
