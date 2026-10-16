package web

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/servanago/servanago/internal/config"
	"github.com/servanago/servanago/internal/probe"
	"github.com/servanago/servanago/internal/store"
)

// noCFServer is a server with no Cloudflare client and no DNS syncer: the CLOUDFLARE_API_TOKEN-unset install.
func noCFServer(t *testing.T) *Server {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	mon := probe.NewMonitor(st, "127.0.0.1:1")
	mon.Dial = func(context.Context, string, time.Duration) error { return errors.New("refused") }
	return New(Deps{Cfg: config.Config{Host: "panel.example.com"}, Store: st, Apply: txApplier{st}, Probe: mon})
}

func addDomainNoDNS(s *Server, kv ...string) (int, string) {
	v := url.Values{"name": {"example.com"}}
	for i := 0; i < len(kv); i += 2 {
		v.Set(kv[i], kv[i+1])
	}
	w := s.do(req{method: "POST", path: "/domains", body: v.Encode(), hdr: htmxPost})
	return w.Code, w.Body.String()
}

func TestNoDNSDomainNeedsNoZoneOrIP(t *testing.T) {
	s := noCFServer(t)
	if code, body := addDomainNoDNS(s); code != 204 {
		t.Fatalf("add domain without Cloudflare: %d %q", code, body)
	}
	ds, _ := s.deps.Store.ListDomains(context.Background())
	if len(ds) != 1 || ds[0].Name != "example.com" || ds[0].ZoneID != "" || ds[0].DefaultIP != "" || ds[0].CertMode != "per_host" {
		t.Fatalf("a Cloudflare-less domain has no zone, no default IP and per-host certificates: %+v", ds)
	}
}

func TestNoDNSRejectsWildcardCertificates(t *testing.T) {
	s := noCFServer(t)
	code, body := addDomainNoDNS(s, "cert_mode", "wildcard")
	if code != 422 || !strings.Contains(body, "Cloudflare") {
		t.Fatalf("wildcard needs DNS-01: %d %q", code, body)
	}
}

func TestNoDNSAddSiteUnderManagedDomain(t *testing.T) {
	s := noCFServer(t)
	if code, body := addDomainNoDNS(s); code != 204 {
		t.Fatalf("%d %q", code, body)
	}
	code, body := postSite(s, siteForm("hostname", "app.example.com"))
	if code != 204 {
		t.Fatalf("add site: %d %q", code, body)
	}
	rs, _ := s.deps.Store.ListRoutes(context.Background())
	if len(rs) != 1 || rs[0].Subdomain != "app" {
		t.Fatalf("%+v", rs)
	}
	if all, err := s.deps.Store.ListDNS(context.Background()); err != nil || len(all) != 0 {
		t.Errorf("no DNS record row must be created without Cloudflare: %+v %v", all, err)
	}
}

func TestNoDNSAddSiteUnderUnknownDomainSaysAddTheDomain(t *testing.T) {
	s := noCFServer(t)
	code, body := postSite(s, siteForm("hostname", "app.example.org"))
	if code != 422 || !strings.Contains(body, "Domains") || !strings.Contains(body, "example.org") {
		t.Fatalf("want a hint to add the domain first, got %d %q", code, body)
	}
}

func TestNoDNSPagesHideCloudflare(t *testing.T) {
	s := noCFServer(t)
	addDomainNoDNS(s)
	postSite(s, siteForm("hostname", "app.example.com"))
	for _, path := range []string{"/", "/domains", "/sites/new", "/routes/new"} {
		w := s.do(req{path: path})
		if w.Code != 200 {
			t.Fatalf("%s: %d", path, w.Code)
		}
		body := w.Body.String()
		for _, banned := range []string{"Cloudflare token", "UI host", "Resync", "Take over", "<th>DNS", "A record", "zone"} {
			if strings.Contains(body, banned) {
				t.Errorf("%s still shows %q with no Cloudflare", path, banned)
			}
		}
	}
	if body := s.do(req{path: "/"}).Body.String(); !strings.Contains(body, "app.example.com") {
		t.Errorf("dashboard lost the site: %s", body)
	}
}

func TestNoDNSRouteLifecycleDoesNotPanic(t *testing.T) {
	s := noCFServer(t)
	addDomainNoDNS(s)
	if code, body := postSite(s, siteForm("hostname", "app.example.com")); code != 204 {
		t.Fatalf("%d %q", code, body)
	}
	rs, _ := s.deps.Store.ListRoutes(context.Background())
	id := itoa(rs[0].ID)
	if w := s.do(req{method: "POST", path: "/routes/" + id + "/toggle", hdr: htmxPost}); w.Code != 204 {
		t.Errorf("toggle: %d %q", w.Code, w.Body.String())
	}
	if w := s.do(req{method: "DELETE", path: "/routes/" + id + "?delete_dns=on", hdr: htmxPost}); w.Code != 204 {
		t.Errorf("delete with delete_dns: %d %q", w.Code, w.Body.String())
	}
	for _, p := range []string{"/routes/1/dns/resync", "/routes/1/dns/takeover", "/host/dns/resync", "/host/dns/takeover"} {
		if w := s.do(req{method: "POST", path: p, hdr: htmxPost}); w.Code != 404 {
			t.Errorf("%s with no DNS management: %d, want 404", p, w.Code)
		}
	}
}
