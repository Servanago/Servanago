package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/cloudflare/cloudflare-go/v7/option"

	"github.com/servanago/servanago/internal/cfdns"
	"github.com/servanago/servanago/internal/store"
)

func siteForm(kv ...string) url.Values {
	v := url.Values{"hostname": {"oc.example.com"}, "scheme": {"http"}, "upstream_host": {"192.168.25.165"}, "upstream_port": {"9200"}, "enabled": {"on"}}
	for i := 0; i < len(kv); i += 2 {
		v.Set(kv[i], kv[i+1])
	}
	return v
}

func postSite(s *Server, v url.Values) (code int, body string) {
	w := s.do(req{method: "POST", path: "/sites", body: v.Encode(), hdr: htmxPost})
	return w.Code, w.Body.String()
}

func siteServer(t *testing.T) (*Server, *cfFake) {
	t.Helper()
	s, cf, _ := newDNSServer(t)
	// newDNSServer pre-creates example.com; these tests start from an empty install
	if err := s.deps.Store.DeleteDomain(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	s.deps.Cfg.HostIP = "192.168.25.165"
	return s, cf
}

func TestAddSiteCreatesZoneDomainRouteAndRecord(t *testing.T) {
	s, cf := siteServer(t)
	code, body := postSite(s, siteForm())
	if code != 204 {
		t.Fatalf("%d %q", code, body)
	}
	ctx := context.Background()
	ds, _ := s.deps.Store.ListDomains(ctx)
	if len(ds) != 1 || ds[0].Name != "example.com" || ds[0].ZoneID != "zone123" || ds[0].DefaultIP != "192.168.25.165" || ds[0].CertMode != "wildcard" {
		t.Fatalf("domain: %+v", ds)
	}
	rs, _ := s.deps.Store.ListRoutes(ctx)
	if len(rs) != 1 || rs[0].Subdomain != "oc" || rs[0].UpstreamHost != "192.168.25.165" || rs[0].UpstreamPort != 9200 || rs[0].Scheme != "http" || !rs[0].Enabled {
		t.Fatalf("route: %+v", rs)
	}
	recs := cf.dns.Records()
	if len(recs) != 1 || recs[0].Name != "oc.example.com" || recs[0].Content != "192.168.25.165" {
		t.Fatalf("A record is the server address, not the backend: %+v", recs)
	}
}

func TestAddSiteRecordPointsAtServerNotBackend(t *testing.T) {
	s, cf := siteServer(t)
	if code, body := postSite(s, siteForm("upstream_host", "192.168.25.77")); code != 204 {
		t.Fatalf("%d %q", code, body)
	}
	if recs := cf.dns.Records(); len(recs) != 1 || recs[0].Content != "192.168.25.165" {
		t.Fatalf("%+v", recs)
	}
}

func TestAddSiteReusesExistingDomain(t *testing.T) {
	s, cf := siteServer(t)
	ctx := context.Background()
	d, _ := s.deps.Store.CreateDomain(ctx, store.Domain{Name: "example.com", ZoneID: "zone123", DefaultIP: "10.0.0.9", CertMode: "per_host"})
	before := cf.calls.Load()
	if code, body := postSite(s, siteForm()); code != 204 {
		t.Fatalf("%d %q", code, body)
	}
	if cf.calls.Load()-before > 2 { // only the DNS record calls, no zone lookup
		t.Errorf("zone looked up again for a managed domain: %d calls", cf.calls.Load()-before)
	}
	ds, _ := s.deps.Store.ListDomains(ctx)
	rs, _ := s.deps.Store.ListRoutes(ctx)
	if len(ds) != 1 || ds[0].DefaultIP != "10.0.0.9" || ds[0].CertMode != "per_host" || len(rs) != 1 || rs[0].DomainID != d.ID {
		t.Fatalf("%+v %+v", ds, rs)
	}
	if recs := cf.dns.Records(); len(recs) != 1 || recs[0].Content != "10.0.0.9" {
		t.Errorf("existing domain's default IP must win: %+v", recs)
	}
}

func TestAddSiteLongestManagedDomainWins(t *testing.T) {
	s, _ := siteServer(t)
	ctx := context.Background()
	if _, err := s.deps.Store.CreateDomain(ctx, store.Domain{Name: "example.com", ZoneID: "z1", DefaultIP: "10.0.0.1", CertMode: "wildcard"}); err != nil {
		t.Fatal(err)
	}
	lab, err := s.deps.Store.CreateDomain(ctx, store.Domain{Name: "lab.example.com", ZoneID: "z2", DefaultIP: "10.0.0.2", CertMode: "wildcard"})
	if err != nil {
		t.Fatal(err)
	}
	if code, body := postSite(s, siteForm("hostname", "oc.lab.example.com")); code != 204 {
		t.Fatalf("%d %q", code, body)
	}
	rs, _ := s.deps.Store.ListRoutes(ctx)
	if len(rs) != 1 || rs[0].DomainID != lab.ID || rs[0].Subdomain != "oc" {
		t.Fatalf("%+v", rs)
	}
}

func TestAddSiteValidation(t *testing.T) {
	tests := []struct {
		name string
		v    url.Values
		want string
	}{
		{"port missing", siteForm("upstream_port", ""), "port"},
		{"port zero", siteForm("upstream_port", "0"), "port"},
		{"port text", siteForm("upstream_port", "http"), "port"},
		{"host:port in the host field", siteForm("upstream_host", "192.168.25.165:9200"), "upstream host"},
		{"no backend host", siteForm("upstream_host", ""), "upstream host"},
		{"bad scheme", siteForm("scheme", "ftp"), "scheme"},
		{".local hostname", siteForm("hostname", "nas.local"), ".local"},
		{"single label", siteForm("hostname", "oc"), "label"},
		{"hostname with a scheme", siteForm("hostname", "https://oc.example.com"), "hostname"},
		{"hostname with a path", siteForm("hostname", "oc.example.com/x"), "hostname"},
		{"hostname with a port", siteForm("hostname", "oc.example.com:9200"), "hostname"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, _ := siteServer(t)
			code, body := postSite(s, tt.v)
			if code != 422 || !strings.Contains(body, tt.want) {
				t.Fatalf("%d %q", code, body)
			}
			ds, _ := s.deps.Store.ListDomains(context.Background())
			rs, _ := s.deps.Store.ListRoutes(context.Background())
			if len(ds) != 0 || len(rs) != 0 {
				t.Errorf("invalid input left rows behind: %+v %+v", ds, rs)
			}
		})
	}
}

func TestAddSiteZoneNotFound(t *testing.T) {
	s, _ := siteServer(t)
	s.deps.CF = fakeNoZoneClient(t)
	code, body := postSite(s, siteForm("hostname", "oc.nozone.org"))
	if code != 422 || !strings.Contains(body, "no Cloudflare zone") || !strings.Contains(body, "oc.nozone.org, nozone.org") {
		t.Fatalf("%d %q", code, body)
	}
	if ds, _ := s.deps.Store.ListDomains(context.Background()); len(ds) != 0 {
		t.Errorf("domain created without a zone: %+v", ds)
	}
}

func TestAddSiteRejectsZoneApexAndNestedNames(t *testing.T) {
	s, _ := siteServer(t)
	if code, body := postSite(s, siteForm("hostname", "example.com")); code != 422 || !strings.Contains(body, "subdomain") {
		t.Errorf("apex: %d %q", code, body)
	}
	// zone lookup resolves a.b.example.com to example.com; a wildcard cert would not cover two labels
	if code, body := postSite(s, siteForm("hostname", "a.b.example.com")); code != 422 || !strings.Contains(body, "one label") {
		t.Errorf("nested: %d %q", code, body)
	}
}

func TestAddSiteCannotShadowUIHost(t *testing.T) {
	s, _ := siteServer(t)
	s.deps.Cfg.Host = "oc.example.com"
	if code, body := postSite(s, siteForm()); code != 422 || !strings.Contains(body, "UI host") {
		t.Fatalf("%d %q", code, body)
	}
	if ds, _ := s.deps.Store.ListDomains(context.Background()); len(ds) != 0 {
		t.Errorf("domain created for a rejected site: %+v", ds)
	}
}

func TestAddSiteDuplicateHost(t *testing.T) {
	s, _ := siteServer(t)
	postSite(s, siteForm())
	if code, _ := postSite(s, siteForm()); code != 409 {
		t.Errorf("duplicate: %d", code)
	}
}

func TestSitePageHasSeparatePortField(t *testing.T) {
	s, _ := siteServer(t)
	body := s.do(req{path: "/sites/new"}).Body.String()
	for _, want := range []string{`name="hostname"`, `name="upstream_host"`, `name="upstream_port"`, `type="number"`, "Backend port", `hx-post="/sites"`} {
		if !strings.Contains(body, want) {
			t.Errorf("site form missing %q", want)
		}
	}
	if strings.Contains(body, "Add a domain first") {
		t.Error("site form must work with no domains")
	}
	pre := s.do(req{path: "/sites/new?host=sonarr&port=8989"}).Body.String()
	if !strings.Contains(pre, `name="upstream_host" value="sonarr"`) || !strings.Contains(pre, `value="8989"`) {
		t.Errorf("prefill missing")
	}
}

func TestDashboardLinksToAddSite(t *testing.T) {
	s, _ := siteServer(t)
	if body := s.do(req{path: "/"}).Body.String(); !strings.Contains(body, `href="/sites/new"`) {
		t.Errorf("no Add site entry point on an empty dashboard")
	}
}

// fakeNoZoneClient is a Cloudflare client whose account has no zones at all.
func fakeNoZoneClient(t *testing.T) *cfdns.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":[],"result_info":{"page":1,"per_page":20,"count":0,"total_count":0}}`))
	}))
	t.Cleanup(srv.Close)
	return cfdns.New("tok", option.WithBaseURL(srv.URL), option.WithMaxRetries(0))
}
