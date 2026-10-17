package web

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/servanago/servanago/internal/store"
)

func postDomain6(s *Server, name, ip, ip6 string) (int, string) {
	v := url.Values{"name": {name}, "default_ip": {ip}, "default_ip6": {ip6}, "cert_mode": {"wildcard"}}
	w := s.do(req{method: "POST", path: "/domains", body: v.Encode(), hdr: htmxPost})
	return w.Code, w.Body.String()
}

func typesOf(cf *cfFake) map[string]string {
	out := map[string]string{}
	for _, r := range cf.dns.Records() {
		out[r.Type+" "+r.Name] = r.Content
	}
	return out
}

func TestAddDomainWithIPv6(t *testing.T) {
	s := domainServer(t, &cfFake{zones: zonesOK})
	if code, body := postDomain6(s, "example.com", "192.168.1.10", "2001:db8::1"); code != 204 {
		t.Fatalf("%d %q", code, body)
	}
	ds, _ := s.deps.Store.ListDomains(context.Background())
	if len(ds) != 1 || ds[0].DefaultIP != "192.168.1.10" || ds[0].DefaultIP6 != "2001:db8::1" {
		t.Fatalf("%+v", ds)
	}
}

func TestAddDomainIPv6IsOptional(t *testing.T) {
	s := domainServer(t, &cfFake{zones: zonesOK})
	if code, body := postDomain6(s, "example.com", "192.168.1.10", ""); code != 204 {
		t.Fatalf("%d %q", code, body)
	}
	if ds, _ := s.deps.Store.ListDomains(context.Background()); ds[0].DefaultIP6 != "" {
		t.Fatalf("%+v", ds)
	}
}

func TestAddDomainRejectsBadAddressFamilies(t *testing.T) {
	tests := []struct{ name, ip, ip6, want string }{
		{"loopback v6", "192.168.1.10", "::1", "IPv6"},
		{"link-local v6", "192.168.1.10", "fe80::1", "IPv6"},
		{"v4 in the v6 field", "192.168.1.10", "10.0.0.1", "IPv6"},
		{"junk v6", "192.168.1.10", "nope", "IPv6"},
		{"v6 in the v4 field", "2001:db8::1", "", "IPv4"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cf := &cfFake{zones: zonesOK}
			s := domainServer(t, cf)
			code, body := postDomain6(s, "example.com", tt.ip, tt.ip6)
			if code != 422 || !strings.Contains(body, tt.want) {
				t.Fatalf("%d %q", code, body)
			}
			if ds, _ := s.deps.Store.ListDomains(context.Background()); len(ds) != 0 {
				t.Errorf("stored: %+v", ds)
			}
		})
	}
}

func TestRouteOnDualStackDomainGetsAAndAAAA(t *testing.T) {
	s, cf, d := newDNSServer(t)
	d.DefaultIP6 = "2001:db8::1"
	if err := s.deps.Store.UpdateDomain(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	r := addRoute(t, s, d)
	got := typesOf(cf)
	if got["A sonarr.example.com"] != "10.0.0.1" || got["AAAA sonarr.example.com"] != "2001:db8::1" || len(got) != 2 {
		t.Fatalf("%+v", got)
	}
	body := s.do(req{path: "/"}).Body.String()
	if !strings.Contains(body, ">A synced<") || !strings.Contains(body, ">AAAA synced<") {
		t.Errorf("dashboard must show one badge per record:\n%s", body)
	}
	if !strings.Contains(body, `data-dns-ip="A 10.0.0.1, AAAA 2001:db8::1"`) {
		t.Errorf("delete dialog must list both owned records:\n%s", body)
	}
	_ = r
}

func TestRouteRecordIP6Override(t *testing.T) {
	s, cf, d := newDNSServer(t)
	addRoute(t, s, d, "record_ip6", "2001:db8::77")
	if got := typesOf(cf); got["AAAA sonarr.example.com"] != "2001:db8::77" || got["A sonarr.example.com"] != "10.0.0.1" {
		t.Fatalf("%+v", got)
	}
	rs, _ := s.deps.Store.ListSites(context.Background())
	if rs[0].RecordIP6 != "2001:db8::77" {
		t.Fatalf("%+v", rs[0])
	}
}

func TestRouteRejectsBadRecordIP6(t *testing.T) {
	for _, bad := range []string{"::1", "10.0.0.1", "fe80::1", "nope"} {
		s, _, d := newDNSServer(t)
		w := s.do(req{method: "POST", path: "/sites/full", body: form("domain_id", itoa(d.ID), "enabled", "on", "record_ip6", bad).Encode(), hdr: htmxPost})
		if w.Code != 422 || !strings.Contains(w.Body.String(), "record IPv6") {
			t.Errorf("%q: %d %q", bad, w.Code, w.Body.String())
		}
	}
}

func TestEditingRouteClearsAAAA(t *testing.T) {
	s, cf, d := newDNSServer(t)
	r := addRoute(t, s, d, "record_ip6", "2001:db8::77")
	if len(cf.dns.Records()) != 2 {
		t.Fatalf("setup: %+v", typesOf(cf))
	}
	e := form("domain_id", itoa(d.ID), "upstream_host", "192.168.1.20", "upstream_port", "8989", "enabled", "on")
	if w := s.do(req{method: "PUT", path: "/sites/" + itoa(r.ID), body: e.Encode(), hdr: htmxPost}); w.Code != 204 {
		t.Fatalf("%d %q", w.Code, w.Body.String())
	}
	got := typesOf(cf)
	if len(got) != 1 || got["A sonarr.example.com"] != "10.0.0.1" {
		t.Fatalf("clearing the site's IPv6 must delete its owned AAAA: %+v", got)
	}
}

func TestDeleteRouteWithDNSRemovesBothFamilies(t *testing.T) {
	s, cf, d := newDNSServer(t)
	d.DefaultIP6 = "2001:db8::1"
	_ = s.deps.Store.UpdateDomain(context.Background(), d)
	r := addRoute(t, s, d)
	if w := s.do(req{method: "DELETE", path: "/sites/" + itoa(r.ID) + "?delete_dns=on", hdr: htmxPost}); w.Code != 204 {
		t.Fatalf("%d %q", w.Code, w.Body.String())
	}
	if n := len(cf.dns.Records()); n != 0 {
		t.Errorf("%d records left: %+v", n, typesOf(cf))
	}
}

func TestAddSiteUsesHostIPv6ForNewDomain(t *testing.T) {
	s, cf := siteServer(t)
	s.deps.Cfg.HostIP6 = "2001:db8::10"
	if code, body := postSite(s, siteForm()); code != 204 {
		t.Fatalf("%d %q", code, body)
	}
	ds, _ := s.deps.Store.ListDomains(context.Background())
	if len(ds) != 1 || ds[0].DefaultIP6 != "2001:db8::10" {
		t.Fatalf("%+v", ds)
	}
	if got := typesOf(cf); got["AAAA oc.example.com"] != "2001:db8::10" || got["A oc.example.com"] != "192.168.25.165" {
		t.Fatalf("%+v", got)
	}
}

func TestFormsOfferIPv6OnlyWithCloudflare(t *testing.T) {
	s, _, _ := newDNSServer(t)
	if body := s.do(req{path: "/domains"}).Body.String(); !strings.Contains(body, `name="default_ip6"`) {
		t.Error("domain form lacks the IPv6 field")
	}
	if body := s.do(req{path: "/sites/new/full"}).Body.String(); !strings.Contains(body, `name="record_ip6"`) {
		t.Error("site form lacks the IPv6 field")
	}
	n := noCFServer(t)
	_, _ = addDomainNoDNS(n)
	for _, path := range []string{"/domains", "/sites/new/full"} {
		if body := n.do(req{path: path}).Body.String(); strings.Contains(body, "ip6") {
			t.Errorf("%s offers IPv6 fields with no Cloudflare", path)
		}
	}
}

func TestHostCardDualStack(t *testing.T) {
	s, cf := hostServer(t)
	s.deps.DNS.Host.IP6 = "2001:db8::a"
	body := s.do(req{path: "/"}).Body.String()
	if !strings.Contains(body, "192.168.25.165") || !strings.Contains(body, "2001:db8::a") {
		t.Fatalf("pending card must show both addresses:\n%s", body)
	}
	if w := s.do(req{method: "POST", path: "/host/dns/resync", hdr: htmxPost}); w.Code != 204 {
		t.Fatalf("resync: %d %q", w.Code, w.Body.String())
	}
	got := typesOf(cf)
	if got["A servanago.example.com"] != "192.168.25.165" || got["AAAA servanago.example.com"] != "2001:db8::a" {
		t.Fatalf("%+v", got)
	}
	body = s.do(req{path: "/"}).Body.String()
	if strings.Count(body, "synced") < 2 || !strings.Contains(body, "AAAA") {
		t.Errorf("card must show a state per family:\n%s", body)
	}
	rows, _ := s.deps.Store.ListUIDNS(context.Background())
	if len(rows) != 2 || rows[1].Family != store.FamilyAAAA {
		t.Errorf("%+v", rows)
	}
}

func TestHelpExplainsUnusableIPv6(t *testing.T) {
	got, ok := explain(`default IPv6: "::1" must be a usable IPv6 address (loopback, link-local, multicast and IPv4-mapped addresses, and IPv4, are not)`)
	if !ok || !strings.Contains(got.Title, "cannot be used") {
		t.Fatalf("%+v %v", got, ok)
	}
}
