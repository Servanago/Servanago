package web

import (
	"strings"
	"testing"

	"github.com/servanago/servanago/internal/cfdns"
	"github.com/servanago/servanago/internal/cfdns/cftest"
)

const dnsZonesBody = `{"success":true,"errors":[],"messages":[],"result":[{"id":"z1","name":"example.com","status":"active"},{"id":"z2","name":"beta.example.com","status":"pending"}],"result_info":{"page":1,"per_page":50,"count":2,"total_count":2}}`

func dnsServer(t *testing.T) (*Server, *cftest.Fake) {
	t.Helper()
	cf := &cfFake{zones: dnsZonesBody}
	s := domainServer(t, cf)
	cf.dns.AddZone("example.com", "z1")
	return s, cf.dns
}

func TestDNSZonesPageListsAndFilters(t *testing.T) {
	s, _ := dnsServer(t)
	w := s.do(req{path: "/dns"})
	body := w.Body.String()
	if w.Code != 200 || !strings.Contains(body, `<a href="/dns/zones/z1">example.com</a>`) || !strings.Contains(body, "beta.example.com") || !strings.Contains(body, "pending") {
		t.Fatalf("zones page: %d %s", w.Code, body)
	}
	if body = s.do(req{path: "/dns?name=beta"}).Body.String(); !strings.Contains(body, "beta.example.com") || strings.Contains(body, ">example.com</a>") {
		t.Errorf("filter did not hide the apex zone: %s", body)
	}
}

func TestDNSZonesPageWithoutCloudflare(t *testing.T) {
	s := newServer(t, "")
	w := s.do(req{path: "/dns"})
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Cloudflare DNS is not configured") {
		t.Fatalf("no-CF page: %d %s", w.Code, w.Body.String())
	}
}

func TestDNSZonePageRendersRecordsAndBadges(t *testing.T) {
	s, fd := dnsServer(t)
	fd.Add(cftest.Record{Type: "A", Name: "www.example.com", Content: "203.0.113.5", Proxied: true, Comment: "front door"})
	fd.Add(cftest.Record{Type: "CNAME", Name: "cdn.example.com", Content: "www.example.com", TTL: 300, Comment: cfdns.ManagedComment})
	fd.Add(cftest.Record{Type: "TXT", Name: "x.example.com", Content: "v=spf1"})
	w := s.do(req{path: "/dns/zones/z1"})
	body := w.Body.String()
	if w.Code != 200 {
		t.Fatalf("zone page: %d %s", w.Code, body)
	}
	for _, want := range []string{">Create record</button>", "</form>", "203.0.113.5", `title="Cloudflare proxies`, `title="ServanaGo writes`, ">Auto<", "v=spf1", "_dmarc", "300"} {
		if !strings.Contains(body, want) {
			t.Errorf("zone page missing %q", want)
		}
	}
}

func TestDNSRecordCreateRoundTripAndValidation(t *testing.T) {
	s, fd := dnsServer(t)
	w := s.do(req{method: "POST", path: "/dns/zones/z1/records", hdr: htmxPost,
		body: form("type", "MX", "name", "@", "content", "mail.example.com", "priority", "10", "ttl", "3600").Encode()})
	if w.Code != 204 || !strings.HasSuffix(w.Header().Get("HX-Redirect"), "/dns/zones/z1") {
		t.Fatalf("MX create: %d %v", w.Code, w.Header())
	}
	fdRecs := fd.Records()
	if len(fdRecs) != 1 || fdRecs[0].Name != "example.com" || fdRecs[0].Content != "mail.example.com" || fdRecs[0].Priority != 10 || fdRecs[0].TTL != 3600 {
		t.Fatalf("MX stored: %+v", fdRecs)
	}
	if body := s.do(req{path: "/dns/zones/z1"}).Body.String(); !strings.Contains(body, "prio 10") {
		t.Errorf("created record not listed: %s", body)
	}
	// rejections: each row must fail for the named reason
	bad := []struct {
		body string
		want string
	}{
		{form("type", "A", "name", "www two", "content", "203.0.113.7").Encode(), "not a record name"},
		{form("type", "A", "name", "www", "content", "2001:db8::1").Encode(), "IPv4"},
		{form("type", "AAAA", "name", "www", "content", "203.0.113.7").Encode(), "IPv6"},
		{form("type", "MX", "name", "@", "content", "not a domain").Encode(), "mail server"},
		{form("type", "MX", "name", "@", "content", "mail.example.com", "priority", "sixty").Encode(), "priority"},
		{form("type", "SRV", "name", "_s._tcp", "srv_priority", "10", "srv_weight", "5", "srv_port", "99999", "srv_target", "sip.example.com").Encode(), "SRV port"},
		{form("type", "CAA", "name", "@", "caa_flags", "7", "caa_tag", "issue", "caa_value", "letsencrypt.org").Encode(), "CAA flags"},
		{form("type", "TLSA", "name", "@", "content", "x").Encode(), "read-only"},
		{form("type", "TXT", "name", "@", "content", "", "ttl", "10").Encode(), "TTL"},
	}
	for _, b := range bad {
		w := s.do(req{method: "POST", path: "/dns/zones/z1/records", hdr: htmxPost, body: b.body})
		if w.Code != 422 || !strings.Contains(w.Body.String(), b.want) {
			t.Errorf("body %q: got %d %s, want %q", b.body, w.Code, w.Body.String(), b.want)
		}
	}
	if n := len(fd.Records()); n != 1 {
		t.Errorf("rejected forms wrote records: %d", n)
	}
}

func TestDNSRecordUpdateAndDelete(t *testing.T) {
	s, fd := dnsServer(t)
	id := fd.Add(cftest.Record{Type: "A", Name: "www.example.com", Content: "203.0.113.5"})
	w := s.do(req{method: "PUT", path: "/dns/zones/z1/records/" + id, hdr: htmxPost,
		body: form("type", "A", "name", "www", "content", "203.0.113.8", "comment", "moved").Encode()})
	if w.Code != 204 {
		t.Fatalf("update: %d %s", w.Code, w.Body.String())
	}
	if body := s.do(req{path: "/dns/zones/z1"}).Body.String(); !strings.Contains(body, "203.0.113.8") || !strings.Contains(body, "moved") {
		t.Errorf("updated record not listed")
	}
	page := s.do(req{path: "/dns/zones/z1"}).Body.String()
	if !strings.Contains(page, `hx-confirm="Delete record A www.example.com?"`) || !strings.Contains(page, `hx-delete="/dns/zones/z1/records/`+id+`"`) {
		t.Errorf("remove button wiring missing")
	}
	if w := s.do(req{method: "DELETE", path: "/dns/zones/z1/records/" + id, hdr: htmxPost}); w.Code != 204 {
		t.Fatalf("delete: %d", w.Code)
	}
	if n := len(fd.Records()); n != 0 {
		t.Fatalf("record survived delete: %d", n)
	}
	if body := s.do(req{path: "/dns/zones/z1"}).Body.String(); !strings.Contains(body, "No records") {
		t.Errorf("empty state missing after delete")
	}
}
