package web

import (
	"context"
	"strings"
	"testing"

	"github.com/servanago/servanago/internal/store"
)

func addRoute(t *testing.T, s *Server, d store.Domain, extra ...string) store.Site {
	t.Helper()
	kv := append([]string{"enabled", "on"}, extra...)
	w := s.do(req{method: "POST", path: "/sites", body: form(kv...).Encode(), hdr: htmxPost})
	if w.Code != 204 {
		t.Fatalf("create site: %d %q", w.Code, w.Body.String())
	}
	rs, _ := s.deps.Store.ListSites(context.Background())
	return rs[len(rs)-1]
}

func dnsRow(t *testing.T, s *Server, siteID int64) store.DNSRecord {
	t.Helper()
	rt, err := s.deps.Store.GetSite(context.Background(), siteID)
	if err != nil {
		t.Fatal(err)
	}
	d, err := s.deps.Store.GetDNS(context.Background(), rt.Hostnames[0], store.FamilyA)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func newDNSServer(t *testing.T) (*Server, *cfFake, store.Domain) {
	t.Helper()
	cf := &cfFake{zones: zonesOK}
	s := domainServer(t, cf)
	d, err := s.deps.Store.CreateDomain(context.Background(), store.Domain{Name: "example.com", ZoneID: "zone123", DefaultIP: "10.0.0.1", CertMode: "wildcard"})
	if err != nil {
		t.Fatal(err)
	}
	return s, cf, d
}

func TestRouteCreateSyncsDNS(t *testing.T) {
	s, cf, d := newDNSServer(t)
	r := addRoute(t, s, d)
	recs := cf.dns.Records()
	if len(recs) != 1 || recs[0].Name != "sonarr.example.com" || recs[0].Content != "10.0.0.1" {
		t.Fatalf("%+v", recs)
	}
	if row := dnsRow(t, s, r.ID); row.State != "synced" || !row.Owned {
		t.Fatalf("%+v", row)
	}
	if body := s.do(req{path: "/"}).Body.String(); !strings.Contains(body, "synced") {
		t.Errorf("dashboard lacks DNS state: %s", body)
	}
}

func TestDNSFailureKeepsRouteAndRetryWorks(t *testing.T) {
	s, cf, d := newDNSServer(t)
	cf.dns.FailWith("cloudflare is down")
	r := addRoute(t, s, d)
	if rs, _ := s.deps.Store.ListSites(context.Background()); len(rs) != 1 {
		t.Fatal("site reverted by DNS failure")
	}
	if row := dnsRow(t, s, r.ID); row.State != "error" || !strings.Contains(row.Error, "cloudflare is down") {
		t.Fatalf("%+v", row)
	}
	if body := s.do(req{path: "/"}).Body.String(); !strings.Contains(body, "cloudflare is down") || !strings.Contains(body, "Retry") {
		t.Errorf("error/retry not shown: %s", body)
	}
	cf.dns.FailWith("")
	if w := s.do(req{method: "POST", path: "/sites/" + itoa(r.ID) + "/dns/resync", hdr: htmxPost}); w.Code != 204 {
		t.Fatalf("resync: %d", w.Code)
	}
	if row := dnsRow(t, s, r.ID); row.State != "synced" {
		t.Fatalf("%+v", row)
	}
}

func TestConflictAndTakeOver(t *testing.T) {
	s, cf, d := newDNSServer(t)
	cf.dns.Seed("sonarr.example.com", "9.9.9.9")
	r := addRoute(t, s, d)
	if row := dnsRow(t, s, r.ID); row.State != "conflict" {
		t.Fatalf("%+v", row)
	}
	if body := s.do(req{path: "/"}).Body.String(); !strings.Contains(body, "Take over") {
		t.Errorf("take over action missing")
	}
	if w := s.do(req{method: "POST", path: "/sites/" + itoa(r.ID) + "/dns/takeover", hdr: htmxPost}); w.Code != 204 {
		t.Fatalf("takeover: %d", w.Code)
	}
	if row := dnsRow(t, s, r.ID); row.State != "synced" || !row.Owned || cf.dns.Records()[0].Content != "10.0.0.1" {
		t.Fatalf("%+v %+v", row, cf.dns.Records())
	}
}

func TestDeleteConfirmationAndRecordHandling(t *testing.T) {
	// owned: the delete dialog on the edit page offers the record (data-dns-ip is non-empty), and deleting it works
	s, cf, d := newDNSServer(t)
	r := addRoute(t, s, d)
	if body := s.do(req{path: "/sites/" + itoa(r.ID)}).Body.String(); !strings.Contains(body, `data-dns-ip="10.0.0.1"`) {
		t.Errorf("owned record not offered in the delete dialog: %s", body)
	}
	if w := s.do(req{method: "DELETE", path: "/sites/" + itoa(r.ID) + "?delete_dns=on", hdr: htmxPost}); w.Code != 204 {
		t.Fatal(w.Code)
	}
	if len(cf.dns.Records()) != 0 {
		t.Error("owned record not deleted")
	}

	// adopted: the dialog offers nothing to delete (data-dns-ip is empty), and the record stays
	s, cf, d = newDNSServer(t)
	cf.dns.Seed("sonarr.example.com", "10.0.0.1")
	r = addRoute(t, s, d)
	if body := s.do(req{path: "/sites/" + itoa(r.ID)}).Body.String(); !strings.Contains(body, `data-dns-ip=""`) {
		t.Errorf("adopted record offered for deletion: %s", body)
	}
	s.do(req{method: "DELETE", path: "/sites/" + itoa(r.ID), hdr: htmxPost})
	if len(cf.dns.Records()) != 1 {
		t.Error("adopted record deleted")
	}
}

func TestDeleteReportsDNSFailure(t *testing.T) {
	s, cf, d := newDNSServer(t)
	r := addRoute(t, s, d)
	cf.dns.FailWith("nope")
	if w := s.do(req{method: "DELETE", path: "/sites/" + itoa(r.ID) + "?delete_dns=on", hdr: htmxPost}); w.Code != 204 {
		t.Fatalf("site delete must still succeed: %d", w.Code)
	}
	if body := s.do(req{path: "/"}).Body.String(); !strings.Contains(body, "could not be removed") {
		t.Errorf("flash missing: %s", body)
	}
	if body := s.do(req{path: "/"}).Body.String(); strings.Contains(body, "could not be removed") {
		t.Error("flash shown twice")
	}
}

func TestRenameMovesRecord(t *testing.T) {
	s, cf, d := newDNSServer(t)
	r := addRoute(t, s, d)
	e := form("hostnames", "tv.example.com", "enabled", "on")
	if w := s.do(req{method: "PUT", path: "/sites/" + itoa(r.ID), body: e.Encode(), hdr: htmxPost}); w.Code != 200 {
		t.Fatalf("%d %q", w.Code, w.Body.String())
	}
	recs := cf.dns.Records()
	if len(recs) != 1 || recs[0].Name != "tv.example.com" {
		t.Fatalf("%+v", recs)
	}
}

func TestDeleteRecordOnlyWhenAskedAndOwned(t *testing.T) {
	del := func(s *Server, id int64, q string) {
		t.Helper()
		if w := s.do(req{method: "DELETE", path: "/sites/" + itoa(id) + q, hdr: htmxPost}); w.Code != 204 {
			t.Fatalf("delete: %d %q", w.Code, w.Body.String())
		}
	}
	// owned, not asked: the site goes, the record stays
	s, cf, d := newDNSServer(t)
	del(s, addRoute(t, s, d).ID, "")
	if len(cf.dns.Records()) != 1 {
		t.Error("record deleted without being asked")
	}
	// owned, asked: both go
	s, cf, d = newDNSServer(t)
	del(s, addRoute(t, s, d).ID, "?delete_dns=on")
	if len(cf.dns.Records()) != 0 {
		t.Error("asked record not deleted")
	}
	// adopted, asked: never deleted
	s, cf, d = newDNSServer(t)
	cf.dns.Seed("sonarr.example.com", "10.0.0.1")
	del(s, addRoute(t, s, d).ID, "?delete_dns=on")
	if len(cf.dns.Records()) != 1 {
		t.Error("adopted record deleted")
	}
}

func TestListRowDeletePanel(t *testing.T) {
	// One dialog for the whole page, outside the polled #sites fragment so a refresh cannot close it.
	s, _, d := newDNSServer(t)
	addRoute(t, s, d)
	body := s.do(req{path: "/"}).Body.String()
	if strings.Count(body, "<dialog") != 1 || !strings.Contains(body, `id="delete-dialog"`) || !strings.Contains(body, `name="delete_dns"`) {
		t.Errorf("want one shared dialog with the DNS option:\n%s", body)
	}
	if !strings.Contains(body, `data-host="sonarr.example.com"`) || !strings.Contains(body, `data-dns-ip="10.0.0.1"`) {
		t.Errorf("owned row button lacks its data:\n%s", body)
	}
	if frag := s.do(req{path: "/status"}).Body.String(); strings.Contains(frag, "<dialog") || !strings.Contains(frag, `data-dns-ip="10.0.0.1"`) {
		t.Errorf("polled fragment must carry row data but no dialog:\n%s", frag)
	}
	s, cf, d := newDNSServer(t)
	cf.dns.Seed("sonarr.example.com", "10.0.0.1")
	addRoute(t, s, d)
	if body = s.do(req{path: "/"}).Body.String(); !strings.Contains(body, `data-dns-ip=""`) {
		t.Errorf("adopted row must carry no DNS ip:\n%s", body)
	}
}

// Row actions carry a visible text label next to the icon, so none is an unlabeled mystery button.
func TestRowActionsAreLabelledButtons(t *testing.T) {
	s, cf, d := newDNSServer(t)
	addRoute(t, s, d)
	cf.dns.FailWith("down")
	s.do(req{method: "POST", path: "/sites/1/dns/resync", hdr: htmxPost}) // row ends in DNS error: Retry button
	body := s.do(req{path: "/status"}).Body.String()
	for _, label := range []string{"Edit</a>", "Disable</button>", "Delete</button>", "Retry DNS</button>"} {
		if !strings.Contains(body, label) {
			t.Errorf("no button labelled %q:\n%s", label, body)
		}
	}
	if strings.Count(body, "<svg") < 4 {
		t.Errorf("icons missing:\n%s", body)
	}
}
