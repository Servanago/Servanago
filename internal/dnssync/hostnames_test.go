package dnssync

import (
	"context"
	"testing"

	"github.com/servanago/servanago/internal/store"
)

// setHostnames replaces the fixture site's hostnames and returns the stored site.
func (f *fx) setHostnames(t *testing.T, hs ...string) store.Site {
	t.Helper()
	f.site.Hostnames = hs
	if err := f.st.UpdateSite(context.Background(), f.site); err != nil {
		t.Fatal(err)
	}
	return f.site
}

func (f *fx) rows(t *testing.T) map[string]store.DNSRecord {
	t.Helper()
	all, err := f.st.ListSiteDNS(context.Background(), f.site.ID)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]store.DNSRecord{}
	for _, r := range all {
		out[r.Hostname+" "+r.Family] = r
	}
	return out
}

// cloudflare is the fake zone's records as name to content.
func (f *fx) cloudflare() map[string]string {
	out := map[string]string{}
	for _, r := range f.cf.Records() {
		out[r.Name] = r.Content
	}
	return out
}

func TestEachHostnameGetsItsOwnRecordAndDomainlessOnesAreSkipped(t *testing.T) {
	f := newFx(t)
	f.setHostnames(t, "sonarr.example.com", "tv.example.com", "www.nowhere.test")
	f.reconcile(t)
	got := f.cloudflare()
	if len(got) != 2 || got["sonarr.example.com"] != "10.0.0.1" || got["tv.example.com"] != "10.0.0.1" {
		t.Fatalf("records: %v", got)
	}
	rows := f.rows(t)
	if len(rows) != 2 || rows["tv.example.com A"].State != "synced" || rows["tv.example.com A"].SiteID != f.site.ID {
		t.Fatalf("rows: %+v", rows)
	}
}

func TestHostnameInAnotherDomainUsesThatDomainsIP(t *testing.T) {
	f := newFx(t)
	if _, err := f.st.CreateDomain(context.Background(), store.Domain{Name: "example.org", ZoneID: "z2", DefaultIP: "10.0.0.2", CertMode: "wildcard"}); err != nil {
		t.Fatal(err)
	}
	f.setHostnames(t, "sonarr.example.com", "tv.example.org")
	f.reconcile(t)
	got := f.cloudflare()
	if got["sonarr.example.com"] != "10.0.0.1" || got["tv.example.org"] != "10.0.0.2" {
		t.Fatalf("each name takes its own domain's default IP: %v", got)
	}
}

func TestSiteIPOverrideAppliesToEveryHostname(t *testing.T) {
	f := newFx(t)
	f.site.RecordIP = "10.9.9.9"
	f.setHostnames(t, "sonarr.example.com", "tv.example.com")
	f.reconcile(t)
	if got := f.cloudflare(); got["sonarr.example.com"] != "10.9.9.9" || got["tv.example.com"] != "10.9.9.9" {
		t.Fatalf("%v", got)
	}
}

// Dropping a hostname from the site removes the record ServanaGo created for it, and only that one.
func TestDroppingAHostnameDeletesItsOwnedRecordOnly(t *testing.T) {
	f := newFx(t)
	f.cf.Seed("adopted.example.com", "10.0.0.1") // identical, pre-existing: adopted, never owned
	f.setHostnames(t, "sonarr.example.com", "tv.example.com", "adopted.example.com")
	f.reconcile(t)
	if got := f.cloudflare(); len(got) != 3 {
		t.Fatalf("setup: %v", got)
	}
	f.setHostnames(t, "sonarr.example.com")
	f.reconcile(t)
	got := f.cloudflare()
	if _, ok := got["tv.example.com"]; ok {
		t.Errorf("the owned record of a dropped hostname survived: %v", got)
	}
	if _, ok := got["adopted.example.com"]; !ok {
		t.Errorf("an adopted record was deleted: %v", got)
	}
	if rows := f.rows(t); len(rows) != 1 || rows["sonarr.example.com A"].State != "synced" {
		t.Fatalf("rows after dropping: %+v", rows)
	}
}

func TestChangingThePrimaryKeepsEveryRecord(t *testing.T) {
	f := newFx(t)
	f.setHostnames(t, "sonarr.example.com", "tv.example.com")
	f.reconcile(t)
	writes := f.cf.Writes()
	f.setHostnames(t, "tv.example.com", "sonarr.example.com")
	f.reconcile(t)
	if f.cf.Writes() != writes || len(f.cloudflare()) != 2 {
		t.Fatalf("reordering must not touch Cloudflare: %d writes (was %d), %v", f.cf.Writes(), writes, f.cloudflare())
	}
}

func TestRenamingAHostnameMovesItsRecord(t *testing.T) {
	f := newFx(t)
	f.reconcile(t)
	f.setHostnames(t, "movies.example.com")
	f.reconcile(t)
	got := f.cloudflare()
	if len(got) != 1 || got["movies.example.com"] != "10.0.0.1" {
		t.Fatalf("%v", got)
	}
}
