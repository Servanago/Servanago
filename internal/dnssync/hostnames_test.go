package dnssync

import (
	"context"
	"strings"
	"testing"

	"github.com/servanago/servanago/internal/cfdns/cftest"
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

func TestAliasesAreCNAMEsAndDomainlessOnesAreSkipped(t *testing.T) {
	f := newFx(t)
	f.setHostnames(t, "sonarr.example.com", "tv.example.com", "www.nowhere.test")
	f.reconcile(t)
	got := f.cloudflare()
	if len(got) != 2 || got["sonarr.example.com"] != "10.0.0.1" || got["tv.example.com"] != "sonarr.example.com" {
		t.Fatalf("records: %v", got)
	}
	rows := f.rows(t)
	if r := rows["tv.example.com CNAME"]; len(rows) != 2 || r.State != "synced" || r.SiteID != f.site.ID || r.Error != "" {
		t.Fatalf("rows: %+v", rows)
	}
}

func TestAliasInAnotherZonePointsAtThePrimary(t *testing.T) {
	f := newFx(t)
	if _, err := f.st.CreateDomain(context.Background(), store.Domain{Name: "example.org", ZoneID: "z2", DefaultIP: "10.0.0.2", CertMode: "wildcard"}); err != nil {
		t.Fatal(err)
	}
	f.setHostnames(t, "sonarr.example.com", "tv.example.org")
	f.reconcile(t)
	got := f.cloudflare()
	if got["sonarr.example.com"] != "10.0.0.1" || got["tv.example.org"] != "sonarr.example.com" {
		t.Fatalf("the alias in the other zone is a CNAME to the primary: %v", got)
	}
}

func TestSiteIPOverrideMovesOnlyThePrimaryRecord(t *testing.T) {
	f := newFx(t)
	f.site.RecordIP = "10.9.9.9"
	f.setHostnames(t, "sonarr.example.com", "tv.example.com")
	f.reconcile(t)
	if got := f.cloudflare(); got["sonarr.example.com"] != "10.9.9.9" || got["tv.example.com"] != "sonarr.example.com" {
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

func TestChangingThePrimarySwapsAddressAndAlias(t *testing.T) {
	f := newFx(t)
	f.setHostnames(t, "sonarr.example.com", "tv.example.com")
	f.reconcile(t)
	f.setHostnames(t, "tv.example.com", "sonarr.example.com")
	f.reconcile(t)
	got := f.cloudflare()
	if len(f.cf.Records()) != 2 || got["tv.example.com"] != "10.0.0.1" || got["sonarr.example.com"] != "tv.example.com" {
		t.Fatalf("the new primary holds the address, the old one aliases it: %v", got)
	}
	if rows := f.rows(t); len(rows) != 2 || rows["tv.example.com A"].State != "synced" || rows["sonarr.example.com CNAME"].State != "synced" {
		t.Fatalf("rows: %+v", rows)
	}
}

// A site upgraded from A/AAAA aliases converts on the next reconcile; nothing is left at the name.
func TestOwnedAddressRecordsOfAnAliasBecomeACNAME(t *testing.T) {
	f := newFx(t)
	f.setHostnames(t, "sonarr.example.com")
	f.reconcile(t)
	f.setHostnames(t, "sonarr.example.com", "tv.example.com")
	ctx := context.Background()
	id := f.cf.Add(cftest.Record{Name: "tv.example.com", Content: "10.0.0.1", Comment: "managed by servanago"})
	if err := f.st.UpsertDNS(ctx, store.DNSRecord{Hostname: "tv.example.com", SiteID: f.site.ID, Family: store.FamilyA, CFRecordID: id, Content: "10.0.0.1", Owned: true, State: "synced"}); err != nil {
		t.Fatal(err)
	}
	f.reconcile(t)
	var tv []cftest.Record
	for _, r := range f.cf.Records() {
		if r.Name == "tv.example.com" {
			tv = append(tv, r)
		}
	}
	if len(tv) != 1 || tv[0].Type != "CNAME" || tv[0].Content != "sonarr.example.com" {
		t.Fatalf("%+v", tv)
	}
	if rows := f.rows(t); rows["tv.example.com A"].Hostname != "" || rows["tv.example.com CNAME"].State != "synced" {
		t.Fatalf("rows: %+v", rows)
	}
}

func TestForeignAddressRecordBlocksAnAliasUntilTakeOver(t *testing.T) {
	f := newFx(t)
	f.cf.Seed("tv.example.com", "10.9.9.9")
	f.setHostnames(t, "sonarr.example.com", "tv.example.com")
	f.reconcile(t)
	if r := f.rows(t)["tv.example.com CNAME"]; r.State != "conflict" || f.cloudflare()["tv.example.com"] != "10.9.9.9" {
		t.Fatalf("%+v %v", r, f.cloudflare())
	}
	if err := f.sync.TakeOver(context.Background(), f.site.ID); err != nil {
		t.Fatal(err)
	}
	if r := f.rows(t)["tv.example.com CNAME"]; r.State != "synced" || !r.Owned || f.cloudflare()["tv.example.com"] != "sonarr.example.com" {
		t.Fatalf("%+v %v", r, f.cloudflare())
	}
}

func TestAliasWarnsWhenThePrimaryHasNoManagedRecord(t *testing.T) {
	f := newFx(t)
	f.setHostnames(t, "www.nowhere.test", "tv.example.com")
	f.reconcile(t)
	if r := f.rows(t)["tv.example.com CNAME"]; r.State != "synced" || !strings.Contains(r.Error, "no record managed") {
		t.Fatalf("%+v", r)
	}
}

// A failed create after the address records went leaves no stale rows; the next reconcile finishes the job.
func TestFailedCNAMECreateRetries(t *testing.T) {
	f := newFx(t)
	f.setHostnames(t, "sonarr.example.com")
	f.reconcile(t)
	f.setHostnames(t, "sonarr.example.com", "tv.example.com")
	id := f.cf.Seed("tv.example.com", "10.0.0.1")
	if err := f.st.UpsertDNS(context.Background(), store.DNSRecord{Hostname: "tv.example.com", SiteID: f.site.ID, Family: store.FamilyA, CFRecordID: id, Content: "10.0.0.1", Owned: true, State: "synced"}); err != nil {
		t.Fatal(err)
	}
	f.cf.FailWith("boom")
	f.reconcile(t)
	if r := f.rows(t)["tv.example.com CNAME"]; r.State != "error" {
		t.Fatalf("%+v", r)
	}
	f.cf.FailWith("")
	f.reconcile(t)
	if r := f.rows(t)["tv.example.com CNAME"]; r.State != "synced" || f.cloudflare()["tv.example.com"] != "sonarr.example.com" {
		t.Fatalf("%+v %v", r, f.cloudflare())
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
