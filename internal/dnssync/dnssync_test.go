package dnssync

import (
	"context"
	"strings"
	"testing"

	"github.com/cloudflare/cloudflare-go/v7/option"

	"github.com/servanago/servanago/internal/cfdns"
	"github.com/servanago/servanago/internal/cfdns/cftest"
	"github.com/servanago/servanago/internal/store"
)

type fx struct {
	cf   *cftest.Fake
	st   *store.Store
	sync *Syncer
	dom  store.Domain
	site store.Site
}

func newFx(t *testing.T) *fx {
	t.Helper()
	cf := cftest.New(t)
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	d, err := st.CreateDomain(ctx, store.Domain{Name: "example.com", ZoneID: "z1", DefaultIP: "10.0.0.1", CertMode: "wildcard"})
	if err != nil {
		t.Fatal(err)
	}
	r, err := st.CreateSite(ctx, store.Site{DomainID: d.ID, Subdomain: "sonarr", Scheme: "http", UpstreamHost: "h", UpstreamPort: 1, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	c := cfdns.New("tok", option.WithBaseURL(cf.URL), option.WithMaxRetries(0))
	return &fx{cf, st, New(c, st), d, r}
}

func (f *fx) row(t *testing.T) store.DNSRecord {
	t.Helper()
	d, err := f.st.GetDNS(context.Background(), f.site.ID, store.FamilyA)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func (f *fx) reconcile(t *testing.T) {
	t.Helper()
	if err := f.sync.Reconcile(context.Background(), f.site.ID); err != nil {
		t.Fatal(err)
	}
}

func TestCreate(t *testing.T) {
	f := newFx(t)
	f.reconcile(t)
	recs := f.cf.Records()
	if len(recs) != 1 || recs[0].Name != "sonarr.example.com" || recs[0].Content != "10.0.0.1" || recs[0].Proxied || recs[0].Comment != "managed by servanago" {
		t.Fatalf("%+v", recs)
	}
	if r := f.row(t); r.State != "synced" || !r.Owned || r.CFRecordID != recs[0].ID || r.Content != "10.0.0.1" || r.SyncedAt == "" {
		t.Fatalf("%+v", r)
	}
}

func TestAdoptIdenticalRecord(t *testing.T) {
	f := newFx(t)
	id := f.cf.Seed("sonarr.example.com", "10.0.0.1")
	f.reconcile(t)
	if r := f.row(t); r.State != "synced" || r.Owned || r.CFRecordID != id {
		t.Fatalf("%+v", r)
	}
	if f.cf.Writes() != 0 {
		t.Error("adoption must not write")
	}
}

func TestConflictThenTakeOver(t *testing.T) {
	f := newFx(t)
	id := f.cf.Seed("sonarr.example.com", "9.9.9.9")
	f.reconcile(t)
	r := f.row(t)
	if r.State != "conflict" || r.Owned || !strings.Contains(r.Error, "9.9.9.9") || f.cf.Writes() != 0 {
		t.Fatalf("%+v writes=%d", r, f.cf.Writes())
	}
	if err := f.sync.TakeOver(context.Background(), f.site.ID); err != nil {
		t.Fatal(err)
	}
	r = f.row(t)
	if r.State != "synced" || !r.Owned || r.CFRecordID != id || r.Content != "10.0.0.1" {
		t.Fatalf("%+v", r)
	}
	if recs := f.cf.Records(); len(recs) != 1 || recs[0].Content != "10.0.0.1" {
		t.Fatalf("%+v", recs)
	}
}

func TestIPChangeUpdatesOwnedOnly(t *testing.T) {
	f := newFx(t)
	f.reconcile(t)
	ctx := context.Background()
	f.site.RecordIP = "10.0.0.2"
	if err := f.st.UpdateSite(ctx, f.site); err != nil {
		t.Fatal(err)
	}
	f.reconcile(t)
	if recs := f.cf.Records(); recs[0].Content != "10.0.0.2" || f.row(t).Content != "10.0.0.2" || f.row(t).State != "synced" {
		t.Fatalf("owned record not updated: %+v %+v", recs, f.row(t))
	}

	// adopted record is never modified: a wanted change becomes a conflict
	g := newFx(t)
	g.cf.Seed("sonarr.example.com", "10.0.0.1")
	g.reconcile(t)
	g.site.RecordIP = "10.0.0.5"
	if err := g.st.UpdateSite(ctx, g.site); err != nil {
		t.Fatal(err)
	}
	g.reconcile(t)
	if g.cf.Records()[0].Content != "10.0.0.1" || g.row(t).State != "conflict" || g.cf.Writes() != 0 {
		t.Fatalf("adopted record touched: %+v %+v", g.cf.Records(), g.row(t))
	}
}

func TestResyncIsIdempotent(t *testing.T) {
	f := newFx(t)
	f.reconcile(t)
	w := f.cf.Writes()
	f.reconcile(t)
	f.reconcile(t)
	if f.cf.Writes() != w || len(f.cf.Records()) != 1 {
		t.Fatalf("resync wrote: %d -> %d", w, f.cf.Writes())
	}
}

func TestResyncRecreatesRecordDeletedUpstream(t *testing.T) {
	f := newFx(t)
	f.reconcile(t)
	f.cf.Clear()
	f.reconcile(t)
	if recs := f.cf.Records(); len(recs) != 1 || f.row(t).State != "synced" {
		t.Fatalf("%+v %+v", recs, f.row(t))
	}
}

func TestAPIErrorSetsErrorStateWithoutFailing(t *testing.T) {
	f := newFx(t)
	f.cf.FailWith("cloudflare is down")
	f.reconcile(t) // must not return an error: DNS failure never reverts the site
	if r := f.row(t); r.State != "error" || !strings.Contains(r.Error, "cloudflare is down") {
		t.Fatalf("%+v", r)
	}
	f.cf.FailWith("")
	f.reconcile(t) // retry
	if r := f.row(t); r.State != "synced" || r.Error != "" {
		t.Fatalf("retry: %+v", r)
	}
}

func TestRemoveOnlyOwned(t *testing.T) {
	f := newFx(t)
	f.reconcile(t)
	deleted, err := f.sync.Remove(context.Background(), f.dom.ZoneID, f.row(t))
	if err != nil || !deleted || len(f.cf.Records()) != 0 {
		t.Fatalf("owned: deleted=%v err=%v recs=%v", deleted, err, f.cf.Records())
	}

	g := newFx(t)
	g.cf.Seed("sonarr.example.com", "10.0.0.1")
	g.reconcile(t)
	deleted, err = g.sync.Remove(context.Background(), g.dom.ZoneID, g.row(t))
	if err != nil || deleted || len(g.cf.Records()) != 1 {
		t.Fatalf("adopted: deleted=%v err=%v recs=%v", deleted, err, g.cf.Records())
	}
}

// --- UI host record -------------------------------------------------------

func newHostFx(t *testing.T) *fx {
	t.Helper()
	f := newFx(t)
	f.cf.AddZone("example.com", "z1")
	f.sync.Host = HostSpec{Name: "servanago.example.com", IP: "192.168.25.165"}
	return f
}

func (f *fx) hostRow(t *testing.T) store.DNSRecord {
	t.Helper()
	d, err := f.st.GetUIDNS(context.Background(), store.FamilyA)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func (f *fx) reconcileHost(t *testing.T, takeOver bool) {
	t.Helper()
	if err := f.sync.ReconcileHost(context.Background(), takeOver); err != nil {
		t.Fatal(err)
	}
}

func TestHostCreate(t *testing.T) {
	f := newHostFx(t)
	f.reconcileHost(t, false)
	recs := f.cf.Records()
	if len(recs) != 1 || recs[0].Name != "servanago.example.com" || recs[0].Content != "192.168.25.165" || recs[0].Proxied {
		t.Fatalf("%+v", recs)
	}
	if r := f.hostRow(t); r.State != "synced" || !r.Owned || r.CFRecordID != recs[0].ID {
		t.Fatalf("%+v", r)
	}
}

func TestHostAdoptConflictTakeOver(t *testing.T) {
	f := newHostFx(t)
	f.cf.Seed("servanago.example.com", "192.168.25.165")
	f.reconcileHost(t, false)
	if r := f.hostRow(t); r.State != "synced" || r.Owned || f.cf.Writes() != 0 {
		t.Fatalf("adopt: %+v writes=%d", r, f.cf.Writes())
	}

	g := newHostFx(t)
	g.cf.Seed("servanago.example.com", "192.168.25.99")
	g.reconcileHost(t, false)
	if r := g.hostRow(t); r.State != "conflict" || !strings.Contains(r.Error, "192.168.25.99") || g.cf.Writes() != 0 {
		t.Fatalf("conflict: %+v", r)
	}
	g.reconcileHost(t, true)
	if r := g.hostRow(t); r.State != "synced" || !r.Owned || g.cf.Records()[0].Content != "192.168.25.165" {
		t.Fatalf("take over: %+v %+v", r, g.cf.Records())
	}
}

func TestHostIPChange(t *testing.T) {
	f := newHostFx(t)
	f.reconcileHost(t, false)
	f.sync.Host.IP = "192.168.25.166"
	f.reconcileHost(t, false)
	if f.cf.Records()[0].Content != "192.168.25.166" || f.hostRow(t).State != "synced" {
		t.Fatalf("owned record not repointed: %+v", f.cf.Records())
	}

	g := newHostFx(t)
	g.cf.Seed("servanago.example.com", "192.168.25.165") // adopted
	g.reconcileHost(t, false)
	g.sync.Host.IP = "192.168.25.166"
	g.reconcileHost(t, false)
	if g.cf.Records()[0].Content != "192.168.25.165" || g.hostRow(t).State != "conflict" {
		t.Fatalf("adopted record was touched: %+v %+v", g.cf.Records(), g.hostRow(t))
	}
}

func TestHostIdempotent(t *testing.T) {
	f := newHostFx(t)
	f.reconcileHost(t, false)
	w := f.cf.Writes()
	f.reconcileHost(t, false)
	f.reconcileHost(t, false)
	if f.cf.Writes() != w {
		t.Fatalf("writes %d -> %d", w, f.cf.Writes())
	}
}

func TestHostFailuresBecomeErrorState(t *testing.T) {
	f := newHostFx(t)
	f.sync.Host.Name = "servanago.nozone.org" // no zone for it
	f.reconcileHost(t, false)
	if r := f.hostRow(t); r.State != "error" || !strings.Contains(r.Error, "no Cloudflare zone") {
		t.Fatalf("%+v", r)
	}

	g := newHostFx(t)
	g.cf.FailWith("cloudflare is down")
	g.reconcileHost(t, false)
	if r := g.hostRow(t); r.State != "error" || !strings.Contains(r.Error, "cloudflare is down") {
		t.Fatalf("%+v", r)
	}
	g.cf.FailWith("")
	g.reconcileHost(t, false)
	if r := g.hostRow(t); r.State != "synced" || r.Error != "" {
		t.Fatalf("retry: %+v", r)
	}
}

func TestHostZoneOverride(t *testing.T) {
	f := newHostFx(t)
	f.cf.AddZone("lab.example.com", "z-lab")
	f.sync.Host.Zone = "example.com" // ignore the closer lab.example.com zone
	f.sync.Host.Name = "servanago.lab.example.com"
	f.reconcileHost(t, false)
	if r := f.hostRow(t); r.State != "synced" {
		t.Fatalf("%+v", r)
	}
}

func TestHostDisabledWhenUnconfigured(t *testing.T) {
	f := newFx(t) // Host zero value
	if err := f.sync.ReconcileHost(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if rows, err := f.st.ListUIDNS(context.Background()); err != nil || len(rows) != 0 {
		t.Errorf("a row was written without a configured host: %+v %v", rows, err)
	}
}

// --- IPv6 (dual-stack) -----------------------------------------------------

func (f *fx) row6(t *testing.T) (store.DNSRecord, bool) {
	t.Helper()
	d, err := f.st.GetDNS(context.Background(), f.site.ID, store.FamilyAAAA)
	return d, err == nil
}

func (f *fx) setDomain6(t *testing.T, ip6 string) {
	t.Helper()
	f.dom.DefaultIP6 = ip6
	if err := f.st.UpdateDomain(context.Background(), f.dom); err != nil {
		t.Fatal(err)
	}
}

func (f *fx) recordsByType() map[string]string {
	out := map[string]string{}
	for _, r := range f.cf.Records() {
		out[r.Type] = r.Content
	}
	return out
}

func TestNoIPv6NoAAAA(t *testing.T) {
	f := newFx(t)
	f.reconcile(t)
	if _, ok := f.row6(t); ok {
		t.Error("a domain without an IPv6 address must not get an AAAA row")
	}
	if got := f.recordsByType(); len(got) != 1 || got["A"] != "10.0.0.1" {
		t.Fatalf("%+v", got)
	}
}

func TestDualStackCreatesBothRecords(t *testing.T) {
	f := newFx(t)
	f.setDomain6(t, "2001:db8::1")
	f.reconcile(t)
	if got := f.recordsByType(); len(got) != 2 || got["A"] != "10.0.0.1" || got["AAAA"] != "2001:db8::1" {
		t.Fatalf("records: %+v", got)
	}
	a, q := f.row(t), mustRow6(t, f)
	if a.State != "synced" || q.State != "synced" || !a.Owned || !q.Owned || q.Family != store.FamilyAAAA || q.Content != "2001:db8::1" || q.CFRecordID == a.CFRecordID {
		t.Fatalf("A=%+v AAAA=%+v", a, q)
	}
	for _, r := range f.cf.Records() {
		if r.Proxied || r.Comment != "managed by servanago" {
			t.Errorf("record must be DNS-only and marked managed: %+v", r)
		}
	}
	w := f.cf.Writes()
	f.reconcile(t)
	f.reconcile(t)
	if f.cf.Writes() != w {
		t.Errorf("resync wrote: %d -> %d", w, f.cf.Writes())
	}
}

func mustRow6(t *testing.T, f *fx) store.DNSRecord {
	t.Helper()
	q, ok := f.row6(t)
	if !ok {
		t.Fatal("no AAAA row")
	}
	return q
}

func TestRouteIPv6OverridesDomainDefault(t *testing.T) {
	f := newFx(t)
	f.setDomain6(t, "2001:db8::1")
	f.site.RecordIP6 = "2001:db8::77"
	if err := f.st.UpdateSite(context.Background(), f.site); err != nil {
		t.Fatal(err)
	}
	f.reconcile(t)
	if got := f.recordsByType(); got["AAAA"] != "2001:db8::77" || got["A"] != "10.0.0.1" {
		t.Fatalf("%+v", got)
	}
}

func TestIPv6ChangeLeavesIPv4Alone(t *testing.T) {
	f := newFx(t)
	f.setDomain6(t, "2001:db8::1")
	f.reconcile(t)
	idA := f.row(t).CFRecordID
	f.setDomain6(t, "2001:db8::2")
	f.reconcile(t)
	if got := f.recordsByType(); got["AAAA"] != "2001:db8::2" || got["A"] != "10.0.0.1" {
		t.Fatalf("%+v", got)
	}
	if f.row(t).CFRecordID != idA {
		t.Error("the A record must not be recreated by an IPv6 change")
	}
}

func TestAAAAConflictIsIndependentOfA(t *testing.T) {
	f := newFx(t)
	f.setDomain6(t, "2001:db8::1")
	id := f.cf.Seed("sonarr.example.com", "2001:db8::dead")
	f.reconcile(t)
	if a := f.row(t); a.State != "synced" {
		t.Fatalf("A must sync despite the AAAA conflict: %+v", a)
	}
	q := mustRow6(t, f)
	if q.State != "conflict" || q.Owned || !strings.Contains(q.Error, "2001:db8::dead") || !strings.Contains(q.Error, "2001:db8::1") {
		t.Fatalf("AAAA conflict: %+v", q)
	}
	if err := f.sync.TakeOver(context.Background(), f.site.ID); err != nil {
		t.Fatal(err)
	}
	q = mustRow6(t, f)
	if q.State != "synced" || !q.Owned || q.CFRecordID != id || q.Content != "2001:db8::1" {
		t.Fatalf("take over: %+v", q)
	}
}

func TestAdoptIdenticalAAAA(t *testing.T) {
	f := newFx(t)
	f.setDomain6(t, "2001:db8::1")
	id := f.cf.Seed("sonarr.example.com", "2001:db8::1")
	f.reconcile(t)
	if q := mustRow6(t, f); q.State != "synced" || q.Owned || q.CFRecordID != id {
		t.Fatalf("%+v", q)
	}
}

func TestClearingIPv6RemovesOwnedAAAAOnly(t *testing.T) {
	f := newFx(t)
	f.setDomain6(t, "2001:db8::1")
	f.reconcile(t)
	f.setDomain6(t, "")
	f.reconcile(t)
	if got := f.recordsByType(); len(got) != 1 || got["A"] != "10.0.0.1" {
		t.Fatalf("an owned AAAA must be deleted when no IPv6 is wanted: %+v", got)
	}
	if _, ok := f.row6(t); ok {
		t.Error("the AAAA row must be dropped")
	}

	// an adopted AAAA is not ours to delete: the row goes, the record stays
	g := newFx(t)
	g.setDomain6(t, "2001:db8::1")
	g.cf.Seed("sonarr.example.com", "2001:db8::1")
	g.reconcile(t)
	g.setDomain6(t, "")
	g.reconcile(t)
	if got := g.recordsByType(); got["AAAA"] != "2001:db8::1" {
		t.Fatalf("adopted AAAA was deleted: %+v", got)
	}
	if _, ok := g.row6(t); ok {
		t.Error("the AAAA row must be dropped even when the record is kept")
	}
}

func TestRemoveDeletesOwnedRecordsOfBothFamilies(t *testing.T) {
	f := newFx(t)
	f.setDomain6(t, "2001:db8::1")
	f.reconcile(t)
	for _, rec := range []store.DNSRecord{f.row(t), mustRow6(t, f)} {
		if deleted, err := f.sync.Remove(context.Background(), f.dom.ZoneID, rec); err != nil || !deleted {
			t.Fatalf("%s: deleted=%v err=%v", rec.Family, deleted, err)
		}
	}
	if n := len(f.cf.Records()); n != 0 {
		t.Errorf("%d records left", n)
	}
}

func TestHostDualStack(t *testing.T) {
	f := newHostFx(t)
	f.sync.Host.IP6 = "2001:db8::a"
	f.reconcileHost(t, false)
	if got := f.recordsByType(); len(got) != 2 || got["A"] != "192.168.25.165" || got["AAAA"] != "2001:db8::a" {
		t.Fatalf("%+v", got)
	}
	q, err := f.st.GetUIDNS(context.Background(), store.FamilyAAAA)
	if err != nil || q.State != "synced" || !q.Owned {
		t.Fatalf("%+v %v", q, err)
	}
	w := f.cf.Writes()
	f.reconcileHost(t, false)
	if f.cf.Writes() != w {
		t.Errorf("host resync wrote: %d -> %d", w, f.cf.Writes())
	}
	f.sync.Host.IP6 = ""
	f.reconcileHost(t, false)
	if got := f.recordsByType(); len(got) != 1 || got["A"] != "192.168.25.165" {
		t.Fatalf("clearing the host IPv6 must delete the owned AAAA: %+v", got)
	}
	if _, err := f.st.GetUIDNS(context.Background(), store.FamilyAAAA); err == nil {
		t.Error("the host AAAA row must be dropped")
	}
}

func TestHostAAAAConflict(t *testing.T) {
	f := newHostFx(t)
	f.sync.Host.IP6 = "2001:db8::a"
	f.cf.Seed("servanago.example.com", "2001:db8::bad")
	f.reconcileHost(t, false)
	q, _ := f.st.GetUIDNS(context.Background(), store.FamilyAAAA)
	if q.State != "conflict" || !strings.Contains(q.Error, "2001:db8::bad") {
		t.Fatalf("%+v", q)
	}
	if a := f.hostRow(t); a.State != "synced" {
		t.Errorf("A must sync despite the AAAA conflict: %+v", a)
	}
	f.reconcileHost(t, true)
	if q, _ = f.st.GetUIDNS(context.Background(), store.FamilyAAAA); q.State != "synced" || !q.Owned {
		t.Fatalf("take over: %+v", q)
	}
}
