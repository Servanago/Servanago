package dnssync

import (
	"context"
	"strings"
	"testing"

	"github.com/cloudflare/cloudflare-go/v7/option"

	"github.com/caretakarr/caretakarr/internal/cfdns"
	"github.com/caretakarr/caretakarr/internal/cfdns/cftest"
	"github.com/caretakarr/caretakarr/internal/store"
)

type fx struct {
	cf    *cftest.Fake
	st    *store.Store
	sync  *Syncer
	dom   store.Domain
	route store.Route
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
	r, err := st.CreateRoute(ctx, store.Route{DomainID: d.ID, Subdomain: "sonarr", Scheme: "http", UpstreamHost: "h", UpstreamPort: 1, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	c := cfdns.New("tok", option.WithBaseURL(cf.URL), option.WithMaxRetries(0))
	return &fx{cf, st, New(c, st), d, r}
}

func (f *fx) row(t *testing.T) store.DNSRecord {
	t.Helper()
	d, err := f.st.GetDNS(context.Background(), f.route.ID)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func (f *fx) reconcile(t *testing.T) {
	t.Helper()
	if err := f.sync.Reconcile(context.Background(), f.route.ID); err != nil {
		t.Fatal(err)
	}
}

func TestCreate(t *testing.T) {
	f := newFx(t)
	f.reconcile(t)
	recs := f.cf.Records()
	if len(recs) != 1 || recs[0].Name != "sonarr.example.com" || recs[0].Content != "10.0.0.1" || recs[0].Proxied || recs[0].Comment != "managed by caretakarr" {
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
	if err := f.sync.TakeOver(context.Background(), f.route.ID); err != nil {
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
	f.route.RecordIP = "10.0.0.2"
	if err := f.st.UpdateRoute(ctx, f.route); err != nil {
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
	g.route.RecordIP = "10.0.0.5"
	if err := g.st.UpdateRoute(ctx, g.route); err != nil {
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
	f.reconcile(t) // must not return an error: DNS failure never reverts the route
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
