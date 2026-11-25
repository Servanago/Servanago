package store

import (
	"context"
	"path/filepath"
	"testing"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "g.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestSiteProtectionRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	site, err := s.CreateSite(ctx, Site{Kind: "proxy", Scheme: "http", Hostnames: []string{"a.example.test"}, UpstreamHost: "127.0.0.1", UpstreamPort: 9000, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if site.Guard == nil || site.Guard.CHKind != "pow" || site.Guard.QCapacity != 100 {
		t.Fatalf("defaults missing: %+v", site.Guard)
	}
	d, err := s.CreateAlertDest(ctx, AlertDest{Name: "n", Kind: "ntfy", Target: []byte{1}, Events: "ban", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	site.Guard.BanOn, site.Guard.UAMode, site.Guard.Backends = true, "auto", "10.0.0.2:9000"
	site.X402 = []X402Route{{Path: "/api/", Price: "0.001", Mode: "bots", GrantKind: "token", TokenTTLs: 600}}
	site.AlertDests = []int64{d.ID}
	if err := s.UpdateSite(ctx, site); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetSite(ctx, site.ID)
	if !got.Guard.BanOn || got.Guard.UAMode != "auto" || got.Guard.Backends != "10.0.0.2:9000" || len(got.X402) != 1 || len(got.AlertDests) != 1 {
		t.Fatalf("protection lost: %+v %+v %v", got.Guard, got.X402, got.AlertDests)
	}
	// A caller that never loaded the set leaves it alone.
	bare := got
	bare.Guard, bare.X402, bare.AlertDests = nil, nil, nil
	bare.Notes = "touched"
	if err := s.UpdateSite(ctx, bare); err != nil {
		t.Fatal(err)
	}
	again, _ := s.GetSite(ctx, site.ID)
	if !again.Guard.BanOn || len(again.X402) != 1 {
		t.Errorf("a save without Guard wiped the protection set: %+v", again.Guard)
	}
	list, _ := s.ListSites(ctx)
	if len(list) != 1 || !list[0].Guard.BanOn || len(list[0].X402) != 1 {
		t.Errorf("ListSites protection: %+v", list)
	}
	if err := s.DeleteSite(ctx, site.ID); err != nil {
		t.Fatal(err)
	}
	if n := count(t, s.db, "site_x402") + count(t, s.db, "site_guard") + count(t, s.db, "site_alert_dests"); n != 0 {
		t.Errorf("%d protection rows survive the site", n)
	}
}

func TestPageSiteAndBansAndRouting(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	site, err := s.CreateSite(ctx, Site{Kind: "page", Hostnames: []string{"p.example.test"}, Enabled: true,
		Guard: &SiteGuard{CHKind: "pow", CHDifficulty: "medium"}, Page: SitePage{Status: 301, Target: "https://x.example.test", KeepPath: true}})
	if err != nil {
		t.Fatal(err)
	}
	if !site.Page.IsRedirect() || site.Page.Target != "https://x.example.test" {
		t.Errorf("page: %+v", site.Page)
	}
	if err := s.UpsertBan(ctx, Ban{Client: "1.2.3.4", Source: "auto", Level: 1, CreatedAt: 10, Until: 20}); err != nil {
		t.Fatal(err)
	}
	if bs, _ := s.ListBans(ctx, 15); len(bs) != 1 {
		t.Errorf("bans %v", bs)
	}
	if bs, _ := s.ListBans(ctx, 25); len(bs) != 0 {
		t.Errorf("expired ban listed")
	}
	_ = s.PruneBans(ctx, 30)
	if _, err := s.GetBan(ctx, "1.2.3.4"); !ErrNoRows(err) {
		t.Errorf("pruned ban still there: %v", err)
	}
	all := []AlertDest{{ID: 1, Enabled: true, Events: "ban x402"}, {ID: 2, Enabled: true, Events: "scan"}, {ID: 3, Enabled: false, Events: "ban"}}
	if got := RouteAlert(all, nil, "ban"); len(got) != 1 || got[0].ID != 1 {
		t.Errorf("route %v", got)
	}
	if got := RouteAlert(all, []int64{2}, "ban"); len(got) != 0 {
		t.Errorf("override must narrow: %v", got)
	}
	gs, err := s.GetGuardSettings(ctx)
	if err != nil || gs.BanThreshold != 20 || gs.X402Network != "eip155:8453" {
		t.Errorf("settings %+v %v", gs, err)
	}
}
