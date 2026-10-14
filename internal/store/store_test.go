package store

import (
	"context"
	"path/filepath"
	"testing"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func mustDomain(t *testing.T, s *Store, name string) Domain {
	t.Helper()
	d, err := s.CreateDomain(context.Background(), Domain{Name: name, ZoneID: "z", DefaultIP: "10.0.0.1", CertMode: "wildcard"})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func route(domainID int64, sub string) Route {
	return Route{DomainID: domainID, Subdomain: sub, Scheme: "http", UpstreamHost: "192.168.1.20", UpstreamPort: 8989, Enabled: true}
}

func TestMigrationsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	mustDomain(t, s, "example.com")
	var v int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&v); err != nil || v != 1 {
		t.Fatalf("user_version %d %v", v, err)
	}
	s.Close()
	s, err = Open(path) // reopen: migrations must not re-run (would fail on CREATE TABLE) or lose data
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ds, err := s.ListDomains(context.Background())
	if err != nil || len(ds) != 1 {
		t.Fatalf("domains %v %v", ds, err)
	}
}

func TestDomainCRUD(t *testing.T) {
	s, ctx := open(t), context.Background()
	d := mustDomain(t, s, "example.com")
	got, err := s.GetDomain(ctx, d.ID)
	if err != nil || got.Name != "example.com" || got.CertMode != "wildcard" || got.CreatedAt == "" {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := s.CreateDomain(ctx, Domain{Name: "example.com", ZoneID: "z", DefaultIP: "1.1.1.1", CertMode: "wildcard"}); err == nil {
		t.Error("duplicate name accepted")
	}
	if _, err := s.CreateDomain(ctx, Domain{Name: "b.com", ZoneID: "z", DefaultIP: "1.1.1.1", CertMode: "bogus"}); err == nil {
		t.Error("bad cert_mode accepted")
	}
	d.CertMode = "per_host"
	if err := s.UpdateDomain(ctx, d); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetDomain(ctx, d.ID); got.CertMode != "per_host" {
		t.Errorf("update lost: %+v", got)
	}
	if err := s.DeleteDomain(ctx, d.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetDomain(ctx, d.ID); err == nil {
		t.Error("deleted domain still found")
	}
}

func TestRouteCRUDAndConstraints(t *testing.T) {
	s, ctx := open(t), context.Background()
	d := mustDomain(t, s, "example.com")

	r := route(d.ID, "sonarr")
	r.RecordIP, r.Allowlist, r.BasicUser, r.BasicHash, r.Preset = "10.9.9.9", "192.168.0.0/16", "u", "h", "Sonarr"
	r, err := s.CreateRoute(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.GetRoute(ctx, r.ID)
	if err != nil || got != r {
		t.Fatalf("round trip: %+v vs %+v (%v)", got, r, err)
	}

	if _, err := s.CreateRoute(ctx, route(d.ID, "sonarr")); err == nil {
		t.Error("duplicate (domain, subdomain) accepted")
	}
	for _, p := range []int{0, 65536} {
		bad := route(d.ID, "p")
		bad.UpstreamPort = p
		if _, err := s.CreateRoute(ctx, bad); err == nil {
			t.Errorf("port %d accepted", p)
		}
	}
	bad := route(d.ID, "s")
	bad.Scheme = "ftp"
	if _, err := s.CreateRoute(ctx, bad); err == nil {
		t.Error("bad scheme accepted")
	}

	got.Enabled, got.RecordIP, got.BasicUser, got.BasicHash = false, "", "", ""
	if err := s.UpdateRoute(ctx, got); err != nil {
		t.Fatal(err)
	}
	after, _ := s.GetRoute(ctx, r.ID)
	if after.Enabled || after.RecordIP != "" || after.BasicUser != "" {
		t.Errorf("update/NULL round trip: %+v", after)
	}

	if _, err := s.CreateRoute(ctx, route(d.ID, "radarr")); err != nil {
		t.Fatal(err)
	}
	rs, err := s.ListRoutes(ctx)
	if err != nil || len(rs) != 2 || rs[0].Subdomain != "radarr" {
		t.Fatalf("list (ordered by domain, subdomain): %+v %v", rs, err)
	}

	if err := s.DeleteDomain(ctx, d.ID); err == nil {
		t.Error("domain with routes deleted (FK restrict)")
	}
	if err := s.DeleteRoute(ctx, r.ID); err != nil {
		t.Fatal(err)
	}
}

func TestDNSRecordCascade(t *testing.T) {
	s, ctx := open(t), context.Background()
	d := mustDomain(t, s, "example.com")
	r, _ := s.CreateRoute(ctx, route(d.ID, "sonarr"))
	if _, err := s.GetDNS(ctx, r.ID); err == nil {
		t.Error("want not found before upsert")
	}
	rec := DNSRecord{RouteID: r.ID, CFRecordID: "cf1", Content: "10.0.0.1", Owned: true, State: "synced"}
	if err := s.UpsertDNS(ctx, rec); err != nil {
		t.Fatal(err)
	}
	rec.State, rec.Error = "error", "boom"
	if err := s.UpsertDNS(ctx, rec); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetDNS(ctx, r.ID)
	if err != nil || got.State != "error" || got.Error != "boom" || !got.Owned {
		t.Fatalf("%+v %v", got, err)
	}
	if err := s.UpsertDNS(ctx, DNSRecord{RouteID: r.ID, State: "weird"}); err == nil {
		t.Error("bad state accepted")
	}
	if err := s.DeleteRoute(ctx, r.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetDNS(ctx, r.ID); err == nil {
		t.Error("dns record survived route delete")
	}
}

func TestTxRollback(t *testing.T) {
	s, ctx := open(t), context.Background()
	err := s.Tx(ctx, func(tx *Store) error {
		if _, err := tx.CreateDomain(ctx, Domain{Name: "a.com", ZoneID: "z", DefaultIP: "1.1.1.1", CertMode: "wildcard"}); err != nil {
			return err
		}
		return context.Canceled
	})
	if err == nil {
		t.Fatal("want error")
	}
	if ds, _ := s.ListDomains(ctx); len(ds) != 0 {
		t.Errorf("rollback failed: %+v", ds)
	}
}
