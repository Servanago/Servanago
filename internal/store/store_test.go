package store

import (
	"context"
	"path/filepath"
	"reflect"
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

func site(host string) Site {
	return Site{Hostnames: []string{host}, Scheme: "http", UpstreamHost: "192.168.1.20", UpstreamPort: 8989, Enabled: true}
}

func TestMigrationsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	mustDomain(t, s, "example.com")
	var v int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&v); err != nil || v != LatestVersion() || v != 5 {
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

	r := site("sonarr.example.com")
	r.RecordIP, r.Allowlist, r.BasicUser, r.BasicHash = "10.9.9.9", "192.168.0.0/16", "u", "h"
	r.Stream, r.MaxBody = true, 2<<30
	r.ExtraRoutes = "/cryptpad_websocket=127.0.0.1:3303\n/api=/run/api.sock"
	r, err := s.CreateSite(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.GetSite(ctx, r.ID)
	if err != nil || !reflect.DeepEqual(got, r) {
		t.Fatalf("round trip: %+v vs %+v (%v)", got, r, err)
	}

	if _, err := s.CreateSite(ctx, site("sonarr.example.com")); err == nil {
		t.Error("duplicate hostname accepted")
	}
	for _, p := range []int{0, 65536} {
		bad := site("p.example.com")
		bad.UpstreamPort = p
		if _, err := s.CreateSite(ctx, bad); err == nil {
			t.Errorf("port %d accepted", p)
		}
	}
	bad := site("s.example.com")
	bad.Scheme = "ftp"
	if _, err := s.CreateSite(ctx, bad); err == nil {
		t.Error("bad scheme accepted")
	}

	got.Enabled, got.RecordIP, got.BasicUser, got.BasicHash = false, "", "", ""
	if err := s.UpdateSite(ctx, got); err != nil {
		t.Fatal(err)
	}
	after, _ := s.GetSite(ctx, r.ID)
	if after.Enabled || after.RecordIP != "" || after.BasicUser != "" {
		t.Errorf("update/NULL round trip: %+v", after)
	}

	if _, err := s.CreateSite(ctx, site("radarr.example.com")); err != nil {
		t.Fatal(err)
	}
	rs, err := s.ListSites(ctx)
	if err != nil || len(rs) != 2 || rs[0].Hostnames[0] != "radarr.example.com" {
		t.Fatalf("list (ordered by primary hostname): %+v %v", rs, err)
	}

	// A hostname's domain is optional: deleting the domain leaves the site (the web layer guards the UI path).
	if err := s.DeleteDomain(ctx, d.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSite(ctx, r.ID); err != nil {
		t.Fatal(err)
	}
}

func TestDNSRecordCascade(t *testing.T) {
	s, ctx := open(t), context.Background()
	mustDomain(t, s, "example.com")
	r, _ := s.CreateSite(ctx, site("sonarr.example.com"))
	if _, err := s.GetDNS(ctx, r.Hostnames[0], FamilyA); err == nil {
		t.Error("want not found before upsert")
	}
	rec := DNSRecord{Hostname: r.Hostnames[0], SiteID: r.ID, CFRecordID: "cf1", Content: "10.0.0.1", Owned: true, State: "synced"}
	if err := s.UpsertDNS(ctx, rec); err != nil {
		t.Fatal(err)
	}
	rec.State, rec.Error = "error", "boom"
	if err := s.UpsertDNS(ctx, rec); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetDNS(ctx, r.Hostnames[0], FamilyA)
	if err != nil || got.State != "error" || got.Error != "boom" || !got.Owned || got.Family != FamilyA {
		t.Fatalf("%+v %v", got, err)
	}
	if err := s.UpsertDNS(ctx, DNSRecord{Hostname: r.Hostnames[0], SiteID: r.ID, State: "weird"}); err == nil {
		t.Error("bad state accepted")
	}
	if err := s.DeleteSite(ctx, r.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetDNS(ctx, r.Hostnames[0], FamilyA); err == nil {
		t.Error("dns record survived site delete")
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

func TestListAndDeleteDNS(t *testing.T) {
	s, ctx := open(t), context.Background()
	mustDomain(t, s, "example.com")
	a, _ := s.CreateSite(ctx, site("a.example.com"))
	b, _ := s.CreateSite(ctx, site("b.example.com"))
	for _, r := range []Site{a, b} {
		if err := s.UpsertDNS(ctx, DNSRecord{Hostname: r.Hostnames[0], SiteID: r.ID, State: "synced", Owned: true}); err != nil {
			t.Fatal(err)
		}
	}
	all, err := s.ListDNS(ctx)
	if err != nil || len(all) != 2 {
		t.Fatalf("%v %v", all, err)
	}
	if err := s.DeleteDNS(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if all, _ := s.ListDNS(ctx); len(all) != 1 || all[0].SiteID != b.ID {
		t.Fatalf("%v", all)
	}
}

func TestUIDNSRecord(t *testing.T) {
	s, ctx := open(t), context.Background()
	if _, err := s.GetUIDNS(ctx, FamilyA); err == nil {
		t.Fatal("want not found before upsert")
	}
	rec := DNSRecord{CFRecordID: "cf1", Content: "192.168.1.5", Owned: true, State: "synced", SyncedAt: "now"}
	if err := s.UpsertUIDNS(ctx, rec); err != nil {
		t.Fatal(err)
	}
	rec.State, rec.Error, rec.Owned = "conflict", "points elsewhere", false
	if err := s.UpsertUIDNS(ctx, rec); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetUIDNS(ctx, FamilyA)
	if err != nil || got.State != "conflict" || got.Error != "points elsewhere" || got.Owned || got.CFRecordID != "cf1" {
		t.Fatalf("%+v %v", got, err)
	}
	if err := s.UpsertUIDNS(ctx, DNSRecord{State: "weird"}); err == nil {
		t.Error("bad state accepted")
	}
	if _, err := s.db.Exec("INSERT INTO ui_dns_record (family, state) VALUES ('MX', 'pending')"); err == nil {
		t.Error("an unknown record family was accepted")
	}
}

func TestTOTPLifecycle(t *testing.T) {
	s, ctx := open(t), context.Background()
	u := mustUser(t, s, "admin")
	if _, ok, err := s.GetTOTP(ctx, u.ID); ok || err != nil {
		t.Fatalf("empty: %v %v", ok, err)
	}
	if err := s.SaveTOTP(ctx, u.ID, []byte("sealed1")); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveTOTP(ctx, u.ID, []byte("sealed2")); err != nil { // unconfirmed seed is replaceable
		t.Fatal(err)
	}
	if ok, _ := s.AdvanceTOTPStep(ctx, u.ID, 5); ok {
		t.Fatal("step accepted before enable")
	}
	if err := s.EnableTOTP(ctx, u.ID, 10, []string{"h1", "h2"}); err != nil {
		t.Fatal(err)
	}
	got, ok, _ := s.GetTOTP(ctx, u.ID)
	if !ok || !got.Enabled || string(got.Secret) != "sealed2" || got.LastStep != 10 {
		t.Fatalf("%+v", got)
	}
	if err := s.SaveTOTP(ctx, u.ID, []byte("x")); err == nil {
		t.Error("enabled seed overwritten")
	}
	for _, c := range []struct {
		step int64
		want bool
	}{{10, false}, {9, false}, {11, true}, {11, false}} {
		if ok, _ := s.AdvanceTOTPStep(ctx, u.ID, c.step); ok != c.want {
			t.Errorf("step %d: %v want %v", c.step, ok, c.want)
		}
	}
	if ok, _ := s.UseBackupCode(ctx, u.ID, "h1"); !ok {
		t.Error("first use")
	}
	if ok, _ := s.UseBackupCode(ctx, u.ID, "h1"); ok {
		t.Error("second use")
	}
	if ok, _ := s.UseBackupCode(ctx, u.ID, "nope"); ok {
		t.Error("unknown code")
	}
	if n, _ := s.CountBackupCodes(ctx, u.ID); n != 1 {
		t.Errorf("unused %d", n)
	}
	if err := s.EnableTOTP(ctx, u.ID, 1, nil); err != nil { // idempotent update path
		t.Fatal(err)
	}
}

func TestPasskeysAndResetAuth(t *testing.T) {
	s, ctx := open(t), context.Background()
	u := mustUser(t, s, "admin")
	p := Passkey{ID: "a", RPID: "h.example.com", CredentialID: []byte{1}, Credential: "{}", Name: "laptop"}
	if err := s.AddPasskey(ctx, u.ID, p); err != nil {
		t.Fatal(err)
	}
	p.ID = "b"
	if err := s.AddPasskey(ctx, u.ID, p); err == nil {
		t.Error("duplicate credential id accepted")
	}
	if err := s.TouchPasskey(ctx, []byte{1}, `{"n":2}`); err != nil {
		t.Fatal(err)
	}
	ps, _ := s.ListPasskeys(ctx, u.ID)
	if len(ps) != 1 || ps[0].Credential != `{"n":2}` || ps[0].LastUsedAt == "" {
		t.Fatalf("%+v", ps)
	}
	if err := s.SaveTOTP(ctx, u.ID, []byte("s")); err != nil {
		t.Fatal(err)
	}
	if err := s.EnableTOTP(ctx, u.ID, 1, []string{"x", "y"}); err != nil {
		t.Fatal(err)
	}
	totp, codes, keys, err := s.ResetAuth(ctx, u.ID)
	if err != nil || !totp || codes != 2 || keys != 1 {
		t.Fatalf("%v %d %d %v", totp, codes, keys, err)
	}
	if ps, _ := s.ListPasskeys(ctx, u.ID); len(ps) != 0 {
		t.Error("passkeys left")
	}
	if _, ok, _ := s.GetTOTP(ctx, u.ID); ok {
		t.Error("totp left")
	}
	if ok, _ := s.DeletePasskey(ctx, u.ID, "a"); ok {
		t.Error("deleted a ghost")
	}
}

func TestDNSRecordsPerFamily(t *testing.T) {
	s, ctx := open(t), context.Background()
	mustDomain(t, s, "example.com")
	r, _ := s.CreateSite(ctx, site("app.example.com"))
	a := DNSRecord{Hostname: r.Hostnames[0], SiteID: r.ID, Family: FamilyA, CFRecordID: "a1", Content: "203.0.113.5", Owned: true, State: "synced"}
	aaaa := DNSRecord{Hostname: r.Hostnames[0], SiteID: r.ID, Family: FamilyAAAA, CFRecordID: "q1", Content: "2001:db8::5", Owned: false, State: "conflict", Error: "x"}
	for _, rec := range []DNSRecord{a, aaaa} {
		if err := s.UpsertDNS(ctx, rec); err != nil {
			t.Fatal(err)
		}
	}
	gotA, err := s.GetDNS(ctx, r.Hostnames[0], FamilyA)
	if err != nil || gotA.Content != "203.0.113.5" || gotA.State != "synced" {
		t.Fatalf("A: %+v %v", gotA, err)
	}
	gotQ, err := s.GetDNS(ctx, r.Hostnames[0], FamilyAAAA)
	if err != nil || gotQ.Content != "2001:db8::5" || gotQ.State != "conflict" || gotQ.Family != FamilyAAAA {
		t.Fatalf("AAAA: %+v %v", gotQ, err)
	}
	if all, _ := s.ListDNS(ctx); len(all) != 2 || all[0].Family != FamilyA || all[1].Family != FamilyAAAA {
		t.Fatalf("list must give A then AAAA: %+v", all)
	}
	if err := s.UpsertDNS(ctx, DNSRecord{Hostname: r.Hostnames[0], SiteID: r.ID, Family: "MX", State: "synced"}); err == nil {
		t.Error("an unknown family was accepted")
	}
	if err := s.DeleteDNSRecord(ctx, r.Hostnames[0], FamilyAAAA); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetDNS(ctx, r.Hostnames[0], FamilyAAAA); err == nil {
		t.Error("AAAA row survived its delete")
	}
	if _, err := s.GetDNS(ctx, r.Hostnames[0], FamilyA); err != nil {
		t.Errorf("deleting AAAA must leave A: %v", err)
	}
	_ = s.UpsertDNS(ctx, aaaa)
	if err := s.DeleteDNS(ctx, r.ID); err != nil {
		t.Fatal(err)
	}
	if all, _ := s.ListDNS(ctx); len(all) != 0 {
		t.Errorf("DeleteDNS must remove every family: %+v", all)
	}
	_ = s.UpsertDNS(ctx, a)
	_ = s.UpsertDNS(ctx, aaaa)
	if err := s.DeleteSite(ctx, r.ID); err != nil {
		t.Fatal(err)
	}
	if all, _ := s.ListDNS(ctx); len(all) != 0 {
		t.Errorf("rows survived the site: %+v", all)
	}
}

func TestUIDNSPerFamily(t *testing.T) {
	s, ctx := open(t), context.Background()
	_ = s.UpsertUIDNS(ctx, DNSRecord{Family: FamilyA, Content: "203.0.113.9", State: "synced", Owned: true})
	_ = s.UpsertUIDNS(ctx, DNSRecord{Family: FamilyAAAA, Content: "2001:db8::9", State: "pending", Owned: true})
	if r, err := s.GetUIDNS(ctx, FamilyAAAA); err != nil || r.Content != "2001:db8::9" || r.State != "pending" {
		t.Fatalf("%+v %v", r, err)
	}
	if all, err := s.ListUIDNS(ctx); err != nil || len(all) != 2 {
		t.Fatalf("%+v %v", all, err)
	}
	if err := s.DeleteUIDNS(ctx, FamilyAAAA); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetUIDNS(ctx, FamilyAAAA); err == nil {
		t.Error("AAAA host row survived")
	}
	if _, err := s.GetUIDNS(ctx, FamilyA); err != nil {
		t.Errorf("A host row must stay: %v", err)
	}
}

func TestIPv6FieldsRoundTrip(t *testing.T) {
	s, ctx := open(t), context.Background()
	d, err := s.CreateDomain(ctx, Domain{Name: "example.com", ZoneID: "z", DefaultIP: "10.0.0.1", DefaultIP6: "2001:db8::1", CertMode: "wildcard"})
	if err != nil || d.DefaultIP6 != "2001:db8::1" {
		t.Fatalf("%+v %v", d, err)
	}
	d.DefaultIP6 = ""
	if err := s.UpdateDomain(ctx, d); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetDomain(ctx, d.ID); got.DefaultIP6 != "" {
		t.Errorf("default_ip6 not cleared: %+v", got)
	}
	r := site("app.example.com")
	r.RecordIP6 = "2001:db8::77"
	r, err = s.CreateSite(ctx, r)
	if err != nil || r.RecordIP6 != "2001:db8::77" {
		t.Fatalf("%+v %v", r, err)
	}
	r.RecordIP6 = ""
	if err := s.UpdateSite(ctx, r); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetSite(ctx, r.ID); got.RecordIP6 != "" {
		t.Errorf("record_ip6 not cleared: %+v", got)
	}
}
