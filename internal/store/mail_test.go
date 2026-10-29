package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"
)

// seedMailDomain writes one full row and returns its id.
func seedMailDomain(t *testing.T, s *Store, ctx context.Context, name string, md MailDomain) int64 {
	t.Helper()
	md.Name = name
	id, created, err := s.UpsertMailDomain(ctx, md)
	if err != nil || !created {
		t.Fatalf("upsert %s: %v created=%v", name, err, created)
	}
	return id
}

func mailSeed() MailDomain {
	return MailDomain{Name: "example.test", PMServerID: 11, PMDomainID: 22, DKIMHost: "sel.example.test", DKIMText: "v=DKIM1 k=rsa p=AAA",
		ReturnPath: "pm-bounces.example.test", HookUser: "mailx", HookPassHash: "$2a$10$hash",
		DNSSetup: "wrote some rows", DKIMState: "verified", RPState: "pending", LMTPAddr: "192.168.1.9:24"}
}

func TestMailSettingsRoundTrip(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	ctx := context.Background()
	cur, _ := s.GetSettings(ctx)
	cur.MailToken, cur.MailLMTP, cur.MailTLS, cur.MailUser, cur.MailPass, cur.UpdatedAt =
		[]byte{7, 8}, "127.0.0.1:2424", "starttls", "relay", []byte{9}, now
	if err := s.SaveSettings(ctx, cur); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetSettings(ctx)
	if string(got.MailToken) != "\x07\x08" || got.MailLMTP != "127.0.0.1:2424" ||
		got.MailTLS != "starttls" || got.MailUser != "relay" || string(got.MailPass) != "\x09" {
		t.Fatalf("mail settings round trip: %+v", got)
	}
	cur.MailToken = nil // cleared token comes back as none
	if err := s.SaveSettings(ctx, cur); err != nil {
		t.Fatal(err)
	}
	if got, _ = s.GetSettings(ctx); got.MailToken != nil || got.MailLMTP != "127.0.0.1:2424" {
		t.Fatalf("cleared token lost the rest: %+v", got)
	}
}

func TestMailDomainCRUD(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	ctx := context.Background()

	id := seedMailDomain(t, s, ctx, "Example.test", mailSeed()) // the name is lower-cased

	d, err := s.GetMailDomain(ctx, "example.test")
	if err != nil || d.ID != id || d.PMServerID != 11 || d.DKIMText != "v=DKIM1 k=rsa p=AAA" ||
		d.HookPassHash != "$2a$10$hash" || d.DKIMState != "verified" || d.LMTPAddr != "192.168.1.9:24" {
		t.Fatalf("read back: %+v %v", d, err)
	}

	// upsert on the same name updates the provisioning fields and leaves counters alone
	if err := s.CountMail(ctx, id, true, "recv", "delivered"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetMailDNS(ctx, id, "h", "t", "p", "notes"); err != nil {
		t.Fatal(err)
	}
	id2, created, err := s.UpsertMailDomain(ctx, mailSeed())
	if err != nil || created || id2 != id {
		t.Fatalf("re-upsert: %d %v %v", id2, err, created)
	}
	if got, _ := s.GetMailDomain(ctx, "example.test"); got.Recv != 1 || got.Delivered != 1 || got.LastInbound == 0 || got.DNSSetup != "wrote some rows" || got.LastVerify != 0 {
		t.Fatalf("upsert lost counters or notes: %+v", got)
	}

	ds, err := s.ListMailDomains(ctx)
	if err != nil || len(ds) != 1 || ds[0].Name != "example.test" {
		t.Fatalf("list: %+v %v", ds, err)
	}

	if err := s.DeleteMailDomain(ctx, "example.test"); err != nil {
		t.Fatal(err)
	}
	_, err = s.GetMailDomain(ctx, "example.test")
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("deleted row read: %v", err)
	}
}

func TestMailDomainCountersClosed(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	ctx := context.Background()
	id := seedMailDomain(t, s, ctx, "example.test", MailDomain{})
	if err := s.CountMail(ctx, id, false, "nope"); err == nil {
		t.Fatal("an unknown counter must be refused")
	}
	if err := s.CountMail(ctx, id, true, "fallbacks", "deduped", "rejected"); err != nil {
		t.Fatal(err)
	}
	d, _ := s.GetMailDomain(ctx, "example.test")
	if d.Fallbacks != 1 || d.Deduped != 1 || d.Rejected != 1 || d.Recv != 0 || d.LastInbound == 0 {
		t.Fatalf("counters: %+v", d)
	}
}

func TestMailDomainDeleteFailsWhenMissing(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.DeleteMailDomain(context.Background(), "missing.test"); err == nil {
		t.Fatal("deleting an unprovisioned domain must fail")
	}
}

func TestMailEventsAndDelivered(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	ctx := context.Background()
	did := seedMailDomain(t, s, ctx, "example.test", MailDomain{})

	eid, err := s.InsertMailEvent(ctx, MailEvent{DomainID: did, RecordType: "Bounce", RecordID: "b1",
		MessageID: "m1", Address: "a@example.test", Summary: "hard bounce", Payload: `{"x":1}`})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.InsertMailEvent(ctx, MailEvent{DomainID: did, RecordType: "Delivery", Payload: "{}"}); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkMailEventDSN(ctx, eid); err != nil {
		t.Fatal(err)
	}
	evs, err := s.ListMailEvents(ctx, did, 1)
	if err != nil || len(evs) != 1 || evs[0].RecordType != "Delivery" {
		t.Fatalf("newest-first limit: %+v %v", evs, err)
	}
	evs, err = s.ListMailEvents(ctx, did, 10)
	if err != nil || len(evs) != 2 || evs[0].RecordType != "Delivery" || evs[1].RecordType != "Bounce" || evs[1].DSNSent == 0 {
		t.Fatalf("events: %+v %v", evs, err)
	}

	key := "b1b2b3b4"
	first, err := s.DeliverOnce(ctx, key, did)
	if err != nil || !first {
		t.Fatalf("first: %v %v", first, err)
	}
	if again, err := s.DeliverOnce(ctx, key, did); err != nil || again {
		t.Fatalf("second: %v %v", again, err)
	}

	if err := s.DeleteMailDomain(ctx, "example.test"); err != nil {
		t.Fatal(err)
	}
	if evs, _ = s.ListMailEvents(ctx, did, 10); len(evs) != 0 {
		t.Fatalf("events did not cascade: %+v", evs)
	}
}

func TestMailVerifyStatesUpdateLastVerify(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	ctx := context.Background()
	did := seedMailDomain(t, s, ctx, "example.test", MailDomain{})
	if err := s.SetMailVerifyStates(ctx, did, "verified", "failed"); err != nil {
		t.Fatal(err)
	}
	d, _ := s.GetMailDomain(ctx, "example.test")
	if d.DKIMState != "verified" || d.RPState != "failed" || d.LastVerify == 0 {
		t.Fatalf("states: %+v", d)
	}
}