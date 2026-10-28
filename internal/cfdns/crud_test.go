package cfdns

import (
	"context"
	"strings"
	"testing"

	"github.com/servanago/servanago/internal/cfdns/cftest"
)

func TestListZonesSortedAndPaged(t *testing.T) {
	c, f := recordClient(t)
	f.AddZone("zeta.example.com", "z2")
	f.AddZone("alpha.example.com", "z1")
	f.PageSize = 1 // two zones, one per page: the client must walk both pages
	zs, err := c.ListZones(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(zs) != 2 || zs[0].Name != "alpha.example.com" || zs[1].Name != "zeta.example.com" {
		t.Fatalf("names %+v", zs)
	}
	if zs[0].ID != "z1" || zs[0].Status != "active" || zs[1].ID != "z2" {
		t.Fatalf("ids/status %+v", zs)
	}
}

func TestListRecordsSortedWithFields(t *testing.T) {
	c, f := recordClient(t)
	f.Add(cftest.Record{Name: "txt.example.com", Type: "TXT", Content: `"v=spf1 -all"`, TTL: 60})
	f.Add(cftest.Record{Name: "www.example.com", Type: "CNAME", Content: "app.example.com", TTL: 300, Proxied: true, Comment: "main site"})
	f.Add(cftest.Record{Name: "app.example.com", Type: "AAAA", Content: "2001:db8::1"})
	rs, err := c.ListRecords(context.Background(), "z")
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 3 {
		t.Fatalf("records %+v", rs)
	}
	types := []string{rs[0].Type, rs[1].Type, rs[2].Type}
	if types[0] != "AAAA" || types[1] != "CNAME" || types[2] != "TXT" {
		t.Fatalf("sort order %v", types)
	}
	cn := rs[1]
	if cn.ID == "" || cn.Content != "app.example.com" || cn.TTL != 300 || !cn.Proxied || cn.Comment != "main site" {
		t.Fatalf("CNAME fields %+v", cn)
	}
	if rs[2].Content != `"v=spf1 -all"` || rs[2].TTL != 60 {
		t.Fatalf("TXT fields %+v", rs[2])
	}
	if rs[0].TTL != 1 || rs[0].Proxied || rs[0].Comment != "" {
		t.Fatalf("AAAA defaults %+v", rs[0])
	}
}

func TestCreateFullRoundTripsEveryTypeShape(t *testing.T) {
	c, f := recordClient(t)
	ctx := context.Background()
	want := []FullRecord{
		{Type: "A", Name: "a.example.com", Content: "203.0.113.5", TTL: 120, Proxied: true, Comment: "web"},
		{Type: "AAAA", Name: "a6.example.com", Content: "2001:db8::5"},
		{Type: "CNAME", Name: "cdn.example.com", Content: "app.example.com", TTL: 300},
		{Type: "TXT", Name: "x.example.com", Content: `hello world`},
		{Type: "MX", Name: "example.com", Content: "mail.example.com", Priority: 10, TTL: 3600},
		{Type: "NS", Name: "delegated.example.com", Content: "ns1.example.net"},
		{Type: "SRV", Name: "_sip._tcp.example.com", Content: "10 5 8080 sip.example.com"},
		{Type: "CAA", Name: "example.com", Content: `0 issue "letsencrypt.org"`},
	}
	for _, r := range want {
		if _, err := c.CreateRecordFull(ctx, "z", r); err != nil {
			t.Fatalf("create %s: %v", r.Type, err)
		}
	}
	got, err := c.ListRecords(ctx, "z")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("got %d records: %+v", len(got), got)
	}
	byType := map[string]FullRecord{}
	for _, w := range want {
		byType[w.Type] = w
	}
	for _, g := range got {
		w := byType[g.Type]
		if g.Name != w.Name || g.Content != w.Content || g.TTL != int(ttlOf(w)) || g.Proxied != w.Proxied ||
			g.Comment != w.Comment || g.Priority != w.Priority {
			t.Errorf("%s round trip: got %+v want %+v", g.Type, g, w)
		}
	}
	// A record's proxied flag really reached Cloudflare; TXT's did not (the API refuses it there).
	tf := f.Records()
	proxied := map[string]bool{}
	for _, fr := range tf {
		proxied[fr.Type] = fr.Proxied
	}
	if !proxied["A"] || proxied["TXT"] {
		t.Errorf("proxied flag per type: %v", proxied)
	}
}

func TestCreateFullRejectsReadWriteOnlyTypes(t *testing.T) {
	c, _ := recordClient(t)
	for _, typ := range []string{"TLSA", "DS", "SVCB", "HTTPS", "", "TXT2"} {
		if _, err := c.CreateRecordFull(context.Background(), "z", FullRecord{Type: typ, Name: "x.example.com", Content: "z"}); err == nil {
			t.Errorf("type %q was accepted", typ)
		} else if !strings.Contains(err.Error(), "read-only") {
			t.Errorf("type %q: error does not say why: %v", typ, err)
		}
	}
}

func TestUpdateFullRewritesFields(t *testing.T) {
	c, f := recordClient(t)
	ctx := context.Background()
	id, err := c.CreateRecordFull(ctx, "z", FullRecord{Type: "MX", Name: "example.com", Content: "mail.example.com", Priority: 10})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.UpdateRecordFull(ctx, "z", id, FullRecord{Type: "MX", Name: "example.com", Content: "mail2.example.com", Priority: 20, TTL: 7200, Comment: "moved"}); err != nil {
		t.Fatal(err)
	}
	rs, err := c.ListRecords(ctx, "z")
	if err != nil || len(rs) != 1 {
		t.Fatalf("records %+v %v", rs, err)
	}
	r := rs[0]
	if r.ID != id || r.Content != "mail2.example.com" || r.Priority != 20 || r.TTL != 7200 || r.Comment != "moved" {
		t.Fatalf("updated record %+v", r)
	}
	// SRV updates go through the data object and read back as the composed content line.
	srvID, err := c.CreateRecordFull(ctx, "z", FullRecord{Type: "SRV", Name: "_s._tcp.example.com", Content: "10 5 8080 a.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.UpdateRecordFull(ctx, "z", srvID, FullRecord{Type: "SRV", Name: "_s._tcp.example.com", Content: "20 1 8081 b.example.com"}); err != nil {
		t.Fatal(err)
	}
	rs, _ = c.ListRecords(ctx, "z")
	if len(rs) != 2 || rs[0].Type != "MX" || rs[0].Content != "mail2.example.com" || rs[1].Type != "SRV" || rs[1].Content != "20 1 8081 b.example.com" {
		t.Fatalf("SRV round trip %+v", rs)
	}
	if f.Writes() != 4 {
		t.Errorf("writes seen by Cloudflare: %d", f.Writes())
	}
}

func TestCreateFullValidatesSRVAndCAAShapes(t *testing.T) {
	c, _ := recordClient(t)
	bad := []FullRecord{
		{Type: "SRV", Name: "_s._tcp.example.com", Content: "not four fields"},
		{Type: "SRV", Name: "_s._tcp.example.com", Content: "1 2 3 four 5"},
		{Type: "SRV", Name: "_s._tcp.example.com", Content: "x 5 8080 a.example.com"},
		{Type: "CAA", Name: "example.com", Content: "0"},
		{Type: "CAA", Name: "example.com", Content: "zero issue letsencrypt.org"},
	}
	for _, r := range bad {
		if _, err := c.CreateRecordFull(context.Background(), "z", r); err == nil {
			t.Errorf("SRV/CAA shape accepted: %+v", r)
		}
	}
}

func TestListRecordsReportsCloudflareFailure(t *testing.T) {
	c, f := recordClient(t)
	f.FailWith("zone is gone")
	if _, err := c.ListRecords(context.Background(), "z"); err == nil || !strings.Contains(err.Error(), "zone is gone") {
		t.Fatalf("want the API error text, got %v", err)
	}
}
