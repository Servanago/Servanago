package cfdns

import (
	"context"
	"strings"
	"testing"

	"github.com/cloudflare/cloudflare-go/v7/option"

	"github.com/servanago/servanago/internal/cfdns/cftest"
)

func recordClient(t *testing.T) (*Client, *cftest.Fake) {
	t.Helper()
	f := cftest.New(t)
	return New("tok", option.WithBaseURL(f.URL), option.WithMaxRetries(0)), f
}

func TestRecordFamiliesAreIndependent(t *testing.T) {
	c, f := recordClient(t)
	ctx := context.Background()
	idA, err := c.CreateRecord(ctx, "z", "app.example.com", "A", "203.0.113.5")
	if err != nil {
		t.Fatal(err)
	}
	idQ, err := c.CreateRecord(ctx, "z", "app.example.com", "AAAA", "2001:db8::5")
	if err != nil {
		t.Fatal(err)
	}
	if idA == idQ {
		t.Fatal("A and AAAA must be separate records")
	}
	a, err := c.FindRecord(ctx, "z", "app.example.com", "A")
	if err != nil || a == nil || a.ID != idA || a.Content != "203.0.113.5" {
		t.Fatalf("A lookup: %+v %v", a, err)
	}
	q, err := c.FindRecord(ctx, "z", "app.example.com", "AAAA")
	if err != nil || q == nil || q.ID != idQ || q.Content != "2001:db8::5" {
		t.Fatalf("AAAA lookup: %+v %v", q, err)
	}
	types := map[string]string{}
	for _, r := range f.Records() {
		types[r.ID] = r.Type
	}
	if types[idA] != "A" || types[idQ] != "AAAA" {
		t.Errorf("record types sent to Cloudflare: %+v", types)
	}
	if err := c.UpdateRecord(ctx, "z", idQ, "app.example.com", "AAAA", "2001:db8::6"); err != nil {
		t.Fatal(err)
	}
	if q, _ := c.FindRecord(ctx, "z", "app.example.com", "AAAA"); q == nil || q.Content != "2001:db8::6" {
		t.Errorf("AAAA update: %+v", q)
	}
	if a, _ := c.FindRecord(ctx, "z", "app.example.com", "A"); a == nil || a.Content != "203.0.113.5" {
		t.Errorf("updating AAAA changed A: %+v", a)
	}
	if err := c.DeleteRecord(ctx, "z", idQ); err != nil {
		t.Fatal(err)
	}
	if q, _ := c.FindRecord(ctx, "z", "app.example.com", "AAAA"); q != nil {
		t.Errorf("AAAA survived its delete: %+v", q)
	}
}

func TestFindRecordNoneAndDuplicates(t *testing.T) {
	c, f := recordClient(t)
	ctx := context.Background()
	if r, err := c.FindRecord(ctx, "z", "none.example.com", "AAAA"); r != nil || err != nil {
		t.Fatalf("no record: %+v %v", r, err)
	}
	f.Seed("dup.example.com", "2001:db8::1")
	f.Seed("dup.example.com", "2001:db8::2")
	_, err := c.FindRecord(ctx, "z", "dup.example.com", "AAAA")
	if err == nil || !strings.Contains(err.Error(), "multiple AAAA records") {
		t.Fatalf("want a duplicate-record error naming AAAA, got %v", err)
	}
}

func TestRecordFamilyMustBeKnown(t *testing.T) {
	c, _ := recordClient(t)
	if _, err := c.CreateRecord(context.Background(), "z", "x.example.com", "MX", "1.2.3.4"); err == nil {
		t.Error("an unknown family was accepted")
	}
	if _, err := c.FindRecord(context.Background(), "z", "x.example.com", "TXT"); err == nil {
		t.Error("an unknown family was accepted by FindRecord")
	}
}
