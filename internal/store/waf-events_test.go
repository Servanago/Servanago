package store

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestWafEventsRoundTrip(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	id := newScanSite(t, s, "events.example.com")
	now := time.Now().Unix()
	for i := 0; i < 3; i++ {
		if err := s.AddWafEvent(ctx, WafEvent{SiteID: id, TS: now - int64(i), RuleID: "942100", Message: fmt.Sprintf("sql %d", i),
			Phase: 2, Verdict: "detect", Tags: "attack-sqli paranoid", Host: "events.example.com", Path: "/?q=x", Client: "203.0.113.9", Method: "GET"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.AddWafEvent(ctx, WafEvent{SiteID: id, TS: now + 60, RuleID: "930120", Message: "os file", Phase: 1, Verdict: "deny", Host: "events.example.com", Path: "/?p=/etc/passwd", Method: "GET"}); err != nil {
		t.Fatal(err)
	}
	evs, err := s.ListWafEvents(ctx, id, 10)
	if err != nil || len(evs) != 4 {
		t.Fatalf("events: %d (%v)", len(evs), err)
	}
	if evs[0].RuleID != "930120" || evs[0].Verdict != "deny" || evs[0].Tags != "" {
		t.Errorf("newest event wrong: %+v", evs[0])
	}
	if len(evs[1].TagsList()) != 2 {
		t.Errorf("tags not split: %+v", evs[1])
	}
	ags, err := s.WafEventAggregates(ctx, id)
	if err != nil || len(ags) != 2 {
		t.Fatalf("aggregates: %d (%v)", len(ags), err)
	}
	if ags[0].Count != 3 || ags[0].Tags != "attack-sqli paranoid" {
		t.Errorf("loudest aggregate wrong: %+v", ags[0])
	}
	// events of another site do not leak across
	other := newScanSite(t, s, "quiet.example.com")
	if evs, _ := s.ListWafEvents(ctx, other, 10); len(evs) != 0 {
		t.Errorf("foreign events leaked: %d", len(evs))
	}
	if err := s.DeleteWafEvents(ctx, id); err != nil {
		t.Fatal(err)
	}
	if evs, _ := s.ListWafEvents(ctx, id, 100); len(evs) != 0 {
		t.Errorf("delete left %d events", len(evs))
	}
}

// The cap keeps exactly the newest WafEventCap rows, like the audit log.
func TestWafEventCapTrimsOldest(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	id := newScanSite(t, s, "cap.example.com")
	now := time.Now().Unix()
	total := WafEventCap + 7
	for i := 0; i < total; i++ {
		if err := s.AddWafEvent(ctx, WafEvent{SiteID: id, TS: now + int64(i), RuleID: fmt.Sprint(i), Verdict: "detect"}); err != nil {
			t.Fatal(err)
		}
	}
	evs, err := s.ListWafEvents(ctx, id, WafEventCap+10)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != WafEventCap {
		t.Fatalf("kept %d rows, want the cap %d", len(evs), WafEventCap)
	}
	if evs[0].RuleID != fmt.Sprint(total-1) {
		t.Errorf("newest event id %q, want %q", evs[0].RuleID, fmt.Sprint(total-1))
	}
	if evs[WafEventCap-1].RuleID != fmt.Sprint(total-WafEventCap) {
		t.Errorf("oldest kept event id %q, want %q", evs[WafEventCap-1].RuleID, fmt.Sprint(total-WafEventCap))
	}
}
