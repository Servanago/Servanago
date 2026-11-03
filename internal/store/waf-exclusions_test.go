package store

import (
	"context"
	"testing"
)

func TestWafExclusionsRideSites(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	id := newScanSite(t, s, "excl.example.com")
	rt, err := s.GetSite(ctx, id)
	if err != nil || len(rt.Exclusions) != 0 {
		t.Fatalf("fresh site: %+v (%v)", rt, err)
	}
	rows := []WafExclusion{
		{SiteID: id, Kind: "remove", RuleID: "920280", Note: "noisy probes", AddedBy: "admin", AddedAt: 100},
		{SiteID: id, Kind: "narrow", RuleID: "942330", Target: "!ARGS:address_1", Note: "checkout", AddedBy: "admin", AddedAt: 200},
		{SiteID: id, Kind: "remove", RuleID: "attack-rce", AddedBy: "admin", AddedAt: 300},
	}
	for _, x := range rows {
		if err := s.AddWafExclusion(ctx, x); err != nil {
			t.Fatal(err)
		}
	}
	rt, _ = s.GetSite(ctx, id)
	if len(rt.Exclusions) != 3 {
		t.Fatalf("site carries %d exclusions, want 3", len(rt.Exclusions))
	}
	// order: removes before narrows, each group by rule id text (digits then tags)
	if rt.Exclusions[len(rt.Exclusions)-1].Kind != "narrow" {
		t.Errorf("narrow rows must come last: %+v", rt.Exclusions)
	}
	byID := map[string]WafExclusion{}
	for _, x := range rt.Exclusions {
		byID[x.RuleID] = x
	}
	tag, okTag := byID["attack-rce"]
	if !okTag || tag.Kind != "remove" || tag.AddedBy != "admin" || tag.AddedAt != 300 {
		t.Errorf("tag row wrong: %+v", tag)
	}
	if len(tag.TagsList()) != 1 {
		t.Errorf("a tag row must list its tags")
	}
	narrow, okNarrow := byID["942330"]
	if !okNarrow || narrow.Kind != "narrow" || narrow.Target != "!ARGS:address_1" || narrow.AddedAt != 200 {
		t.Errorf("narrow row wrong: %+v", narrow)
	}
	if narrow.IsTag() {
		t.Errorf("a numeric rule id is not a tag: %+v", narrow)
	}
	// list sites fills the same rows
	lst, err := s.ListSites(ctx)
	if err != nil || len(lst) != 1 || len(lst[0].Exclusions) != 3 {
		t.Fatalf("list sites: %d (%v)", len(lst), err)
	}
	// undo one
	if err := s.RemoveWafExclusion(ctx, id, "narrow", "942330", "!ARGS:address_1"); err != nil {
		t.Fatal(err)
	}
	if rt, _ = s.GetSite(ctx, id); len(rt.Exclusions) != 2 {
		t.Errorf("undo left %d rows", len(rt.Exclusions))
	}
	// re-add is idempotent (the save paths may repeat a click)
	if err := s.AddWafExclusion(ctx, rows[1]); err != nil {
		t.Fatal(err)
	}
	if rt, _ = s.GetSite(ctx, id); len(rt.Exclusions) != 3 {
		t.Errorf("re-add did not settle at 3: %d", len(rt.Exclusions))
	}
}
