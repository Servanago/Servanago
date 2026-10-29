package store

import (
	"context"
	"strconv"
	"strings"
	"testing"
)

func newScanSite(t *testing.T, s *Store, host string) int64 {
	t.Helper()
	r, err := s.CreateSite(context.Background(), site(host))
	if err != nil {
		t.Fatal(err)
	}
	return r.ID
}

func TestScanRunsAndHitsLifeCycle(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	stID := newScanSite(t, s, "sonarr.example.com")
	run, err := s.InsertScanRun(ctx, stID, "manual", 1000)
	if err != nil {
		t.Fatal(err)
	}
	hit, err := s.AddScanHit(ctx, ScanHit{RunID: run, SiteID: stID, Path: "/srv/x/eicar.php", Virus: "Win.Test.EICAR", Action: "quarantined", QuarantinedTo: "/var/lib/servanago/quarantine/x/1-eicar.php", UpdatedAt: 1001})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.FinishScanRun(ctx, run, "ok", 12, 1, ""); err != nil {
		t.Fatal(err)
	}
	r, err := s.GetScanRun(ctx, run)
	if err != nil || r.State != "ok" || r.Files != 12 || r.Skipped != 1 || r.FinishedAt == 0 {
		t.Fatalf("run after finish: %+v %v", r, err)
	}
	hits, err := s.ListScanHits(ctx, run)
	if err != nil || len(hits) != 1 || hits[0].Action != "quarantined" || hits[0].Path != "/srv/x/eicar.php" {
		t.Fatalf("hits: %+v %v", hits, err)
	}

	// the dedupe: an unresolved quarantined hit suppresses re-alarm, a resolved one does not
	if ok, err := s.UnresolvedHitPath(ctx, stID, "/srv/x/eicar.php", "Win.Test.EICAR"); err != nil || !ok {
		t.Fatalf("unresolved = %v %v", ok, err)
	}
	if err := s.SetScanHitAction(ctx, hit, "restored", ""); err != nil {
		t.Fatal(err)
	}
	if h, err := s.GetScanHit(ctx, hit); err != nil || h.Action != "restored" || h.QuarantinedTo != "" || h.UpdatedAt == 0 {
		t.Fatalf("hit after restore: %+v %v", h, err)
	}
	if ok, _ := s.UnresolvedHitPath(ctx, stID, "/srv/x/eicar.php", "Win.Test.EICAR"); ok {
		t.Error("a restored hit still suppresses the alarm")
	}

	// listing filters by site and orders newest first
	t2 := newScanSite(t, s, "alpha.example.com")
	if _, err := s.InsertScanRun(ctx, t2, "sweep", 2000); err != nil {
		t.Fatal(err)
	}
	runs, err := s.ListScanRuns(ctx, 0, 10)
	if err != nil || len(runs) != 2 || runs[0].SiteID != t2 {
		t.Fatalf("all runs: %+v %v", runs, err)
	}
	if runs, err := s.ListScanRuns(ctx, stID, 10); err != nil || len(runs) != 1 {
		t.Fatalf("site runs: %+v %v", runs, err)
	}
	at, err := s.LastSweepAt(ctx)
	if err != nil || at != 2000 {
		t.Fatalf("last sweep: %d %v", at, err)
	}
}

func TestScanRetentionAndInterruption(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	stID := newScanSite(t, s, "retention.example.com")
	other := newScanSite(t, s, "other.example.com")
	_ = other
	var ids []int64
	for i := 1; i <= 7; i++ {
		run, err := s.InsertScanRun(ctx, stID, "sweep", int64(i*100))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.AddScanHit(ctx, ScanHit{RunID: run, SiteID: stID, Path: "/srv/x/" + strconv.Itoa(i) + ".php", Virus: "Win.Test.EICAR", Action: "live"}); err != nil {
			t.Fatal(err)
		}
		if err := s.FinishScanRun(ctx, run, "ok", i, 0, ""); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, run)
	}
	if _, err := s.InsertScanRun(ctx, stID, "manual", 8000); err != nil {
		t.Fatal(err)
	}
	if err := s.PruneScanRuns(ctx, 3); err != nil {
		t.Fatal(err)
	}
	runs, _ := s.ListScanRuns(ctx, 0, 100)
	sweep := 0
	for _, r := range runs {
		if r.Trigger == "sweep" {
			sweep++
		}
	}
	if sweep != 3 {
		t.Fatalf("sweep runs kept: %d (want 3), all: %+v", sweep, runs)
	}
	for _, run := range ids[:3] { // the hits of pruned runs went with them
		if hs, _ := s.ListScanHits(ctx, run); len(hs) != 0 {
			t.Fatalf("hits survived the pruned run %d", run)
		}
	}
	// a restart closes open runs
	stuck, _ := s.InsertScanRun(ctx, 2, "manual", 9000)
	if err := s.FailRunningScans(ctx, "interrupted by restart"); err != nil {
		t.Fatal(err)
	}
	if r, err := s.GetScanRun(ctx, stuck); err != nil || r.State != "error" || !strings.Contains(r.Error, "interrupted") {
		t.Fatalf("stuck run: %+v %v", r, err)
	}
}
