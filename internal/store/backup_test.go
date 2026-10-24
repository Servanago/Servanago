package store

import (
	"context"
	"testing"
)

func TestBackupSettingsAndSiteOverrides(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	b, err := s.GetBackupSettings(ctx)
	if err != nil || b.Enabled || b.Dir != "/var/backups/servanago" || b.Sched != "daily@03:00" || b.Keep != 7 || b.KeepWeekly != 4 || !b.Panel || b.Pass != nil {
		t.Fatalf("defaults: %+v %v", b, err)
	}
	b.Enabled, b.Pass, b.Keep = true, []byte("sealed"), 9
	if err := s.SaveBackupSettings(ctx, b); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetBackupSettings(ctx); !got.Enabled || string(got.Pass) != "sealed" || got.Keep != 9 {
		t.Errorf("saved: %+v", got)
	}
	site, err := s.CreateSite(ctx, site("a.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveSiteBackup(ctx, site.ID, SiteBackup{On: true, Sched: "hourly", Keep: 2}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetSiteBackup(ctx, site.ID); !got.On || got.Sched != "hourly" || got.Keep != 2 {
		t.Errorf("site backup: %+v", got)
	}
	if err := s.SaveSiteBackup(ctx, 9999, SiteBackup{}); err == nil {
		t.Error("an unknown site must fail")
	}
}

func TestProfilesVolumesCascadeAndRuns(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	site, err := s.CreateSite(ctx, site("a.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	p := BackupProfile{SiteID: site.ID, Name: "db", Engine: "mariadb", Container: "c", DB: "d", User: "u", Secret: []byte("x")}
	if err := s.AddProfile(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := s.AddProfile(ctx, p); err == nil {
		t.Error("a duplicate profile name must fail")
	}
	if err := s.AddProfile(ctx, BackupProfile{SiteID: site.ID, Name: "z", Engine: "redis"}); err == nil {
		t.Error("an unknown engine must fail the CHECK")
	}
	_ = s.AddVolume(ctx, site.ID, "vol1")
	_ = s.AddVolume(ctx, site.ID, "vol1")
	if v, _ := s.ListVolumes(ctx, site.ID); len(v) != 1 {
		t.Errorf("volumes %v", v)
	}
	if err := s.DeleteSite(ctx, site.ID); err != nil {
		t.Fatal(err)
	}
	if ps, _ := s.ListProfiles(ctx, site.ID); len(ps) != 0 {
		t.Errorf("profiles survived the site: %v", ps)
	}
	if v, _ := s.ListVolumes(ctx, site.ID); len(v) != 0 {
		t.Errorf("volumes survived the site: %v", v)
	}

	r := BackupRun{RunID: "r1", Scope: "shop", Trigger: "manual", Status: "ok", Archive: "a", Started: 10, Finished: 20}
	if fresh, err := s.AddRun(ctx, r); err != nil || !fresh {
		t.Fatalf("first insert: %v %v", fresh, err)
	}
	if fresh, _ := s.AddRun(ctx, r); fresh {
		t.Error("the same run id must not be recorded twice")
	}
	_, _ = s.AddRun(ctx, BackupRun{RunID: "r2", Scope: "shop", Trigger: "schedule", Status: "failed", Error: "boom", Started: 30, Finished: 40})
	last, ok, err := s.LastRuns(ctx)
	if err != nil || last["shop"].RunID != "r2" || ok["shop"] != 20 {
		t.Errorf("last %+v ok %v %v", last, ok, err)
	}
}

func TestPanelSlugIsReserved(t *testing.T) {
	s := open(t)
	site, err := s.CreateSite(context.Background(), site("panel.example.com"))
	if err != nil || site.Slug == "panel" {
		t.Fatalf("slug %q %v", site.Slug, err)
	}
}
