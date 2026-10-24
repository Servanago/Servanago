package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/servanago/servanago/internal/backup"
	"github.com/servanago/servanago/internal/helper"
	"github.com/servanago/servanago/internal/secretbox"
	"github.com/servanago/servanago/internal/store"
)

const testKey = "0123456789abcdef0123456789abcdef-test-key"

// backupFixture builds a data dir whose database has backups on, a passphrase, and one opted-in static site.
func backupFixture(t *testing.T, profiles ...store.BackupProfile) (dir, out, root string) {
	t.Helper()
	t.Setenv("SERVANAGO_SECRET_KEY", testKey)
	base := t.TempDir()
	dir, out, root = filepath.Join(base, "data"), filepath.Join(base, "out"), filepath.Join(base, "site")
	for _, d := range []string{dir, root} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "servanago.db"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	pass, _ := secretbox.Seal(testKey, []byte("a long enough backup passphrase"))
	if err := st.SaveBackupSettings(ctx, store.BackupSettings{Enabled: true, Dir: out, Pass: pass, Sched: "daily@03:00", Keep: 3, KeepWeekly: 1, Panel: true}); err != nil {
		t.Fatal(err)
	}
	site, err := st.CreateSite(ctx, store.Site{Kind: "static", Hostnames: []string{"shop.example.com"}, StaticRoot: root, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SaveSiteBackup(ctx, site.ID, store.SiteBackup{On: true}); err != nil {
		t.Fatal(err)
	}
	for _, p := range profiles {
		p.SiteID = site.ID
		if err := st.AddProfile(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	return dir, out, root
}

func resultsOf(t *testing.T, out string) []backup.Result {
	t.Helper()
	var rs []backup.Result
	ents, _ := os.ReadDir(resultsDir(out))
	for _, e := range ents {
		r, ok := readResult(filepath.Join(resultsDir(out), e.Name()))
		if ok {
			rs = append(rs, r)
		}
	}
	return rs
}

func TestJobRunsWhatIsDueOnceAndBacksOffAfterAFailure(t *testing.T) {
	dir, out, _ := backupFixture(t, store.BackupProfile{Name: "bad", Engine: "sqlite", Path: "missing.sqlite"})
	j, cleanup, err := openJob(dir, filepath.Join(dir, "none.env"))
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	failed, err := j.execute(context.Background(), nil)
	if err != nil || !failed {
		t.Fatalf("failed=%v err=%v", failed, err)
	}
	got := map[string]string{}
	for _, r := range resultsOf(t, out) {
		got[r.Scope] = r.Status
	}
	if got["panel"] != "ok" || got["shop-example-com"] != "failed" && got["shop"] != "failed" {
		t.Fatalf("results %v", got)
	}
	n := len(resultsOf(t, out))
	if failed, err := j.execute(context.Background(), nil); err != nil || failed {
		t.Fatalf("second pass: failed=%v err=%v", failed, err)
	}
	if len(resultsOf(t, out)) != n {
		t.Errorf("a due scope that just ran or just failed ran again: %d -> %d results", n, len(resultsOf(t, out)))
	}
}

func TestJobManualRunThenRestore(t *testing.T) {
	dir, out, root := backupFixture(t)
	j, cleanup, err := openJob(dir, filepath.Join(dir, "none.env"))
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	ctx := context.Background()
	slug := siteSlug(t, j)
	if failed, err := j.execute(ctx, &helper.BackupRequestData{Op: "run", Scope: "site", Slug: slug, Actor: "brian"}); err != nil || failed {
		t.Fatalf("run: failed=%v err=%v", failed, err)
	}
	ins, _ := backup.List(out, slug)
	if len(ins) != 1 || ins[0].Manifest.Trigger != "manual" {
		t.Fatalf("archives %+v", ins)
	}
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("changed"), 0o644); err != nil {
		t.Fatal(err)
	}
	req := &helper.BackupRequestData{Op: "restore", Scope: "site", Slug: slug, Archive: ins[0].Name, Files: true, Actor: "brian"}
	if failed, err := j.execute(ctx, req); err != nil || failed {
		t.Fatalf("restore: failed=%v err=%v", failed, err)
	}
	if b, _ := os.ReadFile(filepath.Join(root, "index.html")); string(b) != "hi" {
		t.Errorf("index.html = %q", b)
	}
	var restore backup.Result
	for _, r := range resultsOf(t, out) {
		if r.Trigger == "restore" {
			restore = r
		}
	}
	if restore.Status != "ok" || restore.Actor != "brian" || restore.Archive != ins[0].Name {
		t.Errorf("restore result %+v", restore)
	}
	if ins, _ := backup.List(out, slug); len(ins) != 2 {
		t.Errorf("a restore must leave its pre-restore archive: %d archives", len(ins))
	}
}

func TestJobRefusesWithoutPassphrase(t *testing.T) {
	dir, _, _ := backupFixture(t)
	st, _ := store.Open(filepath.Join(dir, "servanago.db"))
	set, _ := st.GetBackupSettings(context.Background())
	set.Pass = nil
	_ = st.SaveBackupSettings(context.Background(), set)
	_ = st.Close()
	j, cleanup, err := openJob(dir, filepath.Join(dir, "none.env"))
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if _, err := j.execute(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "passphrase") {
		t.Fatalf("err %v", err)
	}
}

func siteSlug(t *testing.T, j *job) string {
	t.Helper()
	ss, err := j.st.ListSites(context.Background())
	if err != nil || len(ss) != 1 {
		t.Fatalf("sites %v %v", ss, err)
	}
	return ss[0].Slug
}
