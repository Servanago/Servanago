package trafficdb

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestRoundTripAndFilter(t *testing.T) {
	ctx := context.Background()
	d, err := Open(filepath.Join(t.TempDir(), "traffic.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	now := time.Now()
	rows := []Row{
		{TS: now.Unix(), Site: "a", Host: "a.test", Client: "1.1.1.1", Method: "GET", Path: "/x", Status: 200, Outcome: "pass"},
		{TS: now.Unix(), Site: "a", Host: "a.test", Client: "2.2.2.2", Method: "GET", Path: "/admin", Status: 502, Outcome: "pass", Err: "dial tcp: refused"},
		{TS: now.Unix(), Site: "b", Host: "b.test", Client: "1.1.1.1", Method: "GET", Path: "/", Status: 403, Outcome: "banned"},
	}
	if err := d.InsertLog(ctx, rows); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		f    Filter
		want int
	}{
		"all": {Filter{}, 3}, "site": {Filter{Site: "a"}, 2}, "client": {Filter{Client: "1.1.1.1"}, 2},
		"path": {Filter{Path: "adm"}, 1}, "errs": {Filter{ErrOnly: true}, 1}, "outcome": {Filter{Outcome: "banned"}, 1},
		"after": {Filter{AfterID: 2}, 1},
	} {
		got, err := d.List(ctx, tc.f)
		if err != nil || len(got) != tc.want {
			t.Errorf("%s: %d rows, want %d (%v)", name, len(got), tc.want, err)
		}
	}
	if err := d.PutRollups(ctx, []Rollup{{Site: "a", Minute: now.Unix() / 60, Req: 5, Lat: "[]"}}); err != nil {
		t.Fatal(err)
	}
	rs, _ := d.RollupsSince(ctx, "a", false, 0)
	if len(rs) != 1 || rs[0].Req != 5 {
		t.Errorf("rollups %+v", rs)
	}
	if err := d.DeleteSite(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if got, _ := d.List(ctx, Filter{}); len(got) != 1 {
		t.Errorf("after delete %d rows", len(got))
	}
}

func TestPruneKeepsNewestPerSite(t *testing.T) {
	ctx := context.Background()
	d, _ := Open(filepath.Join(t.TempDir(), "t.db"))
	defer d.Close()
	now := time.Now()
	var rows []Row
	for i := 0; i < 10; i++ {
		rows = append(rows, Row{TS: now.Unix(), Site: "a", Host: "h", Client: "c", Method: "GET", Path: "/", Outcome: "pass"})
	}
	rows = append(rows, Row{TS: now.AddDate(0, 0, -30).Unix(), Site: "a", Host: "h", Client: "c", Method: "GET", Path: "/old", Outcome: "pass"})
	_ = d.InsertLog(ctx, rows)
	if err := d.Prune(ctx, now, 7, 90, 4); err != nil {
		t.Fatal(err)
	}
	if got, _ := d.List(ctx, Filter{Limit: 100}); len(got) != 4 {
		t.Errorf("kept %d rows, want 4", len(got))
	}
}

// A file with another schema version is dropped, and an unreadable path degrades to an error, not a panic.
func TestVersionMismatchRecreates(t *testing.T) {
	p := filepath.Join(t.TempDir(), "t.db")
	d, _ := Open(p)
	_ = d.InsertLog(context.Background(), []Row{{TS: 1, Site: "a", Host: "h", Client: "c", Method: "GET", Path: "/", Outcome: "pass"}})
	_, _ = d.db.Exec("PRAGMA user_version = 99")
	_ = d.Close()
	d, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if got, _ := d.List(context.Background(), Filter{}); len(got) != 0 {
		t.Errorf("old rows survived a version change: %d", len(got))
	}
	if _, err := Open(filepath.Join(t.TempDir(), "no", "such", "t.db")); err == nil {
		t.Error("an unreachable path must fail to open")
	}
}
