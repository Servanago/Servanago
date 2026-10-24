package backup

import (
	"strings"
	"testing"
	"time"
)

func at(s string) time.Time {
	t, err := time.ParseInLocation("2006-01-02 15:04", s, time.UTC)
	if err != nil {
		panic(err)
	}
	return t
}

func TestParseSchedRejects(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", "must be hourly"}, {"daily", "must be hourly"}, {"daily@25:00", "00:00-23:59"}, {"daily@3:00", "HH:MM"},
		{"weekly@xyz@03:00", "weekday"}, {"weekly@mon", "must be hourly"}, {"daily@03:60", "00:00-23:59"}, {"hourly@x", "must be hourly"},
	} {
		_, err := ParseSched(tc.in)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: err %v, want %q", tc.in, err, tc.want)
		}
	}
}

func TestDue(t *testing.T) {
	for _, tc := range []struct {
		sched, last, now string
		want             bool
	}{
		{"daily@03:00", "", "2026-10-23 02:00", true},                  // never run
		{"daily@03:00", "2026-10-23 03:01", "2026-10-23 04:00", false}, // ran after today's slot
		{"daily@03:00", "2026-10-22 03:01", "2026-10-23 02:59", false}, // slot not reached yet
		{"daily@03:00", "2026-10-22 03:01", "2026-10-23 03:00", true},  // slot reached
		{"daily@03:00", "2026-10-20 03:01", "2026-10-23 12:00", true},  // missed slots collapse to one run
		{"hourly", "2026-10-23 10:05", "2026-10-23 10:45", false},
		{"hourly", "2026-10-23 09:55", "2026-10-23 10:00", true},
		{"weekly@sun@03:00", "2026-10-18 03:05", "2026-10-23 12:00", false}, // 2026-10-18 is a Sunday
		{"weekly@sun@03:00", "2026-10-17 12:00", "2026-10-23 12:00", true},
		{"weekly@fri@13:00", "2026-10-16 13:05", "2026-10-23 12:00", false}, // this Friday's slot is still ahead
	} {
		c, err := ParseSched(tc.sched)
		if err != nil {
			t.Fatal(err)
		}
		var last time.Time
		if tc.last != "" {
			last = at(tc.last)
		}
		if got := c.Due(last, at(tc.now)); got != tc.want {
			t.Errorf("%s last=%q now=%s: Due=%v, want %v", tc.sched, tc.last, tc.now, got, tc.want)
		}
	}
}

func TestPrune(t *testing.T) {
	var es []Entry
	for d := 0; d < 30; d++ { // one archive per day, 2026-10-23 backwards
		es = append(es, Entry{Name: at("2026-10-23 03:00").AddDate(0, 0, -d).Format("0102"), At: at("2026-10-23 03:00").AddDate(0, 0, -d)})
	}
	del := Prune(es, 7, 4)
	if len(es)-len(del) < 7 || len(es)-len(del) > 7+4 {
		t.Fatalf("kept %d of %d, want 7 to 11", len(es)-len(del), len(es))
	}
	gone := map[string]bool{}
	for _, e := range del {
		gone[e.Name] = true
	}
	for d := 0; d < 7; d++ { // the newest 7 always survive
		if gone[es[d].Name] {
			t.Errorf("newest archive %s was pruned", es[d].Name)
		}
	}
	if gone["1023"] || !gone["0924"] {
		t.Errorf("1023 pruned=%v (want false), 0924 pruned=%v (want true)", gone["1023"], gone["0924"])
	}
	if got := Prune(es, 0, 0); len(got) != len(es)-1 {
		t.Errorf("keep 0 pruned %d of %d, want all but the newest", len(got), len(es))
	}
}
