// Package backup is the backup core: schedules, retention, encrypted archives, safe extraction, SQLite snapshots
// and typed database dumps. It knows nothing about systemd or the helper; `servanago backup-job` and the CLI drive it.
package backup

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Sched is a schedule preset: "hourly", "daily@HH:MM" or "weekly@DOW@HH:MM" (mon..sun), in the host's local time.
type Sched struct {
	kind string
	day  time.Weekday
	h, m int
}

var weekdays = map[string]time.Weekday{"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6}

func ParseSched(s string) (Sched, error) {
	p := strings.Split(s, "@")
	var c Sched
	var hm string
	switch {
	case s == "hourly":
		return Sched{kind: "hourly"}, nil
	case len(p) == 2 && p[0] == "daily":
		c.kind, hm = "daily", p[1]
	case len(p) == 3 && p[0] == "weekly":
		d, ok := weekdays[p[1]]
		if !ok {
			return c, fmt.Errorf("schedule %q: weekday %q must be mon, tue, wed, thu, fri, sat or sun", s, p[1])
		}
		c.kind, c.day, hm = "weekly", d, p[2]
	default:
		return c, fmt.Errorf("schedule %q must be hourly, daily@HH:MM or weekly@DOW@HH:MM", s)
	}
	if _, err := fmt.Sscanf(hm, "%02d:%02d", &c.h, &c.m); err != nil || len(hm) != 5 || c.h > 23 || c.m > 59 || c.h < 0 || c.m < 0 {
		return c, fmt.Errorf("schedule %q: time %q must be HH:MM, 00:00-23:59", s, hm)
	}
	return c, nil
}

// slot is the latest scheduled time at or before now.
func (c Sched) slot(now time.Time) time.Time {
	y, mo, d := now.Date()
	switch c.kind {
	case "hourly":
		return time.Date(y, mo, d, now.Hour(), 0, 0, 0, now.Location())
	case "daily":
		t := time.Date(y, mo, d, c.h, c.m, 0, 0, now.Location())
		if t.After(now) {
			t = t.AddDate(0, 0, -1)
		}
		return t
	}
	t := time.Date(y, mo, d-(int(now.Weekday())-int(c.day)+7)%7, c.h, c.m, 0, 0, now.Location())
	if t.After(now) {
		t = t.AddDate(0, 0, -7)
	}
	return t
}

// Due is true when a scheduled slot has passed since last (the zero time means never run). Missed slots collapse into one run.
func (c Sched) Due(last, now time.Time) bool { return last.Before(c.slot(now)) }

// Interval is the schedule's period, for the stale-backup rule (no success within twice this).
func (c Sched) Interval() time.Duration {
	switch c.kind {
	case "hourly":
		return time.Hour
	case "daily":
		return 24 * time.Hour
	}
	return 7 * 24 * time.Hour
}

// Entry is one archive as retention sees it.
type Entry struct {
	Name string
	At   time.Time
}

// Prune returns the entries to delete: it keeps the newest keep entries plus the newest entry of each of the
// weekly most recent ISO weeks that have one. It never deletes everything (keep below 1 counts as 1).
func Prune(es []Entry, keep, weekly int) []Entry {
	keep = max(keep, 1)
	s := append([]Entry(nil), es...)
	sort.Slice(s, func(i, j int) bool { return s[i].At.After(s[j].At) })
	kept := map[string]bool{}
	weeks := map[string]bool{}
	for i, e := range s {
		y, w := e.At.ISOWeek()
		wk := fmt.Sprintf("%d-%d", y, w)
		if i < keep {
			kept[e.Name] = true
		}
		if !weeks[wk] && len(weeks) < weekly {
			weeks[wk] = true
			kept[e.Name] = true
		}
	}
	var del []Entry
	for _, e := range s {
		if !kept[e.Name] {
			del = append(del, e)
		}
	}
	return del
}
