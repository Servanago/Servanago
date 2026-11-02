package store

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// WafEventCap is how many WAF event rows are kept; older ones are dropped as new ones
// arrive, exactly like the audit log. Tuning data, not state.
const WafEventCap = 10000

// TagsList splits the event's CRS category tags for the templates' chip row.
func (e WafEvent) TagsList() []string { return strings.Fields(e.Tags) }

// TagsList splits the rule's CRS category tags for the templates' chip row.
func (r WafEventRule) TagsList() []string { return strings.Fields(r.Tags) }

// ShortSeen renders a rule's newest event ts as a short UTC column.
func (r WafEventRule) ShortSeen() string {
	if r.LastSeen == 0 {
		return ""
	}
	return time.Unix(r.LastSeen, 0).UTC().Format("Jan 2 15:04")
}

// ShortTime renders an event ts as a short UTC column.
func (e WafEvent) ShortTime() string {
	return time.Unix(e.TS, 0).UTC().Format("Jan 2 15:04:05")
}

// WafEvent is one matched rule of one request, as the panel records it.
type WafEvent struct {
	ID      int64
	SiteID  int64
	TS      int64
	RuleID  string
	Message string
	Phase   int
	Verdict string // deny | detect
	Tags    string // space-separated CRS category tags (attack-sqli...); '' = none
	Host    string
	Path    string
	Client  string
	Method  string
}

// AddWafEvent appends a row and trims the table to the newest WafEventCap rows. Errors are
// returned for the caller's log; a dropped event never blocks a request (the writer drops
// on a busy store instead).
func (s *Store) AddWafEvent(ctx context.Context, e WafEvent) error {
	return s.Tx(ctx, func(tx *Store) error {
		if _, err := tx.q.ExecContext(ctx, `INSERT INTO waf_events (site_id, ts, rule_id, message, phase, verdict, tags, host, path, client, method)
			VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
			e.SiteID, e.TS, e.RuleID, e.Message, e.Phase, e.Verdict, e.Tags, e.Host, e.Path, e.Client, e.Method); err != nil {
			return fmt.Errorf("add waf event: %w", err)
		}
		if _, err := tx.q.ExecContext(ctx, `DELETE FROM waf_events WHERE id <= (SELECT MAX(id) FROM waf_events) - ?`, WafEventCap); err != nil {
			return fmt.Errorf("trim waf events: %w", err)
		}
		return nil
	})
}

// ListWafEvents returns the site's newest matches, newest first.
func (s *Store) ListWafEvents(ctx context.Context, siteID int64, limit int) ([]WafEvent, error) {
	rows, err := s.q.QueryContext(ctx, `SELECT id, site_id, ts, rule_id, message, phase, verdict, tags, host, path, client, method
		FROM waf_events WHERE site_id = ? ORDER BY id DESC LIMIT ?`, siteID, limit)
	if err != nil {
		return nil, fmt.Errorf("list waf events: %w", err)
	}
	defer rows.Close()
	var out []WafEvent
	for rows.Next() {
		var e WafEvent
		if err := rows.Scan(&e.ID, &e.SiteID, &e.TS, &e.RuleID, &e.Message, &e.Phase, &e.Verdict, &e.Tags, &e.Host, &e.Path, &e.Client, &e.Method); err != nil {
			return nil, fmt.Errorf("list waf events: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// WafEventRule is one rule's aggregate: what the tab's "most active rules" table shows.
type WafEventRule struct {
	RuleID   string
	Message  string
	Phase    int
	Verdict  string // the verdict of the rule's most severe event in the group
	Tags     string // the tags of the rule's newest event
	Count    int64
	LastSeen int64
}

// WafEventAggregates groups the site's events of the last 24 hours by rule.
func (s *Store) WafEventAggregates(ctx context.Context, siteID int64) ([]WafEventRule, error) {
	rows, err := s.q.QueryContext(ctx, `SELECT rule_id, message, phase, verdict, tags, count(*), max(ts)
		FROM waf_events WHERE site_id = ? AND ts >= ? GROUP BY rule_id ORDER BY count(*) DESC LIMIT 25`,
		siteID, time.Now().Add(-24*time.Hour).Unix())
	if err != nil {
		return nil, fmt.Errorf("aggregate waf events: %w", err)
	}
	defer rows.Close()
	var out []WafEventRule
	for rows.Next() {
		var r WafEventRule
		if err := rows.Scan(&r.RuleID, &r.Message, &r.Phase, &r.Verdict, &r.Tags, &r.Count, &r.LastSeen); err != nil {
			return nil, fmt.Errorf("aggregate waf events: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// DeleteWafEvents drops a site's event history (the exclusions feature's cleanup, and for
// tests); a site's ruleset is not affected.
func (s *Store) DeleteWafEvents(ctx context.Context, siteID int64) error {
	if _, err := s.q.ExecContext(ctx, `DELETE FROM waf_events WHERE site_id = ?`, siteID); err != nil {
		return fmt.Errorf("delete waf events: %w", err)
	}
	return nil
}
