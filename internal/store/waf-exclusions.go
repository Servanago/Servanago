package store

import (
	"context"
	"fmt"
	"strings"
)

// WafExclusion is one per-site exclusion the admin chose: the rule stops running here
// ("remove") or stops looking at one target ("narrow"). The renderer turns the rows of a
// site into SecRuleRemoveById / SecRuleUpdateTargetById lines before the engine line.
type WafExclusion struct {
	SiteID  int64
	Kind    string // remove | narrow
	RuleID  string // the CRS rule id as text, or a CRS category tag (attack-sqli) for tag removals
	Target  string // narrow only: the target to drop with its negation, "!ARGS:checkout"
	Note    string
	AddedBy string
	AddedAt int64
}

// TagsList splits the CRS category tags of a remove row (none on a numeric rule id).
func (x WafExclusion) TagsList() []string { return strings.Fields(x.RuleID) }

// IsTag reports whether the row names a category tag rather than a numeric rule id.
func (x WafExclusion) IsTag() bool {
	return !isUint(x.RuleID)
}

func isUint(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return len(s) > 0
}

// AddWafExclusion inserts one exclusion row.
func (s *Store) AddWafExclusion(ctx context.Context, x WafExclusion) error {
	if _, err := s.q.ExecContext(ctx, `INSERT OR REPLACE INTO waf_exclusions (site_id, kind, rule_id, target, note, added_by, added_at)
		VALUES (?,?,?,?,?,?,?)`, x.SiteID, x.Kind, x.RuleID, x.Target, x.Note, x.AddedBy, x.AddedAt); err != nil {
		return fmt.Errorf("add waf exclusion: %w", err)
	}
	return nil
}

// RemoveWafExclusion deletes one row (the exclusion's undo); the re-render then drops its line.
func (s *Store) RemoveWafExclusion(ctx context.Context, siteID int64, kind, ruleID, target string) error {
	if _, err := s.q.ExecContext(ctx, `DELETE FROM waf_exclusions WHERE site_id=? AND kind=? AND rule_id=? AND target=?`,
		siteID, kind, ruleID, target); err != nil {
		return fmt.Errorf("remove waf exclusion: %w", err)
	}
	return nil
}

// siteExclusions returns every site's exclusion rows keyed by site id (order stable:
// removes before narrows, then rule id).
func (s *Store) siteExclusions(ctx context.Context) (map[int64][]WafExclusion, error) {
	rows, err := s.q.QueryContext(ctx, `SELECT site_id, kind, rule_id, target, note, added_by, added_at
		FROM waf_exclusions ORDER BY (kind = 'narrow'), rule_id, target`)
	if err != nil {
		return nil, fmt.Errorf("list waf exclusions: %w", err)
	}
	defer rows.Close()
	out := map[int64][]WafExclusion{}
	for rows.Next() {
		var x WafExclusion
		if err := rows.Scan(&x.SiteID, &x.Kind, &x.RuleID, &x.Target, &x.Note, &x.AddedBy, &x.AddedAt); err != nil {
			return nil, fmt.Errorf("list waf exclusions: %w", err)
		}
		out[x.SiteID] = append(out[x.SiteID], x)
	}
	return out, rows.Err()
}
