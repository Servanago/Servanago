// Scan runs and their quarantined hits. One run row per site per scan; hits carry the quarantine
// state the scan page and the MCP tools act on.
package store

import (
	"context"
	"fmt"
	"strings"
)

type ScanRun struct {
	ID         int64
	SiteID     int64
	Trigger    string // manual | sweep | backup
	StartedAt  int64
	FinishedAt int64
	State      string // running | ok | error
	Files      int
	Skipped    int // symlinks and files over the stream size limit
	Error      string
}

type ScanHit struct {
	ID            int64
	RunID         int64
	SiteID        int64
	Path          string
	Virus         string
	Action        string // live | quarantined | restored | ignored | error
	QuarantinedTo string
	UpdatedAt     int64
}

func (s *Store) InsertScanRun(ctx context.Context, siteID int64, trigger string, startedAt int64) (int64, error) {
	res, err := s.q.ExecContext(ctx, "INSERT INTO scan_runs (site_id, trigger, started_at) VALUES (?,?,?)",
		siteID, trigger, startedAt)
	if err != nil {
		return 0, fmt.Errorf("insert scan run: %w", err)
	}
	id, _ := res.LastInsertId()
	return id, nil
}

func (s *Store) FinishScanRun(ctx context.Context, id int64, state string, files, skipped int, errText string) error {
	if _, err := s.q.ExecContext(ctx,
		`UPDATE scan_runs SET finished_at=strftime('%s','now'), state=?, files=?, skipped=?, error=? WHERE id=?`,
		state, files, skipped, errText, id); err != nil {
		return fmt.Errorf("finish scan run %d: %w", id, err)
	}
	return nil
}

// FailRunningScans closes the run rows a restart interrupted (called at startup).
func (s *Store) FailRunningScans(ctx context.Context, errText string) error {
	if _, err := s.q.ExecContext(ctx,
		`UPDATE scan_runs SET finished_at=strftime('%s','now'), state='error', error=? WHERE state='running'`, errText); err != nil {
		return fmt.Errorf("fail running scans: %w", err)
	}
	return nil
}

func (s *Store) GetScanRun(ctx context.Context, id int64) (ScanRun, error) {
	var r ScanRun
	err := s.q.QueryRowContext(ctx,
		`SELECT id, site_id, trigger, started_at, finished_at, state, files, skipped, error FROM scan_runs WHERE id=?`, id).
		Scan(&r.ID, &r.SiteID, &r.Trigger, &r.StartedAt, &r.FinishedAt, &r.State, &r.Files, &r.Skipped, &r.Error)
	if err != nil {
		return r, fmt.Errorf("get scan run %d: %w", id, err)
	}
	return r, nil
}

// ListScanRuns returns the newest runs first; siteID 0 = every site.
func (s *Store) ListScanRuns(ctx context.Context, siteID int64, limit int) ([]ScanRun, error) {
	q := "SELECT id, site_id, trigger, started_at, finished_at, state, files, skipped, error FROM scan_runs"
	if limit <= 0 {
		limit = 50
	}
	args := []any{limit}
	if siteID != 0 {
		q += " WHERE site_id=?"
		args = []any{siteID, limit}
	}
	q += " ORDER BY started_at DESC, id DESC LIMIT ?"
	rows, err := s.q.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list scan runs: %w", err)
	}
	defer rows.Close()
	var out []ScanRun
	for rows.Next() {
		var r ScanRun
		if err := rows.Scan(&r.ID, &r.SiteID, &r.Trigger, &r.StartedAt, &r.FinishedAt, &r.State, &r.Files, &r.Skipped, &r.Error); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RunningScanForSite is the open run row of a site, if any.
func (s *Store) RunningScanForSite(ctx context.Context, siteID int64) (int64, error) {
	var id int64
	err := s.q.QueryRowContext(ctx,
		`SELECT id FROM scan_runs WHERE site_id=? AND state='running' ORDER BY started_at DESC LIMIT 1`, siteID).Scan(&id)
	return id, err
}

// LatestScanForSite is the site's newest finished run; badge query (false = none yet).
func (s *Store) LatestScanForSite(ctx context.Context, siteID int64) (r ScanRun, ok bool, err error) {
	rows, err := s.q.QueryContext(ctx,
		`SELECT id, site_id, trigger, started_at, finished_at, state, files, skipped, error FROM scan_runs
		 WHERE site_id=? AND state!='running' ORDER BY started_at DESC, id DESC LIMIT 1`, siteID)
	if err != nil {
		return r, false, fmt.Errorf("latest scan for site %d: %w", siteID, err)
	}
	defer rows.Close()
	if rows.Next() {
		if err := rows.Scan(&r.ID, &r.SiteID, &r.Trigger, &r.StartedAt, &r.FinishedAt, &r.State, &r.Files, &r.Skipped, &r.Error); err != nil {
			return r, false, err
		}
		return r, true, nil
	}
	return r, false, rows.Err()
}

// LastSweepAt is when the newest sweep run started; at=0 when there is none.
func (s *Store) LastSweepAt(ctx context.Context) (int64, error) {
	var at int64
	err := s.q.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(started_at),0) FROM scan_runs WHERE trigger='sweep'`).Scan(&at)
	if err != nil {
		return 0, fmt.Errorf("last sweep: %w", err)
	}
	return at, nil
}

func (s *Store) AddScanHit(ctx context.Context, h ScanHit) (int64, error) {
	res, err := s.q.ExecContext(ctx,
		`INSERT INTO scan_hits (run_id, site_id, path, virus, action, quarantined_to, updated_at) VALUES (?,?,?,?,?,?,?)`,
		h.RunID, h.SiteID, h.Path, h.Virus, h.Action, h.QuarantinedTo, h.UpdatedAt)
	if err != nil {
		return 0, fmt.Errorf("add scan hit: %w", err)
	}
	id, _ := res.LastInsertId()
	return id, nil
}

func (s *Store) ListScanHits(ctx context.Context, runID int64) ([]ScanHit, error) {
	return s.listScanHitsWhere(ctx, "run_id=?", runID)
}

// ListRunsHits returns the hits of several runs keyed by run id (the scan page's newest-runs view).
func (s *Store) ListRunsHits(ctx context.Context, runIDs []int64) (map[int64][]ScanHit, error) {
	out := map[int64][]ScanHit{}
	if len(runIDs) == 0 {
		return out, nil
	}
	ph := strings.TrimSuffix(strings.Repeat("?,", len(runIDs)), ",") // ids are ints, no escaping concern in IN()
	args := make([]any, len(runIDs))
	for i, id := range runIDs {
		args[i] = id
	}
	rows, err := s.q.QueryContext(ctx,
		`SELECT id, run_id, site_id, path, virus, action, quarantined_to, updated_at FROM scan_hits WHERE run_id IN (`+ph+`) ORDER BY id`, args...)
	if err != nil {
		return nil, fmt.Errorf("list scan hits: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var h ScanHit
		if err := rows.Scan(&h.ID, &h.RunID, &h.SiteID, &h.Path, &h.Virus, &h.Action, &h.QuarantinedTo, &h.UpdatedAt); err != nil {
			return nil, err
		}
		out[h.RunID] = append(out[h.RunID], h)
	}
	return out, rows.Err()
}

func (s *Store) listScanHitsWhere(ctx context.Context, where string, arg any) ([]ScanHit, error) {
	rows, err := s.q.QueryContext(ctx,
		`SELECT id, run_id, site_id, path, virus, action, quarantined_to, updated_at FROM scan_hits WHERE `+where, arg)
	if err != nil {
		return nil, fmt.Errorf("list scan hits: %w", err)
	}
	defer rows.Close()
	var out []ScanHit
	for rows.Next() {
		var h ScanHit
		if err := rows.Scan(&h.ID, &h.RunID, &h.SiteID, &h.Path, &h.Virus, &h.Action, &h.QuarantinedTo, &h.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// UnresolvedHitPath is true when the site already has a hit row for path+virus that is still
// quarantined or ignored: re-finding it must not alarm again.
func (s *Store) UnresolvedHitPath(ctx context.Context, siteID int64, path, virus string) (bool, error) {
	var n int
	err := s.q.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM scan_hits h WHERE h.site_id=? AND h.path=? AND h.virus=? AND h.action IN ('quarantined','ignored')`,
		siteID, path, virus).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("check hit %s: %w", path, err)
	}
	return n > 0, nil
}

// GetScanHit loads one hit, or a not-found error the caller turns into 404.
func (s *Store) GetScanHit(ctx context.Context, id int64) (ScanHit, error) {
	var h ScanHit
	err := s.q.QueryRowContext(ctx,
		`SELECT id, run_id, site_id, path, virus, action, quarantined_to, updated_at FROM scan_hits WHERE id=?`, id).
		Scan(&h.ID, &h.RunID, &h.SiteID, &h.Path, &h.Virus, &h.Action, &h.QuarantinedTo, &h.UpdatedAt)
	if err != nil {
		return h, fmt.Errorf("get scan hit %d: %w", id, err)
	}
	return h, nil
}

// SetScanHitAction moves a hit's quarantine state (the one thing an admin changes about a hit).
func (s *Store) SetScanHitAction(ctx context.Context, id int64, action, quarantinedTo string) error {
	if _, err := s.q.ExecContext(ctx,
		`UPDATE scan_hits SET action=?, quarantined_to=?, updated_at=strftime('%s','now') WHERE id=?`,
		action, quarantinedTo, id); err != nil {
		return fmt.Errorf("set scan hit %d: %w", id, err)
	}
	return nil
}

// PruneScanRuns keeps the newest keep runs per trigger; their hits go by cascade.
func (s *Store) PruneScanRuns(ctx context.Context, keep int) error {
	if _, err := s.q.ExecContext(ctx, `DELETE FROM scan_runs WHERE id IN (
		SELECT id FROM (
			SELECT id, ROW_NUMBER() OVER (PARTITION BY trigger ORDER BY started_at DESC, id DESC) rn FROM scan_runs
		) WHERE rn > ?)`, keep); err != nil {
		return fmt.Errorf("prune scan runs: %w", err)
	}
	return nil
}
