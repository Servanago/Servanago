// Site backup state: global settings, per-site opt-in and overrides, dump profiles, docker volumes and run history.
package store

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// LatestVersion is the schema version a database reaches after every migration: a restored database above it is refused.
func LatestVersion() int {
	files, _ := migrationFS.ReadDir("migrations")
	v := 0
	for _, f := range files {
		if n, err := strconv.Atoi(strings.SplitN(f.Name(), "_", 2)[0]); err == nil {
			v = max(v, n)
		}
	}
	return v
}

type BackupSettings struct {
	Enabled    bool
	Dir        string
	Pass       []byte // secretbox blob, nil = not set
	Sched      string
	Keep       int
	KeepWeekly int
	Panel      bool
	Ntfy       []byte // secretbox blob of the ntfy topic URL, nil = none
}

func (s *Store) GetBackupSettings(ctx context.Context) (BackupSettings, error) {
	var b BackupSettings
	err := s.q.QueryRowContext(ctx, `SELECT backup_enabled, backup_dir, backup_pass, backup_sched, backup_keep, backup_keep_weekly, backup_panel, backup_ntfy
		FROM settings WHERE id=1`).Scan(&b.Enabled, &b.Dir, &b.Pass, &b.Sched, &b.Keep, &b.KeepWeekly, &b.Panel, &b.Ntfy)
	if err != nil {
		return b, fmt.Errorf("read backup settings: %w", err)
	}
	return b, nil
}

func (s *Store) SaveBackupSettings(ctx context.Context, b BackupSettings) error {
	if _, err := s.q.ExecContext(ctx, `UPDATE settings SET backup_enabled=?, backup_dir=?, backup_pass=?, backup_sched=?, backup_keep=?, backup_keep_weekly=?, backup_panel=?, backup_ntfy=? WHERE id=1`,
		b.Enabled, b.Dir, b.Pass, b.Sched, b.Keep, b.KeepWeekly, b.Panel, b.Ntfy); err != nil {
		return fmt.Errorf("save backup settings: %w", err)
	}
	return nil
}

// SiteBackup is a site's opt-in and overrides; "" and 0 inherit the global value.
type SiteBackup struct {
	On         bool
	Sched      string
	Keep       int
	KeepWeekly int
}

func (s *Store) GetSiteBackup(ctx context.Context, siteID int64) (SiteBackup, error) {
	var b SiteBackup
	err := s.q.QueryRowContext(ctx, `SELECT backup_on, backup_sched, backup_keep, backup_keep_weekly FROM sites WHERE id=?`, siteID).
		Scan(&b.On, &b.Sched, &b.Keep, &b.KeepWeekly)
	return b, err
}

func (s *Store) SaveSiteBackup(ctx context.Context, siteID int64, b SiteBackup) error {
	res, err := s.q.ExecContext(ctx, `UPDATE sites SET backup_on=?, backup_sched=?, backup_keep=?, backup_keep_weekly=? WHERE id=?`,
		b.On, b.Sched, b.Keep, b.KeepWeekly, siteID)
	if err != nil {
		return fmt.Errorf("save site backup: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("site %d not found", siteID)
	}
	return nil
}

type BackupProfile struct {
	ID        int64
	SiteID    int64
	Name      string
	Engine    string
	Container string
	DB        string
	User      string
	Secret    []byte // secretbox blob
	Path      string
}

func (s *Store) ListProfiles(ctx context.Context, siteID int64) ([]BackupProfile, error) {
	rows, err := s.q.QueryContext(ctx, `SELECT id, site_id, name, engine, container, db_name, db_user, secret, path FROM backup_profiles WHERE site_id=? ORDER BY name`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BackupProfile
	for rows.Next() {
		var p BackupProfile
		if err := rows.Scan(&p.ID, &p.SiteID, &p.Name, &p.Engine, &p.Container, &p.DB, &p.User, &p.Secret, &p.Path); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) AddProfile(ctx context.Context, p BackupProfile) error {
	if _, err := s.q.ExecContext(ctx, `INSERT INTO backup_profiles (site_id, name, engine, container, db_name, db_user, secret, path) VALUES (?,?,?,?,?,?,?,?)`,
		p.SiteID, p.Name, p.Engine, p.Container, p.DB, p.User, p.Secret, p.Path); err != nil {
		return fmt.Errorf("add dump profile %s: %w", p.Name, err)
	}
	return nil
}

func (s *Store) DeleteProfile(ctx context.Context, siteID int64, name string) error {
	_, err := s.q.ExecContext(ctx, `DELETE FROM backup_profiles WHERE site_id=? AND name=?`, siteID, name)
	return err
}

func (s *Store) ListVolumes(ctx context.Context, siteID int64) ([]string, error) {
	rows, err := s.q.QueryContext(ctx, `SELECT volume FROM backup_volumes WHERE site_id=? ORDER BY volume`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) AddVolume(ctx context.Context, siteID int64, vol string) error {
	_, err := s.q.ExecContext(ctx, `INSERT OR IGNORE INTO backup_volumes (site_id, volume) VALUES (?,?)`, siteID, vol)
	return err
}

func (s *Store) DeleteVolume(ctx context.Context, siteID int64, vol string) error {
	_, err := s.q.ExecContext(ctx, `DELETE FROM backup_volumes WHERE site_id=? AND volume=?`, siteID, vol)
	return err
}

type BackupRun struct {
	RunID, Scope, Trigger, Actor, Status, Archive, Error string
	Bytes, Started, Finished                             int64
}

// AddRun records a result once (the job's result files are read again until they age out); it reports whether the row was new.
func (s *Store) AddRun(ctx context.Context, r BackupRun) (bool, error) {
	res, err := s.q.ExecContext(ctx, `INSERT OR IGNORE INTO backup_runs (run_id, scope, trigger, actor, status, archive, bytes, error, started_at, finished_at) VALUES (?,?,?,?,?,?,?,?,?,?)`,
		r.RunID, r.Scope, r.Trigger, r.Actor, r.Status, r.Archive, r.Bytes, r.Error, r.Started, r.Finished)
	if err != nil {
		return false, fmt.Errorf("record backup run: %w", err)
	}
	n, _ := res.RowsAffected()
	if n > 0 { // keep the newest 2000
		_, _ = s.q.ExecContext(ctx, `DELETE FROM backup_runs WHERE run_id NOT IN (SELECT run_id FROM backup_runs ORDER BY finished_at DESC, run_id LIMIT 2000)`)
	}
	return n > 0, nil
}

// ListRuns returns the newest runs, optionally for one scope.
func (s *Store) ListRuns(ctx context.Context, scope string, limit int) ([]BackupRun, error) {
	q, args := `SELECT run_id, scope, trigger, actor, status, archive, bytes, error, started_at, finished_at FROM backup_runs`, []any{}
	if scope != "" {
		q += ` WHERE scope=?`
		args = append(args, scope)
	}
	q += ` ORDER BY finished_at DESC, run_id LIMIT ?`
	rows, err := s.q.QueryContext(ctx, q, append(args, limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BackupRun
	for rows.Next() {
		var r BackupRun
		if err := rows.Scan(&r.RunID, &r.Scope, &r.Trigger, &r.Actor, &r.Status, &r.Archive, &r.Bytes, &r.Error, &r.Started, &r.Finished); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// LastRuns maps each scope to its newest run and its newest successful run's finish time.
func (s *Store) LastRuns(ctx context.Context) (last map[string]BackupRun, lastOK map[string]int64, err error) {
	rs, err := s.ListRuns(ctx, "", 2000)
	if err != nil {
		return nil, nil, err
	}
	sort.SliceStable(rs, func(i, j int) bool { return rs[i].Finished > rs[j].Finished })
	last, lastOK = map[string]BackupRun{}, map[string]int64{}
	for _, r := range rs {
		if _, ok := last[r.Scope]; !ok {
			last[r.Scope] = r
		}
		if _, ok := lastOK[r.Scope]; !ok && r.Status == "ok" {
			lastOK[r.Scope] = r.Finished
		}
	}
	return last, lastOK, nil
}
