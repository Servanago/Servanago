// Package trafficdb is the disposable SQLite file next to the main database that holds the request
// log and the per-minute rollups. It carries no migration list: the file is created if missing and
// dropped and recreated when its schema version differs. Losing it loses history, never configuration.
package trafficdb

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const schemaVersion = 1

const schema = `
CREATE TABLE IF NOT EXISTS traffic_rollup (
  site_slug TEXT NOT NULL, minute INTEGER NOT NULL,
  req INTEGER NOT NULL, s2 INTEGER NOT NULL, s3 INTEGER NOT NULL, s4 INTEGER NOT NULL, s5 INTEGER NOT NULL,
  blocked INTEGER NOT NULL, challenged INTEGER NOT NULL, queued INTEGER NOT NULL, banned INTEGER NOT NULL, paid INTEGER NOT NULL,
  ratelimited INTEGER NOT NULL, unknown_host INTEGER NOT NULL,
  bytes_out INTEGER NOT NULL,
  lat TEXT NOT NULL,
  PRIMARY KEY (site_slug, minute)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS request_log (
  id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, site_slug TEXT NOT NULL, host TEXT NOT NULL,
  client TEXT NOT NULL, method TEXT NOT NULL, path TEXT NOT NULL,
  status INTEGER NOT NULL, ms INTEGER NOT NULL, bytes INTEGER NOT NULL,
  outcome TEXT NOT NULL, ua TEXT NOT NULL DEFAULT '', ref_origin TEXT NOT NULL DEFAULT '',
  err TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS request_log_site_ts ON request_log(site_slug, ts DESC);
CREATE INDEX IF NOT EXISTS request_log_client ON request_log(client, ts DESC);
`

// DB is an open traffic.db.
type DB struct{ db *sql.DB }

// Row is one request_log row.
type Row struct {
	ID                    int64
	TS                    int64
	Site, Host, Client    string
	Method, Path          string
	Status, MS, Bytes     int
	Outcome, UA, Ref, Err string
}

// Rollup is one site-minute of counters; Lat holds the 20 latency bucket counts as JSON.
type Rollup struct {
	Site                                      string
	Minute                                    int64
	Req, S2, S3, S4, S5                       int64
	Blocked, Challenged, Queued, Banned, Paid int64
	RateLimited, UnknownHost                  int64
	BytesOut                                  int64
	Lat                                       string
}

// Open opens or creates the file; a different stored schema version removes it first.
func Open(path string) (*DB, error) {
	d, err := open(path)
	if err != nil {
		return nil, err
	}
	var v int
	if err := d.QueryRow("PRAGMA user_version").Scan(&v); err != nil {
		_ = d.Close()
		return nil, fmt.Errorf("traffic.db version: %w", err)
	}
	if v != 0 && v != schemaVersion {
		_ = d.Close()
		for _, suffix := range []string{"", "-wal", "-shm"} {
			if err := os.Remove(path + suffix); err != nil && !os.IsNotExist(err) {
				return nil, fmt.Errorf("recreate traffic.db: %w", err)
			}
		}
		if d, err = open(path); err != nil {
			return nil, err
		}
	}
	if _, err := d.Exec(schema); err != nil {
		_ = d.Close()
		return nil, fmt.Errorf("traffic.db schema: %w", err)
	}
	if _, err := d.Exec(fmt.Sprintf("PRAGMA user_version = %d", schemaVersion)); err != nil {
		_ = d.Close()
		return nil, err
	}
	return &DB{d}, nil
}

func open(path string) (*sql.DB, error) {
	d, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)")
	if err != nil {
		return nil, fmt.Errorf("open traffic.db: %w", err)
	}
	d.SetMaxOpenConns(4)
	return d, nil
}

func (d *DB) Close() error { return d.db.Close() }

// InsertLog writes a batch in one transaction.
func (d *DB) InsertLog(ctx context.Context, rows []Row) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	st, err := tx.PrepareContext(ctx, `INSERT INTO request_log (ts, site_slug, host, client, method, path, status, ms, bytes, outcome, ua, ref_origin, err)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer st.Close()
	for _, r := range rows {
		if _, err := st.ExecContext(ctx, r.TS, r.Site, r.Host, r.Client, r.Method, r.Path, r.Status, r.MS, r.Bytes, r.Outcome, r.UA, r.Ref, r.Err); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// PutRollups writes (or replaces) site-minute rows.
func (d *DB) PutRollups(ctx context.Context, rs []Rollup) error {
	if len(rs) == 0 {
		return nil
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	for _, r := range rs {
		if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO traffic_rollup VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			r.Site, r.Minute, r.Req, r.S2, r.S3, r.S4, r.S5, r.Blocked, r.Challenged, r.Queued, r.Banned, r.Paid,
			r.RateLimited, r.UnknownHost, r.BytesOut, r.Lat); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// RollupsSince returns the rows of one site (all sites when slug is empty and all is true) from minute on.
func (d *DB) RollupsSince(ctx context.Context, slug string, all bool, from int64) ([]Rollup, error) {
	q := `SELECT site_slug, minute, req, s2, s3, s4, s5, blocked, challenged, queued, banned, paid, ratelimited, unknown_host, bytes_out, lat
		FROM traffic_rollup WHERE minute >= ?`
	args := []any{from}
	if !all {
		q += " AND site_slug = ?"
		args = append(args, slug)
	}
	rows, err := d.db.QueryContext(ctx, q+" ORDER BY minute", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Rollup
	for rows.Next() {
		var r Rollup
		if err := rows.Scan(&r.Site, &r.Minute, &r.Req, &r.S2, &r.S3, &r.S4, &r.S5, &r.Blocked, &r.Challenged, &r.Queued, &r.Banned, &r.Paid,
			&r.RateLimited, &r.UnknownHost, &r.BytesOut, &r.Lat); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Filter narrows List. Zero fields match everything; Path matches as a substring.
type Filter struct {
	Site, Client, Outcome, Path string
	Status                      int
	ErrOnly                     bool
	Since, Until                int64
	AfterID                     int64 // rows with a greater id only (live tail)
	Limit                       int
}

// List returns newest-first rows.
func (d *DB) List(ctx context.Context, f Filter) ([]Row, error) {
	var where []string
	var args []any
	add := func(cond string, v any) { where = append(where, cond); args = append(args, v) }
	if f.Site != "" {
		add("site_slug = ?", f.Site)
	}
	if f.Client != "" {
		add("client = ?", f.Client)
	}
	if f.Outcome != "" {
		add("outcome = ?", f.Outcome)
	}
	if f.Path != "" {
		add("instr(path, ?) > 0", f.Path)
	}
	if f.Status != 0 {
		add("status = ?", f.Status)
	}
	if f.ErrOnly {
		where = append(where, "err != ''")
	}
	if f.Since != 0 {
		add("ts >= ?", f.Since)
	}
	if f.Until != 0 {
		add("ts <= ?", f.Until)
	}
	if f.AfterID != 0 {
		add("id > ?", f.AfterID)
	}
	q := `SELECT id, ts, site_slug, host, client, method, path, status, ms, bytes, outcome, ua, ref_origin, err FROM request_log`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	if f.Limit <= 0 {
		f.Limit = 100
	}
	rows, err := d.db.QueryContext(ctx, q+fmt.Sprintf(" ORDER BY id DESC LIMIT %d", f.Limit), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Row
	for rows.Next() {
		var r Row
		if err := rows.Scan(&r.ID, &r.TS, &r.Site, &r.Host, &r.Client, &r.Method, &r.Path, &r.Status, &r.MS, &r.Bytes, &r.Outcome, &r.UA, &r.Ref, &r.Err); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Prune deletes log rows older than logDays and beyond keepPerSite per site, and rollups older than rollupDays.
func (d *DB) Prune(ctx context.Context, now time.Time, logDays, rollupDays, keepPerSite int) error {
	if _, err := d.db.ExecContext(ctx, `DELETE FROM request_log WHERE ts < ?`, now.AddDate(0, 0, -logDays).Unix()); err != nil {
		return err
	}
	if _, err := d.db.ExecContext(ctx, `DELETE FROM request_log WHERE id IN (
		SELECT id FROM (SELECT id, ROW_NUMBER() OVER (PARTITION BY site_slug ORDER BY id DESC) AS n FROM request_log) WHERE n > ?)`, keepPerSite); err != nil {
		return err
	}
	_, err := d.db.ExecContext(ctx, `DELETE FROM traffic_rollup WHERE minute < ?`, now.AddDate(0, 0, -rollupDays).Unix()/60)
	return err
}

// DeleteSite drops the rows of a deleted site.
func (d *DB) DeleteSite(ctx context.Context, slug string) error {
	if _, err := d.db.ExecContext(ctx, `DELETE FROM request_log WHERE site_slug = ?`, slug); err != nil {
		return err
	}
	_, err := d.db.ExecContext(ctx, `DELETE FROM traffic_rollup WHERE site_slug = ?`, slug)
	return err
}
