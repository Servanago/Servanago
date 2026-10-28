package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"syscall"
)

// Before 0.5.0 a schema change edited 001_init.sql in place, so a database created from an older 001 keeps
// user_version 1 and never receives the later additions. repairLegacy adds exactly those objects. It is a closed
// list: new schema is always a NNN_*.sql migration and never enters it.
type legacyObject struct {
	name   string
	exists func(context.Context, queryer) (bool, error)
	ddl    string // copied from 001_init.sql
}

type queryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func columnExists(table, col string) func(context.Context, queryer) (bool, error) {
	return func(ctx context.Context, q queryer) (bool, error) {
		var n int
		err := q.QueryRowContext(ctx, `SELECT count(*) FROM pragma_table_info(?) WHERE name = ?`, table, col).Scan(&n)
		return n == 1, err
	}
}

func objectExists(kind, name string) func(context.Context, queryer) (bool, error) {
	return func(ctx context.Context, q queryer) (bool, error) {
		var n int
		err := q.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type = ? AND name = ?`, kind, name).Scan(&n)
		return n == 1, err
	}
}

// ALTER cannot add the table-level CHECKs 001 has on these columns; the application validates them.
var legacyObjects = []legacyObject{
	{"sites.php_extensions", columnExists("sites", "php_extensions"), `ALTER TABLE sites ADD COLUMN php_extensions TEXT NOT NULL DEFAULT ''`},
	{"sites.php_health_path", columnExists("sites", "php_health_path"), `ALTER TABLE sites ADD COLUMN php_health_path TEXT NOT NULL DEFAULT ''`},
	{"sites.site_user", columnExists("sites", "site_user"), `ALTER TABLE sites ADD COLUMN site_user TEXT NOT NULL DEFAULT ''`},
	{"sites.public_dir", columnExists("sites", "public_dir"), `ALTER TABLE sites ADD COLUMN public_dir TEXT NOT NULL DEFAULT ''`},
	{"sites_site_user", objectExists("index", "sites_site_user"), `CREATE UNIQUE INDEX sites_site_user ON sites (site_user) WHERE site_user != ''`},
	{"settings.php_check_json", columnExists("settings", "php_check_json"), `ALTER TABLE settings ADD COLUMN php_check_json TEXT NOT NULL DEFAULT ''`},
	{"settings.php_checked_at", columnExists("settings", "php_checked_at"), `ALTER TABLE settings ADD COLUMN php_checked_at INTEGER NOT NULL DEFAULT 0`},
	{"php_user_defaults", objectExists("table", "php_user_defaults"), `CREATE TABLE php_user_defaults (username TEXT PRIMARY KEY, version TEXT NOT NULL CHECK (version != ''))`},
}

var kindAllowsCGI = regexp.MustCompile(`kind\s+TEXT[^\n]*CHECK\s*\(kind IN \([^)]*'cgi'`)

// vintageGap names what a database lacks that the repair cannot add, or "" when the repair can proceed.
func vintageGap(ctx context.Context, q queryer) (string, error) {
	for _, col := range []string{"fpm_version", "extra_routes"} {
		ok, err := columnExists("sites", col)(ctx, q)
		if err != nil {
			return "", err
		}
		if !ok {
			return "sites." + col + " missing", nil
		}
	}
	var ddl string
	if err := q.QueryRowContext(ctx, `SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'sites'`).Scan(&ddl); err != nil {
		return "", err
	}
	if !kindAllowsCGI.MatchString(ddl) {
		return "sites kind CHECK lacks cgi", nil
	}
	return "", nil
}

func missingLegacy(ctx context.Context, q queryer) ([]legacyObject, error) {
	var missing []legacyObject
	for _, o := range legacyObjects {
		ok, err := o.exists(ctx, q)
		if err != nil {
			return nil, fmt.Errorf("probe %s: %w", o.name, err)
		}
		if !ok {
			missing = append(missing, o)
		}
	}
	return missing, nil
}

// repairLegacy reports whether it changed the database. A database without a sites table is new (migrate builds
// it); one below the vintage gate is refused untouched. Otherwise missing objects are added in one transaction
// after a VACUUM INTO snapshot named <db>.pre-repair.
func repairLegacy(db *sql.DB, path string) (bool, error) {
	if path == ":memory:" {
		return false, nil
	}
	ctx := context.Background()
	var n int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'sites'`).Scan(&n); err != nil {
		return false, fmt.Errorf("read schema: %w", err)
	}
	if n == 0 {
		return false, nil
	}
	gap, err := vintageGap(ctx, db)
	if err != nil {
		return false, fmt.Errorf("read schema: %w", err)
	}
	if gap != "" {
		return false, fmt.Errorf("database %s predates Servanago 0.2.0 (%s); not repairable", path, gap)
	}
	missing, err := missingLegacy(ctx, db)
	if err != nil || len(missing) == 0 {
		return false, err
	}
	if err := snapshot(ctx, db, path); err != nil {
		return false, fmt.Errorf("schema repair: snapshot before repair: %w", err)
	}

	conn, err := db.Conn(ctx)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return false, fmt.Errorf("schema repair: %w", err)
	}
	rollback := func(cause error) (bool, error) {
		if _, rerr := conn.ExecContext(ctx, `ROLLBACK`); rerr != nil {
			cause = errors.Join(cause, rerr)
		}
		return false, cause
	}
	// Re-probe inside the lock: another process may have repaired it since.
	if missing, err = missingLegacy(ctx, conn); err != nil {
		return rollback(err)
	}
	for _, o := range missing {
		if _, err := conn.ExecContext(ctx, o.ddl); err != nil {
			return rollback(fmt.Errorf("schema repair: create %s (snapshot %s.pre-repair): %w", o.name, path, err))
		}
	}
	if _, err := conn.ExecContext(ctx, `COMMIT`); err != nil {
		return rollback(fmt.Errorf("schema repair: commit: %w", err))
	}
	for _, o := range missing {
		slog.Info("schema repair", "object", o.name)
	}
	return len(missing) > 0, nil
}

// snapshot writes a consistent copy of the database to <path>.pre-repair, readable by its owner only (it holds
// password hashes) and owned by whoever owns the database file.
func snapshot(ctx context.Context, db *sql.DB, path string) error {
	dst := path + ".pre-repair"
	if err := os.Remove(dst); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if _, err := db.ExecContext(ctx, `VACUUM INTO '`+strings.ReplaceAll(dst, `'`, `''`)+`'`); err != nil {
		return err
	}
	if err := os.Chmod(dst, 0o600); err != nil {
		return err
	}
	if fi, err := os.Stat(path); err == nil {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			if err := os.Chown(dst, int(st.Uid), int(st.Gid)); err != nil && os.Geteuid() == 0 {
				return err
			}
		}
	}
	return nil
}
