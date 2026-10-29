package store

import (
	"bytes"
	"context"
	"database/sql"
	_ "embed"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// old001.sql is the bee-vintage schema (001_init.sql at 9cc2e79^): it has fpm_version, extra_routes and the
// fastcgi/cgi kinds, and lacks the PHP-from-source and site-user objects the repair adds.
//
//go:embed testdata/old001.sql
var old001 string

// legacyDB writes a file database in the bee state: old001 at user_version 1, one user and one site.
func legacyDB(t *testing.T, schema string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "servanago.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`PRAGMA journal_mode = WAL`, // as on a real host: Open must not rewrite the header of a refused file
		schema,
		`INSERT INTO users (username, password_hash, webauthn_id) VALUES ('admin', 'x', x'01')`,
		`INSERT INTO sites (slug, kind, static_root) VALUES ('site1', 'static', '/srv/site1')`,
		`PRAGMA user_version = 1`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("fixture: %v\n%s", err, q)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// repairedObjects are the eight objects the repair adds, as (table, column) or (table, "") for a whole table.
var repairedColumns = [][2]string{
	{"sites", "php_extensions"}, {"sites", "php_health_path"}, {"sites", "site_user"}, {"sites", "public_dir"},
	{"settings", "php_check_json"}, {"settings", "php_checked_at"},
}

func hasColumn(t *testing.T, db *sql.DB, table, col string) bool {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM pragma_table_info(?) WHERE name = ?`, table, col).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n == 1
}

func hasObject(t *testing.T, db *sql.DB, kind, name string) bool {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type = ? AND name = ?`, kind, name).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n == 1
}

// columnShape is what the repair must match against a fresh database: name, type, notnull, default, pk.
func columnShape(t *testing.T, db *sql.DB, table, col string) string {
	t.Helper()
	var typ string
	var notnull, pk int
	var dflt sql.NullString
	err := db.QueryRow(`SELECT type, "notnull", dflt_value, pk FROM pragma_table_info(?) WHERE name = ?`, table, col).Scan(&typ, &notnull, &dflt, &pk)
	if err != nil {
		t.Fatalf("%s.%s: %v", table, col, err)
	}
	return strings.Join([]string{typ, string(rune('0' + notnull)), dflt.String, string(rune('0' + pk))}, "|")
}

func TestRepairAddsMissingLegacyObjects(t *testing.T) {
	path := legacyDB(t, old001)
	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open legacy: %v", err)
	}
	defer st.Close()
	fresh, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()

	for _, c := range repairedColumns {
		if !hasColumn(t, st.db, c[0], c[1]) {
			t.Errorf("%s.%s missing after repair", c[0], c[1])
			continue
		}
		if got, want := columnShape(t, st.db, c[0], c[1]), columnShape(t, fresh.db, c[0], c[1]); got != want {
			t.Errorf("%s.%s shape %q, fresh DB has %q", c[0], c[1], got, want)
		}
	}
	if !hasObject(t, st.db, "table", "php_user_defaults") {
		t.Error("php_user_defaults missing after repair")
	}
	var idx, freshIdx string
	_ = st.db.QueryRow(`SELECT sql FROM sqlite_master WHERE name = 'sites_site_user'`).Scan(&idx)
	_ = fresh.db.QueryRow(`SELECT sql FROM sqlite_master WHERE name = 'sites_site_user'`).Scan(&freshIdx)
	if idx == "" || idx != freshIdx {
		t.Errorf("sites_site_user = %q, fresh DB has %q", idx, freshIdx)
	}

	var users, sites, ver int
	_ = st.db.QueryRow(`SELECT count(*) FROM users`).Scan(&users)
	_ = st.db.QueryRow(`SELECT count(*) FROM sites WHERE slug = 'site1'`).Scan(&sites)
	_ = st.db.QueryRow(`PRAGMA user_version`).Scan(&ver)
	if users != 1 || sites != 1 {
		t.Errorf("rows lost: users %d sites %d", users, sites)
	}
	if ver != 7 {
		t.Errorf("user_version = %d, want migrations 002..007 applied", ver)
	}

	fi, err := os.Stat(path + ".pre-repair")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("snapshot mode %o, want 0600", fi.Mode().Perm())
	}
	rows, err := st.ListAudit(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	for _, r := range rows {
		if r.Action == "schema.repaired" {
			n++
			if r.Actor != "system" {
				t.Errorf("actor %q, want system", r.Actor)
			}
		}
	}
	if n != 1 {
		t.Errorf("%d schema.repaired audit rows, want 1", n)
	}
}

func TestRepairIsIdempotent(t *testing.T) {
	path := legacyDB(t, old001)
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	snap, err := os.ReadFile(path + ".pre-repair")
	if err != nil {
		t.Fatalf("snapshot after first Open: %v", err)
	}

	st, err = Open(path)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	defer st.Close()
	again, err := os.ReadFile(path + ".pre-repair")
	if err != nil || !bytes.Equal(snap, again) {
		t.Errorf("second Open rewrote the snapshot (err %v)", err)
	}
	rows, _ := st.ListAudit(context.Background(), 10)
	var n int
	for _, r := range rows {
		if r.Action == "schema.repaired" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d schema.repaired rows after two Opens, want 1", n)
	}
}

func TestOpenHealthyDBRepairsNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "servanago.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	st, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := os.Stat(path + ".pre-repair"); err == nil {
		t.Error("a healthy DB got a snapshot")
	}
	rows, _ := st.ListAudit(context.Background(), 10)
	for _, r := range rows {
		if r.Action == "schema.repaired" {
			t.Error("a healthy DB got a schema.repaired row")
		}
	}
}

// Below the gate the repair cannot help (ALTER adds no CHECK and no earlier columns): refuse, touch nothing.
func TestOpenRefusesBelowVintageGate(t *testing.T) {
	for _, tc := range []struct{ name, from, to, want string }{
		{"no fpm_version", "fpm_version", "fpm_old", "fpm_version"},
		{"no extra_routes", "extra_routes", "extra_old", "extra_routes"},
		{"kind check without cgi", "'fastcgi','cgi'", "'fastcgi'", "cgi"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(old001, tc.from) {
				t.Fatalf("fixture no longer contains %q: the case would pass vacuously", tc.from)
			}
			path := legacyDB(t, strings.ReplaceAll(old001, tc.from, tc.to)) // renamed everywhere, CHECKs included
			before, _ := os.ReadFile(path)
			_, err := Open(path)
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "not repairable") {
				t.Fatalf("Open = %v, want a 'not repairable' error naming %q", err, tc.want)
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(before, after) {
				t.Error("a refused Open modified the file")
			}
		})
	}
}

// The backup job opens a copy of the live DB: no snapshot, no repair beside it.
func TestOpenSnapshotDoesNotRepair(t *testing.T) {
	path := legacyDB(t, old001)
	st, err := OpenSnapshot(path)
	if err != nil {
		t.Fatalf("OpenSnapshot: %v", err)
	}
	defer st.Close()
	if hasColumn(t, st.db, "sites", "php_extensions") {
		t.Error("OpenSnapshot repaired the schema")
	}
	if _, err := os.Stat(path + ".pre-repair"); err == nil {
		t.Error("OpenSnapshot wrote a .pre-repair")
	}
}

// A snapshot that cannot be written aborts the repair before any ALTER.
func TestRepairSnapshotFailureAborts(t *testing.T) {
	path := legacyDB(t, old001)
	if err := os.MkdirAll(filepath.Join(path+".pre-repair", "squatter"), 0o755); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	if _, err := Open(path); err == nil || !strings.Contains(err.Error(), "snapshot") {
		t.Fatalf("Open = %v, want a snapshot error", err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Error("a failed snapshot still modified the database")
	}
}
