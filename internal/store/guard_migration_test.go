package store

import (
	"bytes"
	"database/sql"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// seedThrough builds the file at path with migrations 001..n applied the way the app's DSN
// does (foreign keys on), sets user_version n and returns the open handle for seeding.
func seedThrough(t *testing.T, path string, n int) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	files, err := migrationFS.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range files {
		names = append(names, f.Name())
	}
	sort.Strings(names)
	for _, name := range names {
		v, err := strconv.Atoi(strings.SplitN(name, "_", 2)[0])
		if err != nil {
			t.Fatal(err)
		}
		if v > n {
			break
		}
		body, _ := migrationFS.ReadFile("migrations/" + name)
		if _, err := db.Exec(string(body)); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}
	if _, err := db.Exec("PRAGMA user_version = " + strconv.Itoa(n)); err != nil {
		t.Fatal(err)
	}
	return db
}

func count(t *testing.T, db *sql.DB, table string) int {
	t.Helper()
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// Migration 013 rebuilds sites (kind 'page'), so every child table keeps its rows, and the
// scan and backup ntfy settings become alert destinations with the same sealed bytes.
func TestMigration013KeepsRowsAndCopiesNtfy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pre013.db")
	db := seedThrough(t, path, 12)
	for _, q := range []string{
		`INSERT INTO sites (id, slug, kind, scheme, upstream_host, upstream_port, enabled) VALUES (1, 'probe', 'proxy', 'http', '127.0.0.1', 65002, 1)`,
		`INSERT INTO sites (id, slug, kind, static_root, fpm_version, enabled, rl_requests, rl_window, waf, waf_mode) VALUES (2, 'wp', 'php', '/srv/www/wp', '8.4', 1, 30, '1m', 'wordpress', 'block')`,
		`INSERT INTO site_hostnames (site_id, hostname, is_primary) VALUES (1, 'probe.example.test', 1), (2, 'wp.example.test', 1)`,
		`INSERT INTO dns_records (hostname, site_id, family, cf_record_id) VALUES ('probe.example.test', 1, 'A', 'cf1')`,
		`INSERT INTO waf_exclusions (site_id, kind, rule_id, target, note, added_by, added_at) VALUES (2, 'remove', '942100', '', 'fp', 'admin', 1)`,
		`INSERT INTO snippets (id, name, body) VALUES (1, 'compress', 'encode gzip')`,
		`INSERT INTO site_snippets (site_id, snippet_id) VALUES (1, 1)`,
		`UPDATE settings SET scan_ntfy = x'0a0b', scan_ntfy_token = x'0c', backup_ntfy = x'0d0e' WHERE id = 1`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("seed %q: %v", q, err)
		}
	}
	before := map[string]int{}
	for _, tb := range []string{"sites", "site_hostnames", "dns_records", "waf_exclusions", "site_snippets", "snippets"} {
		before[tb] = count(t, db, tb)
	}
	_ = db.Close()

	s, err := Open(path) // applies 013
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	for tb, n := range before {
		if got := count(t, s.db, tb); got != n {
			t.Errorf("%s: %d rows before, %d after the 013 rebuild", tb, n, got)
		}
	}
	var wafMode string
	var rl int
	if err := s.db.QueryRow(`SELECT waf_mode, rl_requests FROM sites WHERE id = 2`).Scan(&wafMode, &rl); err != nil || wafMode != "block" || rl != 30 {
		t.Errorf("site 2 columns after rebuild: %q %d %v", wafMode, rl, err)
	}
	rows, err := s.db.Query(`PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatal(err)
	}
	if rows.Next() {
		t.Error("foreign_key_check reports a violation after 013")
	}
	_ = rows.Close()

	type dest struct {
		name, kind, events string
		target, secret     []byte
	}
	var got []dest
	dr, err := s.db.Query(`SELECT name, kind, events, target_sealed, secret_sealed FROM alert_dests ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	for dr.Next() {
		var d dest
		if err := dr.Scan(&d.name, &d.kind, &d.events, &d.target, &d.secret); err != nil {
			t.Fatal(err)
		}
		got = append(got, d)
	}
	_ = dr.Close()
	if len(got) != 2 ||
		got[0].name != "ntfy: backup" || got[0].events != "backup" || !bytes.Equal(got[0].target, []byte{0x0d, 0x0e}) || got[0].secret != nil ||
		got[1].name != "ntfy: scan" || got[1].events != "scan" || !bytes.Equal(got[1].target, []byte{0x0a, 0x0b}) || !bytes.Equal(got[1].secret, []byte{0x0c}) {
		t.Errorf("ntfy destinations after 013: %+v", got)
	}
	if got[0].kind != "ntfy" || got[1].kind != "ntfy" {
		t.Errorf("destination kinds: %q %q", got[0].kind, got[1].kind)
	}
	if n := count(t, s.db, "guard_settings"); n != 1 {
		t.Errorf("guard_settings rows = %d, want the seeded one", n)
	}
}

// With no ntfy configured nothing is copied.
func TestMigration013WithoutNtfyCreatesNoDestinations(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "fresh.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if n := count(t, s.db, "alert_dests"); n != 0 {
		t.Errorf("alert_dests has %d rows on a database that never configured ntfy", n)
	}
}

// The new kind carries no upstream, root or commands; the old cross-column CHECKs still bite.
func TestKindPageCheck(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "kind.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.db.Exec(`INSERT INTO sites (slug, kind) VALUES ('parked', 'page')`); err != nil {
		t.Fatalf("a bare page site is refused: %v", err)
	}
	for name, q := range map[string]string{
		"page with an upstream":     `INSERT INTO sites (slug, kind, upstream_host, upstream_port) VALUES ('bad1', 'page', 'h', 80)`,
		"page with a static root":   `INSERT INTO sites (slug, kind, static_root) VALUES ('bad2', 'page', '/x')`,
		"page with a site user":     `INSERT INTO sites (slug, kind, site_user) VALUES ('bad3', 'page', 'u')`,
		"proxy without an upstream": `INSERT INTO sites (slug, kind) VALUES ('bad4', 'proxy')`,
		"unknown kind":              `INSERT INTO sites (slug, kind) VALUES ('bad5', 'redirect')`,
	} {
		if _, err := s.db.Exec(q); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}
