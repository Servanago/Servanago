package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// TestMigrationRebuildKeepsChildRows pins migration 011's sites rebuild against SQLite's
// DROP TABLE implicit DELETE: at the app's foreign_keys-enabled DSN the rebuild once emptied
// site_hostnames and dns_records of every site's rows (bee, 2026-11-03). migrate must apply
// the rebuild with FK enforcement off (sqlite.org/lang_altertable.html §8, step 1).
func TestMigrationRebuildKeepsChildRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pre.db")

	// Seed the pre-0.20.0 state: schema through 010, one site with rows in every child table
	// the rebuild would cascade away, user_version 10.
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	files, err := migrationFS.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(files))
	for _, f := range files {
		names = append(names, f.Name())
	}
	sort.Strings(names)
	for _, name := range names {
		n, err := strconv.Atoi(strings.SplitN(name, "_", 2)[0])
		if err != nil {
			t.Fatal(err)
		}
		if n > 10 {
			break
		}
		body, _ := migrationFS.ReadFile("migrations/" + name)
		if _, err := db.Exec(string(body)); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}
	if _, err := db.Exec(`INSERT INTO sites (id, slug, kind, scheme, upstream_host, upstream_port, enabled)
		VALUES (1, 'probe', 'proxy', 'http', '127.0.0.1', 65002, 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO site_hostnames (site_id, hostname, is_primary)
		VALUES (1, 'probe.example.test', 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO dns_records (hostname, site_id, family, cf_record_id)
		VALUES ('probe.example.test', 1, 'A', 'cf1')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("PRAGMA user_version = 10"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := Open(path) // migrate applies 011 here
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	r, err := s.GetSite(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Hostnames) != 1 || r.Hostnames[0] != "probe.example.test" {
		t.Fatalf("hostnames lost through the 011 rebuild: %v", r.Hostnames)
	}
	var dns int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM dns_records").Scan(&dns); err != nil || dns != 1 {
		t.Fatalf("dns rows lost through the 011 rebuild: %d %v", dns, err)
	}
	var uv int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&uv); err != nil || uv != LatestVersion() {
		t.Fatalf("user_version %d %v (want %d)", uv, err, LatestVersion())
	}
}
