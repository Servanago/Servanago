// Package store is the SQLite persistence layer. A Store wraps either the DB or an open transaction.
package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

type querier interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type Store struct {
	db *sql.DB
	q  querier
	tx bool
}

// Open opens (creating if needed) the database, repairs the schema gaps of pre-0.5.0 databases (repair.go) and
// applies pending migrations. ":memory:" is for tests.
func Open(path string) (*Store, error) { return openDB(path, true) }

// OpenSnapshot opens a copy of the database (the backup job's) without repairing it: a repair belongs to the
// live database, not to a scratch copy.
func OpenSnapshot(path string) (*Store, error) { return openDB(path, false) }

func openDB(path string, repair bool) (*Store, error) {
	dsn := "file:" + path + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
	if path == ":memory:" {
		dsn = "file::memory:?_pragma=foreign_keys(1)"
	} else {
		dsn += "&_pragma=journal_mode(WAL)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %s: %w", path, err)
	}
	if path == ":memory:" {
		db.SetMaxOpenConns(1) // each in-memory connection is a separate database
	}
	var repaired bool
	if repair {
		var err error
		if repaired, err = repairLegacy(db, path); err != nil {
			db.Close()
			return nil, err
		}
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	st := &Store{db: db, q: db}
	if repaired {
		e := AuditEntry{At: time.Now().UTC().Format(time.RFC3339), Actor: "system", Action: "schema.repaired", Target: "database"}
		if err := st.AddAudit(context.Background(), e); err != nil {
			slog.Error("audit schema.repaired", "error", err)
		}
	}
	return st, nil
}

func (s *Store) Close() error { return s.db.Close() }

func migrate(db *sql.DB) error {
	var cur int
	if err := db.QueryRow("PRAGMA user_version").Scan(&cur); err != nil {
		return fmt.Errorf("read user_version: %w", err)
	}
	files, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return err
	}
	names := make([]string, 0, len(files))
	for _, f := range files {
		names = append(names, f.Name())
	}
	sort.Strings(names) // NNN_ prefix orders them

	type migration struct {
		name string
		n    int
	}
	var pending []migration
	for _, name := range names {
		n, err := strconv.Atoi(strings.SplitN(name, "_", 2)[0])
		if err != nil {
			return fmt.Errorf("migration %s: bad NNN_ prefix", name)
		}
		if n > cur {
			pending = append(pending, migration{name, n})
		}
	}
	if len(pending) == 0 {
		return nil
	}

	// A rebuild migration (011) follows SQLite's 12-step table-rebuild procedure, whose first
	// step is foreign_keys=OFF on the connection: with them on, DROP TABLE runs an implicit
	// DELETE whose ON DELETE CASCADE takes the app's child rows with the old table. The pragma
	// is a no-op inside a transaction, so it is set on here, before the migration's own
	// transaction starts, and restored before the connection returns to the pool.
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("migration connection: %w", err)
	}
	defer func() {
		_, _ = conn.ExecContext(ctx, "PRAGMA foreign_keys=ON")
		_ = conn.Close() // release back to the pool with FK enforcement on
	}()
	if _, err := conn.ExecContext(ctx, "PRAGMA foreign_keys=OFF"); err != nil {
		return fmt.Errorf("migration connection: %w", err)
	}
	for _, m := range pending {
		body, _ := migrationFS.ReadFile("migrations/" + m.name)
		tx, err := conn.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(string(body)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migration %s: %w", m.name, err)
		}
		if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", m.n)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migration %s: set version: %w", m.name, err)
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// Tx runs fn in a transaction, committing on nil and rolling back otherwise. Nested calls join the outer tx.
func (s *Store) Tx(ctx context.Context, fn func(*Store) error) error {
	if s.tx {
		return fn(s)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(&Store{db: s.db, q: tx, tx: true}); err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			return errors.Join(err, rbErr)
		}
		return err
	}
	return tx.Commit()
}

func nullInt(n int) any {
	if n == 0 {
		return nil
	}
	return n
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}
