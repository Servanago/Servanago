package backup

import (
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

// SnapshotSQLite writes a consistent copy of the SQLite database src to dst (VACUUM INTO) without creating a file
// beside src. A WAL database in use is opened read-only in place (its -shm already exists, so ownership is untouched);
// when that is not possible, or no -wal exists, the files are copied to scratch and the copy is read. dst must not exist.
func SnapshotSQLite(src, dst, scratch string) error {
	if _, err := os.Lstat(dst); err == nil {
		return fmt.Errorf("%s already exists", dst)
	}
	if _, err := os.Stat(src + "-wal"); err == nil {
		if err := vacuumInto("file:"+escape(src)+"?mode=ro", dst); err == nil {
			return checkSQLite(dst)
		}
		_ = os.Remove(dst)
	}
	tmp, err := os.MkdirTemp(scratch, "snap-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	for _, suf := range []string{"", "-wal", "-shm"} {
		if err := copyFile(src+suf, filepath.Join(tmp, "db"+suf)); err != nil && !(suf != "" && errors.Is(err, os.ErrNotExist)) {
			return err
		}
	}
	if err := vacuumInto("file:"+escape(filepath.Join(tmp, "db")), dst); err != nil {
		return err
	}
	return checkSQLite(dst)
}

func escape(p string) string { return (&url.URL{Path: p}).EscapedPath() }

func vacuumInto(dsn, dst string) error {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	if _, err := db.Exec("VACUUM INTO '" + strings.ReplaceAll(dst, "'", "''") + "'"); err != nil {
		return fmt.Errorf("snapshot: %w", err)
	}
	return nil
}

func checkSQLite(path string) error {
	db, err := sql.Open("sqlite", "file:"+escape(path)+"?mode=ro")
	if err != nil {
		return err
	}
	defer db.Close()
	var res string
	if err := db.QueryRow("PRAGMA integrity_check").Scan(&res); err != nil {
		return fmt.Errorf("integrity check: %w", err)
	}
	if res != "ok" {
		return fmt.Errorf("snapshot of a database failed its integrity check: %s", res)
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	return errors.Join(err, out.Close())
}
