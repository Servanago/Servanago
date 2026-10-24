package backup

import (
	"archive/tar"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// RestorePanel restores the panel scope from an archive: the database (refused when its schema is newer than
// maxSchema), the Caddy data, the last-known-good config and the environment file. The service must be stopped.
func RestorePanel(path, pass, dataDir, envFile string, maxSchema int, chown func(string, *tar.Header) error) error {
	if _, err := VerifyChecksum(path); err != nil {
		return err
	}
	tr, closeFn, err := Open(path, pass)
	if err != nil {
		return err
	}
	defer func() { _ = closeFn() }()
	x := Extractor{Dest: dataDir, Chown: chown}
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return err
	}
	var gotDB bool
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		switch {
		case h.Name == "panel/servanago.db":
			tmp := filepath.Join(dataDir, ".servanago.db.restore")
			if err := writeEntry(tmp, h, tr); err != nil {
				return err
			}
			defer os.Remove(tmp)
			if v, err := schemaOf(tmp); err != nil {
				return err
			} else if v > maxSchema {
				return fmt.Errorf("archive database is schema %d, this binary knows up to %d: install a newer servanago first", v, maxSchema)
			}
			if chown != nil {
				if err := chown(tmp, h); err != nil {
					return err
				}
			}
			_ = os.Remove(filepath.Join(dataDir, "servanago.db-wal"))
			_ = os.Remove(filepath.Join(dataDir, "servanago.db-shm"))
			if err := os.Rename(tmp, filepath.Join(dataDir, "servanago.db")); err != nil {
				return err
			}
			gotDB = true
		case strings.HasPrefix(h.Name, "panel/caddy/"):
			if err := x.Extract(strings.TrimPrefix(h.Name, "panel/"), h, tr); err != nil {
				return err
			}
		case h.Name == "panel/caddy-last-good.json":
			if err := x.Extract("caddy-last-good.json", h, tr); err != nil {
				return err
			}
		case h.Name == "panel/servanago.env" && envFile != "":
			if err := os.MkdirAll(filepath.Dir(envFile), 0o755); err != nil {
				return err
			}
			if err := (Extractor{Dest: filepath.Dir(envFile), Chown: chown}).Extract(filepath.Base(envFile), h, tr); err != nil {
				return err
			}
		}
	}
	if !gotDB {
		return errors.New("the archive has no panel database")
	}
	return nil
}

func writeEntry(path string, h *tar.Header, r io.Reader) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, err = io.Copy(f, r)
	return errors.Join(err, f.Close())
}

func schemaOf(path string) (int, error) {
	db, err := sql.Open("sqlite", "file:"+escape(path)+"?mode=ro&immutable=1")
	if err != nil {
		return 0, err
	}
	defer db.Close()
	var v int
	if err := db.QueryRow("PRAGMA user_version").Scan(&v); err != nil {
		return 0, fmt.Errorf("read the archived database: %w", err)
	}
	return v, nil
}
