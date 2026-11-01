package updatejob

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// The database is WAL: the three files are one unit and are copied only while the services are stopped.
var dbSuffixes = []string{"", "-wal", "-shm"}

// copyDB copies servanago.db (and its -wal/-shm, when they exist) to servanago.db.pre-<tag>, keeping the owner so
// the copy reads like the other .pre-* files. An existing copy is never overwritten: the caller picks a free tag.
func copyDB(dir, tag string) error {
	src := filepath.Join(dir, "servanago.db")
	if _, err := os.Stat(src); err != nil {
		return err
	}
	for _, s := range dbSuffixes {
		if _, err := os.Lstat(src + ".pre-" + tag + s); err == nil {
			return errors.New(src + ".pre-" + tag + s + " already exists")
		}
	}
	for _, s := range dbSuffixes {
		if err := copyFile(src+s, src+".pre-"+tag+s, true); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}

// restoreDB puts the copy back over the live files; a live -wal/-shm the copy did not have is removed.
func restoreDB(dir, tag string) error {
	live := filepath.Join(dir, "servanago.db")
	if _, err := os.Stat(live + ".pre-" + tag); err != nil {
		return err
	}
	for _, s := range dbSuffixes {
		if err := copyFile(live+".pre-"+tag+s, live+s, false); errors.Is(err, fs.ErrNotExist) {
			if err := os.Remove(live + s); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
		} else if err != nil {
			return err
		}
	}
	return nil
}

// copyFile writes dst through a temp file and a rename, with src's owner and mode.
func copyFile(src, dst string, noReplace bool) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	fi, err := os.Stat(src)
	if err != nil {
		return err
	}
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		_ = os.Lchown(tmp, int(st.Uid), int(st.Gid)) // fails for a non-root caller, which then keeps its own ids
	}
	_ = os.Chmod(tmp, fi.Mode().Perm())
	if noReplace {
		if _, err := os.Lstat(dst); err == nil {
			_ = os.Remove(tmp)
			return errors.New(dst + " already exists")
		}
	}
	return os.Rename(tmp, dst)
}
