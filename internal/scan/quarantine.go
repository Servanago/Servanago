// Quarantine moves an infected file out of the served path without ever chowning it: a rename
// to a directory under DATA_DIR, with a copy fallback when that crosses filesystems.
package scan

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

var quarantineN atomic.Int64

// Quarantine moves path into dir as <unix>-<n>-<basename> and returns the new path. The file
// keeps its mode and (on a plain rename) its owner; a cross-filesystem rename falls back to a
// copy+unlink, which lands the copy under ServanaGo's user by necessity of the filesystem.
func Quarantine(path, dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", fmt.Errorf("make %s: %w", dir, err)
	}
	to := filepath.Join(dir, fmt.Sprintf("%d-%d-%s", time.Now().Unix(), quarantineN.Add(1), filepath.Base(path)))
	if err := os.Rename(path, to); err == nil {
		return to, nil
	}
	// EXDEV (a different filesystem) or a rename the directory forbids; copy the bytes over.
	if err := copyFile(path, to); err != nil {
		return "", err
	}
	if err := os.Remove(path); err != nil {
		_ = os.Remove(to) // do not leave a live copy in the quarantine
		return "", fmt.Errorf("unlink the quarantined file: %w", err)
	}
	return to, nil
}

func copyFile(from, to string) error {
	src, err := os.Open(from)
	if err != nil {
		return fmt.Errorf("open for quarantine: %w", err)
	}
	defer src.Close()
	info, err := src.Stat()
	if err != nil {
		return err
	}
	dst, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, info.Mode())
	if err != nil {
		return fmt.Errorf("quarantine copy: %w", err)
	}
	modeErr := dst.Chmod(info.Mode()) // umask would eat the original bits on create
	if _, err = dst.ReadFrom(src); err != nil {
		_ = dst.Close()
		_ = os.Remove(to)
		return err
	}
	if err := dst.Close(); err != nil {
		return fmt.Errorf("close the copy: %w", err)
	}
	if modeErr != nil {
		return fmt.Errorf("keep the original mode: %w", modeErr)
	}
	return nil
}

// Restore moves a quarantined file back to its original path. It refuses when the original
// exists again: restoring would overwrite a file the site gained since.
func Restore(quarantinedTo, original string) error {
	if original == "" {
		return errors.New("the original path is unknown")
	}
	if _, err := os.Stat(original); err == nil || !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%s already exists again", original)
	}
	if _, err := os.Stat(filepath.Dir(original)); err != nil {
		return fmt.Errorf("the site folder is gone: %w", err)
	}
	return os.Rename(quarantinedTo, original)
}
