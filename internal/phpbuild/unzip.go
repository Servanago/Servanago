package phpbuild

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const maxUnzipped = 500 << 20 // an extension's source is a few MB; this only stops a zip bomb

// unzip extracts a zip into dst (created). It trusts nothing in the archive: names must stay inside dst, only plain
// files and directories are written, and the total size is capped.
func unzip(file, dst string) error {
	zr, err := zip.OpenReader(file)
	if err != nil {
		return fmt.Errorf("open %s: %w", filepath.Base(file), err)
	}
	defer zr.Close()
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	var total int64
	for _, f := range zr.File {
		name := filepath.Clean(filepath.FromSlash(f.Name))
		if filepath.IsAbs(name) || name == ".." || strings.HasPrefix(name, ".."+string(filepath.Separator)) || strings.ContainsRune(f.Name, 0) {
			return fmt.Errorf("%s: entry %q leaves the destination", filepath.Base(file), f.Name)
		}
		out := filepath.Join(dst, name)
		mode := f.Mode()
		switch {
		case f.FileInfo().IsDir():
			if err := os.MkdirAll(out, 0o755); err != nil {
				return err
			}
		case mode.IsRegular():
			total += int64(f.UncompressedSize64)
			if total > maxUnzipped {
				return fmt.Errorf("%s: more than %d MB unpacked", filepath.Base(file), maxUnzipped>>20)
			}
			if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
				return err
			}
			if err := extractFile(f, out, mode.Perm()&^0o022); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%s: entry %q is not a file or directory", filepath.Base(file), f.Name)
		}
	}
	return nil
}

func extractFile(f *zip.File, out string, perm os.FileMode) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	w, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm|0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(w, io.LimitReader(rc, maxUnzipped)); err != nil {
		w.Close()
		return err
	}
	return w.Close()
}

// onlyChild returns the single directory inside dir: GitHub zipballs hold one top-level directory named after the commit.
func onlyChild(dir string) (string, error) {
	es, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	if len(es) != 1 || !es[0].IsDir() {
		return "", fmt.Errorf("%s: expected one top-level directory, found %d entries", dir, len(es))
	}
	return filepath.Join(dir, es[0].Name()), nil
}
