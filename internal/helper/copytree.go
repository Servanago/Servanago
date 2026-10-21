package helper

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// copyTree copies a build tree that an unprivileged user produced into a root-owned location. It trusts nothing in
// src: only directories, regular files and symlinks that stay inside the managed tree are copied; setuid, setgid,
// sticky and group/other write bits are dropped; dst must not exist. chown, when set, is applied to every created entry
// (root:root in the helper; nil in tests, which do not run as root).
//
// allowAbs is the one absolute prefix a symlink may point into (the final /opt/servanago/php: builds are compiled
// with their final paths, so a link they create may name one).
func copyTree(src, dst, allowAbs string, chown func(path string) error) error {
	if _, err := os.Lstat(dst); err == nil {
		return fmt.Errorf("%s already exists", dst)
	}
	src = filepath.Clean(src)
	err := filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		out := filepath.Join(dst, rel)
		fi, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			if err := os.Mkdir(out, 0o755); err != nil {
				return err
			}
		case fi.Mode()&fs.ModeSymlink != 0:
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			if err := checkLink(src, path, target, allowAbs); err != nil {
				return err
			}
			if err := os.Symlink(target, out); err != nil {
				return err
			}
			if chown != nil { // Lchown: never follow the link we just made
				if err := chown(out); err != nil {
					return err
				}
			}
			return nil
		case fi.Mode().IsRegular():
			if err := copyFile(path, out, fi.Mode()); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%s: %v is not a file, directory or symlink", path, fi.Mode().Type())
		}
		if chown != nil {
			return chown(out)
		}
		return nil
	})
	if err != nil {
		_ = os.RemoveAll(dst)
		return fmt.Errorf("copy %s: %w", src, err)
	}
	return nil
}

// checkLink refuses a symlink that could point out of the build: an absolute target must be under allowAbs, a
// relative one must resolve inside src.
func checkLink(src, link, target, allowAbs string) error {
	if filepath.IsAbs(target) {
		t := filepath.Clean(target)
		if allowAbs != "" && (t == allowAbs || strings.HasPrefix(t, allowAbs+"/")) {
			return nil
		}
		return fmt.Errorf("%s: symlink to %s leaves the build", link, target)
	}
	resolved := filepath.Join(filepath.Dir(link), target)
	if rel, err := filepath.Rel(src, resolved); err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
		return fmt.Errorf("%s: symlink to %s leaves the build", link, target)
	}
	return nil
}

func copyFile(src, dst string, mode fs.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	perm := mode.Perm() &^ 0o022 // no setuid/setgid/sticky (not in Perm), and nothing group- or world-writable
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Chmod(dst, perm) // OpenFile applies the umask
}
