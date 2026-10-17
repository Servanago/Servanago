package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// deniedRoots can never be a static root, nor anything under them. "/" itself is denied too, but only "/" itself:
// /home and /srv are legitimate. The data directory is added at call time.
var deniedRoots = []string{"/etc", "/proc", "/sys", "/dev", "/root"}

// ValidateStaticRoot checks an admin-supplied static site root and returns its symlink-resolved path.
// The path must be absolute, resolve to an existing directory, sit outside the denied trees and the data
// directory, and, when allowed is non-empty, inside one of those prefixes. Symlinks are resolved first, so
// a link cannot point a permitted-looking path at a denied or out-of-allowlist directory.
func ValidateStaticRoot(root, dataDir string, allowed []string) (string, error) {
	if root == "" || strings.ContainsRune(root, 0) {
		return "", errors.New("static root: path is empty or contains a NUL byte")
	}
	if !filepath.IsAbs(root) {
		return "", fmt.Errorf("static root %q: must be an absolute path", root)
	}
	resolved, err := filepath.EvalSymlinks(filepath.Clean(root))
	if err != nil {
		return "", fmt.Errorf("static root %q: %w", root, err)
	}
	fi, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("static root %q: %w", root, err)
	}
	if !fi.IsDir() {
		return "", fmt.Errorf("static root %q: not a directory", root)
	}
	if resolved == "/" {
		return "", fmt.Errorf("static root %q: not allowed (the filesystem root)", root)
	}
	denied := append([]string{dataDir}, deniedRoots...)
	for _, d := range denied {
		for _, base := range resolvedForms(d) {
			if under(resolved, base) {
				return "", fmt.Errorf("static root %q: not allowed (%s is off limits)", root, d)
			}
		}
	}
	if len(allowed) > 0 {
		ok := false
		for _, a := range allowed {
			for _, base := range resolvedForms(a) {
				ok = ok || under(resolved, base)
			}
		}
		if !ok {
			return "", fmt.Errorf("static root %q: outside the allowed roots (SERVANAGO_STATIC_ROOTS)", root)
		}
	}
	return resolved, nil
}

// StaticRootReadable reports whether the server can list root: the site page shows this, a failure never stops anything.
func StaticRootReadable(root string) error {
	f, err := os.Open(root)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Readdirnames(1); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

// resolvedForms is p cleaned, plus its symlink-resolved form when that differs (/etc may be a link).
func resolvedForms(p string) []string {
	if abs, err := filepath.Abs(p); err == nil {
		p = abs
	}
	out := []string{filepath.Clean(p)}
	if r, err := filepath.EvalSymlinks(p); err == nil && r != out[0] {
		out = append(out, r)
	}
	return out
}

func under(p, base string) bool { return p == base || strings.HasPrefix(p, base+"/") }
