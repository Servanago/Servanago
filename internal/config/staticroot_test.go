package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mkdir(t *testing.T, parts ...string) string {
	t.Helper()
	p := filepath.Join(parts...)
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestValidateStaticRoot(t *testing.T) {
	tmp := t.TempDir()
	data := mkdir(t, tmp, "data")
	site := mkdir(t, tmp, "srv", "site")
	other := mkdir(t, tmp, "srv", "site2")
	file := filepath.Join(tmp, "file.txt")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	toEtc := filepath.Join(tmp, "to-etc")
	toSite := filepath.Join(tmp, "to-site")
	if err := os.Symlink("/etc", toEtc); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(site, toSite); err != nil {
		t.Fatal(err)
	}
	allowed := []string{filepath.Join(tmp, "srv", "site")}

	for _, tt := range []struct {
		name, root string
		allowed    []string
		want       string // "" = accepted; otherwise a substring of the error
	}{
		{"plain directory", site, nil, ""},
		{"symlink to a directory resolves", toSite, nil, ""},
		{"empty", "", nil, "empty"},
		{"NUL byte", site + "\x00/x", nil, "NUL"},
		{"relative", "srv/site", nil, "absolute"},
		{"missing", filepath.Join(tmp, "nope"), nil, "no such file"},
		{"a file, not a directory", file, nil, "directory"},
		{"filesystem root", "/", nil, "not allowed"},
		{"/etc", "/etc", nil, "not allowed"},
		{"under /etc", "/etc/ssl", nil, "not allowed"},
		{"traversal into /etc", filepath.Join(site, "..", "..", "..", "..", "..", "..", "etc"), nil, "not allowed"},
		{"/proc", "/proc", nil, "not allowed"},
		{"/sys", "/sys", nil, "not allowed"},
		{"/dev", "/dev", nil, "not allowed"},
		{"data dir", data, nil, "not allowed"},
		{"symlink escaping to /etc", toEtc, nil, "not allowed"},
		{"inside the allowlist", site, allowed, ""},
		{"sibling sharing a name prefix", other, allowed, "allowed"},
		{"outside the allowlist", data, allowed, "allowed"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateStaticRoot(tt.root, data, tt.allowed)
			if tt.want == "" {
				if err != nil || !filepath.IsAbs(got) {
					t.Fatalf("got %q, %v", got, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got %q, %v; want error containing %q", got, err, tt.want)
			}
		})
	}
}

// A symlink inside the allowlist that points outside it must not smuggle a root past the allowlist.
func TestValidateStaticRootSymlinkOutOfAllowlist(t *testing.T) {
	tmp := t.TempDir()
	inside := mkdir(t, tmp, "allowed")
	outside := mkdir(t, tmp, "outside")
	link := filepath.Join(inside, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateStaticRoot(link, filepath.Join(tmp, "data"), []string{inside}); err == nil {
		t.Fatal("symlink out of the allowlist accepted")
	}
}

func TestStaticRootReadable(t *testing.T) {
	dir := mkdir(t, t.TempDir(), "r")
	if err := StaticRootReadable(dir); err != nil {
		t.Fatalf("readable dir: %v", err)
	}
	if os.Geteuid() == 0 {
		t.Skip("root reads everything")
	}
	if err := os.Chmod(dir, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	if err := StaticRootReadable(dir); err == nil {
		t.Fatal("unreadable dir reported readable")
	}
}

// Whatever the input, an accepted root is an absolute, clean directory outside the denied trees.
func FuzzValidateStaticRoot(f *testing.F) {
	for _, s := range []string{"", "/", "/etc", "/etc/../etc", "/tmp", "/tmp/../etc/passwd", "relative", "/\x00", "//etc//", "/proc/self/root", "/dev/null", "/root/.ssh"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, root string) {
		got, err := ValidateStaticRoot(root, "/nonexistent-data-dir", nil)
		if err != nil {
			return
		}
		if !filepath.IsAbs(got) || got != filepath.Clean(got) || got == "/" {
			t.Fatalf("%q accepted as %q", root, got)
		}
		for _, d := range []string{"/etc", "/proc", "/sys", "/dev", "/root"} {
			if got == d || strings.HasPrefix(got, d+"/") {
				t.Fatalf("%q resolved into denied %s: %q", root, d, got)
			}
		}
	})
}
