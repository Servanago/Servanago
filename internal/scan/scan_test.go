package scan

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/servanago/servanago/internal/scan/fake"
)

func TestPingAgainstFakeClamd(t *testing.T) {
	sock, _ := fake.Clamd(t, "")
	if err := New(sock).Ping(context.Background()); err != nil {
		t.Fatalf("PING: %v", err)
	}
	if err := New("/tmp/nonexistent-clamd.sock").Ping(context.Background()); err == nil {
		t.Error("a missing socket answered PONG")
	}
}

func TestScanFileVerdicts(t *testing.T) {
	sock, _ := fake.Clamd(t, "")
	c := New(sock)
	ctx := context.Background()
	root := t.TempDir()

	clean := filepath.Join(root, "clean.php")
	if err := os.WriteFile(clean, []byte("<?php echo 'hi';\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	v, err := c.ScanFile(ctx, clean)
	if err != nil || !v.Clean || v.Virus != "" {
		t.Fatalf("clean verdict: %+v %v", v, err)
	}
	bad := filepath.Join(root, "bad.php")
	fake.Infected(t, bad)
	v, err = c.ScanFile(ctx, bad)
	if err != nil || v.Clean || v.Virus != "Eicar-Test-Signature" {
		t.Fatalf("hit verdict: %+v %v", v, err)
	}
	if v, err := c.ScanFile(ctx, filepath.Join(root, "missing.php")); err != nil || v.Err != "unreadable" {
		t.Fatalf("missing file: %+v %v", v, err)
	}
}

func TestScanTreeReportsHitsAndSkips(t *testing.T) {
	sock, calls := fake.Clamd(t, "")
	c := New(sock)
	ctx := context.Background()
	root := t.TempDir()

	// served content: clean at top, nested clean dir, one infected, one symlink, one folder symlink
	big := filepath.Join(root, "big.bin")
	if f, err := os.Create(big); err != nil {
		t.Fatal(err)
	} else if err := f.Truncate(maxStream + 1); err != nil { // sparse: cheap to build
		t.Fatal(err)
	} else {
		f.Close()
	}
	fake.Infected(t, filepath.Join(root, "eicar.php"))
	if err := os.Mkdir(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sub", "clean.txt"), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "sub"), filepath.Join(root, "sublink")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(big, filepath.Join(root, "filelink")); err != nil {
		t.Fatal(err)
	}

	var hits []string
	res, err := c.ScanTree(ctx, root, func(path, virus string) error {
		hits = append(hits, filepath.Base(path)+"="+virus)
		return nil
	})
	if err != nil {
		t.Fatalf("scan tree: %v (%+v)", err, res)
	}
	// 2 regular scannable files (eicar.php + sub/clean.txt); big.bin unstreamed, the symlinks skipped
	if res.Files != 2 || res.Skipped != 3 || len(hits) != 1 || hits[0] != "eicar.php=Eicar-Test-Signature" {
		t.Fatalf("result %+v hits %v", res, hits)
	}
	if calls() != 2 {
		t.Errorf("streams sent: %d", calls())
	}
}

func TestScanTreeCarriesClamdFailure(t *testing.T) {
	sock, _ := fake.Clamd(t, "ERROR: engine overloaded")
	c := New(sock)
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := c.ScanTree(context.Background(), root, func(string, string) error { return nil })
	if err != nil || len(res.Errs) == 0 || !strings.Contains(res.Errs[0], "engine overloaded") || res.Files != 0 {
		t.Fatalf("daemon errors are recorded, not fatal: %+v %v", res, err)
	}
	// a dead socket is transport failure: the walk aborts with the dial error
	res, err = New("/tmp/nonexistent-clamd.sock").ScanTree(context.Background(), root, func(string, string) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "clamd socket") || len(res.Errs) == 0 {
		t.Fatalf("dead daemon: %+v %v", res, err)
	}
}

func TestScanTreeHitCallbackAborts(t *testing.T) {
	sock, _ := fake.Clamd(t, "")
	c := New(sock)
	root := t.TempDir()
	fake.Infected(t, filepath.Join(root, "eicar.php"))
	var got int
	if _, err := c.ScanTree(context.Background(), root, func(string, string) error { got++; return errors.New("quarantine refused") }); err == nil || got != 1 || !strings.Contains(err.Error(), "quarantine refused") {
		t.Fatalf("callback error not fatal: %d %v", got, err)
	}
}

func TestQuarantineAndRestoreRoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "quarantine", "web")
	home := t.TempDir()
	src := filepath.Join(home, "site", "eicar.php")
	if err := os.Mkdir(filepath.Dir(src), 0o755); err != nil {
		t.Fatal(err)
	}
	fake.Infected(t, src)
	to, err := Quarantine(src, dir)
	if err != nil || !strings.HasPrefix(to, dir+string(os.PathSeparator)) || !strings.HasSuffix(to, "-eicar.php") {
		t.Fatalf("quarantine: %q %v", to, err)
	}
	if _, err := os.Stat(src); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("the original path still holds the file")
	}
	info, err := os.Stat(to)
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("quarantined mode: %v %v", info, err)
	}
	if err := Restore(to, src); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if _, err := os.Stat(src); err != nil {
		t.Fatal("restore did not move the file home")
	}
	if _, err := os.Stat(to); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("restore left the quarantined copy behind")
	}
	// restoring twice, or into a slot that exists, is refused
	if err := Restore(to, src); err == nil {
		t.Error("restore from a path that no longer exists was accepted")
	}
	fake.Infected(t, filepath.Join(dir, "x.php"))
	if err := Restore(filepath.Join(dir, "x.php"), src); err == nil || !strings.Contains(err.Error(), "exists again") {
		t.Fatalf("restore over an existing path was accepted: %v", err)
	}
	if err := Restore(filepath.Join(dir, "x.php"), ""); err == nil || !strings.Contains(err.Error(), "original path is unknown") {
		t.Fatalf("restore without an original path was accepted: %v", err)
	}
}

func TestQuarantineFallsBackToCopy(t *testing.T) {
	// same-filesystem rename cannot be forced here; the copy fallback is the documented EXDEV path.
	// This test keeps the fallback reachable: a directory that rename cannot cross is hard to fake,
	// so instead verify copyFile directly.
	dir := t.TempDir()
	src := filepath.Join(dir, "src", "a.php")
	if err := os.Mkdir(filepath.Dir(src), 0o755); err != nil {
		t.Fatal(err)
	}
	big := strings.Repeat("x", 200)
	if err := os.WriteFile(src, []byte(big), 0o642); err != nil {
		t.Fatal(err)
	}
	to := filepath.Join(dir, "dst", "a.php")
	if err := os.Mkdir(filepath.Dir(to), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(src, to); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(to); err != nil || string(got) != big {
		t.Fatalf("copied bytes: %d %v", len(got), err)
	}
	info, err := os.Stat(to)
	srcInfo, serr := os.Stat(src)
	if serr != nil {
		t.Fatal(serr)
	}
	if err != nil || info.Mode() != srcInfo.Mode() { // the copy keeps the original mode, umask included
		t.Fatalf("copied mode: %v vs %v %v", info.Mode(), srcInfo.Mode(), err)
	}
}
