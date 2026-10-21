//go:build smoke

package phpbuild

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/servanago/servanago/internal/runtimes"
)

// TestSmokeRealBuild compiles a real PHP and every library into SMOKE_ROOT (an empty directory), over the real network
// with the real GPG check. It takes tens of minutes, so it is not part of the gate:
//
//	SMOKE_ROOT=/tmp/x SMOKE_VERSION=8.4.27 go test -tags smoke -run SmokeRealBuild -timeout 3h ./internal/phpbuild
//
// It does not use systemd or the helper: Root and Stage are one directory, so there is no bind mount.
func TestSmokeRealBuild(t *testing.T) {
	root := os.Getenv("SMOKE_ROOT")
	if root == "" {
		t.Skip("set SMOKE_ROOT")
	}
	ver := os.Getenv("SMOKE_VERSION")
	if ver == "" {
		ver = "8.4.27"
	}
	dir := filepath.Join(root, "job")
	opt := filepath.Join(root, "opt")
	for _, d := range []string{dir, opt} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	jb, _ := json.Marshal(Job{Version: ver, N: 1, Jobs: 8})
	if err := os.WriteFile(filepath.Join(dir, JobFile), jb, 0o644); err != nil {
		t.Fatal(err)
	}
	e := Env{
		Get: HTTPGet, Run: RunCmd, Root: opt, Stage: opt, Log: os.Stdout,
		Verify: func(ctx context.Context, file, sig string) error { return VerifyGPG(ctx, Keyring, file, sig) },
	}
	ctx := context.Background()
	if err := Fetch(ctx, e, dir); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if err := Build(ctx, e, dir); err != nil {
		t.Fatalf("build: %v", err)
	}
	prefix := filepath.Join(opt, ver+"-1")
	out, err := exec.Command(filepath.Join(prefix, "bin/php"), "-v").CombinedOutput()
	if err != nil || !strings.HasPrefix(string(out), "PHP "+ver+" ") {
		t.Fatalf("php -v: %v\n%s", err, out)
	}
	extDirOut, err := exec.Command(filepath.Join(prefix, "bin/php-config"), "--extension-dir").Output()
	if err != nil {
		t.Fatal(err)
	}
	extDir := strings.TrimSpace(string(extDirOut))
	args := []string{"-n", "-d", "extension_dir=" + extDir}
	for _, x := range runtimes.SharedExtensions(runtimes.Branch(ver)) {
		if _, err := os.Stat(filepath.Join(extDir, x.Name+".so")); err != nil {
			t.Errorf("%s.so missing: %v", x.Name, err)
		}
		args = append(args, "-d", x.Directive())
	}
	// Every shared extension loads together, as a site that ticks them all would load them.
	out, err = exec.Command(filepath.Join(prefix, "bin/php"), append(args, "-m")...).CombinedOutput()
	if err != nil || strings.Contains(string(out), "Warning") || strings.Contains(string(out), "Unable to load") {
		t.Fatalf("loading every extension: %v\n%s", err, out)
	}
	t.Logf("php -m:\n%s", out)
	if out, err := exec.Command(filepath.Join(prefix, "sbin/php-fpm"), "-v").CombinedOutput(); err != nil || !strings.Contains(string(out), "fpm-fcgi") {
		t.Errorf("php-fpm -v: %v\n%s", err, out)
	}
	libs, _ := os.ReadFile(filepath.Join(prefix, "libs.txt"))
	t.Logf("libs.txt:\n%s", libs)
}
