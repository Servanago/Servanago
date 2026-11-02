//go:build smoke

package phplibs

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestSmokeRealLibraries downloads the pinned libraries that need no system tool beyond a C compiler and make, checks
// their sha256, and runs their real recipes into a temp prefix. It proves the pinned sums and the recipe flags, which
// no unit test can. Run: go test -tags smoke -run SmokeRealLibraries -timeout 30m -v ./internal/phplibs
func TestSmokeRealLibraries(t *testing.T) {
	for _, tt := range []struct{ name, artifact string }{
		{"bzip2", "lib/libbz2.so"},
		{"libsodium", "lib/libsodium.so"},
		{"openldap", "lib/libldap.so"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r, err := Resolve(t.Context(), nil, tt.name)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := http.Get(r.URL)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			data, err := io.ReadAll(resp.Body)
			if err != nil || resp.StatusCode != 200 {
				t.Fatalf("download %s: %d %v", r.URL, resp.StatusCode, err)
			}
			if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != r.Sum {
				t.Fatalf("sha256 of %s is %x, the pinned sum is %s", r.URL, sum, r.Sum)
			}
			work, prefix := t.TempDir(), filepath.Join(t.TempDir(), "prefix")
			tarball := filepath.Join(work, "src.tar")
			if err := os.WriteFile(tarball, data, 0o644); err != nil {
				t.Fatal(err)
			}
			if out, err := exec.Command("tar", "-xf", tarball, "-C", work).CombinedOutput(); err != nil {
				t.Fatalf("tar: %v\n%s", err, out)
			}
			src := filepath.Join(work, SourceDir(r))
			for _, c := range Recipe(r, prefix, nil, 4) {
				cmd := exec.Command(c.Name, c.Args...)
				cmd.Dir = filepath.Join(src, c.Dir)
				cmd.Env = append(os.Environ(), c.Env...)
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("%s %v: %v\n%.4000s", c.Name, c.Args, err, out)
				}
			}
			if _, err := os.Stat(filepath.Join(prefix, tt.artifact)); err != nil {
				t.Errorf("recipe left no %s: %v", tt.artifact, err)
			}
		})
	}
}
