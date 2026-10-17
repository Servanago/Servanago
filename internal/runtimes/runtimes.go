// Package runtimes detects installed runtimes: ServanaGo reports Node.js and php-fpm binaries
// and shows the install command; it never installs anything.
package runtimes

import (
	"context"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// PHPVersion is one installed php-fpm binary.
type PHPVersion struct {
	Version string // from the binary name: php-fpm8.2 -> "8.2"
	Path    string // the executable; the pool's binary when a site picks this version
}

// Opt is a pick-list entry: one version, marked when it is the stored one.
type Opt struct {
	Version  string
	Selected bool
}

// Report is what the UI shows.
type Report struct {
	Node       NodeReport
	PHP        []PHPVersion // newest version first
	PHPInstall string       // shown when empty, unless overridden
	Franken    FrankenReport
}

// FrankenPaths are where a frankenphp binary is looked for (the helper accepts exactly these).
var FrankenPaths = []string{"/usr/local/bin/frankenphp", "/usr/bin/frankenphp", "/opt/frankenphp/frankenphp"}

type FrankenReport struct {
	Installed bool
	Path      string // the first of FrankenPaths that exists
	Version   string // "1.5.0" (v prefix trimmed); "" when `version` printed nothing usable
	Install   string // the pointer for the admin to follow
}

type NodeReport struct {
	Installed bool
	Version   string // "20.11.0" (v prefix trimmed)
	Install   string // the command for the admin to run
}

// RunExec is the test seam (real: os/exec).
type RunExec interface {
	LookupPath(bin string) (string, error)
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
	Glob(pattern string) ([]string, error)
}

// OsExec is the real seam: lookups through PATH, subprocesses, filesystem globs.
type OsExec struct{}

func (OsExec) LookupPath(bin string) (string, error) { return exec.LookPath(bin) }
func (OsExec) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).Output()
}
func (OsExec) Glob(pattern string) ([]string, error) { return filepath.Glob(pattern) }

// Detect reports node and every php-fpm binary found in the usual Debian/Ubuntu paths.
// A missing node is a Report with Installed=false, never an error: detection is best-effort.
func Detect(ctx context.Context, ex RunExec) Report {
	var r Report
	if _, err := ex.LookupPath("node"); err == nil {
		if out, err := ex.Run(ctx, "node", "--version"); err == nil {
			r.Node.Installed = true
			r.Node.Version = strings.TrimPrefix(strings.TrimSpace(string(out)), "v")
		}
	}
	r.Node.Install = "sudo apt install nodejs"

	var php []PHPVersion
	for _, dir := range []string{"/usr/sbin", "/usr/bin", "/usr/local/bin"} {
		m, _ := ex.Glob(dir + "/php-fpm*") // pattern errors are impossible for a fixed pattern
		for _, p := range m {
			v := strings.TrimPrefix(filepath.Base(p), "php-fpm")
			if v != "" {
				php = append(php, PHPVersion{v, p})
			}
		}
	}
	sort.Slice(php, func(i, j int) bool { return newest(php[i].Version, php[j].Version) })
	r.PHP = dedupe(php) // the first path searched wins for a repeated version
	if len(r.PHP) > 0 {
		r.PHPInstall = "sudo apt install php" + r.PHP[0].Version + "-fpm"
	}
	r.Franken.Install = "https://frankenphp.dev/docs/#getting-started"
	for _, p := range FrankenPaths {
		if m, _ := ex.Glob(p); len(m) == 1 { // Glob of a literal path is an existence test through the seam
			r.Franken.Installed, r.Franken.Path = true, p
			if out, err := ex.Run(ctx, p, "version"); err == nil { // "FrankenPHP v1.5.0 PHP 8.4.1 Caddy ..."
				if f := strings.Fields(string(out)); len(f) > 1 {
					r.Franken.Version = strings.TrimPrefix(f[1], "v")
				}
			}
			break
		}
	}
	return r
}

// newest returns true when a and b are sorted a-before-b: first version, then version parts.
func newest(a, b string) bool {
	as, bs := splitVersion(a), splitVersion(b)
	for i := 0; i < len(as) || i < len(bs); i++ {
		av, bv := 0, 0
		if i < len(as) {
			av = as[i]
		}
		if i < len(bs) {
			bv = bs[i]
		}
		if av != bv {
			return av > bv
		}
	}
	return false // equal versions keep search-path priority
}

func splitVersion(v string) []int {
	var out []int
	for _, part := range strings.Split(v, ".") {
		if n, err := strconv.Atoi(part); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func dedupe(v []PHPVersion) []PHPVersion {
	var out []PHPVersion
	for i, p := range v {
		if i > 0 && p.Version == out[len(out)-1].Version {
			continue
		}
		out = append(out, p)
	}
	return out
}
