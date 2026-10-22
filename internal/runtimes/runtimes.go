// Package runtimes detects installed runtimes: ServanaGo reports Node.js and php-fpm binaries
// and shows the install command; it never installs anything.
package runtimes

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// PHPRoot is where ServanaGo's own PHP builds live: PHPRoot/<version>-<n>/{sbin,bin,...}. A variable so tests can point it elsewhere.
var PHPRoot = "/opt/servanago/php"

// BuildRE is a build directory name: 8.4.27-1 is the first build of PHP 8.4.27.
var BuildRE = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+-[0-9]+$`)

// PHPVersion is one installed php-fpm binary, as a label a site can pin: a distro version ("8.2"), a
// source build ("8.4.27-1") or a branch of source builds ("8.4", following the newest build there).
type PHPVersion struct {
	Version string // the label: php-fpm8.2 -> "8.2"; a source build keeps its directory name
	Path    string // the executable; the pool's binary when a site picks this version
	Source  bool   // built by ServanaGo under PHPRoot
}

// Opt is a pick-list entry: one version, marked when it is the stored one.
type Opt struct {
	Version  string
	Selected bool
}

// Report is what the UI shows.
type Report struct {
	Node     NodeReport
	PHP      []PHPVersion // newest version first
	Franken  FrankenReport
	FCGIWrap FCGIWrapReport
}

// PHPFrom lists the installed php-fpm versions built by ServanaGo (source=true) or by the distro.
func (r Report) PHPFrom(source bool) []PHPVersion {
	var out []PHPVersion
	for _, p := range r.PHP {
		if p.Source == source {
			out = append(out, p)
		}
	}
	return out
}

// FCGIWrapPaths are where fcgiwrap is looked for (the helper accepts exactly these).
var FCGIWrapPaths = []string{"/usr/sbin/fcgiwrap", "/usr/bin/fcgiwrap", "/usr/local/bin/fcgiwrap"}

type FCGIWrapReport struct {
	Installed bool
	Path      string // the first of FCGIWrapPaths that exists
	Install   string // the command for the admin to run
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

	php := sourceBuilds(ex)
	for _, dir := range []string{"/usr/sbin", "/usr/bin", "/usr/local/bin"} {
		m, _ := ex.Glob(dir + "/php-fpm*") // pattern errors are impossible for a fixed pattern
		for _, p := range m {
			v := strings.TrimPrefix(filepath.Base(p), "php-fpm")
			if v != "" {
				php = append(php, PHPVersion{Version: v, Path: p})
			}
		}
	}
	sort.SliceStable(php, func(i, j int) bool { return newest(php[i].Version, php[j].Version) })
	r.PHP = dedupe(php) // the first one listed wins for a repeated label: source builds, then the first path searched
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
	r.FCGIWrap.Install = "sudo apt install fcgiwrap"
	for _, p := range FCGIWrapPaths {
		if m, _ := ex.Glob(p); len(m) == 1 {
			r.FCGIWrap.Installed, r.FCGIWrap.Path = true, p
			break
		}
	}
	return r
}

// sourceBuilds lists ServanaGo's own builds: one entry per build directory plus one per branch (8.4)
// pointing at the newest build there, so a site pinned to a branch follows security releases.
func sourceBuilds(ex RunExec) []PHPVersion {
	m, _ := ex.Glob(PHPRoot + "/*-*/sbin/php-fpm")
	var builds []PHPVersion
	for _, p := range m {
		label := filepath.Base(filepath.Dir(filepath.Dir(p)))
		if BuildRE.MatchString(label) {
			builds = append(builds, PHPVersion{Version: label, Path: p, Source: true})
		}
	}
	sort.SliceStable(builds, func(i, j int) bool { return newest(builds[i].Version, builds[j].Version) })
	out := append([]PHPVersion(nil), builds...)
	seen := map[string]bool{}
	for _, b := range builds {
		if br := Branch(b.Version); !seen[br] {
			seen[br] = true
			out = append(out, PHPVersion{Version: br, Path: b.Path, Source: true})
		}
	}
	return out
}

// BuildLibs lists the library directories a build was compiled against (its libs.txt); nil when unreadable.
func BuildLibs(label string) []string {
	if !BuildRE.MatchString(label) {
		return nil
	}
	b, err := os.ReadFile(filepath.Join(PHPRoot, label, "libs.txt"))
	if err != nil {
		return nil
	}
	return strings.Fields(string(b))
}

// Branch is the major.minor of a build label or version: 8.4.27-1 -> 8.4.
func Branch(label string) string {
	parts := strings.SplitN(label, ".", 3)
	if len(parts) < 2 {
		return label
	}
	return parts[0] + "." + parts[1]
}

// Resolve maps a site's pinned label to an installed binary. A source build that has since been pruned
// falls back to the newest build of its branch (fallback=true, so the UI can say so); a label with no match is not ok.
func Resolve(label string, installed []PHPVersion) (v PHPVersion, fallback, ok bool) {
	if label == "" {
		return PHPVersion{}, false, false
	}
	for _, p := range installed {
		if p.Version == label {
			return p, false, true
		}
	}
	if BuildRE.MatchString(label) {
		for _, p := range installed {
			if p.Version == Branch(label) {
				return p, true, true
			}
		}
	}
	return PHPVersion{}, false, false
}

// Newer reports whether version a is later than b (8.4.27 vs 8.4.9, 8.4.27-2 vs 8.4.27-1).
func Newer(a, b string) bool { return newest(a, b) }

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
	for _, part := range strings.FieldsFunc(v, func(r rune) bool { return r == '.' || r == '-' }) { // 8.4.27-1: the build number counts
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
