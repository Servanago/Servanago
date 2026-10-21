package runtimes

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type fakeExec struct {
	paths   map[string]string // node -> /usr/bin/node
	out     map[string]string // "node --version" -> output
	globs   map[string][]string
	ranWith []string // recorded commands
}

func (f *fakeExec) LookupPath(bin string) (string, error) {
	p, ok := f.paths[bin]
	if !ok {
		return "", errors.New("not found")
	}
	return p, nil
}
func (f *fakeExec) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	key := name
	for _, a := range args {
		key += " " + a
	}
	f.ranWith = append(f.ranWith, key)
	if out, ok := f.out[key]; ok {
		return []byte(out), nil
	}
	return nil, errors.New("no such command")
}
func (f *fakeExec) Glob(pattern string) ([]string, error) { return f.globs[pattern], nil }

func TestDetect(t *testing.T) {
	tests := []struct {
		name          string
		ex            *fakeExec
		nodeInstalled bool
		nodeVersion   string
		phpVersions   []string
	}{
		{
			name: "both installed",
			ex: &fakeExec{
				paths: map[string]string{"node": "/usr/bin/node"},
				out:   map[string]string{"node --version": "v20.11.0\n"},
				globs: map[string][]string{"/usr/sbin/php-fpm*": {"/usr/sbin/php-fpm8.2"}, "/usr/bin/php-fpm*": {"/usr/bin/php-fpm8.1", "/usr/bin/php-fpm8.4"}},
			},
			nodeInstalled: true, nodeVersion: "20.11.0", phpVersions: []string{"8.4", "8.2", "8.1"},
		},
		{
			name:          "php only, node missing",
			ex:            &fakeExec{globs: map[string][]string{"/usr/sbin/php-fpm*": nil}},
			nodeInstalled: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Detect(context.Background(), tt.ex)
			if r.Node.Installed != tt.nodeInstalled {
				t.Errorf("node installed: %+v", r.Node)
			}
			if tt.nodeInstalled && r.Node.Version != tt.nodeVersion {
				t.Errorf("node version %q", r.Node.Version)
			}
			if r.Node.Install == "" {
				t.Error("node install command missing")
			}
			var got []string
			for _, p := range r.PHP {
				got = append(got, p.Version)
			}
			if len(got) != len(tt.phpVersions) {
				t.Fatalf("php versions: %v, want %v", got, tt.phpVersions)
			}
			for i := range got {
				if got[i] != tt.phpVersions[i] {
					t.Fatalf("php versions: %v, want %v", got, tt.phpVersions)
				}
			}
		})
	}
}

func TestDetectFrankenPHP(t *testing.T) {
	ex := &fakeExec{
		globs: map[string][]string{"/usr/bin/frankenphp": {"/usr/bin/frankenphp"}, "/opt/frankenphp/frankenphp": {"/opt/frankenphp/frankenphp"}},
		out:   map[string]string{"/usr/bin/frankenphp version": "FrankenPHP v1.5.0 PHP 8.4.1 Caddy v2.9.1 h1:abc\n"},
	}
	r := Detect(context.Background(), ex)
	if f := r.Franken; !f.Installed || f.Path != "/usr/bin/frankenphp" || f.Version != "1.5.0" {
		t.Errorf("first searched path must win: %+v", f)
	}
	if r := Detect(context.Background(), &fakeExec{}); r.Franken.Installed || r.Franken.Install == "" {
		t.Errorf("absent frankenphp: %+v", r.Franken)
	}
}

func TestDetectFCGIWrap(t *testing.T) {
	r := Detect(context.Background(), &fakeExec{globs: map[string][]string{"/usr/bin/fcgiwrap": {"/usr/bin/fcgiwrap"}, "/usr/local/bin/fcgiwrap": {"/usr/local/bin/fcgiwrap"}}})
	if f := r.FCGIWrap; !f.Installed || f.Path != "/usr/bin/fcgiwrap" {
		t.Errorf("first searched path must win: %+v", f)
	}
	if r := Detect(context.Background(), &fakeExec{}); r.FCGIWrap.Installed || r.FCGIWrap.Install == "" {
		t.Errorf("absent fcgiwrap: %+v", r.FCGIWrap)
	}
}

func labels(v []PHPVersion) []string {
	var out []string
	for _, p := range v {
		out = append(out, p.Version)
	}
	return out
}

func TestDetectSourceBuilds(t *testing.T) {
	ex := &fakeExec{globs: map[string][]string{
		PHPRoot + "/*-*/sbin/php-fpm": {PHPRoot + "/8.4.9-1/sbin/php-fpm", PHPRoot + "/8.4.27-1/sbin/php-fpm", PHPRoot + "/8.3.36-2/sbin/php-fpm", PHPRoot + "/junk-1/sbin/php-fpm"},
		"/usr/sbin/php-fpm*":          {"/usr/sbin/php-fpm8.4", "/usr/sbin/php-fpm8.1"},
	}}
	r := Detect(context.Background(), ex)
	want := []string{"8.4.27-1", "8.4.9-1", "8.4", "8.3.36-2", "8.3", "8.1"}
	if got := labels(r.PHP); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("labels %v, want %v", got, want)
	}
	for _, p := range r.PHP {
		switch p.Version {
		case "8.4": // the branch label follows the newest build, and wins over the distro 8.4
			if p.Path != PHPRoot+"/8.4.27-1/sbin/php-fpm" || !p.Source {
				t.Errorf("branch 8.4: %+v", p)
			}
		case "8.1":
			if p.Source {
				t.Errorf("apt build marked as source: %+v", p)
			}
		}
	}
	if r.PHPInstall != "sudo apt install php8.1-fpm" { // the hint names a distro package, never a build directory
		t.Errorf("install hint %q", r.PHPInstall)
	}
}

func TestResolve(t *testing.T) {
	inst := []PHPVersion{
		{"8.4.27-1", "/b/8.4.27-1", true}, {"8.4.9-1", "/b/8.4.9-1", true}, {"8.4", "/b/8.4.27-1", true},
		{"8.2", "/usr/sbin/php-fpm8.2", false},
	}
	tests := []struct {
		label, path string
		fallback    bool
		ok          bool
	}{
		{"8.4.9-1", "/b/8.4.9-1", false, true}, // exact build
		{"8.4", "/b/8.4.27-1", false, true},    // branch follows the newest
		{"8.2", "/usr/sbin/php-fpm8.2", false, true},
		{"8.4.20-1", "/b/8.4.27-1", true, true}, // pruned exact build falls back to its branch
		{"8.3.1-1", "", false, false},           // no such branch at all
		{"7.4", "", false, false},
		{"", "", false, false},
	}
	for _, tt := range tests {
		v, fb, ok := Resolve(tt.label, inst)
		if ok != tt.ok || fb != tt.fallback || v.Path != tt.path {
			t.Errorf("Resolve(%q) = %+v fallback=%v ok=%v, want %q fallback=%v ok=%v", tt.label, v, fb, ok, tt.path, tt.fallback, tt.ok)
		}
	}
}

func TestPHPPDupesSortedNewestFirst(t *testing.T) {
	ex := &fakeExec{globs: map[string][]string{
		"/usr/sbin/php-fpm*": {"/usr/sbin/php-fpm7.4", "/usr/sbin/php-fpm8.2"},
		"/usr/bin/php-fpm*":  {"/usr/bin/php-fpm8.2"}}}
	r := Detect(context.Background(), ex)
	if len(r.PHP) != 2 || r.PHP[0].Version != "8.2" || r.PHP[1].Version != "7.4" {
		t.Fatalf("versions: %+v", r.PHP)
	}
	if r.PHP[0].Path != "/usr/sbin/php-fpm8.2" { // the first searched dir wins
		t.Errorf("winner path %q", r.PHP[0].Path)
	}
	if r.PHPInstall != "sudo apt install php8.2-fpm" {
		t.Errorf("php install %q", r.PHPInstall)
	}
}
