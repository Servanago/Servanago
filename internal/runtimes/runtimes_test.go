package runtimes

import (
	"context"
	"errors"
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
