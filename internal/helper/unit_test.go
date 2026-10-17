package helper

import (
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeSeam is the fake systemd/filesystem the helper tests run against, never the real host.
type fakeSeam struct {
	written                        map[string][]byte // path -> content written, last write wins (like a real file)
	atUnit                         string            // when set, Lstat at this path reports the unit existing
	previous                       []byte            // the content atUnit held before this call
	isSymlink                      bool              // when Lstat is called for atUnit, report a symlink instead
	verify, reload, enable         error
	verifiedWith, enabled, removed string
	reloadCalls                    int
	status                         StatusData
	statusErr                      error
	statusName                     string
	logs                           []string
	logsErr                        error
	logLines                       int
}

func newFakeSeam() *fakeSeam { return &fakeSeam{written: map[string][]byte{}} }

func (s *fakeSeam) Lstat(path string) (fs.FileInfo, error) {
	if path != s.atUnit {
		return nil, fs.ErrNotExist
	}
	if s.isSymlink {
		return symlinkFI{}, nil
	}
	return plainFI{}, nil
}
func (s *fakeSeam) ReadFile(path string) ([]byte, error) {
	if path == s.atUnit && !s.isSymlink {
		return append([]byte(nil), s.previous...), nil
	}
	return nil, fs.ErrNotExist
}
func (s *fakeSeam) WriteFile(path string, data []byte, perm fs.FileMode) error {
	s.written = map[string][]byte{path: append([]byte(nil), data...)}
	return nil
}
func (s *fakeSeam) Remove(path string) error {
	s.removed = path
	delete(s.written, path) // the fake tracks what a real filesystem would hold
	return nil
}
func (s *fakeSeam) VerifyUnit(path string) error { s.verifiedWith = path; return s.verify }
func (s *fakeSeam) DaemonReload() error          { s.reloadCalls++; return s.reload }
func (s *fakeSeam) Enable(name string) error     { s.enabled = name; return s.enable }
func (s *fakeSeam) UnitStatus(name string) (StatusData, error) {
	s.statusName = name
	return s.status, s.statusErr
}
func (s *fakeSeam) UnitLogs(name string, lines int) ([]string, error) {
	s.statusName = name
	s.logLines = lines
	if s.logsErr != nil {
		return nil, s.logsErr
	}
	return s.logs, nil
}

// Minimal fs.FileInfo fakes: one plain regular file, one symlink.
type plainFI struct{ fs.FileInfo }

func (plainFI) Mode() fs.FileMode  { return 0o644 }
func (plainFI) IsDir() bool        { return false }
func (plainFI) Name() string       { return "unit" }
func (plainFI) Size() int64        { return 0 }
func (plainFI) ModTime() time.Time { return time.Time{} }
func (plainFI) Sys() any           { return nil }

type symlinkFI struct{ plainFI }

func (symlinkFI) Mode() fs.FileMode { return fs.ModeSymlink | 0o777 }

func TestUnitInstallHappyPath(t *testing.T) {
	seam := newFakeSeam()
	req, err := DecodeRequest([]byte(`{"action":"unit-install","spec":{"slug":"blog"}}`))
	if err != nil {
		t.Fatal(err)
	}
	resp := NewActions(seam).UnitInstall(req)
	if !resp.OK {
		t.Fatalf("unit-install failed: %+v", resp)
	}
	path := filepath.Join(systemdUnitDir, "servanago-blog.service")
	content := seam.written[path]
	if content == nil {
		t.Fatalf("nothing written to %s (writes: %v)", path, keys(seam.written))
	}
	if !strings.Contains(string(content), "servanago-blog.service") && !strings.Contains(string(content), "blog") {
		t.Errorf("unit content does not name the unit:\n%s", content)
	}
	if seam.verifiedWith != path || seam.enabled != "servanago-blog.service" || seam.reloadCalls != 1 {
		t.Errorf("verify=%q enable=%q reloads=%d", seam.verifiedWith, seam.enabled, seam.reloadCalls)
	}
}

func keys(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestUnitInstallRejections(t *testing.T) {
	blog := string(filepath.Join(systemdUnitDir, "servanago-blog.service"))
	tests := []struct {
		name string
		spec string          // request body
		seam func(*fakeSeam) // hostile state
	}{
		{"traversal slug", `{"slug":"../etc"}`, func(*fakeSeam) {}},
		{"overlong slug", `{"slug":"` + strings.Repeat("a", 80) + `"}`, func(*fakeSeam) {}},
		{"symlink target", `{"slug":"blog"}`, func(s *fakeSeam) { s.atUnit = blog; s.isSymlink = true }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seam := newFakeSeam()
			tt.seam(seam)
			req, err := DecodeRequest([]byte(`{"action":"unit-install","spec":` + tt.spec + `}`))
			if err != nil {
				t.Fatal(err)
			}
			if resp := NewActions(seam).UnitInstall(req); resp.OK {
				t.Fatalf("accepted: %+v", resp)
			} else if resp.Error == "" {
				t.Fatal("error response without a message")
			}
			if len(seam.written) != 0 {
				t.Errorf("host was written: %v", keys(seam.written))
			}
		})
	}
}

func TestUnitInstallVerifyFailureRestoresPrevious(t *testing.T) {
	path := filepath.Join(systemdUnitDir, "servanago-blog.service")
	req, _ := DecodeRequest([]byte(`{"action":"unit-install","spec":{"slug":"blog"}}`))

	// With a previous (last-known-good) unit: restore it and report the failure.
	seam := newFakeSeam()
	seam.atUnit, seam.previous = path, []byte("old body")
	seam.verify = errors.New("bad unit")
	resp := NewActions(seam).UnitInstall(req)
	if resp.OK || !strings.Contains(resp.Error, "bad unit") {
		t.Fatalf("verify failure misreported: %+v", resp)
	}
	if string(seam.written[path]) != "old body" {
		t.Errorf("previous unit not restored, written: %q", seam.written[path])
	}

	// Without one: remove the file.
	seam = newFakeSeam()
	seam.verify = errors.New("bad unit")
	if resp := NewActions(seam).UnitInstall(req); resp.OK {
		t.Fatal("verify failure returned OK")
	}
	if seam.removed != path || len(seam.written) != 0 {
		t.Errorf("new unit not removed: removed=%q left=%v", seam.removed, keys(seam.written))
	}
}
