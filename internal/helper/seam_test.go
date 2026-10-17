package helper

import (
	"io/fs"
	"time"
)

// fakeSeam is the fake systemd/filesystem the helper tests run against, never the real host.
type fakeSeam struct {
	written                        map[string][]byte // path -> content written, last write wins per path
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
	removeErr                      error
	userAdded, userHome            string
	userRemoved                    string
	fpmTested, fpmTestBin          string
	fpmTestErr                     error
	started, stopped               string
	startStopErr                   error
	disabled                       string
	disableErr                     error
	binErr                         error
	binChecked                     string
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
	s.written[path] = append([]byte(nil), data...) // upsert: a real file keeps every other file
	return nil
}
func (s *fakeSeam) MkdirAll(path string, perm fs.FileMode) error { return nil }
func (s *fakeSeam) Remove(path string) error {
	s.removed = path
	if s.removeErr != nil {
		return s.removeErr
	}
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
func (s *fakeSeam) UserAdd(user, home string) error {
	s.userAdded, s.userHome = user, home
	return nil
}
func (s *fakeSeam) UserRemove(user string) error { s.userRemoved = user; return nil }
func (s *fakeSeam) FPMTest(bin, conf string) error {
	s.fpmTestBin, s.fpmTested = bin, conf
	return s.fpmTestErr
}
func (s *fakeSeam) CheckBinary(path string) error { s.binChecked = path; return s.binErr }
func (s *fakeSeam) StartUnit(name string) error   { s.started = name; return s.startStopErr }
func (s *fakeSeam) StopUnit(name string) error    { s.stopped = name; return s.startStopErr }
func (s *fakeSeam) DisableUnit(name string) error {
	s.disabled = name
	return s.disableErr
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
