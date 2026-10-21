package helper

import (
	"io/fs"
	"strings"
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
	fpmTestIni                     string

	// PHP build seam
	files        map[string][]byte // ReadFile and Lstat see these (path -> content), besides atUnit
	missing      []string
	free         uint64
	jobDirCalls  []string
	dirs         map[string][]string // ReadDir results
	removedAll   []string
	renamed      [][2]string
	installed    [][2]string
	installErr   error
	execOut      map[string]string // "bin arg arg" -> output
	execErr      error
	fetched      map[string][]byte
	fetchErr     error
	userErr      error
	exe          string
	unitStatuses map[string]StatusData // per-unit UnitStatus for the build units
	unitLogs     map[string][]string
	checked      []string
	exist        map[string]bool // paths Lstat reports as existing directories
	readBack     bool            // ReadFile returns what WriteFile stored (for the state file round trip)
}

func newFakeSeam() *fakeSeam { return &fakeSeam{written: map[string][]byte{}} }

func (s *fakeSeam) Lstat(path string) (fs.FileInfo, error) {
	if s.exist[path] {
		return dirFI{}, nil
	}
	if _, ok := s.files[path]; ok {
		return plainFI{}, nil
	}
	if path != s.atUnit {
		return nil, fs.ErrNotExist
	}
	if s.isSymlink {
		return symlinkFI{}, nil
	}
	return plainFI{}, nil
}
func (s *fakeSeam) ReadFile(path string) ([]byte, error) {
	if b, ok := s.files[path]; ok {
		return append([]byte(nil), b...), nil
	}
	if b, ok := s.written[path]; ok && s.readBack {
		return append([]byte(nil), b...), nil
	}
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
	if st, ok := s.unitStatuses[name]; ok {
		return st, nil
	}
	return s.status, s.statusErr
}
func (s *fakeSeam) UnitLogs(name string, lines int) ([]string, error) {
	s.statusName = name
	s.logLines = lines
	if s.logsErr != nil {
		return nil, s.logsErr
	}
	if l, ok := s.unitLogs[name]; ok {
		return l, nil
	}
	return s.logs, nil
}
func (s *fakeSeam) UserAdd(user, home string) error {
	s.userAdded, s.userHome = user, home
	return nil
}
func (s *fakeSeam) UserRemove(user string) error { s.userRemoved = user; return nil }
func (s *fakeSeam) FPMTest(bin, conf, ini string) error {
	s.fpmTestBin, s.fpmTested, s.fpmTestIni = bin, conf, ini
	return s.fpmTestErr
}
func (s *fakeSeam) CheckBinary(path string) error {
	s.binChecked = path
	s.checked = append(s.checked, path)
	return s.binErr
}

func (s *fakeSeam) Missing([]string) []string        { return s.missing }
func (s *fakeSeam) FreeBytes(string) (uint64, error) { return s.free, nil }
func (s *fakeSeam) JobDir(dir, user string) error {
	s.jobDirCalls = append(s.jobDirCalls, dir+" "+user)
	return nil
}
func (s *fakeSeam) ReadDir(path string) ([]string, error) { return s.dirs[path], nil }
func (s *fakeSeam) RemoveAll(path string) error {
	s.removedAll = append(s.removedAll, path)
	return nil
}
func (s *fakeSeam) Rename(oldPath, newPath string) error {
	s.renamed = append(s.renamed, [2]string{oldPath, newPath})
	return nil
}
func (s *fakeSeam) InstallTree(src, dst string) error {
	s.installed = append(s.installed, [2]string{src, dst})
	return s.installErr
}
func (s *fakeSeam) UserOK(string) error  { return s.userErr }
func (s *fakeSeam) Exe() (string, error) { return s.exe, nil }
func (s *fakeSeam) Exec(name string, args ...string) (string, error) {
	return s.execOut[strings.Join(append([]string{name}, args...), " ")], s.execErr
}
func (s *fakeSeam) Fetch(url string, limit int64) ([]byte, error) {
	if s.fetchErr != nil {
		return nil, s.fetchErr
	}
	if b, ok := s.fetched[url]; ok {
		return b, nil
	}
	return nil, fs.ErrNotExist
}
func (s *fakeSeam) StartUnit(name string) error { s.started = name; return s.startStopErr }
func (s *fakeSeam) StopUnit(name string) error  { s.stopped = name; return s.startStopErr }
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

type dirFI struct{ plainFI }

func (dirFI) Mode() fs.FileMode { return fs.ModeDir | 0o755 }
func (dirFI) IsDir() bool       { return true }

type symlinkFI struct{ plainFI }

func (symlinkFI) Mode() fs.FileMode { return fs.ModeSymlink | 0o777 }
