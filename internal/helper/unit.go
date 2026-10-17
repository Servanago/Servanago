package helper

import (
	"fmt"
	"io/fs"
)

// unit.go: the shared helper plumbing.

// systemdUnitDir is where managed units live; the file name is always servanago-<slug>.service.
const systemdUnitDir = "/etc/systemd/system"

// Seam is the systemd/filesystem the helper talks to. The running helper uses the real seam;
// tests use a fake, so nothing here ever touches a real host in tests.
type Seam interface {
	Lstat(path string) (fs.FileInfo, error)
	ReadFile(path string) ([]byte, error)
	WriteFile(path string, data []byte, perm fs.FileMode) error
	MkdirAll(path string, perm fs.FileMode) error
	Remove(path string) error
	VerifyUnit(path string) error // systemd-analyze verify
	DaemonReload() error          // systemctl daemon-reload
	Enable(name string) error     // systemctl enable
	DisableUnit(name string) error
	StartUnit(name string) error
	StopUnit(name string) error
	UserAdd(user, root string) error
	UserRemove(user string) error
	FPMTest(bin, conf string) error
	CheckBinary(path string) error // a regular, executable file owned by root that no one else can write
	UnitStatus(name string) (StatusData, error)
	UnitLogs(name string, lines int) ([]string, error)
}

type Actions struct{ s Seam }

func NewActions(s Seam) Actions { return Actions{s} }

// defaultLogLines bounds the unit-logs tail.
const defaultLogLines, maxLogLines = 20, 500

// UnitStatus reports one managed unit's systemd state for the dashboard.
func (a Actions) UnitStatus(r Request) Response {
	name, err := a.unit(r)
	if err != nil {
		return Response{Error: err.Error()}
	}
	st, err := a.s.UnitStatus(name)
	if err != nil {
		return Response{Error: fmt.Sprintf("%s: %v", name, err)}
	}
	return Response{OK: true, Status: &st}
}

// UnitLogs tails one managed unit's journal.
func (a Actions) UnitLogs(r Request) Response {
	name, err := a.unit(r)
	if err != nil {
		return Response{Error: err.Error()}
	}
	lines := r.SpecLines()
	if lines == 0 {
		lines = defaultLogLines
	}
	if lines < 0 || lines > maxLogLines {
		return Response{Error: fmt.Sprintf("lines %d: 0-%d (0 = default %d)", lines, maxLogLines, defaultLogLines)}
	}
	log, err := a.s.UnitLogs(name, lines)
	if err != nil {
		return Response{Error: fmt.Sprintf("%s: %v", name, err)}
	}
	return Response{OK: true, Logs: log}
}

// unit resolves the request's validated slug to its servanago-<slug>.service name.
func (a Actions) unit(r Request) (string, error) {
	slug, err := r.Slug()
	if err != nil {
		return "", err
	}
	return unitName(slug)
}
