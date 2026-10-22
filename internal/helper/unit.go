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
	FPMTest(bin, conf, ini string) error // ini "" = the binary's own php.ini
	CheckBinary(path string) error       // a regular, executable file owned by root that no one else can write
	UnitStatus(name string) (StatusData, error)
	UnitLogs(name string, lines int) ([]string, error)

	// PHP builds (php.go). Every argument is derived or validated by the action, never taken from a caller.
	Missing(tools []string) []string                  // tools not found on PATH
	FreeBytes(path string) (uint64, error)            // free space on the filesystem holding path (or its nearest existing parent)
	JobDir(dir, user string) error                    // recreate dir (and dir/root) empty, owned by user
	ReadDir(path string) ([]string, error)            // entry names
	RemoveAll(path string) error                      // callers confine path under a managed root first
	Rename(oldPath, newPath string) error             // atomic move into place
	InstallTree(src, dst string) error                // copy a build tree root-owned: regular files, dirs and contained symlinks only; dst must not exist
	Exec(name string, args ...string) (string, error) // run a binary the helper chose and return its combined output
	Fetch(url string, limit int64) ([]byte, error)    // https GET with a size cap
	UserOK(name string) error                         // an existing, non-system user with a login shell
	Exe() (string, error)                             // the helper's own binary, which the job units run

	// Named site users (user.go).
	UserInfo(name string) (UserData, error)                        // Exists=false for an unknown name; an error for an existing user a site may not run as
	UserCreate(name, home string, login bool, dirs []string) error // a locked login user whose home must not exist yet; dirs are created inside it, owned by the user
	EvalSymlinks(path string) (string, error)
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
	unit := name
	if sock, _, ok := a.socketUnit(name); ok { // cgi: the socket is what stays up ("active (listening)")
		unit = sock
	}
	st, err := a.s.UnitStatus(unit)
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
