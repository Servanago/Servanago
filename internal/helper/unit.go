package helper

import (
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
)

// systemdUnitDir is where managed units live; the file name is always servanago-<slug>.service.
const systemdUnitDir = "/etc/systemd/system"

// Seam is the systemd/filesystem the helper talks to. The running helper uses the real seam;
// tests use a fake, so nothing here ever touches a real host in tests.
type Seam interface {
	Lstat(path string) (fs.FileInfo, error)
	ReadFile(path string) ([]byte, error)
	WriteFile(path string, data []byte, perm fs.FileMode) error
	Remove(path string) error
	VerifyUnit(path string) error // systemd-analyze verify
	DaemonReload() error          // systemctl daemon-reload
	Enable(name string) error     // systemctl enable
	UnitStatus(name string) (StatusData, error)
	UnitLogs(name string, lines int) ([]string, error)
}

type Actions struct{ s Seam }

func NewActions(s Seam) Actions { return Actions{s} }

// siteUnitTemplate is the only unit body the helper ever writes: the caller supplies a validated
// slug, never content. The body is a placeholder shell until the Node provider (M6) defines the
// real ExecStart and user; the write-verify-reload-enable path is what this action owns.
func siteUnitTemplate(slug string) []byte {
	return []byte(fmt.Sprintf(`[Unit]
Description=ServanaGo site %s
After=network.target

[Service]
# ponytail: placeholder body; the Node provider (M6) defines the real ExecStart and user.
Type=oneshot
ExecStart=/bin/true

[Install]
WantedBy=multi-user.target
`, slug))
}

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

// UnitInstall writes servanago-<slug>.service from the template, verifies it, reloads systemd
// and enables the unit; a failed verify restores the previous content or removes the new file
// so the host is left exactly as it was.
func (a Actions) UnitInstall(r Request) Response {
	slug, err := r.Slug()
	if err != nil {
		return Response{Error: err.Error()}
	}
	name, err := unitName(slug)
	if err != nil {
		return Response{Error: err.Error()}
	}
	path := filepath.Join(systemdUnitDir, name)
	// A symlink at the unit path would route the write outside the directory: refuse it.
	if fi, err := a.s.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return Response{Error: name + " exists as a symlink; refusing to write"}
	}
	var (
		prev    []byte
		hasPrev bool
	)
	if fi, err := a.s.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink == 0 {
		if b, err := a.s.ReadFile(path); err == nil {
			prev, hasPrev = b, true
		}
	}
	if err := a.s.WriteFile(path, siteUnitTemplate(slug), 0o644); err != nil {
		return Response{Error: fmt.Sprintf("write %s: %v", name, err)}
	}
	if err := a.s.VerifyUnit(path); err != nil {
		// Leave the host exactly as it was: restore the previous unit or remove the new file.
		if hasPrev {
			if werr := a.s.WriteFile(path, prev, 0o644); werr != nil {
				slog.Error("helper restore previous unit", "path", path, "error", werr)
			}
		} else if rerr := a.s.Remove(path); rerr != nil {
			slog.Error("helper remove failed unit", "path", path, "error", rerr)
		}
		return Response{Error: fmt.Sprintf("systemd-analyze verify failed: %v", err)}
	}
	if err := a.s.DaemonReload(); err != nil {
		return Response{Error: fmt.Sprintf("systemctl daemon-reload: %v", err)}
	}
	if err := a.s.Enable(name); err != nil {
		return Response{Error: fmt.Sprintf("systemctl enable %s: %v", name, err)}
	}
	return Response{OK: true}
}
