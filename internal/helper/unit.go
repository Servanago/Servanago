package helper

import (
	"fmt"
	"io/fs"
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
		if hasPrev {
			a.s.WriteFile(path, prev, 0o644)
		} else {
			a.s.Remove(path)
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
