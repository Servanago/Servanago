package helper

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	osuser "os/user"
	"strconv"
	"strings"
	"syscall"
)

// RealSeam is what the running helper uses: os calls plus the systemctl tools. Tests never
// touch this; they use fakeSeam. Every command is a fixed systemd incantation with a
// helper-derived argument only.
type RealSeam struct{}

func (RealSeam) Lstat(path string) (fs.FileInfo, error) { return os.Lstat(path) }
func (RealSeam) ReadFile(path string) ([]byte, error)   { return os.ReadFile(path) }
func (RealSeam) WriteFile(path string, data []byte, perm fs.FileMode) error {
	return os.WriteFile(path, data, perm)
}
func (RealSeam) Remove(path string) error { return os.Remove(path) }
func (RealSeam) MkdirAll(path string, perm fs.FileMode) error {
	return os.MkdirAll(path, perm)
}

// UserAdd creates the system user with the site folder as its home. It is idempotent (editing a site
// calls it again) and never touches the folder: ServanaGo does not change ownership or permissions
// of the admin's files.
func (RealSeam) UserAdd(user, home string) error {
	if _, err := osuser.Lookup(user); err == nil {
		return nil
	}
	if home == "" {
		home = "/nonexistent"
	}
	out, err := exec.Command("useradd", "--system", "--user-group", "--no-create-home",
		"--home-dir", home, "--shell", "/usr/sbin/nologin", user).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, firstLines(out))
	}
	return nil
}
func (RealSeam) UserRemove(user string) error {
	out, err := exec.Command("userdel", user).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, firstLines(out))
	}
	return nil
}
func (RealSeam) FPMTest(bin, conf string) error {
	out, err := exec.Command(bin, "-t", "-y", conf).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, firstLines(out))
	}
	return nil
}

// CheckBinary refuses a binary the site user (or anyone but root) could have replaced: the unit runs it.
func (RealSeam) CheckBinary(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	switch {
	case !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0:
		return fmt.Errorf("%s is not an executable file", path)
	case !ok || st.Uid != 0 || fi.Mode().Perm()&0o022 != 0:
		return fmt.Errorf("%s must be owned by root and not writable by group or others", path)
	}
	return nil
}
func (RealSeam) StartUnit(name string) error {
	out, err := exec.Command("systemctl", "start", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, firstLines(out))
	}
	return nil
}
func (RealSeam) StopUnit(name string) error {
	out, err := exec.Command("systemctl", "stop", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, firstLines(out))
	}
	return nil
}
func (RealSeam) DisableUnit(name string) error {
	out, err := exec.Command("systemctl", "disable", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, firstLines(out))
	}
	return nil
}

func (RealSeam) VerifyUnit(path string) error {
	out, err := exec.Command("systemd-analyze", "verify", path).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, firstLines(out))
	}
	return nil
}
func (RealSeam) DaemonReload() error {
	out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, firstLines(out))
	}
	return nil
}
func (RealSeam) Enable(name string) error {
	out, err := exec.Command("systemctl", "enable", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, firstLines(out))
	}
	return nil
}

func (RealSeam) UnitStatus(name string) (StatusData, error) {
	out, err := exec.Command("systemctl", "show", "-p", "ActiveState", "-p", "SubState", "-p", "ExecMainPID", name).Output()
	if err != nil {
		return StatusData{}, fmt.Errorf("%w: %s", err, firstLines(out))
	}
	return parseShow(out)
}

// parseShow reads `systemctl show` output by key: systemd prints properties in its own order, not the
// order of -p. A PID of 0 (no main process) is reported as empty.
func parseShow(out []byte) (StatusData, error) {
	var st StatusData
	for _, line := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "ActiveState":
			st.ActiveState = v
		case "SubState":
			st.SubState = v
		case "ExecMainPID":
			if v != "0" {
				st.PID = v
			}
		}
	}
	if st.ActiveState == "" {
		return StatusData{}, fmt.Errorf("systemctl show: no ActiveState in %q", firstLines(out))
	}
	return st, nil
}

func (RealSeam) UnitLogs(name string, lines int) ([]string, error) {
	out, err := exec.Command("journalctl", "-u", name, "-n", strconv.Itoa(lines), "--no-pager").Output()
	if err != nil {
		return nil, fmt.Errorf("%w: %s", err, firstLines(out))
	}
	return strings.Split(strings.TrimRight(string(out), "\n"), "\n"), nil
}

// firstLines keeps command diagnostics readable in journal error entries.
func firstLines(out []byte) string {
	s := strings.TrimSpace(string(out))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	if len(s) > 200 {
		return s[:200]
	}
	return s
}
