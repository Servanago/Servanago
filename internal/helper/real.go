package helper

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"strings"
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

func (RealSeam) VerifyUnit(path string) error {
	out, err := exec.Command("systemd-analyze", "verify", path).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, firstLines(out))
	}
	return nil
}
func (RealSeam) DaemonReload() error {
	out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, firstLines(out))
	}
	return nil
}
func (RealSeam) Enable(name string) error {
	out, err := exec.Command("systemctl", "enable", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, firstLines(out))
	}
	return nil
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
