package helper

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	osuser "os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/servanago/servanago/internal/runtimes"
)

// phpreal.go: the real implementations of the PHP build seam methods (php.go decides what to ask for; these only do it).

func (RealSeam) Missing(tools []string) []string {
	var out []string
	for _, t := range tools {
		if _, err := exec.LookPath(t); err != nil {
			out = append(out, t)
		}
	}
	return out
}

// FreeBytes measures the filesystem that holds path, or its nearest existing parent (the build directory may not exist yet).
func (RealSeam) FreeBytes(path string) (uint64, error) {
	for {
		var st syscall.Statfs_t
		err := syscall.Statfs(path, &st)
		if err == nil {
			return st.Bavail * uint64(st.Bsize), nil
		}
		parent := filepath.Dir(path)
		if parent == path || !errors.Is(err, os.ErrNotExist) {
			return 0, err
		}
		path = parent
	}
}

// JobDir recreates dir and dir/root empty and owned by user, so the unprivileged job can write there.
func (RealSeam) JobDir(dir, user string) error {
	u, err := osuser.Lookup(user)
	if err != nil {
		return err
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	for _, d := range []string{dir, dir + "/root"} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
		if err := os.Chown(d, uid, gid); err != nil {
			return err
		}
	}
	return nil
}

func (RealSeam) ReadDir(path string) ([]string, error) {
	es, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(es))
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out, nil
}

func (RealSeam) RemoveAll(path string) error { return os.RemoveAll(path) }
func (RealSeam) Rename(oldPath, newPath string) error {
	return os.Rename(oldPath, newPath)
}

func (RealSeam) InstallTree(src, dst string) error {
	return copyTree(src, dst, runtimes.PHPRoot, func(p string) error { return os.Lchown(p, 0, 0) })
}

// Exec runs a binary the action chose (a path under /opt/servanago/php) with fixed arguments.
func (RealSeam) Exec(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}

// Fetch is an https GET of a fixed URL with a size cap.
func (RealSeam) Fetch(url string, limit int64) ([]byte, error) {
	if !strings.HasPrefix(url, "https://") {
		return nil, fmt.Errorf("%s: only https is allowed", url)
	}
	client := &http.Client{Timeout: 2 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s: larger than %d bytes", url, limit)
	}
	return b, nil
}

// UserOK accepts an existing user with a login shell and a regular uid: system accounts (below 1000, nobody) never get a default.
func (RealSeam) UserOK(name string) error {
	u, err := osuser.Lookup(name)
	if err != nil {
		return err
	}
	if uid, err := strconv.Atoi(u.Uid); err != nil || uid < 1000 || uid >= 65534 {
		return fmt.Errorf("uid %s is not a regular login user", u.Uid)
	}
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		p := strings.Split(sc.Text(), ":")
		if len(p) == 7 && p[0] == name {
			if sh := filepath.Base(p[6]); sh == "nologin" || sh == "false" || p[6] == "" {
				return fmt.Errorf("it has no login shell (%s)", p[6])
			}
			return nil
		}
	}
	return fmt.Errorf("not found in /etc/passwd")
}

func (RealSeam) Exe() (string, error) { return os.Executable() }
