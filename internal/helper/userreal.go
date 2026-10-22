package helper

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	osuser "os/user"
	"path/filepath"
	"strconv"
	"strings"
)

// userreal.go: the real implementations of the named-user seam methods (user.go decides what to ask for).

// privilegedGroups are groups whose members a site must never run as: each one is root, or close to it.
var privilegedGroups = []string{"root", "sudo", "wheel", "admin", "adm", "docker", "lxd"}

// UserInfo reports a named user. An unknown name is Exists=false, not an error; a user that exists but may not run
// a site (a system account, or a member of a privileged group) is an error.
func (RealSeam) UserInfo(name string) (UserData, error) {
	u, err := osuser.Lookup(name)
	var unknown osuser.UnknownUserError
	if errors.As(err, &unknown) {
		return UserData{}, nil
	}
	if err != nil {
		return UserData{}, err
	}
	if uid, err := strconv.Atoi(u.Uid); err != nil || uid < 1000 || uid >= 65534 {
		return UserData{}, fmt.Errorf("uid %s is not a regular user", u.Uid)
	}
	g, err := osuser.LookupGroupId(u.Gid)
	if err != nil {
		return UserData{}, err
	}
	if grp, err := privilegedMembership(name, u.Gid); err != nil {
		return UserData{}, err
	} else if grp != "" {
		return UserData{}, fmt.Errorf("it is in the %s group, which is too privileged to run a site", grp)
	}
	return UserData{Exists: true, Home: u.HomeDir, Group: g.Name, Login: RealSeam{}.UserOK(name) == nil}, nil
}

// privilegedMembership returns the first privileged group the user belongs to (as a member or by primary gid), or "".
func privilegedMembership(name, gid string) (string, error) {
	f, err := os.Open("/etc/group")
	if err != nil {
		return "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		p := strings.Split(sc.Text(), ":")
		if len(p) < 4 {
			continue
		}
		for _, bad := range privilegedGroups {
			if p[0] != bad {
				continue
			}
			if p[2] == gid {
				return bad, nil
			}
			for _, m := range strings.Split(p[3], ",") {
				if m == name {
					return bad, nil
				}
			}
		}
	}
	return "", sc.Err()
}

// UserCreate adds a login user whose password is locked (no password login, no ssh keys until the admin adds
// them), makes its home 0711 so Caddy can reach the public folder, and creates dirs owned by the user.
func (RealSeam) UserCreate(name, home string, login bool, dirs []string) error {
	if _, err := os.Lstat(home); err == nil {
		return fmt.Errorf("%s already exists", home)
	}
	shell := "/usr/sbin/nologin"
	if login {
		shell = "/bin/bash"
	}
	if out, err := exec.Command("useradd", "--user-group", "--create-home", "--home-dir", home, "--shell", shell, name).CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, firstLines(out))
	}
	u, err := osuser.Lookup(name)
	if err != nil {
		return err
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	if err := os.Chmod(home, 0o711); err != nil {
		return err
	}
	for _, d := range dirs { // each path from just below the home down, so no parent is left root-owned
		rel, err := filepath.Rel(home, d)
		if err != nil || strings.HasPrefix(rel, "..") {
			return fmt.Errorf("%s is not inside %s", d, home)
		}
		cur := home
		for _, part := range strings.Split(rel, "/") {
			cur = filepath.Join(cur, part)
			if err := os.Mkdir(cur, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
				return err
			}
			if err := os.Lchown(cur, uid, gid); err != nil {
				return err
			}
		}
	}
	return nil
}

func (RealSeam) EvalSymlinks(path string) (string, error) { return filepath.EvalSymlinks(path) }
