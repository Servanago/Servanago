package helper

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// user.go: sites that run as a named user (a hostname such as luckyedward.com) instead of the generated
// sg-<slug>. The user is either created here (a locked login user) or already exists and passes UserInfo.
// Nothing in a user's files is ever chowned except the directories this file creates in a home it just made.

var (
	namedUserRE = regexp.MustCompile(`^[a-z]([a-z0-9._-]{0,30}[a-z0-9])?$`)
	groupRE     = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)
	publicSegRE = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*$`) // no leading dot: .git and .. never match
)

// ValidateUser checks a named site user. "sg-" is the generated users' prefix, so it is reserved.
func ValidateUser(name string) error {
	if !namedUserRE.MatchString(name) {
		return fmt.Errorf("user %q: must start with a letter and use only a-z, 0-9, '.', '_' or '-' (at most 32 characters, ending in a letter or digit)", name)
	}
	if name == "root" || name == "servanago" || strings.HasPrefix(name, "sg-") {
		return fmt.Errorf("user %q is reserved", name)
	}
	return nil
}

// DeriveUser is the default user name for a site: its first hostname cut to the 32 characters a Linux user name
// may have, trailing dots and dashes trimmed. It fails when that is not a valid name (a hostname starting with a
// digit), so the admin types one.
func DeriveUser(host string) (string, error) {
	h := strings.ToLower(host)
	if len(h) > 32 {
		h = h[:32]
	}
	h = strings.TrimRight(h, ".-_")
	if err := ValidateUser(h); err != nil {
		return "", err
	}
	return h, nil
}

// ValidatePublic checks the served folder inside a site folder: a clean relative path whose parts do not start with a dot.
func ValidatePublic(p string) error {
	if p == "" || len(p) > 100 {
		return fmt.Errorf("public folder %q: 1-100 characters", p)
	}
	for _, seg := range strings.Split(p, "/") {
		if !publicSegRE.MatchString(seg) {
			return fmt.Errorf("public folder %q: a relative path such as public or web/html, no empty parts, no part starting with a dot", p)
		}
	}
	return nil
}

// validateNewHome: a home ServanaGo may create is one directory directly under /home or /srv.
func validateNewHome(home string) error {
	if home == "" {
		return errors.New("home: required to create a user")
	}
	if err := validateRoot(home, false); err != nil {
		return fmt.Errorf("home: %w", err)
	}
	for _, base := range []string{"/home/", "/srv/"} {
		if rest, ok := strings.CutPrefix(home, base); ok && rest != "" && !strings.Contains(rest, "/") {
			return nil
		}
	}
	return fmt.Errorf("home %q must be one directory directly under /home or /srv", home)
}

// inside resolves path and home and returns the resolved path when it is strictly inside the home.
func (a Actions) inside(path, home string) (string, error) {
	rp, err := a.s.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("folder %s: %w", path, err)
	}
	rh, err := a.s.EvalSymlinks(home)
	if err != nil {
		return "", fmt.Errorf("home %s: %w", home, err)
	}
	if !strings.HasPrefix(rp, rh+"/") {
		return "", fmt.Errorf("folder %s must be inside the user's home %s", path, home)
	}
	return rp, nil
}

// UserCheck reports whether a named user exists and may run a site; an unknown name is not an error (it can be created).
func (a Actions) UserCheck(r Request) Response {
	if err := ValidateUser(r.Vals.User); err != nil {
		return Response{Error: err.Error()}
	}
	info, err := a.s.UserInfo(r.Vals.User)
	if err != nil {
		return Response{Error: fmt.Sprintf("user %s: %v", r.Vals.User, err)}
	}
	return Response{OK: true, User: &info}
}

// userAddNamed creates the named user, or checks that an existing one may run the site and owns its folder.
func (a Actions) userAddNamed(s Spec) Response {
	if err := ValidateUser(s.User); err != nil {
		return Response{Error: err.Error()}
	}
	if err := validateRoot(s.Root, false); err != nil {
		return Response{Error: err.Error()}
	}
	if s.Public != "" {
		if err := ValidatePublic(s.Public); err != nil {
			return Response{Error: err.Error()}
		}
	}
	info, err := a.s.UserInfo(s.User)
	if err != nil {
		return Response{Error: fmt.Sprintf("user %s: %v", s.User, err)}
	}
	if info.Exists {
		if _, err := a.inside(s.Root, info.Home); err != nil {
			return Response{Error: err.Error()}
		}
		return Response{OK: true, User: &info}
	}
	if err := validateNewHome(s.Home); err != nil {
		return Response{Error: err.Error()}
	}
	if !strings.HasPrefix(s.Root, s.Home+"/") {
		return Response{Error: fmt.Sprintf("folder %s must be inside the user's home %s", s.Root, s.Home)}
	}
	dirs := []string{s.Root}
	if s.Public != "" {
		dirs = append(dirs, s.Root+"/"+s.Public)
	}
	if err := a.s.UserCreate(s.User, s.Home, s.Shell, dirs); err != nil {
		return Response{Error: fmt.Sprintf("create user %s: %v", s.User, err)}
	}
	return Response{OK: true, User: &UserData{Exists: true, Home: s.Home, Group: s.User, Login: s.Shell}}
}

// siteIdentity is who a site's unit runs as and what it may touch. Root and RW are resolved paths for a named user.
type siteIdentity struct {
	User, Group string
	Root        string // the site folder: the unit's working directory
	RW          string // space-separated ReadWritePaths
	Web         string // the served folder: Root, or Root/Public
}

// identity validates the user and folders of a unit-install spec. Called before anything is written.
func (a Actions) identity(s Spec) (siteIdentity, error) {
	id := siteIdentity{User: "sg-" + s.Slug, Group: "sg-" + s.Slug, Root: s.Root, RW: s.Root, Web: s.Root}
	if s.Public != "" {
		switch s.Kind {
		case "php", "frankenphp", "static":
		default:
			return id, errors.New("public folder: only php, frankenphp and static sites have one")
		}
		if err := ValidatePublic(s.Public); err != nil {
			return id, err
		}
	}
	if s.User != "" {
		if err := ValidateUser(s.User); err != nil {
			return id, err
		}
		info, err := a.s.UserInfo(s.User)
		if err != nil {
			return id, fmt.Errorf("user %s: %w", s.User, err)
		}
		if !info.Exists {
			return id, fmt.Errorf("user %s does not exist", s.User)
		}
		if err := validateRoot(info.Home, false); err != nil {
			return id, fmt.Errorf("home of %s: %w", s.User, err)
		}
		if !groupRE.MatchString(info.Group) {
			return id, fmt.Errorf("group %q of %s is not a plain group name", info.Group, s.User)
		}
		rr, err := a.inside(s.Root, info.Home)
		if err != nil {
			return id, err
		}
		if err := validateRoot(rr, false); err != nil {
			return id, err
		}
		id.User, id.Group, id.Root, id.RW, id.Web = s.User, info.Group, rr, rr, rr
		for _, d := range []string{"/tmp", "/logs"} { // writable when they are real directories, never through a symlink
			if fi, err := a.s.Lstat(info.Home + d); err == nil && fi.IsDir() {
				id.RW += " " + info.Home + d
			}
		}
	}
	if s.Public != "" {
		w := id.Root + "/" + s.Public
		if fi, err := a.s.Lstat(w); err != nil || !fi.IsDir() {
			return id, fmt.Errorf("public folder %s does not exist", w)
		}
		rroot, err := a.s.EvalSymlinks(id.Root)
		if err != nil {
			return id, fmt.Errorf("folder %s: %w", id.Root, err)
		}
		rw, err := a.s.EvalSymlinks(w)
		if err != nil || !strings.HasPrefix(rw, rroot+"/") {
			return id, fmt.Errorf("public folder %s must stay inside the site folder", w)
		}
		if err := validateRoot(rw, false); err != nil {
			return id, err
		}
		id.Web = rw
	}
	return id, nil
}
