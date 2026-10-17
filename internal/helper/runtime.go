package helper

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// runtime.go: privileged work the runtime site kinds need — a dedicated system user,
// per-site systemd units, php-fpm pools, and start/stop control. Unit names and file
// paths are built only from validated fields; unit and pool content always comes from
// the templates below, never from callers.

// nodeUnitTemplate is the sandboxed unit for a Node.js site. The start command is the
// admin's own text; systemd runs it as the unprivileged site user, never root.
func nodeUnitTemplate(user, root, start string) []byte {
	esc := systemdEscape(strings.ReplaceAll(start, "'", `'\''`))
	return []byte(fmt.Sprintf(`[Unit]
Description=ServanaGo site %s (Node.js)
After=network.target

[Service]
User=%s
Group=%s
WorkingDirectory=%s
ExecStart=/bin/sh -c '%s'
Restart=on-failure
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=%s

[Install]
WantedBy=multi-user.target
`, user, user, user, root, esc, root))
}

// poolTemplate is the per-site php-fpm pool; the socket is what Caddy dials.
func poolTemplate(slug, user string) []byte {
	return []byte(fmt.Sprintf(`; per-site pool for ServanaGo site %s; written by the helper
[global]
daemonize=no
error_log=/proc/self/fd/2

[servanago-%s]
user=%s
group=%s
listen=/run/servanago/%s.sock
listen.owner=servanago
listen.group=servanago
listen.mode=0660
pm=dynamic
pm.max_children=10
pm.start_servers=2
pm.min_spare_servers=1
pm.max_spare_servers=3
catch_workers_output=yes
`, slug, slug, user, user, slug))
}

// phpUnitTemplate runs exactly one pool — its own php-fpm master per site.
//
// There is deliberately no User= here: php-fpm's master starts as root, creates the socket in the
// root-owned /run/servanago, and drops its workers to the site user through the pool's user=. A master
// started as the site user could not create the socket. The runtime directory is declared (and preserved)
// here as well as in the helper unit, so a helper restart does not delete every site socket.
func phpUnitTemplate(user, fpmBin, confPath, root string) []byte {
	return []byte(fmt.Sprintf(`[Unit]
Description=ServanaGo site %s (php-fpm %s)
After=network.target

[Service]
Type=simple
ExecStart=%s -F -y %s
RuntimeDirectory=servanago
RuntimeDirectoryMode=0755
RuntimeDirectoryPreserve=yes
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/run/servanago %s

[Install]
WantedBy=multi-user.target
`, user, filepath.Base(fpmBin), fpmBin, confPath, root))
}

var fpmBinRE = regexp.MustCompile(`^(?:/usr/(?:sbin|bin)|/usr/local/bin)/php-fpm[0-9]+(?:\.[0-9]+)*$`)

// UserAdd creates the sg-<slug> system user (a no-op when it exists). The optional root becomes its
// home directory; nothing in it is ever chowned.
func (a Actions) UserAdd(r Request) Response {
	slug, err := r.Slug()
	if err != nil {
		return Response{Error: err.Error()}
	}
	if err := validateRoot(r.Vals.Root, true); err != nil {
		return Response{Error: err.Error()}
	}
	user := "sg-" + slug
	if err := a.s.UserAdd(user, r.Vals.Root); err != nil {
		return Response{Error: fmt.Sprintf("useradd %s: %v", user, err)}
	}
	return Response{OK: true}
}

// UserRemove deletes the sg-<slug> user; the site's files stay where they are.
func (a Actions) UserRemove(r Request) Response {
	slug, err := r.Slug()
	if err != nil {
		return Response{Error: err.Error()}
	}
	if err := a.s.UserRemove("sg-" + slug); err != nil {
		return Response{Error: fmt.Sprintf("userdel sg-%s: %v", slug, err)}
	}
	return Response{OK: true}
}

// validateKindSpec checks a unit-install spec for kind node or php.
func validateKindSpec(s Spec) error {
	switch s.Kind {
	case "node":
		if err := validateRoot(s.Root, false); err != nil {
			return err
		}
		if s.Port < 1024 || s.Port > 65535 {
			return fmt.Errorf("port %d: a node site uses 1024-65535", s.Port)
		}
		if err := validateStart(s.Start); err != nil {
			return err
		}
	case "php":
		if err := validateRoot(s.Root, false); err != nil {
			return err
		}
		if !fpmBinRE.MatchString(s.FPMBin) {
			return fmt.Errorf("php-fpm binary %q must be a detected /usr/{sbin,bin,local/bin}/php-fpm<version>", s.FPMBin)
		}
		if got := strings.TrimPrefix(filepath.Base(s.FPMBin), "php-fpm"); got != s.FPMVersion {
			return fmt.Errorf("fpm version %q does not match the binary %q", s.FPMVersion, s.FPMBin)
		}
	default:
		return fmt.Errorf("kind %q must be node or php", s.Kind)
	}
	return nil
}

// validateRoot: absolute, bounded, no NUL. Optional=true accepts "" (absent).
func validateRoot(root string, optional bool) error {
	if root == "" {
		if optional {
			return nil
		}
		return fmt.Errorf("root: required")
	}
	if root[0] != '/' {
		return fmt.Errorf("root %q must be an absolute path", root)
	}
	if len(root) > 4096 || root != filepath.Clean(root) {
		return fmt.Errorf("root %q must be a clean absolute path (no .., //, ./ or trailing slash)", root)
	}
	// The root is written into unit text (WorkingDirectory=, ReadWritePaths=), where whitespace splits a
	// path list, a line break starts a new directive, and %, $ and \ are expanded by systemd.
	if strings.IndexFunc(root, func(r rune) bool {
		return r < 0x20 || r == 0x7f || r == ' ' || r == '%' || r == '$' || r == '\\' || r == '"' || r == '\''
	}) >= 0 {
		return fmt.Errorf("root %q must not contain spaces, control characters or any of: percent, dollar, backslash, quotes", root)
	}
	return nil
}

// ValidateRoot and ValidateStart are the helper's own rules, exported so the web form refuses a bad
// value before it is saved instead of after.
func ValidateRoot(root string) error { return validateRoot(root, false) }
func ValidateStart(cmd string) error { return validateStart(cmd) }

// validateStart bounds the admin's start command. It is written inside a quoted ExecStart= line, so a
// line break would begin a new unit directive; tabs are fine.
func validateStart(start string) error {
	if start == "" || len(start) > 2000 {
		return fmt.Errorf("start command: 1-2000 characters")
	}
	if strings.IndexFunc(start, func(r rune) bool { return (r < 0x20 && r != '\t') || r == 0x7f }) >= 0 {
		return fmt.Errorf("start command: no line breaks or control characters")
	}
	return nil
}

// systemdEscape keeps text literal for systemd: it expands % specifiers and $VAR in ExecStart, even
// inside a shell -c string, and the command is meant for sh, not for systemd.
func systemdEscape(s string) string {
	return strings.NewReplacer("%", "%%", "$", "$$").Replace(s)
}

// unitTemplates render the unit (and, for php, the pool) from validated fields only.
func (a Actions) unitFor(s Spec) (unitPath string, content []byte) {
	user := "sg-" + s.Slug
	if s.Kind == "node" {
		return filepath.Join(systemdUnitDir, "servanago-"+s.Slug+".service"), nodeUnitTemplate(user, s.Root, s.Start)
	}
	conf := filepath.Join("/etc/servanago/fpm", s.Slug+".conf")
	return filepath.Join(systemdUnitDir, "servanago-"+s.Slug+".service"), phpUnitTemplate(user, s.FPMBin, conf, s.Root)
}

// UnitInstall writes the template unit (plus the pool for php), verifies each artifact
// the way the apply path demands (systemd-analyze verify; php-fpm -t), then reloads and
// enables the unit. Each failed verification leaves the host exactly as it was.
func (a Actions) UnitInstall(r Request) Response {
	slug, err := r.Slug()
	if err != nil {
		return Response{Error: err.Error()}
	}
	if err := validateKindSpec(r.Vals); err != nil {
		return Response{Error: err.Error()}
	}
	s := r.Vals

	// The pool exists before the unit so both verify against their target state.
	if s.Kind == "php" {
		conf := "/etc/servanago/fpm/" + slug + ".conf"
		if err := a.s.MkdirAll("/etc/servanago/fpm", 0o755); err != nil {
			return Response{Error: fmt.Sprintf("create fpm config dir: %v", err)}
		}
		if resp := a.put(conf, poolTemplate(slug, "sg-"+slug), func(path string) error {
			return a.s.FPMTest(s.FPMBin, path)
		}); !resp.OK {
			return resp
		}
	}
	unitPath, content := a.unitFor(s)
	if resp := a.put(unitPath, content, a.s.VerifyUnit); !resp.OK {
		return resp
	}
	name := "servanago-" + slug + ".service"
	if err := a.s.DaemonReload(); err != nil {
		return Response{Error: fmt.Sprintf("systemctl daemon-reload: %v", err)}
	}
	if err := a.s.Enable(name); err != nil {
		return Response{Error: fmt.Sprintf("systemctl enable %s: %v", name, err)}
	}
	return Response{OK: true}
}

// UnitRemove disables the unit and removes the unit and (for php) the pool file; both removals
// tolerate absent files, and the reload makes systemd forget the unit.
func (a Actions) UnitRemove(r Request) Response {
	slug, err := r.Slug()
	if err != nil {
		return Response{Error: err.Error()}
	}
	name := "servanago-" + slug + ".service"
	_ = a.s.DisableUnit(name)
	_ = a.s.Remove(filepath.Join(systemdUnitDir, name))
	_ = a.s.Remove("/etc/servanago/fpm/" + slug + ".conf")
	if err := a.s.DaemonReload(); err != nil {
		return Response{Error: fmt.Sprintf("systemctl daemon-reload: %v", err)}
	}
	return Response{OK: true}
}

// UnitStart starts the managed unit.
func (a Actions) UnitStart(r Request) Response {
	name, err := a.unit(r)
	if err != nil {
		return Response{Error: err.Error()}
	}
	if err := a.s.StartUnit(name); err != nil {
		return Response{Error: fmt.Sprintf("systemctl start %s: %v", name, err)}
	}
	return Response{OK: true}
}

// UnitStop stops the managed unit.
func (a Actions) UnitStop(r Request) Response {
	name, err := a.unit(r)
	if err != nil {
		return Response{Error: err.Error()}
	}
	if err := a.s.StopUnit(name); err != nil {
		return Response{Error: fmt.Sprintf("systemctl stop %s: %v", name, err)}
	}
	return Response{OK: true}
}

// put is write-from-template with the standard protections: refuse symlink targets, keep the
// previous content, verify, and roll back (restore or remove) when verification fails.
func (a Actions) put(path string, content []byte, verify func(path string) error) Response {
	if fi, err := a.s.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return Response{Error: filepath.Base(path) + " exists as a symlink; refusing to write"}
	}
	prev, hasPrev := []byte(nil), false
	if fi, err := a.s.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink == 0 {
		if b, err := a.s.ReadFile(path); err == nil {
			prev, hasPrev = b, true
		}
	}
	name := filepath.Base(path)
	if err := a.s.WriteFile(path, content, 0o644); err != nil {
		return Response{Error: fmt.Sprintf("write %s: %v", name, err)}
	}
	if err := verify(path); err != nil {
		if hasPrev {
			a.s.WriteFile(path, prev, 0o644)
		} else {
			a.s.Remove(path)
		}
		return Response{Error: fmt.Sprintf("%s failed to verify: %v", name, err)}
	}
	return Response{OK: true}
}
