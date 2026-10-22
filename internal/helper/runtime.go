package helper

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/servanago/servanago/internal/runtimes"
)

// runtime.go: privileged work the runtime site kinds need — a dedicated system user,
// per-site systemd units, php-fpm pools, and start/stop control. Unit names and file
// paths are built only from validated fields; unit and pool content always comes from
// the templates below, never from callers.

// nodeUnitTemplate is the sandboxed unit for a Node.js site. The start command is the
// admin's own text; systemd runs it as the unprivileged site user, never root.
func nodeUnitTemplate(id siteIdentity, start string) []byte {
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
`, id.User, id.User, id.Group, id.Root, esc, id.RW))
}

// frankenUnitTemplate runs one FrankenPHP php-server per site, as the unprivileged site user, on a loopback
// port Caddy proxies to. The site user's home is the webroot, so Caddy's per-user data and config dirs are
// pointed at the unit's private /tmp instead of letting FrankenPHP create .local and .config inside it.
func frankenUnitTemplate(id siteIdentity, bin string, port int) []byte {
	return []byte(fmt.Sprintf(`[Unit]
Description=ServanaGo site %s (FrankenPHP)
After=network.target

[Service]
User=%s
Group=%s
WorkingDirectory=%s
Environment=XDG_DATA_HOME=/tmp/xdg-data XDG_CONFIG_HOME=/tmp/xdg-config
ExecStart=%s php-server --root %s --listen 127.0.0.1:%d
Restart=on-failure
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=%s

[Install]
WantedBy=multi-user.target
`, id.User, id.User, id.Group, id.Root, bin, id.Web, port, id.RW))
}

// cgiServiceTemplate runs fcgiwrap as the site user. It is socket-activated: systemd (root) creates and owns the
// socket below, so the unprivileged service never needs to write into /run/servanago.
func cgiServiceTemplate(slug string, id siteIdentity, bin string) []byte {
	return []byte(fmt.Sprintf(`[Unit]
Description=ServanaGo site %s (CGI via fcgiwrap)
Requires=servanago-%s.socket
After=servanago-%s.socket

[Service]
User=%s
Group=%s
WorkingDirectory=%s
ExecStart=%s
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=%s
`, id.User, slug, slug, id.User, id.Group, id.Root, bin, id.RW))
}

// staticServiceTemplate serves a static folder as the site's user: `servanago serve-static` takes the socket
// systemd hands it (the same socket unit as cgi) and only reads the folder.
func staticServiceTemplate(slug string, id siteIdentity, exe string) []byte {
	return []byte(fmt.Sprintf(`[Unit]
Description=ServanaGo site %s (static files)
Requires=servanago-%s.socket
After=servanago-%s.socket

[Service]
User=%s
Group=%s
WorkingDirectory=%s
ExecStart=%s serve-static --root %s
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=read-only
`, id.User, slug, slug, id.User, id.Group, id.Root, exe, id.Web))
}

// cgiSocketTemplate is the socket Caddy dials: owned by the servanago user, mode 0660.
func cgiSocketTemplate(slug string) []byte {
	return []byte(fmt.Sprintf(`[Unit]
Description=ServanaGo site %s (fcgiwrap socket)

[Socket]
ListenStream=/run/servanago/%s.sock
SocketUser=servanago
SocketGroup=servanago
SocketMode=0660

[Install]
WantedBy=sockets.target
`, slug, slug))
}

// socketUnit is the .socket unit beside a service, when the site has one (kind cgi): its file exists.
func (a Actions) socketUnit(service string) (name, path string, ok bool) {
	name = strings.TrimSuffix(service, ".service") + ".socket"
	path = filepath.Join(systemdUnitDir, name)
	_, err := a.s.Lstat(path)
	return name, path, err == nil
}

// poolTemplate is the per-site php-fpm pool; the socket is what Caddy dials.
func poolTemplate(slug string, id siteIdentity) []byte {
	return []byte(fmt.Sprintf(`; per-site pool for ServanaGo site %s; written by the helper
[global]
daemonize=no

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
`, slug, slug, id.User, id.Group, slug))
}

// phpUnitTemplate runs exactly one pool — its own php-fpm master per site.
//
// There is deliberately no User= here: php-fpm's master starts as root, creates the socket in the
// root-owned /run/servanago, and drops its workers to the site user through the pool's user=. A master
// started as the site user could not create the socket. The runtime directory is declared (and preserved)
// here as well as in the helper unit, so a helper restart does not delete every site socket.
func phpUnitTemplate(id siteIdentity, fpmBin, confPath, ini string) []byte {
	args := "-F -y " + confPath
	if ini != "" { // a source build reads the site's own ini (its extensions); distro builds keep their php.ini
		args += " -c " + ini
	}
	return []byte(fmt.Sprintf(`[Unit]
Description=ServanaGo site %s (php-fpm %s)
After=network.target

[Service]
Type=simple
ExecStart=%s %s
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
`, id.User, filepath.Base(fpmBin), fpmBin, args, id.RW))
}

var fpmBinRE = regexp.MustCompile(`^(?:/usr/(?:sbin|bin)|/usr/local/bin)/php-fpm[0-9]+(?:\.[0-9]+)*$`)

// UserAdd creates the sg-<slug> system user (a no-op when it exists). The optional root becomes its
// home directory; nothing in it is ever chowned.
func (a Actions) UserAdd(r Request) Response {
	slug, err := r.Slug()
	if err != nil {
		return Response{Error: err.Error()}
	}
	if r.Vals.User != "" {
		return a.userAddNamed(r.Vals)
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

// validateKindSpec checks a unit-install spec for kind node, php or frankenphp.
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
		if label, ok := sourceBuild(s.FPMBin); ok { // one of ServanaGo's own builds: pinned by exact label or by branch
			if s.FPMVersion != label && s.FPMVersion != runtimes.Branch(label) {
				return fmt.Errorf("fpm version %q does not match the build %q (use %s or %s)", s.FPMVersion, s.FPMBin, label, runtimes.Branch(label))
			}
		} else {
			if !fpmBinRE.MatchString(s.FPMBin) {
				return fmt.Errorf("php-fpm binary %q must be a detected /usr/{sbin,bin,local/bin}/php-fpm<version> or a build under %s", s.FPMBin, runtimes.PHPRoot)
			}
			if got := strings.TrimPrefix(filepath.Base(s.FPMBin), "php-fpm"); got != s.FPMVersion {
				return fmt.Errorf("fpm version %q does not match the binary %q", s.FPMVersion, s.FPMBin)
			}
		}
		if _, err := runtimes.ParseExtensions(s.Extensions); err != nil {
			return err
		}
	case "frankenphp":
		if err := validateRoot(s.Root, false); err != nil {
			return err
		}
		if s.Port < 1024 || s.Port > 65535 {
			return fmt.Errorf("port %d: a frankenphp site uses 1024-65535", s.Port)
		}
		if !slices.Contains(runtimes.FrankenPaths, s.FrankenBin) {
			return fmt.Errorf("frankenphp binary %q must be one of %v", s.FrankenBin, runtimes.FrankenPaths)
		}
	case "cgi":
		if err := validateRoot(s.Root, false); err != nil {
			return err
		}
		if !slices.Contains(runtimes.FCGIWrapPaths, s.FCGIBin) {
			return fmt.Errorf("fcgiwrap binary %q must be one of %v", s.FCGIBin, runtimes.FCGIWrapPaths)
		}
	case "static": // only a site with its own user is served by a unit; the others stay in Caddy
		if err := validateRoot(s.Root, false); err != nil {
			return err
		}
		if s.User == "" {
			return errors.New("static: a unit serves a site that has a user; a static site without one is served by Caddy")
		}
	default:
		return fmt.Errorf("kind %q must be node, php, frankenphp, cgi or static", s.Kind)
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
func (a Actions) unitFor(s Spec, id siteIdentity, exe string) (unitPath string, content []byte) {
	path := filepath.Join(systemdUnitDir, "servanago-"+s.Slug+".service")
	switch s.Kind {
	case "node":
		return path, nodeUnitTemplate(id, s.Start)
	case "frankenphp":
		return path, frankenUnitTemplate(id, s.FrankenBin, s.Port)
	case "cgi":
		return path, cgiServiceTemplate(s.Slug, id, s.FCGIBin)
	case "static":
		return path, staticServiceTemplate(s.Slug, id, exe)
	}
	conf := filepath.Join("/etc/servanago/fpm", s.Slug+".conf")
	return path, phpUnitTemplate(id, s.FPMBin, conf, siteINI(s))
}

// siteINIPath is a source build site's own php.ini; "" for a distro build, which keeps its php.ini and conf.d.
func siteINI(s Spec) string {
	if _, ok := sourceBuild(s.FPMBin); !ok {
		return ""
	}
	return "/etc/servanago/php/" + s.Slug + ".ini"
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
	id, err := a.identity(s)
	if err != nil {
		return Response{Error: err.Error()}
	}
	exe := ""
	if s.Kind == "static" { // the unit runs the helper's own binary
		if exe, err = a.s.Exe(); err != nil || exe == "" {
			return Response{Error: fmt.Sprintf("the helper cannot find its executable: %v", err)}
		}
		if err := validateRoot(exe, false); err != nil {
			return Response{Error: fmt.Sprintf("helper executable: %v", err)}
		}
		if err := a.s.CheckBinary(exe); err != nil {
			return Response{Error: fmt.Sprintf("helper executable: %v", err)}
		}
	}
	// The unit runs this binary; refuse one the site user could have swapped.
	if bin := map[string]string{"frankenphp": s.FrankenBin, "cgi": s.FCGIBin}[s.Kind]; bin != "" {
		if err := a.s.CheckBinary(bin); err != nil {
			return Response{Error: fmt.Sprintf("%s binary: %v", s.Kind, err)}
		}
	}

	// The pool exists before the unit so both verify against their target state.
	if s.Kind == "php" {
		// The unit runs this binary as root (the php-fpm master): refuse one anyone else could have replaced.
		if err := a.s.CheckBinary(s.FPMBin); err != nil {
			return Response{Error: fmt.Sprintf("php-fpm binary: %v", err)}
		}
		conf := "/etc/servanago/fpm/" + slug + ".conf"
		if err := a.s.MkdirAll("/etc/servanago/fpm", 0o755); err != nil {
			return Response{Error: fmt.Sprintf("create fpm config dir: %v", err)}
		}
		ini := siteINI(s)
		if ini != "" {
			if err := a.checkBuildHas(s); err != nil {
				return Response{Error: err.Error()}
			}
			if err := a.s.MkdirAll("/etc/servanago/php", 0o755); err != nil {
				return Response{Error: fmt.Sprintf("create php config dir: %v", err)}
			}
			label, _ := sourceBuild(s.FPMBin)
			if resp := a.put(ini, phpINITemplate(slug, runtimes.Branch(label), s.Extensions), func(string) error { return nil }); !resp.OK {
				return resp
			}
		}
		if resp := a.put(conf, poolTemplate(slug, id), func(path string) error {
			return a.s.FPMTest(s.FPMBin, path, ini)
		}); !resp.OK {
			return resp
		}
	}
	unitPath, content := a.unitFor(s, id, exe)
	name := "servanago-" + slug + ".service"
	if s.Kind == "cgi" || s.Kind == "static" { // the socket is what is enabled and started; the service is activated by it
		// The service Requires= the socket and the socket needs the service, so each verifies only once the other is
		// on disk: write the socket unchecked, verify the service, then verify the socket.
		sockName := "servanago-" + slug + ".socket"
		sockPath := filepath.Join(systemdUnitDir, sockName)
		_, serr := a.s.Lstat(sockPath)
		_, uerr := a.s.Lstat(unitPath)
		sockNew, unitNew := serr != nil, uerr != nil // a failed install removes only what it created
		if resp := a.put(sockPath, cgiSocketTemplate(slug), func(string) error { return nil }); !resp.OK {
			return resp
		}
		resp := a.put(unitPath, content, a.s.VerifyUnit)
		if resp.OK {
			if resp = a.put(sockPath, cgiSocketTemplate(slug), a.s.VerifyUnit); !resp.OK && unitNew {
				_ = a.s.Remove(unitPath)
			}
		}
		if !resp.OK {
			if sockNew {
				_ = a.s.Remove(sockPath)
			}
			return resp
		}
		name = sockName
	} else if resp := a.put(unitPath, content, a.s.VerifyUnit); !resp.OK {
		return resp
	}
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
	if sock, path, ok := a.socketUnit(name); ok { // a cgi site: the socket goes first, or it would restart the service
		_ = a.s.StopUnit(sock)
		_ = a.s.StopUnit(name)
		_ = a.s.DisableUnit(sock)
		_ = a.s.Remove(path)
	}
	_ = a.s.DisableUnit(name)
	_ = a.s.Remove(filepath.Join(systemdUnitDir, name))
	_ = a.s.Remove("/etc/servanago/fpm/" + slug + ".conf")
	_ = a.s.Remove("/etc/servanago/php/" + slug + ".ini")
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
	if sock, _, ok := a.socketUnit(name); ok { // cgi: listening is "started"; fcgiwrap runs on demand
		name = sock
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
	if sock, _, ok := a.socketUnit(name); ok {
		if err := a.s.StopUnit(sock); err != nil {
			return Response{Error: fmt.Sprintf("systemctl stop %s: %v", sock, err)}
		}
	}
	if err := a.s.StopUnit(name); err != nil {
		return Response{Error: fmt.Sprintf("systemctl stop %s: %v", name, err)}
	}
	return Response{OK: true}
}

// put is write-from-template with the standard protections: refuse symlink targets, keep the
// previous content, verify, and roll back (restore or remove) when verification fails.
func (a Actions) put(path string, content []byte, verify func(path string) error) Response {
	return a.putPerm(path, content, 0o644, verify)
}

// putPerm is put with an explicit file mode (the shims are executable).
func (a Actions) putPerm(path string, content []byte, perm fs.FileMode, verify func(path string) error) Response {
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
	if err := a.s.WriteFile(path, content, perm); err != nil {
		return Response{Error: fmt.Sprintf("write %s: %v", name, err)}
	}
	if err := verify(path); err != nil {
		// Leave the host as it was: restore the previous file or remove the new one. A failed rollback leaves a
		// bad file on disk, so it is reported along with the verify failure.
		var rerr error
		if hasPrev {
			rerr = a.s.WriteFile(path, prev, perm)
		} else {
			rerr = a.s.Remove(path)
		}
		if rerr != nil {
			slog.Error("helper rollback after failed verify", "path", path, "error", rerr)
			return Response{Error: fmt.Sprintf("%s failed to verify: %v; rollback also failed, %s may still be on disk: %v", name, err, path, rerr)}
		}
		return Response{Error: fmt.Sprintf("%s failed to verify: %v", name, err)}
	}
	return Response{OK: true}
}
