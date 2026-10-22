package helper

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/servanago/servanago/internal/phpbuild"
	"github.com/servanago/servanago/internal/runtimes"
)

// php.go: ServanaGo's own PHP builds. The helper starts the unprivileged build job (two fixed units, see
// jobUnit), reports its state, copies the finished tree into the root-owned /opt/servanago/php, prunes builds, and
// writes the per-user default-PHP files. It never runs downloaded source as root.

const (
	fetchUnit = "servanago-phpfetch.service" // network on: downloads and verifies; OnSuccess starts buildUnit
	buildUnit = "servanago-phpbuild.service" // no network: compiles under a bind mount of root/ at /opt/servanago/php
	buildUser = "sg-phpbuild"

	phpUsersDir  = "/etc/servanago/php-users"
	composerDir  = "/opt/servanago/composer"
	composerPhar = composerDir + "/composer.phar"
	composerURL  = "https://getcomposer.org/download/latest-stable/composer.phar"

	minFreeBytes = 10 << 30 // a build needs room for sources, objects and the stage tree
)

// phpTools are what the build needs from the host. ServanaGo never installs them; a missing one is reported with the
// apt line that provides it.
var phpTools = []struct{ tool, pkg string }{
	{"gcc", "gcc"}, {"g++", "g++"}, {"make", "make"}, {"pkg-config", "pkg-config"}, {"perl", "perl"},
	{"cmake", "cmake"}, {"gpg", "gnupg"}, {"xz", "xz-utils"}, {"tar", "tar"},
	{"bison", "bison"}, {"flex", "flex"}, // PostgreSQL 18's configure (libpq) refuses to run without them, although the tarball ships the generated parsers
	{"autoconf", "autoconf"}, {"automake", "automake"}, {"libtoolize", "libtool"}, {"m4", "m4"}, // phpize, for the PECL extensions
}

var (
	versionRE = regexp.MustCompile(`^[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,3}$`)               // 8.4.27
	labelRE   = regexp.MustCompile(`^[0-9]{1,2}\.[0-9]{1,2}(\.[0-9]{1,3}-[0-9]{1,3})?$`) // 8.4 or 8.4.27-1
	libDirRE  = regexp.MustCompile(`^[a-z0-9][a-z0-9._+-]{0,63}$`)                       // zlib-1.3.1
	userRE    = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)
)

// sourceBuild reports whether bin is <PHPRoot>/<ver>-<n>/sbin/php-fpm, and the build's label.
func sourceBuild(bin string) (label string, ok bool) {
	rel, found := strings.CutPrefix(bin, runtimes.PHPRoot+"/")
	if !found {
		return "", false
	}
	p := strings.Split(rel, "/")
	if len(p) != 3 || p[1] != "sbin" || p[2] != "php-fpm" || !runtimes.BuildRE.MatchString(p[0]) {
		return "", false
	}
	return p[0], true
}

// phpINITemplate is a source-build site's php.ini: the extensions it selected (the core set when none) and a few
// production defaults. Extensions come from the allowlist only.
func phpINITemplate(slug, branch string, selected []string) []byte {
	names, _ := runtimes.ParseExtensions(selected) // validated before this point; canonical load order
	if len(names) == 0 {
		names = runtimes.CoreExtensions
	}
	var b strings.Builder
	fmt.Fprintf(&b, "; php.ini for ServanaGo site %s; written by the helper\n", slug)
	for _, e := range runtimes.SharedExtensions(branch) { // an extension compiled into this branch is not loaded again
		for _, n := range names {
			if n == e.Name {
				b.WriteString(e.Directive() + "\n")
			}
		}
	}
	b.WriteString("expose_php=Off\ndisplay_errors=Off\nlog_errors=On\n")
	return []byte(b.String())
}

// jobUnit renders the fetch or build unit. Both run `servanago php-job` as the sg-phpbuild user, sandboxed to the job
// directory; the build unit has no network and sees root/ as /opt/servanago/php so every prefix is its final path.
func jobUnit(phase, exe string, cpuPercent int) []byte {
	head, extra, timeout := "", "", "3h"
	if phase == "fetch" {
		head = "Description=ServanaGo PHP build: download and verify the source\nOnSuccess=" + buildUnit + "\n"
	} else {
		head = "Description=ServanaGo PHP build: compile\n"
		extra = "PrivateNetwork=yes\nBindPaths=" + phpbuild.Dir + "/root:" + runtimes.PHPRoot + "\n"
		timeout = "8h"
	}
	return []byte(fmt.Sprintf(`[Unit]
%s
[Service]
Type=oneshot
User=%s
Group=%s
WorkingDirectory=%s
ExecStart=%s php-job %s %s
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=%s
%sMemoryMax=4G
CPUQuota=%d%%
TimeoutStartSec=%s
`, head, buildUser, buildUser, phpbuild.Dir, exe, phase, phpbuild.Dir, phpbuild.Dir, extra, cpuPercent, timeout))
}

// PHPBuild starts a build of one PHP version: preflight, a fresh job directory, the two units, then the fetch unit.
// It returns at once; php-status follows the job.
func (a Actions) PHPBuild(r Request) Response {
	ver := r.Vals.PHPVersion
	if !versionRE.MatchString(ver) {
		return Response{Error: fmt.Sprintf("php version %q must look like 8.4.27", ver)}
	}
	var tools []string
	for _, t := range phpTools {
		tools = append(tools, t.tool)
	}
	if miss := a.s.Missing(tools); len(miss) > 0 {
		var pkgs []string
		for _, t := range phpTools {
			for _, m := range miss {
				if t.tool == m {
					pkgs = append(pkgs, t.pkg)
				}
			}
		}
		return Response{Error: fmt.Sprintf("build tools missing: %s. Install them once with: sudo apt install %s", strings.Join(miss, ", "), strings.Join(pkgs, " "))}
	}
	if free, err := a.s.FreeBytes(filepath.Dir(phpbuild.Dir)); err != nil {
		return Response{Error: fmt.Sprintf("free space: %v", err)}
	} else if free < minFreeBytes {
		return Response{Error: fmt.Sprintf("a build needs %d GB free under %s, %d GB available", minFreeBytes>>30, filepath.Dir(phpbuild.Dir), free>>30)}
	}
	if st := a.state(); (st.Phase == phpbuild.PhaseFetching || st.Phase == phpbuild.PhaseBuilding) && a.jobActive() {
		return Response{Error: fmt.Sprintf("a build of PHP %s is already running", st.Version)}
	}
	exe, err := a.s.Exe()
	if err != nil {
		return Response{Error: fmt.Sprintf("find the servanago binary: %v", err)}
	}
	if err := validateRoot(exe, false); err != nil { // it is written into a unit file
		return Response{Error: fmt.Sprintf("servanago binary path: %v", err)}
	}
	job := phpbuild.Job{Version: ver, N: a.nextBuildN(ver), Jobs: max(1, runtime.NumCPU()/2)}
	if err := a.s.UserAdd(buildUser, phpbuild.Dir); err != nil {
		return Response{Error: fmt.Sprintf("useradd %s: %v", buildUser, err)}
	}
	if err := a.s.MkdirAll(runtimes.PHPRoot, 0o755); err != nil { // the bind mount target, root-owned
		return Response{Error: fmt.Sprintf("create %s: %v", runtimes.PHPRoot, err)}
	}
	if err := a.s.JobDir(phpbuild.Dir, buildUser); err != nil {
		return Response{Error: fmt.Sprintf("prepare the job directory: %v", err)}
	}
	jb, _ := json.Marshal(job)
	sb, _ := json.Marshal(phpbuild.State{Phase: phpbuild.PhaseFetching, Version: ver, N: job.N})
	for path, b := range map[string][]byte{phpbuild.Dir + "/" + phpbuild.JobFile: jb, phpbuild.Dir + "/" + phpbuild.StateFile: sb} {
		if err := a.s.WriteFile(path, b, 0o644); err != nil {
			return Response{Error: fmt.Sprintf("write %s: %v", filepath.Base(path), err)}
		}
	}
	cpu := max(100, runtime.NumCPU()*50) // half of all cores, as a systemd CPUQuota percentage
	// The build unit goes first: the fetch unit names it in OnSuccess= and verifies against it.
	if resp := a.put(systemdUnitDir+"/"+buildUnit, jobUnit("build", exe, cpu), a.s.VerifyUnit); !resp.OK {
		return resp
	}
	if resp := a.put(systemdUnitDir+"/"+fetchUnit, jobUnit("fetch", exe, cpu), a.s.VerifyUnit); !resp.OK {
		return resp
	}
	if err := a.s.DaemonReload(); err != nil {
		return Response{Error: fmt.Sprintf("systemctl daemon-reload: %v", err)}
	}
	_ = a.s.StopUnit(fetchUnit) // clears a failed state left by the previous job
	_ = a.s.StopUnit(buildUnit)
	if err := a.s.StartUnit(fetchUnit); err != nil {
		return Response{Error: fmt.Sprintf("systemctl start %s: %v", fetchUnit, err)}
	}
	return Response{OK: true, Build: &phpbuild.State{Phase: phpbuild.PhaseFetching, Version: ver, N: job.N}}
}

// nextBuildN is the next free build number for a version: 8.4.27-1 exists, so the next build is 8.4.27-2.
func (a Actions) nextBuildN(ver string) int {
	names, _ := a.s.ReadDir(runtimes.PHPRoot)
	n := 0
	for _, name := range names {
		if v, k, ok := strings.Cut(name, "-"); ok && v == ver {
			if i, err := strconv.Atoi(k); err == nil && i > n {
				n = i
			}
		}
	}
	return n + 1
}

// state reads the job's state file; no file means no job (idle).
func (a Actions) state() phpbuild.State {
	b, err := a.s.ReadFile(phpbuild.Dir + "/" + phpbuild.StateFile)
	if err != nil {
		return phpbuild.State{Phase: phpbuild.PhaseIdle}
	}
	var st phpbuild.State
	if json.Unmarshal(b, &st) != nil || st.Phase == "" {
		return phpbuild.State{Phase: phpbuild.PhaseFailed, Message: "the job's state file is unreadable"}
	}
	return st
}

func (a Actions) jobActive() bool {
	for _, u := range []string{fetchUnit, buildUnit} {
		if st, err := a.s.UnitStatus(u); err == nil && (st.ActiveState == "active" || st.ActiveState == "activating") {
			return true
		}
	}
	return false
}

// PHPStatus reports the job's phase and the tail of its journal. A unit that systemd marks failed fails the job even
// when the job died before it could say so (killed, out of memory).
func (a Actions) PHPStatus(r Request) Response {
	st := a.state()
	if st.Phase == phpbuild.PhaseFetching || st.Phase == phpbuild.PhaseBuilding {
		for _, u := range []string{fetchUnit, buildUnit} {
			if us, err := a.s.UnitStatus(u); err == nil && us.ActiveState == "failed" {
				st.Phase, st.Message = phpbuild.PhaseFailed, u+" failed; see the log below"
			}
		}
	}
	lines := r.SpecLines()
	if lines == 0 {
		lines = defaultLogLines
	}
	if lines < 0 || lines > maxLogLines {
		return Response{Error: fmt.Sprintf("lines %d: 0-%d (0 = default %d)", lines, maxLogLines, defaultLogLines)}
	}
	var logs []string
	if st.Phase != phpbuild.PhaseIdle {
		units := []string{buildUnit}
		if st.Phase == phpbuild.PhaseFetching {
			units = []string{fetchUnit}
		} else if st.Phase == phpbuild.PhaseFailed {
			units = []string{fetchUnit, buildUnit}
		}
		for _, u := range units {
			if l, err := a.s.UnitLogs(u, lines); err == nil {
				logs = append(logs, l...)
			}
		}
		if len(logs) > lines {
			logs = logs[len(logs)-lines:]
		}
	}
	return Response{OK: true, Build: &st, Logs: logs}
}

// PHPInstall copies a finished build, and any library it was built against that is not installed yet, from the job's
// stage into /opt/servanago/php as root-owned files, then checks the result. A failed check removes the build.
func (a Actions) PHPInstall(r Request) Response {
	ver := r.Vals.PHPVersion
	if !versionRE.MatchString(ver) {
		return Response{Error: fmt.Sprintf("php version %q must look like 8.4.27", ver)}
	}
	st := a.state()
	if st.Phase != phpbuild.PhaseBuilt || st.Version != ver {
		return Response{Error: fmt.Sprintf("there is no finished build of PHP %s to install (state: %s)", ver, st.Phase)}
	}
	if a.jobActive() {
		return Response{Error: "the build job is still running"}
	}
	label := phpbuild.Job{Version: ver, N: st.N}.Label()
	if !runtimes.BuildRE.MatchString(label) {
		return Response{Error: fmt.Sprintf("build label %q is invalid", label)}
	}
	final := runtimes.PHPRoot + "/" + label
	if _, err := a.s.Lstat(final); err == nil {
		return Response{Error: label + " is already installed"}
	}
	stage := phpbuild.Dir + "/root"

	libs, _ := a.s.ReadDir(stage + "/libs")
	if len(libs) > 0 {
		if err := a.s.MkdirAll(runtimes.PHPRoot+"/libs", 0o755); err != nil {
			return Response{Error: fmt.Sprintf("create %s/libs: %v", runtimes.PHPRoot, err)}
		}
	}
	for _, lib := range libs {
		if !libDirRE.MatchString(lib) {
			return Response{Error: fmt.Sprintf("library directory %q has an unexpected name", lib)}
		}
		real := runtimes.PHPRoot + "/libs/" + lib
		if _, err := a.s.Lstat(real); err == nil { // libraries are immutable: an installed one is never replaced
			continue
		}
		if err := a.moveTree(stage+"/libs/"+lib, real); err != nil {
			return Response{Error: fmt.Sprintf("install %s: %v", lib, err)}
		}
	}
	if err := a.moveTree(stage+"/"+label, final); err != nil {
		return Response{Error: fmt.Sprintf("install %s: %v", label, err)}
	}
	if err := a.verifyBuild(final, ver); err != nil {
		_ = a.s.RemoveAll(final)
		return Response{Error: fmt.Sprintf("%s failed verification and was removed: %v", label, err)}
	}
	a.saveBuildLog(label)
	_ = a.s.RemoveAll(phpbuild.Dir) // sources, objects and stage are no longer needed
	return Response{OK: true}
}

// moveTree copies src to dst.tmp root-owned, then renames it into place so a failure leaves no half-installed tree.
func (a Actions) moveTree(src, dst string) error {
	tmp := dst + ".tmp"
	_ = a.s.RemoveAll(tmp)
	if err := a.s.InstallTree(src, tmp); err != nil {
		_ = a.s.RemoveAll(tmp)
		return err
	}
	return a.s.Rename(tmp, dst)
}

// verifyBuild is what "installed" means: root-owned binaries, the version asked for, and every extension built.
func (a Actions) verifyBuild(dir, ver string) error {
	for _, b := range []string{"/sbin/php-fpm", "/bin/php"} {
		if err := a.s.CheckBinary(dir + b); err != nil {
			return err
		}
	}
	out, err := a.s.Exec(dir+"/bin/php", "-v")
	if err != nil {
		return fmt.Errorf("php -v: %w", err)
	}
	if !strings.HasPrefix(out, "PHP "+ver+" ") {
		return fmt.Errorf("php -v did not report %s: %.80s", ver, strings.TrimSpace(out))
	}
	extDir, err := a.s.Exec(dir+"/bin/php-config", "--extension-dir")
	if err != nil {
		return fmt.Errorf("php-config --extension-dir: %w", err)
	}
	if extDir = strings.TrimSpace(extDir); !strings.HasPrefix(extDir, dir+"/") {
		return fmt.Errorf("php-config --extension-dir is %q, outside the build", extDir)
	}
	have, err := a.s.ReadDir(extDir)
	if err != nil {
		return fmt.Errorf("read the extension directory: %w", err)
	}
	var missing []string
	for _, e := range runtimes.SharedExtensions(runtimes.Branch(ver)) {
		found := false
		for _, h := range have {
			found = found || h == e.Name+".so"
		}
		if !found {
			missing = append(missing, e.Name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("extensions not built: %s", strings.Join(missing, ", "))
	}
	return nil
}

// checkBuildHas refuses a site whose extensions its build does not contain (a build made before apcu or imagick were
// offered has no apcu.so): php-fpm would only warn at start, and the site would run without the extension.
func (a Actions) checkBuildHas(s Spec) error {
	label, _ := sourceBuild(s.FPMBin)
	dir := runtimes.PHPRoot + "/" + label
	out, err := a.s.Exec(dir+"/bin/php-config", "--extension-dir")
	if err != nil {
		return fmt.Errorf("php-config of %s: %w", label, err)
	}
	extDir := strings.TrimSpace(out)
	if !strings.HasPrefix(extDir, dir+"/") {
		return fmt.Errorf("php-config of %s reports an extension directory outside the build: %q", label, extDir)
	}
	have, err := a.s.ReadDir(extDir)
	if err != nil {
		return fmt.Errorf("read the extension directory of %s: %w", label, err)
	}
	want, _ := runtimes.ParseExtensions(s.Extensions) // validated before this point
	if len(want) == 0 {
		want = runtimes.CoreExtensions
	}
	var missing []string
	for _, e := range runtimes.SharedExtensions(runtimes.Branch(label)) {
		if !slices.Contains(want, e.Name) {
			continue
		}
		if !slices.Contains(have, e.Name+".so") {
			missing = append(missing, e.Name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("PHP build %s does not contain %s; build PHP again to get it, or untick it for this site", label, strings.Join(missing, ", "))
	}
	return nil
}

// saveBuildLog keeps the job's journal beside the other ServanaGo logs. Best effort: a missing log never fails an install.
func (a Actions) saveBuildLog(label string) {
	var all []string
	for _, u := range []string{fetchUnit, buildUnit} {
		if l, err := a.s.UnitLogs(u, 100000); err == nil {
			all = append(all, l...)
		}
	}
	if err := a.s.MkdirAll("/var/log/servanago", 0o755); err != nil {
		return
	}
	_ = a.s.WriteFile("/var/log/servanago/php-build-"+label+".log", []byte(strings.Join(all, "\n")+"\n"), 0o644)
}

// PHPPrune removes one build, then every library directory no remaining build lists in its libs.txt. If any build has no
// readable libs.txt the libraries are left alone.
func (a Actions) PHPPrune(r Request) Response {
	label := r.Vals.Build
	if !runtimes.BuildRE.MatchString(label) {
		return Response{Error: fmt.Sprintf("build %q must look like 8.4.27-1", label)}
	}
	dir := runtimes.PHPRoot + "/" + label
	if fi, err := a.s.Lstat(dir); err != nil || fi.Mode()&fs.ModeSymlink != 0 || !fi.IsDir() {
		return Response{Error: label + " is not an installed build"}
	}
	if err := a.s.RemoveAll(dir); err != nil {
		return Response{Error: fmt.Sprintf("remove %s: %v", label, err)}
	}
	names, err := a.s.ReadDir(runtimes.PHPRoot)
	if err != nil {
		return Response{OK: true}
	}
	used := map[string]bool{}
	for _, n := range names {
		if !runtimes.BuildRE.MatchString(n) {
			continue
		}
		b, err := a.s.ReadFile(runtimes.PHPRoot + "/" + n + "/libs.txt")
		if err != nil {
			return Response{OK: true} // cannot tell what this build needs: keep every library
		}
		for _, l := range strings.Fields(string(b)) {
			used[l] = true
		}
	}
	libs, _ := a.s.ReadDir(runtimes.PHPRoot + "/libs")
	for _, l := range libs {
		if libDirRE.MatchString(l) && !used[l] {
			_ = a.s.RemoveAll(runtimes.PHPRoot + "/libs/" + l)
		}
	}
	return Response{OK: true}
}

const pathScript = `#!/bin/sh
# ServanaGo: print the php binary chosen for the current user (set on the PHP page); print nothing to mean "use the distro php".
root=${SERVANAGO_PHP_ROOT:-/opt/servanago/php}
map=${SERVANAGO_PHP_USERS:-/etc/servanago/php-users}
label=$(head -n 1 "$map/$(id -un)" 2>/dev/null) || exit 0
case $label in
  ''|*[!0-9.-]*|*..*|.*|*-) exit 0 ;;
esac
if [ -x "$root/$label/bin/php" ]; then
  echo "$root/$label/bin/php"
  exit 0
fi
b=${label#*.}
b=${label%%.*}.${b%%.*}
d=$(ls -d "$root/$b".*-* 2>/dev/null | sort -V | tail -n 1)
if [ -n "$d" ] && [ -x "$d/bin/php" ]; then
  echo "$d/bin/php"
fi
`

const phpShim = `#!/bin/sh
# ServanaGo: runs the PHP chosen for this user, else the distro php.
dir=$(dirname "$0")
bin=$("$dir/servanago-php-path" 2>/dev/null)
[ -n "$bin" ] || bin=/usr/bin/php
if [ ! -x "$bin" ]; then
  echo "php: no PHP found (none installed at $bin and no ServanaGo default set)" >&2
  exit 127
fi
# A site's user: the second line of its map file is the site's php.ini, so the command line has the site's extensions.
ini=$(sed -n 2p "${SERVANAGO_PHP_USERS:-/etc/servanago/php-users}/$(id -un)" 2>/dev/null)
case $bin in
  /opt/servanago/php/*) if [ -n "$ini" ] && [ -r "$ini" ]; then set -- -c "$ini" "$@"; fi ;;
esac
exec "$bin" "$@"
`

const composerShim = `#!/bin/sh
# ServanaGo: composer under the same PHP that "php" resolves to.
dir=$(dirname "$0")
exec "$dir/php" "${SERVANAGO_COMPOSER:-` + composerPhar + `}" "$@"
`

const profileScript = `# ServanaGo: put this user's default PHP first on PATH (set on the PHP page). Login shells only; /usr/local/bin/php covers the rest.
if [ -x /usr/local/bin/servanago-php-path ]; then
  _sg_php=$(/usr/local/bin/servanago-php-path 2>/dev/null)
  if [ -n "$_sg_php" ]; then
    PATH=$(dirname "$_sg_php"):$PATH
    export PATH
  fi
  unset _sg_php
fi
`

// PHPUserDefault sets or clears a login user's default PHP. It always (re)writes the shims, so one call is enough to
// make a host consistent; the label is stored, not a path, so a branch follows new builds without another call.
func (a Actions) PHPUserDefault(r Request) Response {
	user, label := r.Vals.User, r.Vals.PHPVersion
	if !userRE.MatchString(user) {
		return Response{Error: fmt.Sprintf("user %q is not a valid user name", user)}
	}
	if label != "" && !labelRE.MatchString(label) {
		return Response{Error: fmt.Sprintf("php version %q must be a branch like 8.4 or a build like 8.4.27-1", label)}
	}
	if err := a.s.UserOK(user); err != nil {
		return Response{Error: fmt.Sprintf("user %s: %v", user, err)}
	}
	content := label + "\n"
	if slug := r.Vals.Slug; slug != "" && label != "" { // a site's user: the command line loads the site's own ini
		if err := ValidateSlug(slug); err != nil {
			return Response{Error: err.Error()}
		}
		content += "/etc/servanago/php/" + slug + ".ini\n"
	}
	if err := a.s.MkdirAll(phpUsersDir, 0o755); err != nil {
		return Response{Error: fmt.Sprintf("create %s: %v", phpUsersDir, err)}
	}
	none := func(string) error { return nil }
	for path, c := range map[string]struct {
		body string
		mode fs.FileMode
	}{
		"/usr/local/bin/servanago-php-path": {pathScript, 0o755},
		"/usr/local/bin/php":                {phpShim, 0o755},
		"/usr/local/bin/composer":           {composerShim, 0o755},
		"/etc/profile.d/servanago-php.sh":   {profileScript, 0o644},
	} {
		if resp := a.putPerm(path, []byte(c.body), c.mode, none); !resp.OK {
			return resp
		}
	}
	file := phpUsersDir + "/" + user
	if label == "" {
		if err := a.s.Remove(file); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return Response{Error: fmt.Sprintf("remove %s: %v", file, err)}
		}
		return Response{OK: true}
	}
	if resp := a.putPerm(file, []byte(content), 0o644, none); !resp.OK {
		return resp
	}
	return Response{OK: true}
}

// Composer downloads composer.phar and installs it root-owned, after checking the sha256 getcomposer.org publishes for it.
func (a Actions) Composer(r Request) Response {
	sumBody, err := a.s.Fetch(composerURL+".sha256", 1<<10)
	if err != nil {
		return Response{Error: fmt.Sprintf("download the composer checksum: %v", err)}
	}
	fields := strings.Fields(string(sumBody))
	if len(fields) == 0 || len(fields[0]) != 64 {
		return Response{Error: "the composer checksum file is not a sha256"}
	}
	want := strings.ToLower(fields[0])
	if _, err := hex.DecodeString(want); err != nil {
		return Response{Error: "the composer checksum file is not a sha256"}
	}
	phar, err := a.s.Fetch(composerURL, 20<<20)
	if err != nil {
		return Response{Error: fmt.Sprintf("download composer: %v", err)}
	}
	if sum := sha256.Sum256(phar); hex.EncodeToString(sum[:]) != want {
		return Response{Error: "composer.phar does not match its published sha256; not installed"}
	}
	if err := a.s.MkdirAll(composerDir, 0o755); err != nil {
		return Response{Error: fmt.Sprintf("create %s: %v", composerDir, err)}
	}
	if resp := a.put(composerPhar, phar, func(string) error { return nil }); !resp.OK {
		return resp
	}
	return Response{OK: true}
}
