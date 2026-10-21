package helper

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/servanago/servanago/internal/phpbuild"
	"github.com/servanago/servanago/internal/runtimes"
)

func req(t *testing.T, action, spec string) Request {
	t.Helper()
	r, err := DecodeRequest([]byte(`{"action":"` + action + `","spec":` + spec + `}`))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

const srcBin = "/opt/servanago/php/8.4.27-1/sbin/php-fpm"

// builtSeam is a fake host with an installed build under dir whose extension directory holds the .so files of
// every shared extension of its branch, except those named in lacking.
func builtSeam(label string, lacking ...string) *fakeSeam {
	s := newFakeSeam()
	dir := runtimes.PHPRoot + "/" + label
	ext := dir + "/lib/php/extensions/no-debug-non-zts-20240924"
	s.execOut = map[string]string{dir + "/bin/php-config --extension-dir": ext + "\n"}
	s.dirs = map[string][]string{}
	for _, e := range runtimes.SharedExtensions(runtimes.Branch(label)) {
		if !slices.Contains(lacking, e.Name) {
			s.dirs[ext] = append(s.dirs[ext], e.Name+".so")
		}
	}
	return s
}

// A build made before an extension was offered does not have its .so: the site is refused, not started without it.
func TestSourceBuildMissingExtensionIsRefused(t *testing.T) {
	seam := builtSeam("8.4.27-1", "apcu", "imagick")
	r := req(t, ActionUnitInstall, `{"kind":"php","slug":"blog","root":"/srv/blog","fpm_bin":"`+srcBin+`","fpm_version":"8.4","extensions":["apcu","curl","imagick"]}`)
	resp := NewActions(seam).UnitInstall(r)
	if resp.OK || !strings.Contains(resp.Error, "does not contain apcu, imagick") || len(seam.written) != 0 {
		t.Fatalf("%+v written=%v", resp, keys(seam.written))
	}
	// An extension the site did not select is not needed.
	r = req(t, ActionUnitInstall, `{"kind":"php","slug":"blog","root":"/srv/blog","fpm_bin":"`+srcBin+`","fpm_version":"8.4","extensions":["curl"]}`)
	if resp := NewActions(seam).UnitInstall(r); !resp.OK {
		t.Fatalf("a build without apcu must serve a site that did not ask for it: %+v", resp)
	}
}

func TestSourceBuildUnitInstall(t *testing.T) {
	seam := builtSeam("8.4.27-1")
	r := req(t, ActionUnitInstall, `{"kind":"php","slug":"blog","root":"/srv/blog","fpm_bin":"`+srcBin+`","fpm_version":"8.4","extensions":["curl","mbstring"]}`)
	if resp := NewActions(seam).UnitInstall(r); !resp.OK {
		t.Fatalf("install: %+v", resp)
	}
	ini := string(seam.written["/etc/servanago/php/blog.ini"])
	for _, want := range []string{"extension=mbstring\n", "extension=curl\n", "expose_php=Off"} {
		if !strings.Contains(ini, want) {
			t.Errorf("ini missing %q:\n%s", want, ini)
		}
	}
	if strings.Contains(ini, "opcache") { // a selection replaces the core set
		t.Errorf("selection must not add the core set:\n%s", ini)
	}
	unit := string(seam.written["/etc/systemd/system/servanago-blog.service"])
	if !strings.Contains(unit, "ExecStart="+srcBin+" -F -y /etc/servanago/fpm/blog.conf -c /etc/servanago/php/blog.ini\n") {
		t.Errorf("unit does not use the site's ini:\n%s", unit)
	}
	if seam.fpmTestIni != "/etc/servanago/php/blog.ini" || seam.binChecked != srcBin {
		t.Errorf("fpm test ini %q, binary checked %q", seam.fpmTestIni, seam.binChecked)
	}
}

func TestSourceBuildDefaultsToCoreExtensions(t *testing.T) {
	seam := builtSeam("8.4.27-1")
	r := req(t, ActionUnitInstall, `{"kind":"php","slug":"blog","root":"/srv/blog","fpm_bin":"`+srcBin+`","fpm_version":"8.4.27-1"}`)
	if resp := NewActions(seam).UnitInstall(r); !resp.OK {
		t.Fatalf("install: %+v", resp)
	}
	ini := string(seam.written["/etc/servanago/php/blog.ini"])
	for _, want := range []string{"extension=mbstring", "zend_extension=opcache", "extension=sqlite3", "extension=pdo_sqlite"} {
		if !strings.Contains(ini, want) {
			t.Errorf("core set missing %q:\n%s", want, ini)
		}
	}
}

// PHP 8.5 compiles opcache in and ships no opcache.so: loading it would only warn, so the ini leaves it out.
func TestPHP85INIOmitsOpcache(t *testing.T) {
	seam := builtSeam("8.5.12-1")
	bin := "/opt/servanago/php/8.5.12-1/sbin/php-fpm"
	r := req(t, ActionUnitInstall, `{"kind":"php","slug":"blog","root":"/srv/blog","fpm_bin":"`+bin+`","fpm_version":"8.5","extensions":["opcache","mbstring"]}`)
	if resp := NewActions(seam).UnitInstall(r); !resp.OK {
		t.Fatalf("install: %+v", resp)
	}
	ini := string(seam.written["/etc/servanago/php/blog.ini"])
	if strings.Contains(ini, "opcache") || !strings.Contains(ini, "extension=mbstring") {
		t.Errorf("8.5 ini:\n%s", ini)
	}
}

func TestPHP85InstallDoesNotExpectOpcacheSO(t *testing.T) {
	seam := installedSeam()
	seam.files[phpbuild.Dir+"/state.json"] = []byte(`{"phase":"built","version":"8.5.12","n":1}`)
	final := runtimes.PHPRoot + "/8.5.12-1"
	ext := final + "/lib/php/extensions/no-debug-non-zts-20250925"
	seam.execOut = map[string]string{final + "/bin/php -v": "PHP 8.5.12 (cli)\n", final + "/bin/php-config --extension-dir": ext + "\n"}
	var so []string
	for _, e := range runtimes.SharedExtensions("8.5") {
		so = append(so, e.Name+".so")
	}
	seam.dirs[ext] = so
	if resp := NewActions(seam).PHPInstall(req(t, ActionPHPInstall, `{"php_version":"8.5.12"}`)); !resp.OK {
		t.Fatalf("install: %+v", resp)
	}
}

// A distro build keeps its own php.ini and conf.d: no site ini, no -c, but the binary is checked like any php binary.
func TestDistroBuildKeepsItsIni(t *testing.T) {
	seam := newFakeSeam()
	r := req(t, ActionUnitInstall, `{"kind":"php","slug":"blog","root":"/srv/blog","fpm_bin":"/usr/sbin/php-fpm8.2","fpm_version":"8.2"}`)
	if resp := NewActions(seam).UnitInstall(r); !resp.OK {
		t.Fatalf("install: %+v", resp)
	}
	if _, ok := seam.written["/etc/servanago/php/blog.ini"]; ok {
		t.Error("a distro build must not get a site ini")
	}
	if u := string(seam.written["/etc/systemd/system/servanago-blog.service"]); strings.Contains(u, " -c ") {
		t.Errorf("distro unit passes -c:\n%s", u)
	}
	if seam.fpmTestIni != "" || seam.binChecked != "/usr/sbin/php-fpm8.2" {
		t.Errorf("ini %q checked %q", seam.fpmTestIni, seam.binChecked)
	}
}

func TestSourceBuildRejections(t *testing.T) {
	head := `{"kind":"php","slug":"site1","root":"/srv/x",`
	tests := []struct{ name, spec, want string }{
		{"version of another build", head + `"fpm_bin":"` + srcBin + `","fpm_version":"8.3"}`, "does not match the build"},
		{"another build's exact label", head + `"fpm_bin":"` + srcBin + `","fpm_version":"8.4.27-2"}`, "does not match the build"},
		{"unknown extension", head + `"fpm_bin":"` + srcBin + `","fpm_version":"8.4","extensions":["curl","evil"]}`, "not one of the available"},
		{"ini injection", head + `"fpm_bin":"` + srcBin + `","fpm_version":"8.4","extensions":["curl\nauto_prepend_file=/tmp/x"]}`, "not one of the available"},
		{"traversal in the binary", head + `"fpm_bin":"/opt/servanago/php/8.4.27-1/sbin/../../../../bin/sh","fpm_version":"8.4"}`, "php-fpm binary"},
		{"not a build directory", head + `"fpm_bin":"/opt/servanago/php/libs/sbin/php-fpm","fpm_version":"8.4"}`, "php-fpm binary"},
		{"wrong binary in a build", head + `"fpm_bin":"/opt/servanago/php/8.4.27-1/bin/php","fpm_version":"8.4"}`, "php-fpm binary"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seam := newFakeSeam()
			resp := NewActions(seam).UnitInstall(req(t, ActionUnitInstall, tt.spec))
			if resp.OK || !strings.Contains(resp.Error, tt.want) {
				t.Fatalf("response %+v, want an error mentioning %q", resp, tt.want)
			}
			if len(seam.written) != 0 {
				t.Errorf("host was written: %v", keys(seam.written))
			}
		})
	}
}

// php-fpm's master runs as root: a binary someone else could write is refused before anything is written.
func TestPHPFPMBinaryMustBeTrusted(t *testing.T) {
	seam := newFakeSeam()
	seam.binErr = errors.New("must be owned by root")
	resp := NewActions(seam).UnitInstall(req(t, ActionUnitInstall, `{"kind":"php","slug":"site1","root":"/srv/x","fpm_bin":"/usr/sbin/php-fpm8.2","fpm_version":"8.2"}`))
	if resp.OK || !strings.Contains(resp.Error, "owned by root") || len(seam.written) != 0 {
		t.Fatalf("untrusted php-fpm accepted: %+v written=%v", resp, keys(seam.written))
	}
}

func TestUnitRemoveDropsSiteINI(t *testing.T) {
	seam := newFakeSeam()
	if resp := NewActions(seam).UnitRemove(req(t, ActionUnitRemove, `{"slug":"blog"}`)); !resp.OK {
		t.Fatal(resp.Error)
	}
	// Remove records the last path; the ini goes after the pool, before the reload.
	if seam.removed != "/etc/servanago/php/blog.ini" {
		t.Errorf("last removal %q", seam.removed)
	}
}

// FuzzSiteINI: whatever extension list is accepted, every ini line is a comment, a known load directive, or one of the fixed defaults.
func FuzzSiteINI(f *testing.F) {
	f.Add("curl")
	f.Add("curl\nauto_prepend_file=/x")
	f.Add("mbstring;extension=evil")
	f.Add("")
	f.Fuzz(func(t *testing.T, name string) {
		spec := Spec{Kind: "php", Slug: "site1", Root: "/srv/x", FPMBin: srcBin, FPMVersion: "8.4", Extensions: []string{name, "intl"}}
		seam := builtSeam("8.4.27-1")
		if resp := NewActions(seam).UnitInstall(Request{Action: ActionUnitInstall, Vals: spec}); !resp.OK {
			return
		}
		ok := map[string]bool{"expose_php=Off": true, "display_errors=Off": true, "log_errors=On": true}
		for _, e := range runtimes.PHPExtensions {
			ok[e.Directive()] = true
		}
		for _, line := range strings.Split(strings.TrimSpace(string(seam.written["/etc/servanago/php/site1.ini"])), "\n") {
			if !strings.HasPrefix(line, ";") && !ok[line] {
				t.Fatalf("unexpected ini line %q for extension %q", line, name)
			}
		}
	})
}

func newPHPSeam() *fakeSeam {
	s := newFakeSeam()
	s.free = 50 << 30
	s.exe = "/usr/bin/servanago"
	s.files = map[string][]byte{}
	s.dirs = map[string][]string{}
	s.exist = map[string]bool{}
	return s
}

func TestPHPBuildStarts(t *testing.T) {
	seam := newPHPSeam()
	seam.dirs[runtimes.PHPRoot] = []string{"8.4.27-1", "8.4.27-2", "8.3.36-1", "libs", "8.4.27-x"}
	resp := NewActions(seam).PHPBuild(req(t, ActionPHPBuild, `{"php_version":"8.4.27"}`))
	if !resp.OK || resp.Build == nil || resp.Build.N != 3 || resp.Build.Phase != phpbuild.PhaseFetching {
		t.Fatalf("build: %+v", resp)
	}
	if seam.started != fetchUnit {
		t.Errorf("started %q", seam.started)
	}
	if len(seam.jobDirCalls) != 1 || seam.jobDirCalls[0] != phpbuild.Dir+" sg-phpbuild" || seam.userAdded != "sg-phpbuild" {
		t.Errorf("job dir %v user %q", seam.jobDirCalls, seam.userAdded)
	}
	var job phpbuild.Job
	if err := json.Unmarshal(seam.written[phpbuild.Dir+"/job.json"], &job); err != nil || job.Version != "8.4.27" || job.N != 3 || job.Jobs < 1 {
		t.Errorf("job.json %+v (%v)", job, err)
	}
	fetch := string(seam.written[systemdUnitDir+"/"+fetchUnit])
	build := string(seam.written[systemdUnitDir+"/"+buildUnit])
	for _, want := range []string{"User=sg-phpbuild", "OnSuccess=" + buildUnit, "ExecStart=/usr/bin/servanago php-job fetch " + phpbuild.Dir, "MemoryMax=4G", "ProtectSystem=strict"} {
		if !strings.Contains(fetch, want) {
			t.Errorf("fetch unit missing %q:\n%s", want, fetch)
		}
	}
	if strings.Contains(fetch, "PrivateNetwork") || strings.Contains(fetch, "BindPaths") {
		t.Errorf("fetch unit needs the network and the real tree:\n%s", fetch)
	}
	for _, want := range []string{"PrivateNetwork=yes", "BindPaths=" + phpbuild.Dir + "/root:" + runtimes.PHPRoot, "ExecStart=/usr/bin/servanago php-job build " + phpbuild.Dir, "User=sg-phpbuild"} {
		if !strings.Contains(build, want) {
			t.Errorf("build unit missing %q:\n%s", want, build)
		}
	}
}

func TestPHPBuildRejections(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*fakeSeam)
		spec  string
		want  string
	}{
		{"bad version", func(*fakeSeam) {}, `{"php_version":"8.4"}`, "must look like"},
		{"injection in version", func(*fakeSeam) {}, `{"php_version":"8.4.27;rm -rf /"}`, "must look like"},
		{"missing tools", func(s *fakeSeam) { s.missing = []string{"cmake", "gpg"} }, `{"php_version":"8.4.27"}`, "sudo apt install cmake gnupg"},
		{"no disk", func(s *fakeSeam) { s.free = 1 << 30 }, `{"php_version":"8.4.27"}`, "10 GB"},
		{"already running", func(s *fakeSeam) {
			s.files[phpbuild.Dir+"/state.json"] = []byte(`{"phase":"building","version":"8.4.26"}`)
			s.unitStatuses = map[string]StatusData{buildUnit: {ActiveState: "active"}}
		}, `{"php_version":"8.4.27"}`, "already running"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seam := newPHPSeam()
			tt.setup(seam)
			resp := NewActions(seam).PHPBuild(req(t, ActionPHPBuild, tt.spec))
			if resp.OK || !strings.Contains(resp.Error, tt.want) {
				t.Fatalf("%+v, want an error mentioning %q", resp, tt.want)
			}
			if seam.started != "" || len(seam.written) != 0 || len(seam.jobDirCalls) != 0 {
				t.Errorf("the host was touched: started=%q written=%v", seam.started, keys(seam.written))
			}
		})
	}
	// A recorded "running" state with no active unit is a dead job, not a block.
	seam := newPHPSeam()
	seam.files[phpbuild.Dir+"/state.json"] = []byte(`{"phase":"building","version":"8.4.26"}`)
	if resp := NewActions(seam).PHPBuild(req(t, ActionPHPBuild, `{"php_version":"8.4.27"}`)); !resp.OK {
		t.Errorf("a dead job blocked a new build: %+v", resp)
	}
}

func TestPHPStatus(t *testing.T) {
	seam := newPHPSeam()
	a := NewActions(seam)
	if resp := a.PHPStatus(req(t, ActionPHPStatus, `{}`)); !resp.OK || resp.Build.Phase != phpbuild.PhaseIdle || len(resp.Logs) != 0 {
		t.Fatalf("idle: %+v", resp)
	}
	seam.files[phpbuild.Dir+"/state.json"] = []byte(`{"phase":"building","version":"8.4.27","n":2}`)
	seam.unitLogs = map[string][]string{buildUnit: {"make[1]: Entering directory"}}
	resp := a.PHPStatus(req(t, ActionPHPStatus, `{}`))
	if resp.Build.Phase != phpbuild.PhaseBuilding || resp.Build.N != 2 || len(resp.Logs) != 1 {
		t.Fatalf("building: %+v", resp)
	}
	// A unit systemd marked failed fails the job even though the job never wrote "failed" (killed, out of memory).
	seam.unitStatuses = map[string]StatusData{buildUnit: {ActiveState: "failed"}}
	if resp := a.PHPStatus(req(t, ActionPHPStatus, `{}`)); resp.Build.Phase != phpbuild.PhaseFailed || !strings.Contains(resp.Build.Message, buildUnit) {
		t.Fatalf("failed unit: %+v", resp)
	}
	if resp := a.PHPStatus(req(t, ActionPHPStatus, `{"lines":9999}`)); resp.OK {
		t.Error("a huge log tail must be refused")
	}
}

func installedSeam() *fakeSeam {
	s := newPHPSeam()
	s.files[phpbuild.Dir+"/state.json"] = []byte(`{"phase":"built","version":"8.4.27","n":1}`)
	s.dirs[phpbuild.Dir+"/root/libs"] = []string{"zlib-1.3.1", "openssl-3.5.0"}
	s.exist[runtimes.PHPRoot+"/libs/zlib-1.3.1"] = true // already installed: never replaced
	final := runtimes.PHPRoot + "/8.4.27-1"
	extDir := final + "/lib/php/extensions/no-debug-non-zts-20240924"
	s.execOut = map[string]string{
		final + "/bin/php -v":                     "PHP 8.4.27 (cli) (built: Oct 21 2026)\n",
		final + "/bin/php-config --extension-dir": extDir + "\n",
	}
	var so []string
	for _, e := range runtimes.PHPExtensions {
		so = append(so, e.Name+".so")
	}
	s.dirs[extDir] = so
	return s
}

func TestPHPInstall(t *testing.T) {
	seam := installedSeam()
	resp := NewActions(seam).PHPInstall(req(t, ActionPHPInstall, `{"php_version":"8.4.27"}`))
	if !resp.OK {
		t.Fatalf("install: %+v", resp)
	}
	final := runtimes.PHPRoot + "/8.4.27-1"
	want := [][2]string{
		{phpbuild.Dir + "/root/libs/openssl-3.5.0", runtimes.PHPRoot + "/libs/openssl-3.5.0.tmp"}, // zlib is skipped: installed already
		{phpbuild.Dir + "/root/8.4.27-1", final + ".tmp"},
	}
	if len(seam.installed) != 2 || seam.installed[0] != want[0] || seam.installed[1] != want[1] {
		t.Errorf("copies %v, want %v", seam.installed, want)
	}
	if len(seam.renamed) != 2 || seam.renamed[1] != [2]string{final + ".tmp", final} {
		t.Errorf("renames %v", seam.renamed)
	}
	if got := strings.Join(seam.checked, " "); !strings.Contains(got, final+"/sbin/php-fpm") || !strings.Contains(got, final+"/bin/php") {
		t.Errorf("binaries checked: %v", seam.checked)
	}
	if seam.removedAll[len(seam.removedAll)-1] != phpbuild.Dir {
		t.Errorf("the job directory was not cleaned up: %v", seam.removedAll)
	}
	if _, ok := seam.written["/var/log/servanago/php-build-8.4.27-1.log"]; !ok {
		t.Errorf("build log not kept: %v", keys(seam.written))
	}
}

func TestPHPInstallRejections(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*fakeSeam)
		spec  string
		want  string
	}{
		{"bad version", func(*fakeSeam) {}, `{"php_version":"../x"}`, "must look like"},
		{"nothing built", func(s *fakeSeam) { delete(s.files, phpbuild.Dir+"/state.json") }, `{"php_version":"8.4.27"}`, "no finished build"},
		{"other version built", func(*fakeSeam) {}, `{"php_version":"8.4.28"}`, "no finished build"},
		{"still running", func(s *fakeSeam) { s.unitStatuses = map[string]StatusData{fetchUnit: {ActiveState: "active"}} }, `{"php_version":"8.4.27"}`, "still running"},
		{"already installed", func(s *fakeSeam) { s.exist[runtimes.PHPRoot+"/8.4.27-1"] = true }, `{"php_version":"8.4.27"}`, "already installed"},
		{"hostile library name", func(s *fakeSeam) { s.dirs[phpbuild.Dir+"/root/libs"] = []string{"../../etc"} }, `{"php_version":"8.4.27"}`, "unexpected name"},
		{"copy fails", func(s *fakeSeam) { s.installErr = errors.New("symlink leaves the build") }, `{"php_version":"8.4.27"}`, "leaves the build"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seam := installedSeam()
			tt.setup(seam)
			resp := NewActions(seam).PHPInstall(req(t, ActionPHPInstall, tt.spec))
			if resp.OK || !strings.Contains(resp.Error, tt.want) {
				t.Fatalf("%+v, want an error mentioning %q", resp, tt.want)
			}
		})
	}
}

// A build that fails verification is removed again, so a half-good build is never offered to a site.
func TestPHPInstallVerificationFailureRemovesBuild(t *testing.T) {
	final := runtimes.PHPRoot + "/8.4.27-1"
	extDir := final + "/lib/php/extensions/no-debug-non-zts-20240924"
	tests := []struct {
		name  string
		setup func(*fakeSeam)
		want  string
	}{
		{"binary not root-owned", func(s *fakeSeam) { s.binErr = errors.New("must be owned by root") }, "owned by root"},
		{"wrong version", func(s *fakeSeam) { s.execOut[final+"/bin/php -v"] = "PHP 8.4.26 (cli)\n" }, "did not report 8.4.27"},
		{"extension missing", func(s *fakeSeam) { s.dirs[extDir] = []string{"mbstring.so"} }, "extensions not built"},
		{"extension dir outside the build", func(s *fakeSeam) { s.execOut[final+"/bin/php-config --extension-dir"] = "/usr/lib/php\n" }, "extension-dir"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seam := installedSeam()
			tt.setup(seam)
			resp := NewActions(seam).PHPInstall(req(t, ActionPHPInstall, `{"php_version":"8.4.27"}`))
			if resp.OK || !strings.Contains(resp.Error, tt.want) {
				t.Fatalf("%+v, want an error mentioning %q", resp, tt.want)
			}
			if len(seam.removedAll) == 0 || seam.removedAll[len(seam.removedAll)-1] != final {
				t.Errorf("the failed build was not removed: %v", seam.removedAll)
			}
		})
	}
}

func TestPHPPrune(t *testing.T) {
	seam := newPHPSeam()
	seam.exist[runtimes.PHPRoot+"/8.4.9-1"] = true
	seam.dirs[runtimes.PHPRoot] = []string{"8.4.27-1", "libs"} // 8.4.9-1 is gone after the removal
	seam.files[runtimes.PHPRoot+"/8.4.27-1/libs.txt"] = []byte("zlib-1.3.1\nopenssl-3.5.0\n")
	seam.dirs[runtimes.PHPRoot+"/libs"] = []string{"zlib-1.3.1", "openssl-3.5.0", "openssl-3.4.0", "curl-8.9.0"}
	if resp := NewActions(seam).PHPPrune(req(t, ActionPHPPrune, `{"build":"8.4.9-1"}`)); !resp.OK {
		t.Fatalf("prune: %+v", resp)
	}
	got := strings.Join(seam.removedAll, " ")
	for _, want := range []string{runtimes.PHPRoot + "/8.4.9-1", runtimes.PHPRoot + "/libs/openssl-3.4.0", runtimes.PHPRoot + "/libs/curl-8.9.0"} {
		if !strings.Contains(got, want) {
			t.Errorf("not removed: %s (removed: %s)", want, got)
		}
	}
	if strings.Contains(got, "zlib-1.3.1") || strings.Contains(got, "openssl-3.5.0") {
		t.Errorf("a library a remaining build uses was removed: %s", got)
	}
}

func TestPHPPruneKeepsLibsWhenABuildHasNoList(t *testing.T) {
	seam := newPHPSeam()
	seam.exist[runtimes.PHPRoot+"/8.4.9-1"] = true
	seam.dirs[runtimes.PHPRoot] = []string{"8.4.27-1"} // no libs.txt for it
	seam.dirs[runtimes.PHPRoot+"/libs"] = []string{"zlib-1.3.1"}
	if resp := NewActions(seam).PHPPrune(req(t, ActionPHPPrune, `{"build":"8.4.9-1"}`)); !resp.OK {
		t.Fatalf("prune: %+v", resp)
	}
	if strings.Contains(strings.Join(seam.removedAll, " "), "libs/") {
		t.Errorf("libraries removed although a build's needs are unknown: %v", seam.removedAll)
	}
}

func TestPHPPruneRejections(t *testing.T) {
	for _, tt := range []struct{ name, build, want string }{
		{"traversal", "../../etc", "must look like"},
		{"a library name", "libs", "must look like"},
		{"empty", "", "must look like"},
		{"not installed", "8.1.1-1", "not an installed build"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			seam := newPHPSeam()
			resp := NewActions(seam).PHPPrune(Request{Action: ActionPHPPrune, Vals: Spec{Build: tt.build}})
			if resp.OK || !strings.Contains(resp.Error, tt.want) || len(seam.removedAll) != 0 {
				t.Fatalf("%+v removed=%v", resp, seam.removedAll)
			}
		})
	}
}

func TestPHPUserDefault(t *testing.T) {
	seam := newPHPSeam()
	a := NewActions(seam)
	if resp := a.PHPUserDefault(req(t, ActionPHPUserDefault, `{"user":"brian","php_version":"8.4"}`)); !resp.OK {
		t.Fatalf("set: %+v", resp)
	}
	if got := string(seam.written["/etc/servanago/php-users/brian"]); got != "8.4\n" {
		t.Errorf("mapping %q", got)
	}
	for _, p := range []string{"/usr/local/bin/php", "/usr/local/bin/composer", "/usr/local/bin/servanago-php-path", "/etc/profile.d/servanago-php.sh"} {
		if len(seam.written[p]) == 0 {
			t.Errorf("%s not written", p)
		}
	}
	if resp := a.PHPUserDefault(req(t, ActionPHPUserDefault, `{"user":"brian"}`)); !resp.OK || seam.removed != "/etc/servanago/php-users/brian" {
		t.Errorf("clear: %+v removed %q", resp, seam.removed)
	}
}

func TestPHPUserDefaultRejections(t *testing.T) {
	tests := []struct {
		name, user, label string
		userErr           error
		want              string
	}{
		{"path in user", "../root", "8.4", nil, "not a valid user"},
		{"slash in user", "a/b", "8.4", nil, "not a valid user"},
		{"empty user", "", "8.4", nil, "not a valid user"},
		{"uppercase user", "Brian", "8.4", nil, "not a valid user"},
		{"traversal label", "brian", "../../x", nil, "must be a branch"},
		{"shell in label", "brian", "8.4;id", nil, "must be a branch"},
		{"newline label", "brian", "8.4\nroot", nil, "must be a branch"},
		{"system user", "daemon", "8.4", errors.New("uid 1 is not a regular login user"), "regular login user"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seam := newPHPSeam()
			seam.userErr = tt.userErr
			resp := NewActions(seam).PHPUserDefault(Request{Action: ActionPHPUserDefault, Vals: Spec{User: tt.user, PHPVersion: tt.label}})
			if resp.OK || !strings.Contains(resp.Error, tt.want) {
				t.Fatalf("%+v, want an error mentioning %q", resp, tt.want)
			}
			if len(seam.written) != 0 {
				t.Errorf("host was written: %v", keys(seam.written))
			}
		})
	}
}

func TestComposerInstall(t *testing.T) {
	phar := []byte("<?php phar")
	sum := sha256.Sum256(phar)
	good := hex.EncodeToString(sum[:])
	seam := newPHPSeam()
	seam.fetched = map[string][]byte{composerURL: phar, composerURL + ".sha256": []byte(good + "  composer.phar\n")}
	if resp := NewActions(seam).Composer(req(t, ActionComposer, `{}`)); !resp.OK || string(seam.written[composerPhar]) != string(phar) {
		t.Fatalf("install: %+v", resp)
	}
	seam = newPHPSeam()
	seam.fetched = map[string][]byte{composerURL: []byte("tampered"), composerURL + ".sha256": []byte(good + "  composer.phar\n")}
	if resp := NewActions(seam).Composer(req(t, ActionComposer, `{}`)); resp.OK || !strings.Contains(resp.Error, "does not match") || len(seam.written) != 0 {
		t.Fatalf("a tampered phar was installed: %+v", resp)
	}
	seam = newPHPSeam()
	seam.fetched = map[string][]byte{composerURL: phar, composerURL + ".sha256": []byte("not a hash")}
	if resp := NewActions(seam).Composer(req(t, ActionComposer, `{}`)); resp.OK || len(seam.written) != 0 {
		t.Fatalf("a bad checksum file was accepted: %+v", resp)
	}
}

func TestCopyTree(t *testing.T) {
	src := filepath.Join(t.TempDir(), "stage")
	mk := func(p, content string, mode os.FileMode) {
		t.Helper()
		full := filepath.Join(src, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(full, mode); err != nil {
			t.Fatal(err)
		}
	}
	mk("bin/php", "elf", 0o4777)        // setuid and world-writable: both must go
	mk("lib/libz.so.1.3", "lib", 0o666) // no execute bit stays none
	if err := os.Symlink("libz.so.1.3", filepath.Join(src, "lib/libz.so")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/opt/servanago/php/libs/zlib-1.3.1/lib/libz.so", filepath.Join(src, "lib/abs")); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "out")
	if err := copyTree(src, dst, "/opt/servanago/php", nil); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(filepath.Join(dst, "bin/php"))
	if err != nil || fi.Mode().Perm() != 0o755 || fi.Mode()&os.ModeSetuid != 0 {
		t.Errorf("bin/php mode %v (%v)", fi.Mode(), err)
	}
	if fi, _ := os.Lstat(filepath.Join(dst, "lib/libz.so.1.3")); fi.Mode().Perm() != 0o644 {
		t.Errorf("lib mode %v", fi.Mode())
	}
	if l, err := os.Readlink(filepath.Join(dst, "lib/libz.so")); err != nil || l != "libz.so.1.3" {
		t.Errorf("relative link: %q %v", l, err)
	}
	if err := copyTree(src, dst, "/opt/servanago/php", nil); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("an existing destination must be refused: %v", err)
	}
}

func TestCopyTreeRefusesEscapes(t *testing.T) {
	tests := []struct {
		name, target, want string
	}{
		{"relative escape", "../../etc/passwd", "leaves the build"},
		{"relative escape via subdir", "sub/../../x", "leaves the build"},
		{"absolute outside", "/etc/shadow", "leaves the build"},
		{"absolute in a lookalike prefix", "/opt/servanago/php-evil/x", "leaves the build"},
		{"absolute traversal out of the prefix", "/opt/servanago/php/../../etc/shadow", "leaves the build"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := filepath.Join(t.TempDir(), "stage")
			if err := os.MkdirAll(src, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(tt.target, filepath.Join(src, "link")); err != nil {
				t.Fatal(err)
			}
			dst := filepath.Join(t.TempDir(), "out")
			err := copyTree(src, dst, "/opt/servanago/php", nil)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err %v, want %q", err, tt.want)
			}
			if _, statErr := os.Lstat(dst); statErr == nil {
				t.Error("a refused copy left a partial tree behind")
			}
		})
	}
}

func TestCopyTreeRefusesSpecialFiles(t *testing.T) {
	src := filepath.Join(t.TempDir(), "stage")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("mkfifo", filepath.Join(src, "pipe")).Run(); err != nil {
		t.Skip("mkfifo unavailable")
	}
	if err := copyTree(src, filepath.Join(t.TempDir(), "out"), "", nil); err == nil || !strings.Contains(err.Error(), "not a file") {
		t.Errorf("a fifo was copied: %v", err)
	}
}

// The shims are shell: run them against a temp tree through the same environment overrides a test host can set.
func TestUserDefaultShell(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	dir := t.TempDir()
	root, users, bin := filepath.Join(dir, "php"), filepath.Join(dir, "users"), filepath.Join(dir, "bin")
	for _, d := range []string{users, bin} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	fakePHP := func(label string) {
		p := filepath.Join(root, label, "bin")
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p, "php"), []byte("#!/bin/sh\necho \""+label+" $*\"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, l := range []string{"8.4.9-1", "8.4.27-1", "8.3.36-1"} {
		fakePHP(l)
	}
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write("servanago-php-path", pathScript)
	write("php", phpShim)
	write("composer", composerShim)
	me, _ := exec.Command("id", "-un").Output()
	user := strings.TrimSpace(string(me))
	setLabel := func(label string) {
		if label == "" {
			_ = os.Remove(filepath.Join(users, user))
			return
		}
		if err := os.WriteFile(filepath.Join(users, user), []byte(label+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run := func(name string, args ...string) string {
		cmd := exec.Command(filepath.Join(bin, name), args...)
		cmd.Env = append(os.Environ(), "SERVANAGO_PHP_ROOT="+root, "SERVANAGO_PHP_USERS="+users, "SERVANAGO_COMPOSER=-composer.phar")
		out, _ := cmd.CombinedOutput()
		return strings.TrimSpace(string(out))
	}
	tests := []struct{ label, want string }{
		{"8.4", "8.4.27-1 -v"},      // a branch follows the newest build, 27 beats 9
		{"8.4.9-1", "8.4.9-1 -v"},   // an exact build
		{"8.4.20-1", "8.4.27-1 -v"}, // a pruned exact build falls back to its branch
		{"8.3", "8.3.36-1 -v"},
		{"7.4", ""},     // nothing installed for the branch: the resolver prints nothing and the shim uses the distro php
		{"../../x", ""}, // never leaves the root
		{"8.4;id", ""},
		{"", ""}, // no mapping at all
	}
	for _, tt := range tests {
		setLabel(tt.label)
		path := run("servanago-php-path")
		if tt.want == "" {
			if path != "" {
				t.Errorf("label %q: resolver printed %q, want nothing", tt.label, path)
			}
			continue
		}
		out, err := exec.Command(path, "-v").CombinedOutput()
		if err != nil || strings.TrimSpace(string(out)) != tt.want {
			t.Errorf("label %q: %q (%v), want %q", tt.label, out, err, tt.want)
		}
	}
	setLabel("8.4")
	if got := run("php", "-v"); got != "8.4.27-1 -v" {
		t.Errorf("php shim: %q", got)
	}
	if got := run("composer", "about"); got != "8.4.27-1 -composer.phar about" {
		t.Errorf("composer shim: %q", got)
	}
}
