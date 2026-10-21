package phpbuild

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/servanago/servanago/internal/phplibs"
)

type fixture struct {
	t        *testing.T
	dir      string
	root     string
	feeds    map[string][]byte
	ran      []string
	verified []string
	verr     error
	runErr   func(c phplibs.Cmd) error
	libs     []phplibs.Resolved
	exts     []phplibs.ExtSource
}

// zipOf builds a zip in memory from name -> content.
func zipOf(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

const phpTar = "php source bytes"

func sum(b string) string { s := sha256.Sum256([]byte(b)); return hex.EncodeToString(s[:]) }

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{t: t, dir: t.TempDir(), root: t.TempDir(), feeds: map[string][]byte{}}
	rel, _ := json.Marshal(map[string]any{"version": "8.4.27", "source": []map[string]string{
		{"filename": "php-8.4.27.tar.gz", "sha256": sum("other")},
		{"filename": "php-8.4.27.tar.xz", "sha256": sum(phpTar)},
	}})
	f.feeds["https://www.php.net/releases/index.php?json&version=8.4.27"] = rel
	f.feeds["https://www.php.net/distributions/php-8.4.27.tar.xz"] = []byte(phpTar)
	f.feeds["https://www.php.net/distributions/php-8.4.27.tar.xz.asc"] = []byte("sig")
	f.feeds["https://zlib.example/zlib-1.3.1.tar.xz"] = []byte("zlib")
	f.feeds["https://ssl.example/openssl-3.5.0.tar.gz"] = []byte("openssl")
	f.libs = []phplibs.Resolved{
		{Name: "zlib", Version: "1.3.1", URL: "https://zlib.example/zlib-1.3.1.tar.xz", Algo: phplibs.AlgoSHA256, Sum: sum("zlib")},
		{Name: "openssl", Version: "3.5.0", URL: "https://ssl.example/openssl-3.5.0.tar.gz", Algo: phplibs.AlgoSHA256, Sum: sum("openssl")},
		{Name: "imagemagick", Version: "7.1.2-34", URL: "https://im.example/ImageMagick-7.1.2-34.tar.xz", Algo: phplibs.AlgoSHA256, Sum: sum("im")},
	}
	f.feeds["https://im.example/ImageMagick-7.1.2-34.tar.xz"] = []byte("im")
	const sha = "819fce90c469a5666b1706036cd66120af419f1f"
	f.exts = []phplibs.ExtSource{
		{Name: "apcu", Package: "apcu/apcu", Version: "5.1.28", URL: "https://api.github.com/repos/krakjoe/apcu/zipball/" + sha, Commit: sha},
		{Name: "imagick", Package: "imagick/imagick", Version: "3.8.1", URL: "https://api.github.com/repos/Imagick/imagick/zipball/" + sha, Commit: sha},
	}
	for _, x := range f.exts {
		f.feeds[x.URL] = zipOf(t, map[string]string{"owner-" + x.Name + "-819fce9/config.m4": "dnl", "owner-" + x.Name + "-819fce9/" + x.Name + ".c": "/* c */"})
	}
	job, _ := json.Marshal(Job{Version: "8.4.27", N: 2, Jobs: 4})
	if err := os.WriteFile(filepath.Join(f.dir, JobFile), job, 0o644); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) env() Env {
	return Env{
		Root: f.root, Stage: f.root, // same tree: no seeding
		Get: func(ctx context.Context, url string) ([]byte, error) {
			b, ok := f.feeds[url]
			if !ok {
				return nil, fmt.Errorf("no such feed %s", url)
			}
			return b, nil
		},
		Run: func(ctx context.Context, c phplibs.Cmd) error {
			f.ran = append(f.ran, c.Name+" "+strings.Join(c.Args, " "))
			if f.runErr != nil {
				return f.runErr(c)
			}
			// Pretend the install happened, so the build can write libs.txt beside the binaries.
			if c.Name == "make" && len(c.Args) == 1 && c.Args[0] == "install" {
				_ = os.MkdirAll(filepath.Join(f.root, "8.4.27-2"), 0o755)
			}
			return nil
		},
		Verify: func(ctx context.Context, file, sig string) error {
			f.verified = append(f.verified, filepath.Base(file))
			return f.verr
		},
		Libs: func(ctx context.Context) ([]phplibs.Resolved, error) { return f.libs, nil },
		Exts: func(ctx context.Context) ([]phplibs.ExtSource, error) { return f.exts, nil },
	}
}

func (f *fixture) state() State {
	f.t.Helper()
	var st State
	if err := readJSON(filepath.Join(f.dir, StateFile), &st); err != nil {
		f.t.Fatal(err)
	}
	return st
}

func TestFetch(t *testing.T) {
	f := newFixture(t)
	if err := Fetch(context.Background(), f.env(), f.dir); err != nil {
		t.Fatal(err)
	}
	if st := f.state(); st.Phase != PhaseBuilding || st.N != 2 {
		t.Errorf("state %+v", st)
	}
	if len(f.verified) != 1 || f.verified[0] != "php-8.4.27.tar.xz" {
		t.Errorf("verified %v", f.verified)
	}
	for _, name := range []string{"php-8.4.27.tar.xz", "php-8.4.27.tar.xz.asc", "zlib-1.3.1.tar.xz", "openssl-3.5.0.tar.gz"} {
		if _, err := os.Stat(filepath.Join(f.dir, "src", name)); err != nil {
			t.Errorf("%s not downloaded: %v", name, err)
		}
	}
	var p plan
	if err := readJSON(filepath.Join(f.dir, "plan.json"), &p); err != nil || len(p.Libs) != 3 || len(p.Exts) != 2 || p.Libs[0].Have {
		t.Errorf("plan %+v (%v)", p, err)
	}
}

// Every row fails closed and says why; the state file records the failure for the PHP page.
func TestFetchFailsClosed(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*fixture)
		want  string
	}{
		{"php tarball tampered", func(f *fixture) { f.feeds["https://www.php.net/distributions/php-8.4.27.tar.xz"] = []byte("evil") }, "sha256 mismatch"},
		{"bad php signature", func(f *fixture) { f.verr = errors.New("BADSIG") }, "signature: BADSIG"},
		{"php.net has no checksum for the file", func(f *fixture) {
			f.feeds["https://www.php.net/releases/index.php?json&version=8.4.27"] = []byte(`{"version":"8.4.27","source":[]}`)
		}, "publishes no sha256"},
		{"php.net answers for another version", func(f *fixture) {
			f.feeds["https://www.php.net/releases/index.php?json&version=8.4.27"] = []byte(`{"version":"8.4.26","source":[]}`)
		}, "no release record"},
		{"php.net unreachable", func(f *fixture) { delete(f.feeds, "https://www.php.net/releases/index.php?json&version=8.4.27") }, "release record"},
		{"library tarball tampered", func(f *fixture) { f.feeds["https://zlib.example/zlib-1.3.1.tar.xz"] = []byte("evil") }, "zlib-1.3.1: sha256 mismatch"},
		{"library tarball missing", func(f *fixture) { delete(f.feeds, "https://ssl.example/openssl-3.5.0.tar.gz") }, "download openssl-3.5.0"},
		{"library over plain http", func(f *fixture) { f.libs[0].URL = "http://zlib.example/zlib-1.3.1.tar.xz" }, "not an https URL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			tt.setup(f)
			err := Fetch(context.Background(), f.env(), f.dir)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err %v, want one mentioning %q", err, tt.want)
			}
			if st := f.state(); st.Phase != PhaseFailed || !strings.Contains(st.Message, tt.want) {
				t.Errorf("state %+v", st)
			}
			if _, statErr := os.Stat(filepath.Join(f.dir, "plan.json")); statErr == nil {
				t.Error("a failed fetch must not leave a plan for build to use")
			}
		})
	}
}

func TestFetchRejectsBadJob(t *testing.T) {
	for _, job := range []string{`{"version":"8.4","n":1}`, `{"version":"8.4.27;id","n":1}`, `{"version":"8.4.27","n":0}`, `{"version":"../x","n":1}`} {
		f := newFixture(t)
		if err := os.WriteFile(filepath.Join(f.dir, JobFile), []byte(job), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := Fetch(context.Background(), f.env(), f.dir); err == nil || !strings.Contains(err.Error(), "not a valid build") {
			t.Errorf("%s accepted: %v", job, err)
		}
	}
}

func TestFetchReusesInstalledLibraries(t *testing.T) {
	f := newFixture(t)
	if err := os.MkdirAll(filepath.Join(f.root, "libs", "zlib-1.3.1"), 0o755); err != nil {
		t.Fatal(err)
	}
	delete(f.feeds, "https://zlib.example/zlib-1.3.1.tar.xz") // would fail if it were downloaded
	if err := Fetch(context.Background(), f.env(), f.dir); err != nil {
		t.Fatal(err)
	}
	var p plan
	if err := readJSON(filepath.Join(f.dir, "plan.json"), &p); err != nil || !p.Libs[0].Have || p.Libs[1].Have {
		t.Errorf("plan %+v (%v)", p, err)
	}
}

func TestFetchSeedsTheStage(t *testing.T) {
	f := newFixture(t)
	stage := t.TempDir()
	if err := os.MkdirAll(filepath.Join(f.root, "libs", "zlib-1.3.1"), 0o755); err != nil {
		t.Fatal(err)
	}
	e := f.env()
	e.Stage = stage
	var copied [][2]string
	e.Copy = func(ctx context.Context, from, to string) error {
		copied = append(copied, [2]string{from, to})
		return nil
	}
	if err := Fetch(context.Background(), e, f.dir); err != nil {
		t.Fatal(err)
	}
	want := [2]string{filepath.Join(f.root, "libs", "zlib-1.3.1"), filepath.Join(stage, "libs", "zlib-1.3.1")}
	if len(copied) != 1 || copied[0] != want {
		t.Errorf("seeded %v, want %v", copied, want)
	}
}

func TestBuild(t *testing.T) {
	f := newFixture(t)
	if err := Fetch(context.Background(), f.env(), f.dir); err != nil {
		t.Fatal(err)
	}
	f.ran = nil
	if err := Build(context.Background(), f.env(), f.dir); err != nil {
		t.Fatal(err)
	}
	if st := f.state(); st.Phase != PhaseBuilt || st.Version != "8.4.27" || st.N != 2 {
		t.Errorf("state %+v", st)
	}
	all := strings.Join(f.ran, "\n")
	for _, want := range []string{"tar -xf " + filepath.Join(f.dir, "src", "zlib-1.3.1.tar.xz"), "--prefix=" + filepath.Join(f.root, "8.4.27-2"), "make -j4", "make install"} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q in:\n%s", want, all)
		}
	}
	if strings.Index(all, "zlib-1.3.1.tar.xz") > strings.Index(all, "openssl-3.5.0.tar.gz") {
		t.Errorf("libraries must build in order:\n%s", all)
	}
	libs, err := os.ReadFile(filepath.Join(f.root, "8.4.27-2", "libs.txt"))
	if err != nil || string(libs) != "zlib-1.3.1\nopenssl-3.5.0\nimagemagick-7.1.2-34\n" {
		t.Errorf("libs.txt %q (%v)", libs, err)
	}
}

// The extensions are built after PHP itself, with the build's own phpize, from the single directory the zipball holds.
func TestBuildExtensions(t *testing.T) {
	f := newFixture(t)
	if err := Fetch(context.Background(), f.env(), f.dir); err != nil {
		t.Fatal(err)
	}
	var cmds []phplibs.Cmd
	f.runErr = func(c phplibs.Cmd) error { cmds = append(cmds, c); return nil }
	prefix := filepath.Join(f.root, "8.4.27-2")
	if err := os.MkdirAll(prefix, 0o755); err != nil { // what the recorded `make install` would have created
		t.Fatal(err)
	}
	if err := Build(context.Background(), f.env(), f.dir); err != nil {
		t.Fatal(err)
	}
	phpInstall, apcuPhpize, imagickConf := -1, -1, -1
	for i, c := range cmds {
		switch {
		case c.Name == "make" && len(c.Args) == 1 && c.Args[0] == "install" && strings.Contains(c.Dir, "php-8.4.27"):
			phpInstall = i
		case c.Name == filepath.Join(prefix, "bin/phpize") && strings.Contains(c.Dir, "ext-apcu"):
			apcuPhpize = i
			if filepath.Base(filepath.Dir(c.Dir)) != "ext-apcu" || filepath.Base(c.Dir) != "owner-apcu-819fce9" {
				t.Errorf("phpize ran in %s", c.Dir)
			}
		case strings.Contains(c.Dir, "ext-imagick") && c.Name == "./configure":
			imagickConf = i
			if !strings.Contains(strings.Join(c.Args, " "), "--with-php-config="+filepath.Join(prefix, "bin/php-config")) ||
				!strings.Contains(strings.Join(c.Args, " "), filepath.Join(f.root, "libs", "imagemagick-7.1.2-34")) {
				t.Errorf("imagick configure: %v", c.Args)
			}
		}
	}
	if phpInstall < 0 || apcuPhpize < phpInstall || imagickConf < apcuPhpize {
		t.Errorf("order: php install %d, apcu phpize %d, imagick configure %d", phpInstall, apcuPhpize, imagickConf)
	}
}

func TestFetchExtensionsFailClosed(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*fixture)
		want  string
	}{
		{"not a zip", func(f *fixture) { f.feeds[f.exts[0].URL] = []byte("<html>rate limited</html>") }, "not a zip file"},
		{"download fails", func(f *fixture) { delete(f.feeds, f.exts[1].URL) }, "download imagick 3.8.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			tt.setup(f)
			err := Fetch(context.Background(), f.env(), f.dir)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err %v, want %q", err, tt.want)
			}
			if _, statErr := os.Stat(filepath.Join(f.dir, "plan.json")); statErr == nil {
				t.Error("a failed fetch left a plan")
			}
		})
	}
}

// A zip that tries to write outside its directory, or holds a symlink, is refused before anything is compiled.
func TestUnzipRefusesEscapes(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"parent directory": {"../evil": "x"},
		"deep parent":      {"a/../../evil": "x"},
		"absolute":         {"/etc/evil": "x"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			file := filepath.Join(dir, "x.zip")
			if err := os.WriteFile(file, zipOf(t, files), 0o644); err != nil {
				t.Fatal(err)
			}
			dst := filepath.Join(dir, "out")
			if err := unzip(file, dst); err == nil || !strings.Contains(err.Error(), "leaves the destination") {
				t.Fatalf("err %v", err)
			}
			if _, err := os.Stat(filepath.Join(dir, "evil")); err == nil {
				t.Error("a file was written outside the destination")
			}
		})
	}
}

func TestUnzipRefusesSymlinks(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	h := &zip.FileHeader{Name: "top/link"}
	h.SetMode(os.ModeSymlink | 0o777)
	w, _ := zw.CreateHeader(h)
	_, _ = w.Write([]byte("/etc/passwd"))
	_ = zw.Close()
	dir := t.TempDir()
	file := filepath.Join(dir, "x.zip")
	if err := os.WriteFile(file, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := unzip(file, filepath.Join(dir, "out")); err == nil || !strings.Contains(err.Error(), "not a file or directory") {
		t.Fatalf("err %v", err)
	}
}

func TestOnlyChild(t *testing.T) {
	dir := t.TempDir()
	if _, err := onlyChild(dir); err == nil {
		t.Error("an empty directory has no top-level directory")
	}
	for _, d := range []string{"a", "b"} {
		_ = os.Mkdir(filepath.Join(dir, d), 0o755)
	}
	if _, err := onlyChild(dir); err == nil {
		t.Error("two entries must be refused")
	}
}

func TestBuildSkipsInstalledLibraries(t *testing.T) {
	f := newFixture(t)
	if err := os.MkdirAll(filepath.Join(f.root, "libs", "zlib-1.3.1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Fetch(context.Background(), f.env(), f.dir); err != nil {
		t.Fatal(err)
	}
	f.ran = nil
	if err := Build(context.Background(), f.env(), f.dir); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.ran {
		if strings.Contains(c, "zlib-1.3.1.tar.xz") {
			t.Errorf("an installed library was rebuilt: %s", c)
		}
	}
	// It is still listed, because the build links against it.
	if libs, _ := os.ReadFile(filepath.Join(f.root, "8.4.27-2", "libs.txt")); !strings.Contains(string(libs), "zlib-1.3.1") {
		t.Errorf("libs.txt %q", libs)
	}
}

func TestBuildFailureIsRecorded(t *testing.T) {
	f := newFixture(t)
	if err := Fetch(context.Background(), f.env(), f.dir); err != nil {
		t.Fatal(err)
	}
	f.runErr = func(c phplibs.Cmd) error {
		if c.Name == "./configure" && strings.Contains(strings.Join(c.Args, " "), "--enable-fpm") {
			return errors.New("exit status 1")
		}
		return nil
	}
	err := Build(context.Background(), f.env(), f.dir)
	if err == nil || !strings.Contains(err.Error(), "build php: ./configure") {
		t.Fatalf("err %v", err)
	}
	if st := f.state(); st.Phase != PhaseFailed || !strings.Contains(st.Message, "configure") {
		t.Errorf("state %+v", st)
	}
	if _, statErr := os.Stat(filepath.Join(f.root, "8.4.27-2", "libs.txt")); statErr == nil {
		t.Error("a failed build must not look finished")
	}
}

func TestBuildNeedsAPlan(t *testing.T) {
	f := newFixture(t)
	if err := Build(context.Background(), f.env(), f.dir); err == nil || !strings.Contains(err.Error(), "read the plan") {
		t.Fatalf("err %v", err)
	}
}

func TestPHPConfigure(t *testing.T) {
	args, env := PHPConfigure("8.4.27", "/opt/servanago/php/8.4.27-1", map[string]string{"openssl": "/opt/servanago/php/libs/openssl-3.5.0"})
	got := strings.Join(args, " ")
	for _, want := range []string{"--prefix=/opt/servanago/php/8.4.27-1", "--enable-fpm", "--disable-cgi", "--without-pear", "--with-openssl ", "--enable-opcache=shared",
		"--enable-mbstring=shared", "--with-curl=shared", "--with-mysqli=shared,mysqlnd", "--with-pdo-pgsql=shared"} {
		if !strings.Contains(got+" ", want) {
			t.Errorf("configure missing %q:\n%s", want, got)
		}
	}
	if !strings.Contains(strings.Join(env, " "), "-Wl,-rpath,/opt/servanago/php/libs/openssl-3.5.0/lib") {
		t.Errorf("no RUNPATH to the library in %v", env)
	}
	// PHP 8.5 builds opcache in and dropped the flag.
	args85, _ := PHPConfigure("8.5.12", "/p", nil)
	if strings.Contains(strings.Join(args85, " "), "opcache") {
		t.Errorf("8.5 configure still names opcache: %v", args85)
	}
}
