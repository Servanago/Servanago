package phpbuild

import (
	"context"
	"crypto/sha256"
	"crypto/sha3"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/servanago/servanago/internal/phplibs"
)

// Env is what the job needs from outside: HTTP, running commands, checking a signature, and where trees live.
// The units set Root to /opt/servanago/php (the build unit bind-mounts Stage there) and Stage to Dir/root; a test
// points both at a temp directory.
type Env struct {
	Get    phplibs.Getter
	Run    func(ctx context.Context, c phplibs.Cmd) error         // c.Dir is absolute
	Verify func(ctx context.Context, file, sig string) error      // GPG: a good signature from a key in the PHP keyring
	Libs   func(ctx context.Context) ([]phplibs.Resolved, error)  // nil = resolve every library from its feed
	Exts   func(ctx context.Context) ([]phplibs.ExtSource, error) // nil = resolve every PECL extension from Packagist
	Copy   func(ctx context.Context, from, to string) error       // seeds an installed library into the stage; nil = cp -a
	Root   string
	Stage  string
	Log    io.Writer
}

var versionRE = regexp.MustCompile(`^[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,3}$`)

// plan is what fetch leaves for build: the verified files and which libraries still need compiling.
type plan struct {
	PHPFile string    `json:"php_file"`
	Libs    []planLib `json:"libs"`
	Exts    []planExt `json:"exts"`
}

// planExt is a PECL extension's source: a GitHub zipball of the commit Packagist names.
type planExt struct {
	phplibs.ExtSource
	File string `json:"file"`
}

type planLib struct {
	phplibs.Resolved
	File string `json:"file,omitempty"` // downloaded tarball in src/
	Have bool   `json:"have"`           // already installed (and seeded into the stage): not rebuilt
}

func (l planLib) dir() string { return phplibs.Dir(l.Resolved) }

func readJSON(file string, v any) error {
	b, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// SetState writes the state file atomically (the helper reads it while the job runs).
func SetState(dir string, st State) error {
	b, _ := json.Marshal(st)
	tmp := filepath.Join(dir, StateFile+".tmp")
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, StateFile))
}

// Fail records a failed job. The message is what the PHP page shows next to the log.
func Fail(dir string, job Job, err error) {
	_ = SetState(dir, State{Phase: PhaseFailed, Version: job.Version, N: job.N, Message: err.Error()})
}

func (e Env) logf(format string, a ...any) {
	if e.Log != nil {
		fmt.Fprintf(e.Log, format+"\n", a...)
	}
}

func checkSum(algo string, data []byte, want string) error {
	var got string
	switch algo {
	case phplibs.AlgoSHA256:
		s := sha256.Sum256(data)
		got = hex.EncodeToString(s[:])
	case phplibs.AlgoSHA3:
		s := sha3.Sum256(data)
		got = hex.EncodeToString(s[:])
	default:
		return fmt.Errorf("unknown checksum algorithm %q", algo)
	}
	if got != strings.ToLower(want) {
		return fmt.Errorf("%s mismatch: got %s, want %s", algo, got, want)
	}
	return nil
}

type phpRelease struct {
	Version string `json:"version"`
	Source  []struct {
		Filename string `json:"filename"`
		SHA256   string `json:"sha256"`
	} `json:"source"`
}

// Fetch downloads and verifies the PHP source (GPG and the sha256 php.net publishes) and every library tarball
// (the checksum their release feed publishes), seeds already-installed libraries into the stage, and leaves plan.json.
// It runs with network access; Build runs without.
func Fetch(ctx context.Context, e Env, dir string) (err error) {
	var job Job
	if err := readJSON(filepath.Join(dir, JobFile), &job); err != nil {
		return fmt.Errorf("read the job: %w", err)
	}
	defer func() {
		if err != nil {
			Fail(dir, job, err)
		}
	}()
	if !versionRE.MatchString(job.Version) || job.N < 1 {
		return fmt.Errorf("job %+v is not a valid build", job)
	}
	if err := SetState(dir, State{Phase: PhaseFetching, Version: job.Version, N: job.N}); err != nil {
		return err
	}
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		return err
	}

	phpFile, err := e.fetchPHP(ctx, src, job.Version)
	if err != nil {
		return err
	}
	p := plan{PHPFile: phpFile}
	if p.Libs, err = e.fetchLibs(ctx, dir, src); err != nil {
		return err
	}
	if p.Exts, err = e.fetchExts(ctx, src); err != nil {
		return err
	}
	pb, _ := json.Marshal(p)
	if err := os.WriteFile(filepath.Join(dir, "plan.json"), pb, 0o644); err != nil {
		return err
	}
	return SetState(dir, State{Phase: PhaseBuilding, Version: job.Version, N: job.N})
}

// fetchPHP downloads the PHP tarball into src: the version's release record gives the sha256, and the detached
// signature is checked against the PHP keyring. It returns the tarball's file name.
func (e Env) fetchPHP(ctx context.Context, src, version string) (string, error) {
	body, err := e.Get(ctx, "https://www.php.net/releases/index.php?json&version="+version)
	if err != nil {
		return "", fmt.Errorf("php.net release record: %w", err)
	}
	var rel phpRelease
	if err := json.Unmarshal(body, &rel); err != nil || rel.Version != version {
		return "", fmt.Errorf("php.net returned no release record for %s", version)
	}
	phpFile := "php-" + version + ".tar.xz"
	sum := ""
	for _, s := range rel.Source {
		if s.Filename == phpFile {
			sum = s.SHA256
		}
	}
	if sum == "" {
		return "", fmt.Errorf("php.net publishes no sha256 for %s", phpFile)
	}
	e.logf("downloading %s", phpFile)
	tarball, err := e.Get(ctx, "https://www.php.net/distributions/"+phpFile)
	if err != nil {
		return "", fmt.Errorf("download %s: %w", phpFile, err)
	}
	if err := checkSum(phplibs.AlgoSHA256, tarball, sum); err != nil {
		return "", fmt.Errorf("%s: %w", phpFile, err)
	}
	sig, err := e.Get(ctx, "https://www.php.net/distributions/"+phpFile+".asc")
	if err != nil {
		return "", fmt.Errorf("download the %s signature: %w", phpFile, err)
	}
	if err := os.WriteFile(filepath.Join(src, phpFile), tarball, 0o644); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(src, phpFile+".asc"), sig, 0o644); err != nil {
		return "", err
	}
	if err := e.Verify(ctx, filepath.Join(src, phpFile), filepath.Join(src, phpFile+".asc")); err != nil {
		return "", fmt.Errorf("%s signature: %w", phpFile, err)
	}
	e.logf("%s: sha256 and GPG signature verified", phpFile)
	return phpFile, nil
}

// fetchLibs resolves every library, reuses (and seeds into the stage) the ones already installed under the same
// directory name, and downloads and checksums the rest into src.
func (e Env) fetchLibs(ctx context.Context, dir, src string) ([]planLib, error) {
	libs := e.Libs
	if libs == nil {
		libs = func(ctx context.Context) ([]phplibs.Resolved, error) {
			var out []phplibs.Resolved
			for _, n := range phplibs.Names() {
				r, err := phplibs.Resolve(ctx, e.Get, n)
				if err != nil {
					return nil, err
				}
				out = append(out, r)
			}
			return out, nil
		}
	}
	resolved, err := libs(ctx)
	if err != nil {
		return nil, err
	}
	var out []planLib
	for _, r := range resolved {
		l := planLib{Resolved: r}
		if _, err := os.Lstat(filepath.Join(e.Root, "libs", l.dir())); err == nil { // installed: seed it, do not rebuild
			l.Have = true
			if e.Stage != e.Root {
				copyLib := e.Copy
				if copyLib == nil {
					copyLib = func(ctx context.Context, from, to string) error {
						return e.Run(ctx, phplibs.Cmd{Dir: dir, Name: "cp", Args: []string{"-a", from, to}})
					}
				}
				if err := os.MkdirAll(filepath.Join(e.Stage, "libs"), 0o755); err != nil {
					return nil, err
				}
				if err := copyLib(ctx, filepath.Join(e.Root, "libs", l.dir()), filepath.Join(e.Stage, "libs", l.dir())); err != nil {
					return nil, fmt.Errorf("reuse %s: %w", l.dir(), err)
				}
			}
			e.logf("%s: already installed, reused", l.dir())
			out = append(out, l)
			continue
		}
		u, err := url.Parse(r.URL)
		if err != nil || u.Scheme != "https" {
			return nil, fmt.Errorf("%s: %q is not an https URL", r.Name, r.URL)
		}
		l.File = path.Base(u.Path)
		if l.File == "" || l.File == "." || l.File == "/" || strings.ContainsAny(l.File, `\`) {
			return nil, fmt.Errorf("%s: cannot name the tarball %q", r.Name, r.URL)
		}
		e.logf("downloading %s", r.URL)
		data, err := e.Get(ctx, r.URL)
		if err != nil {
			return nil, fmt.Errorf("download %s: %w", l.dir(), err)
		}
		if err := checkSum(r.Algo, data, r.Sum); err != nil {
			return nil, fmt.Errorf("%s: %w", l.dir(), err)
		}
		if err := os.WriteFile(filepath.Join(src, l.File), data, 0o644); err != nil {
			return nil, err
		}
		e.logf("%s: %s verified%s", l.dir(), r.Algo, map[bool]string{true: " (pinned, not feed-tracked)"}[r.Pinned])
		out = append(out, l)
	}
	return out, nil
}

// fetchExts downloads the PECL extension sources. Packagist and GitHub publish no checksum for these (decided: trust
// them over HTTPS at the commit Packagist names), so the log records the commit and the zipball's sha256 for anyone
// who wants to audit a build.
func (e Env) fetchExts(ctx context.Context, src string) ([]planExt, error) {
	exts := e.Exts
	if exts == nil {
		exts = func(ctx context.Context) ([]phplibs.ExtSource, error) {
			var out []phplibs.ExtSource
			for _, n := range phplibs.ExtNames() {
				x, err := phplibs.ResolveExt(ctx, e.Get, n)
				if err != nil {
					return nil, err
				}
				out = append(out, x)
			}
			return out, nil
		}
	}
	extSrc, err := exts(ctx)
	if err != nil {
		return nil, err
	}
	var out []planExt
	for _, x := range extSrc {
		e.logf("downloading %s", x.URL)
		data, err := e.Get(ctx, x.URL)
		if err != nil {
			return nil, fmt.Errorf("download %s %s: %w", x.Name, x.Version, err)
		}
		if len(data) < 4 || string(data[:2]) != "PK" {
			return nil, fmt.Errorf("%s %s: the download is not a zip file", x.Name, x.Version)
		}
		file := "ext-" + x.Name + "-" + x.Version + ".zip"
		if err := os.WriteFile(filepath.Join(src, file), data, 0o644); err != nil {
			return nil, err
		}
		sum := sha256.Sum256(data)
		e.logf("%s %s (%s) commit %s sha256 %x: no checksum is published, trusted at that commit over HTTPS", x.Name, x.Version, x.Package, x.Commit, sum)
		out = append(out, planExt{ExtSource: x, File: file})
	}
	return out, nil
}

// Build compiles the libraries that are not installed yet and then PHP, each into its final prefix under e.Root.
func Build(ctx context.Context, e Env, dir string) (err error) {
	var job Job
	var p plan
	if err := readJSON(filepath.Join(dir, JobFile), &job); err != nil {
		return fmt.Errorf("read the job: %w", err)
	}
	defer func() {
		if err != nil {
			Fail(dir, job, err)
		}
	}()
	if err := readJSON(filepath.Join(dir, "plan.json"), &p); err != nil {
		return fmt.Errorf("read the plan: %w", err)
	}
	if !versionRE.MatchString(job.Version) || job.N < 1 {
		return fmt.Errorf("job %+v is not a valid build", job)
	}
	if err := SetState(dir, State{Phase: PhaseBuilding, Version: job.Version, N: job.N}); err != nil {
		return err
	}
	b := builder{Env: e, src: filepath.Join(dir, "src"), work: filepath.Join(dir, "work")}
	if err := os.MkdirAll(b.work, 0o755); err != nil {
		return err
	}
	deps, err := b.libs(ctx, p.Libs, job.Jobs)
	if err != nil {
		return err
	}
	prefix, err := b.php(ctx, job, p.PHPFile, deps)
	if err != nil {
		return err
	}
	if err := b.exts(ctx, p.Exts, prefix, deps, job.Jobs); err != nil {
		return err
	}
	var used []string
	for _, l := range p.Libs {
		used = append(used, l.dir())
	}
	if err := os.WriteFile(filepath.Join(prefix, "libs.txt"), []byte(strings.Join(used, "\n")+"\n"), 0o644); err != nil {
		return fmt.Errorf("record the libraries: %w", err)
	}
	return SetState(dir, State{Phase: PhaseBuilt, Version: job.Version, N: job.N})
}

// builder is one Build run: the Env plus the directories Fetch filled (src) and compilation uses (work).
type builder struct {
	Env
	src, work string
}

func (b builder) run(ctx context.Context, c phplibs.Cmd) error {
	b.logf("+ %s %s", c.Name, strings.Join(c.Args, " "))
	return b.Run(ctx, c)
}

func (b builder) unpack(ctx context.Context, file, into string) error {
	if err := os.MkdirAll(into, 0o755); err != nil {
		return err
	}
	return b.run(ctx, phplibs.Cmd{Dir: b.work, Name: "tar", Args: []string{"-xf", filepath.Join(b.src, file), "-C", into}})
}

// libs builds the libraries that are not installed yet and returns every library's prefix by name.
func (b builder) libs(ctx context.Context, libs []planLib, jobs int) (map[string]string, error) {
	deps := map[string]string{}
	for _, l := range libs {
		prefix := filepath.Join(b.Root, "libs", l.dir())
		if !l.Have {
			b.logf("== building %s", l.dir())
			into := filepath.Join(b.work, l.Name)
			if err := b.unpack(ctx, l.File, into); err != nil {
				return nil, fmt.Errorf("unpack %s: %w", l.dir(), err)
			}
			srcDir := filepath.Join(into, phplibs.SourceDir(l.Resolved))
			for _, c := range phplibs.Recipe(l.Resolved, prefix, deps, jobs) {
				c.Dir = filepath.Join(srcDir, c.Dir)
				if err := b.run(ctx, c); err != nil {
					return nil, fmt.Errorf("build %s: %s: %w", l.dir(), c.Name, err)
				}
			}
		}
		deps[l.Name] = prefix
	}
	return deps, nil
}

// php compiles and installs PHP itself against deps and returns its prefix.
func (b builder) php(ctx context.Context, job Job, phpFile string, deps map[string]string) (string, error) {
	b.logf("== building PHP %s", job.Version)
	if err := b.unpack(ctx, phpFile, b.work); err != nil {
		return "", fmt.Errorf("unpack php: %w", err)
	}
	srcDir := filepath.Join(b.work, "php-"+job.Version)
	prefix := filepath.Join(b.Root, job.Label())
	args, env := PHPConfigure(job.Version, prefix, deps)
	jobs := fmt.Sprintf("-j%d", max(job.Jobs, 1))
	for _, c := range []phplibs.Cmd{
		{Dir: srcDir, Env: env, Name: "./configure", Args: args},
		{Dir: srcDir, Env: env, Name: "make", Args: []string{jobs}},
		{Dir: srcDir, Env: env, Name: "make", Args: []string{"install"}},
	} {
		if err := b.run(ctx, c); err != nil {
			return "", fmt.Errorf("build php: %s: %w", c.Name, err)
		}
	}
	return prefix, nil
}

// exts builds the PECL extensions against the PHP just installed, with its own phpize, as shared objects in its
// extension directory.
func (b builder) exts(ctx context.Context, exts []planExt, prefix string, deps map[string]string, jobs int) error {
	for _, x := range exts {
		b.logf("== building %s %s", x.Name, x.Version)
		into := filepath.Join(b.work, "ext-"+x.Name)
		if err := unzip(filepath.Join(b.src, x.File), into); err != nil {
			return fmt.Errorf("unpack %s: %w", x.Name, err)
		}
		top, err := onlyChild(into)
		if err != nil {
			return fmt.Errorf("unpack %s: %w", x.Name, err)
		}
		cmds, err := phplibs.ExtRecipe(x.ExtSource, prefix, deps, jobs)
		if err != nil {
			return fmt.Errorf("build %s: %w", x.Name, err)
		}
		for _, c := range cmds {
			c.Dir = filepath.Join(top, c.Dir)
			if err := b.run(ctx, c); err != nil {
				return fmt.Errorf("build %s: %s: %w", x.Name, filepath.Base(c.Name), err)
			}
		}
	}
	return nil
}
