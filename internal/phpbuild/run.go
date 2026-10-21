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
	Run    func(ctx context.Context, c phplibs.Cmd) error        // c.Dir is absolute
	Verify func(ctx context.Context, file, sig string) error     // GPG: a good signature from a key in the PHP keyring
	Libs   func(ctx context.Context) ([]phplibs.Resolved, error) // nil = resolve every library from its feed
	Copy   func(ctx context.Context, from, to string) error      // seeds an installed library into the stage; nil = cp -a
	Root   string
	Stage  string
	Log    io.Writer
}

var versionRE = regexp.MustCompile(`^[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,3}$`)

// plan is what fetch leaves for build: the verified files and which libraries still need compiling.
type plan struct {
	PHPFile string    `json:"php_file"`
	Libs    []planLib `json:"libs"`
}

type planLib struct {
	phplibs.Resolved
	File string `json:"file,omitempty"` // downloaded tarball in src/
	Have bool   `json:"have"`           // already installed (and seeded into the stage): not rebuilt
}

func (l planLib) dir() string { return l.Name + "-" + l.Version }

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

	// PHP: the version's release record gives the sha256; the detached signature is checked against the PHP keyring.
	body, err := e.Get(ctx, "https://www.php.net/releases/index.php?json&version="+job.Version)
	if err != nil {
		return fmt.Errorf("php.net release record: %w", err)
	}
	var rel phpRelease
	if err := json.Unmarshal(body, &rel); err != nil || rel.Version != job.Version {
		return fmt.Errorf("php.net returned no release record for %s", job.Version)
	}
	phpFile := "php-" + job.Version + ".tar.xz"
	sum := ""
	for _, s := range rel.Source {
		if s.Filename == phpFile {
			sum = s.SHA256
		}
	}
	if sum == "" {
		return fmt.Errorf("php.net publishes no sha256 for %s", phpFile)
	}
	e.logf("downloading %s", phpFile)
	tarball, err := e.Get(ctx, "https://www.php.net/distributions/"+phpFile)
	if err != nil {
		return fmt.Errorf("download %s: %w", phpFile, err)
	}
	if err := checkSum(phplibs.AlgoSHA256, tarball, sum); err != nil {
		return fmt.Errorf("%s: %w", phpFile, err)
	}
	sig, err := e.Get(ctx, "https://www.php.net/distributions/"+phpFile+".asc")
	if err != nil {
		return fmt.Errorf("download the %s signature: %w", phpFile, err)
	}
	if err := os.WriteFile(filepath.Join(src, phpFile), tarball, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(src, phpFile+".asc"), sig, 0o644); err != nil {
		return err
	}
	if err := e.Verify(ctx, filepath.Join(src, phpFile), filepath.Join(src, phpFile+".asc")); err != nil {
		return fmt.Errorf("%s signature: %w", phpFile, err)
	}
	e.logf("%s: sha256 and GPG signature verified", phpFile)

	// Libraries.
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
		return err
	}
	p := plan{PHPFile: phpFile}
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
					return err
				}
				if err := copyLib(ctx, filepath.Join(e.Root, "libs", l.dir()), filepath.Join(e.Stage, "libs", l.dir())); err != nil {
					return fmt.Errorf("reuse %s: %w", l.dir(), err)
				}
			}
			e.logf("%s: already installed, reused", l.dir())
			p.Libs = append(p.Libs, l)
			continue
		}
		u, err := url.Parse(r.URL)
		if err != nil || u.Scheme != "https" {
			return fmt.Errorf("%s: %q is not an https URL", r.Name, r.URL)
		}
		l.File = path.Base(u.Path)
		if l.File == "" || l.File == "." || l.File == "/" || strings.ContainsAny(l.File, `\`) {
			return fmt.Errorf("%s: cannot name the tarball %q", r.Name, r.URL)
		}
		e.logf("downloading %s", r.URL)
		data, err := e.Get(ctx, r.URL)
		if err != nil {
			return fmt.Errorf("download %s: %w", l.dir(), err)
		}
		if err := checkSum(r.Algo, data, r.Sum); err != nil {
			return fmt.Errorf("%s: %w", l.dir(), err)
		}
		if err := os.WriteFile(filepath.Join(src, l.File), data, 0o644); err != nil {
			return err
		}
		e.logf("%s: %s verified%s", l.dir(), r.Algo, map[bool]string{true: " (pinned, not feed-tracked)"}[r.Pinned])
		p.Libs = append(p.Libs, l)
	}
	pb, _ := json.Marshal(p)
	if err := os.WriteFile(filepath.Join(dir, "plan.json"), pb, 0o644); err != nil {
		return err
	}
	return SetState(dir, State{Phase: PhaseBuilding, Version: job.Version, N: job.N})
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
	src, work := filepath.Join(dir, "src"), filepath.Join(dir, "work")
	if err := os.MkdirAll(work, 0o755); err != nil {
		return err
	}
	run := func(c phplibs.Cmd) error {
		e.logf("+ %s %s", c.Name, strings.Join(c.Args, " "))
		return e.Run(ctx, c)
	}
	unpack := func(file, into string) error {
		if err := os.MkdirAll(into, 0o755); err != nil {
			return err
		}
		return run(phplibs.Cmd{Dir: work, Name: "tar", Args: []string{"-xf", filepath.Join(src, file), "-C", into}})
	}

	deps := map[string]string{}
	for _, l := range p.Libs {
		prefix := filepath.Join(e.Root, "libs", l.dir())
		if !l.Have {
			e.logf("== building %s", l.dir())
			into := filepath.Join(work, l.Name)
			if err := unpack(l.File, into); err != nil {
				return fmt.Errorf("unpack %s: %w", l.dir(), err)
			}
			srcDir := filepath.Join(into, phplibs.SourceDir(l.Resolved))
			for _, c := range phplibs.Recipe(l.Resolved, prefix, deps, job.Jobs) {
				c.Dir = filepath.Join(srcDir, c.Dir)
				if err := run(c); err != nil {
					return fmt.Errorf("build %s: %s: %w", l.dir(), c.Name, err)
				}
			}
		}
		deps[l.Name] = prefix
	}

	e.logf("== building PHP %s", job.Version)
	if err := unpack(p.PHPFile, work); err != nil {
		return fmt.Errorf("unpack php: %w", err)
	}
	srcDir := filepath.Join(work, "php-"+job.Version)
	prefix := filepath.Join(e.Root, job.Label())
	args, env := PHPConfigure(job.Version, prefix, deps)
	jobs := fmt.Sprintf("-j%d", max(job.Jobs, 1))
	for _, c := range []phplibs.Cmd{
		{Dir: srcDir, Env: env, Name: "./configure", Args: args},
		{Dir: srcDir, Env: env, Name: "make", Args: []string{jobs}},
		{Dir: srcDir, Env: env, Name: "make", Args: []string{"install"}},
	} {
		if err := run(c); err != nil {
			return fmt.Errorf("build php: %s: %w", c.Name, err)
		}
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
