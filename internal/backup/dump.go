package backup

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// Profile is one typed dump: the job builds the command from these fields only, never from free text. Rows come from
// SQLite, which the unprivileged web process writes, so every field is validated again here.
type Profile struct {
	Name      string // label inside the archive: dumps/<name>.*
	Engine    string // mariadb | postgres | sqlite
	Container string // mariadb | postgres: a running docker container
	DB        string
	User      string
	Path      string // sqlite: relative to the site root
	Secret    string // the database password, in the child's environment only
}

var (
	profNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	ctrRE      = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)
	dbRE       = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.$-]{0,63}$`)
)

// ValidVolume reports whether s can name a docker volume.
func ValidVolume(s string) bool { return ctrRE.MatchString(s) }

func (p Profile) Validate() error {
	if !profNameRE.MatchString(p.Name) {
		return fmt.Errorf("profile name %q must be 1-32 characters of a-z, 0-9, _ and -", p.Name)
	}
	switch p.Engine {
	case "mariadb", "postgres":
		if !ctrRE.MatchString(p.Container) {
			return fmt.Errorf("profile %s: container %q is not a valid container name", p.Name, p.Container)
		}
		if !dbRE.MatchString(p.DB) || !dbRE.MatchString(p.User) {
			return fmt.Errorf("profile %s: database and user must be 1-64 characters of letters, digits, _ . $ -, not starting with -", p.Name)
		}
		if strings.ContainsAny(p.Secret, "\x00\n") {
			return fmt.Errorf("profile %s: the password has a line break or NUL", p.Name)
		}
	case "sqlite":
		c := p.Path
		if c == "" || c != cleanRel(c) || strings.ContainsRune(c, 0) {
			return fmt.Errorf("profile %s: sqlite path %q must be a clean relative path inside the site", p.Name, c)
		}
	default:
		return fmt.Errorf("profile %s: engine %q must be mariadb, postgres or sqlite", p.Name, p.Engine)
	}
	return nil
}

func cleanRel(p string) string {
	c := strings.TrimPrefix(strings.TrimSpace(p), "./")
	if strings.HasPrefix(c, "/") || c == ".." || strings.HasPrefix(c, "../") || strings.Contains(c, "/../") || strings.HasSuffix(c, "/..") {
		return ""
	}
	return strings.TrimSuffix(c, "/")
}

// Cmd is one command the job runs. Env holds the secret; it is never part of Args.
type Cmd struct {
	Name string
	Args []string
	Env  []string
}

// DumpCmd builds the dump command. maria selects the binary: mariadb-dump, or mysqldump for older images.
func DumpCmd(p Profile, maria string) (Cmd, error) {
	if err := p.Validate(); err != nil {
		return Cmd{}, err
	}
	switch p.Engine {
	case "mariadb":
		return dockerCmd(p, "MYSQL_PWD", maria, "-u", p.User, "--single-transaction", "--routines", "--triggers", "--events", p.DB), nil
	case "postgres":
		return dockerCmd(p, "PGPASSWORD", "pg_dump", "-U", p.User, "-Fc", p.DB), nil
	}
	return Cmd{}, fmt.Errorf("profile %s: %s has no command", p.Name, p.Engine)
}

// RestoreCmd builds the command that feeds a dump back into the database (the dump is its stdin).
func RestoreCmd(p Profile) (Cmd, error) {
	if err := p.Validate(); err != nil {
		return Cmd{}, err
	}
	switch p.Engine {
	case "mariadb":
		return dockerCmd(p, "MYSQL_PWD", "mariadb", "-u", p.User, p.DB), nil
	case "postgres":
		return dockerCmd(p, "PGPASSWORD", "pg_restore", "--clean", "--if-exists", "--no-owner", "-U", p.User, "-d", p.DB), nil
	}
	return Cmd{}, fmt.Errorf("profile %s: %s has no command", p.Name, p.Engine)
}

func dockerCmd(p Profile, envName string, tool string, args ...string) Cmd {
	c := Cmd{Name: "docker", Args: []string{"exec", "-i"}}
	if p.Secret != "" {
		c.Args = append(c.Args, "-e", envName) // bare -e: docker reads the value from its own environment
		c.Env = []string{envName + "=" + p.Secret}
	}
	c.Args = append(c.Args, p.Container, tool)
	c.Args = append(c.Args, args...)
	return c
}

// Exec runs c with stdin and stdout and returns the clipped stderr. Tests replace it.
type Exec func(ctx context.Context, c Cmd, stdin io.Reader, stdout io.Writer) (string, error)

// OsExec is the real Exec.
func OsExec(ctx context.Context, c Cmd, stdin io.Reader, stdout io.Writer) (string, error) {
	cmd := exec.CommandContext(ctx, c.Name, c.Args...)
	cmd.Env = append(os.Environ(), c.Env...)
	cmd.Stdin, cmd.Stdout = stdin, stdout
	var se bytes.Buffer
	cmd.Stderr = &limitBuf{b: &se, n: 2048}
	err := cmd.Run()
	return clip(strings.TrimSpace(se.String()), 200), err
}

type limitBuf struct {
	b *bytes.Buffer
	n int
}

func (l *limitBuf) Write(p []byte) (int, error) {
	if r := l.n - l.b.Len(); r > 0 {
		l.b.Write(p[:min(len(p), r)])
	}
	return len(p), nil
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
