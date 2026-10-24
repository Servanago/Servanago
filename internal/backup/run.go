package backup

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// Plan is what to back up for one scope. The job builds it from SQLite and the env file.
type Plan struct {
	Scope      string // "panel" or a site slug
	Root       string // site files directory ("" = none); validated by Env.CheckRoot and resolved before use
	Profiles   []Profile
	Volumes    []string
	DataDir    string // panel: /var/lib/servanago
	EnvFile    string // panel: the environment file that holds SERVANAGO_SECRET_KEY
	Keep       int
	KeepWeekly int
}

// Env carries the seams a run needs; tests replace them.
type Env struct {
	Dir, Scratch, Pass string
	Host, Version      string
	Schema             int
	Now                func() time.Time
	Exec               Exec
	Volume             func(name string) (string, error)
	Running            func() (map[string]bool, error)
	CheckRoot          func(root string) error
	Chgrp              func(path string) error
	Chown              func(path string, h *tar.Header) error
	Free               func(path string) (uint64, error)

	// Volume restore: the containers that mount a volume, and the calls that stop and start them.
	Users       func(volume string) ([]Container, error)
	Stop, Start func(id string) error
	IsRunning   func(id string) (bool, error)
	VolumeChown func(path string, h *tar.Header) error // numeric ids from the header, never host names
}

// Result is one scope's run, written as a result file for the service to ingest.
type Result struct {
	RunID    string `json:"run_id"`
	Scope    string `json:"scope"`
	Trigger  string `json:"trigger"`
	Actor    string `json:"actor,omitempty"`
	Status   string `json:"status"` // ok | failed | skipped
	Archive  string `json:"archive,omitempty"`
	Bytes    int64  `json:"bytes,omitempty"`
	Error    string `json:"error,omitempty"`
	Started  int64  `json:"started"`
	Finished int64  `json:"finished"`
}

func newRunID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// RunScope backs one scope up, prunes it, and reports. It never panics on bad input: every failure is a Result.
func RunScope(ctx context.Context, e Env, p Plan, trigger string) Result {
	now := e.Now()
	r := Result{RunID: newRunID(), Scope: p.Scope, Trigger: trigger, Started: now.Unix()}
	finish := func(status string, err error) Result {
		r.Status, r.Finished = status, e.Now().Unix()
		if err != nil {
			r.Error = clip(err.Error(), 400)
		}
		return r
	}
	root, err := resolveRoot(e, p.Root)
	if err != nil {
		return finish("failed", err)
	}
	if need, err := estimate(root, p); err != nil {
		return finish("failed", err)
	} else if free, err := e.Free(e.Dir); err == nil && free < need+need/10+(64<<20) {
		return finish("skipped", fmt.Errorf("%d MB free in %s, this backup needs about %d MB", free>>20, e.Dir, need>>20))
	}
	started := now.UTC().Truncate(time.Second)
	for { // names carry the start second: a pre-restore backup right after a manual one must not take its name
		if _, err := os.Lstat(filepath.Join(e.Dir, p.Scope, ArchiveName(p.Scope, started))); err != nil {
			break
		}
		started = started.Add(time.Second)
	}
	m := Manifest{Scope: p.Scope, RunID: r.RunID, Trigger: trigger, Host: e.Host, Version: e.Version, Schema: e.Schema, Started: started}
	for _, pr := range p.Profiles {
		m.Profiles = append(m.Profiles, pr.Name)
	}
	m.Volumes = p.Volumes
	name, n, err := Create(CreateOpts{Dir: e.Dir, Scratch: e.Scratch, Pass: e.Pass, Chgrp: e.Chgrp}, m, func(b *Builder) error {
		return fill(ctx, e, b, p, root)
	})
	if err != nil {
		return finish("failed", err)
	}
	r.Archive, r.Bytes = name, n
	if _, err := PruneScope(e.Dir, p.Scope, p.Keep, p.KeepWeekly); err != nil {
		return finish("failed", fmt.Errorf("archive written, pruning failed: %w", err))
	}
	return finish("ok", nil)
}

func resolveRoot(e Env, root string) (string, error) {
	if root == "" {
		return "", nil
	}
	if err := e.CheckRoot(root); err != nil {
		return "", err
	}
	real, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("site root %s: %w", root, err)
	}
	if err := e.CheckRoot(real); err != nil { // a symlink must not lead into a denied tree
		return "", err
	}
	return real, nil
}

// estimate sums the sizes of what a plan reads, so a run can be refused before it fills the disk.
func estimate(root string, p Plan) (uint64, error) {
	var n uint64
	add := func(dir string) {
		_ = filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
			if err == nil && d.Type().IsRegular() {
				if fi, err := d.Info(); err == nil {
					n += uint64(fi.Size())
				}
			}
			return nil
		})
	}
	if root != "" {
		add(root)
	}
	if p.DataDir != "" {
		add(p.DataDir)
	}
	return n, nil
}

func fill(ctx context.Context, e Env, b *Builder, p Plan, root string) error {
	if p.Scope == "panel" {
		return fillPanel(e, b, p)
	}
	if root != "" {
		if err := b.AddTree("files", "files", root); err != nil {
			return fmt.Errorf("site files: %w", err)
		}
	}
	for _, pr := range p.Profiles {
		if err := dumpProfile(ctx, e, b, pr, root); err != nil {
			return fmt.Errorf("dump %s: %w", pr.Name, err)
		}
	}
	for _, v := range p.Volumes {
		dir, err := e.Volume(v)
		if err != nil {
			return err
		}
		if err := b.AddTree("volumes/"+v, "volume", dir); err != nil {
			return fmt.Errorf("volume %s: %w", v, err)
		}
	}
	return nil
}

func fillPanel(e Env, b *Builder, p Plan) error {
	snap := filepath.Join(e.Scratch, "panel-snapshot.db")
	defer os.Remove(snap)
	if err := SnapshotSQLite(filepath.Join(p.DataDir, "servanago.db"), snap, e.Scratch); err != nil {
		return fmt.Errorf("panel database: %w", err)
	}
	if err := b.AddFile("panel/servanago.db", "panel", snap); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(p.DataDir, "caddy")); err == nil {
		if err := b.AddTree("panel/caddy", "panel", filepath.Join(p.DataDir, "caddy")); err != nil {
			return fmt.Errorf("caddy data: %w", err)
		}
	}
	for _, f := range []struct{ name, path string }{
		{"panel/caddy-last-good.json", filepath.Join(p.DataDir, "caddy-last-good.json")},
		{"panel/servanago.env", p.EnvFile},
	} {
		if f.path == "" {
			continue
		}
		if err := b.AddFile(f.name, "panel", f.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// confine resolves rel inside root and refuses a path that leaves it (including through symlinks).
func confine(root, rel string) (string, error) {
	p, err := filepath.EvalSymlinks(filepath.Join(root, rel))
	if err != nil {
		return "", err
	}
	if p != root && !strings.HasPrefix(p, root+"/") {
		return "", fmt.Errorf("%s resolves outside the site root", rel)
	}
	return p, nil
}

func dumpProfile(ctx context.Context, e Env, b *Builder, pr Profile, root string) error {
	if err := pr.Validate(); err != nil {
		return err
	}
	if pr.Engine == "sqlite" {
		if root == "" {
			return errors.New("a sqlite profile needs a site with files")
		}
		src, err := confine(root, pr.Path)
		if err != nil {
			return err
		}
		out := filepath.Join(e.Scratch, "dump-"+pr.Name+".sqlite")
		defer os.Remove(out)
		if err := SnapshotSQLite(src, out, e.Scratch); err != nil {
			return err
		}
		return b.AddFile("dumps/"+pr.Name+".sqlite", "dump", out)
	}
	run, err := e.Running()
	if err != nil {
		return err
	}
	if !run[pr.Container] {
		return fmt.Errorf("container %s is not running", pr.Container)
	}
	ext, tools := ".sql", []string{"mariadb-dump", "mysqldump"}
	if pr.Engine == "postgres" {
		ext, tools = ".pgdump", []string{"pg_dump"}
	}
	var last error
	for _, tool := range tools {
		c, err := DumpCmd(pr, tool)
		if err != nil {
			return err
		}
		var buf bytes.Buffer
		cctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
		se, err := e.Exec(cctx, c, nil, &buf)
		cancel()
		if err == nil {
			return b.AddReader("dumps/"+pr.Name+ext, "dump", &buf)
		}
		last = fmt.Errorf("%w: %s", err, se)
		if !strings.Contains(se, "not found") { // only a missing binary tries the next name
			break
		}
	}
	return last
}

// RestoreOpts is what to restore from an archive.
type RestoreOpts struct {
	Files, Dumps bool
	Volumes      []string
}

// RestoreSite restores a site's files, dumps and/or volumes from one archive. It first takes a pre-restore backup of
// the current state and aborts if that fails. Volumes go first, in a pass of their own, so a database container is
// running again when the dump pass needs it.
func RestoreSite(ctx context.Context, e Env, p Plan, archive string, o RestoreOpts) error {
	files, dumps := o.Files, o.Dumps
	if !files && !dumps && len(o.Volumes) == 0 {
		return errors.New("nothing to restore: choose files, dumps or volumes")
	}
	if !ValidName(archive) || !strings.HasPrefix(archive, p.Scope+"-") {
		return fmt.Errorf("archive name %q is not valid for %s", archive, p.Scope)
	}
	path := filepath.Join(e.Dir, p.Scope, archive)
	m, err := VerifyChecksum(path)
	if err != nil {
		return err
	}
	if m.Scope != p.Scope {
		return fmt.Errorf("archive belongs to %s, not %s", m.Scope, p.Scope)
	}
	for _, v := range o.Volumes {
		if !slices.Contains(p.Volumes, v) || !slices.Contains(m.Volumes, v) {
			return fmt.Errorf("volume %q is not switched on for this site and in this archive", v)
		}
	}
	root, err := resolveRoot(e, p.Root)
	if err != nil {
		return err
	}
	if res := RunScope(ctx, e, p, "pre-restore"); res.Status != "ok" {
		return fmt.Errorf("pre-restore backup %s: %s", res.Status, res.Error)
	}
	if len(o.Volumes) > 0 {
		if err := restoreVolumes(e, path, o.Volumes); err != nil {
			return fmt.Errorf("%w (the pre-restore archive holds the state from before)", err)
		}
	}
	if !files && !dumps {
		return nil
	}
	tr, closeFn, err := Open(path, e.Pass)
	if err != nil {
		return err
	}
	defer func() { _ = closeFn() }()
	byName := map[string]Profile{}
	for _, pr := range p.Profiles {
		byName[pr.Name] = pr
	}
	x := Extractor{Dest: root, Chown: e.Chown}
	first := true
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if first {
			first = false
			if h.Name != "manifest.json" {
				return errors.New("archive does not start with its manifest")
			}
			continue
		}
		switch {
		case files && root != "" && strings.HasPrefix(h.Name, "files/"):
			if err := x.Extract(strings.TrimPrefix(h.Name, "files/"), h, tr); err != nil {
				return err
			}
		case dumps && strings.HasPrefix(h.Name, "dumps/"):
			if err := restoreDump(ctx, e, byName, root, h, tr); err != nil {
				return err
			}
		}
	}
}

func restoreDump(ctx context.Context, e Env, profiles map[string]Profile, root string, h *tar.Header, r io.Reader) error {
	base := strings.TrimPrefix(h.Name, "dumps/")
	name := strings.TrimSuffix(base, filepath.Ext(base))
	pr, ok := profiles[name]
	if !ok || h.Typeflag != tar.TypeReg {
		return nil // a profile that no longer exists is not restored
	}
	if err := pr.Validate(); err != nil {
		return err
	}
	if pr.Engine == "sqlite" {
		dst, err := confine(root, pr.Path)
		if err != nil {
			return err
		}
		tmp, err := os.CreateTemp(filepath.Dir(dst), ".restore-*")
		if err != nil {
			return err
		}
		defer os.Remove(tmp.Name())
		if _, err := io.Copy(tmp, r); err != nil {
			tmp.Close()
			return err
		}
		fi, serr := os.Stat(dst)
		if serr == nil {
			_ = tmp.Chmod(fi.Mode().Perm())
			own := &tar.Header{}
			own.Uid, own.Gid = ownerOf(fi)
			if e.Chown != nil {
				if err := e.Chown(tmp.Name(), own); err != nil {
					tmp.Close()
					return err
				}
			}
		}
		if err := tmp.Close(); err != nil {
			return err
		}
		_ = os.Remove(dst + "-wal")
		_ = os.Remove(dst + "-shm")
		return os.Rename(tmp.Name(), dst)
	}
	run, err := e.Running()
	if err != nil {
		return err
	}
	if !run[pr.Container] {
		return fmt.Errorf("container %s is not running", pr.Container)
	}
	c, err := RestoreCmd(pr)
	if err != nil {
		return err
	}
	if se, err := e.Exec(ctx, c, r, io.Discard); err != nil {
		return fmt.Errorf("restore %s: %w: %s", pr.Name, err, se)
	}
	return nil
}
