package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/servanago/servanago/internal/backup"
	"github.com/servanago/servanago/internal/helper"
	"github.com/servanago/servanago/internal/secretbox"
	"github.com/servanago/servanago/internal/store"
)

// backupjob.go: `servanago backup-job run`, the unit the helper installs (root, see internal/helper/backup.go), and the
// pieces the `servanago backup` command shares. The job reads its plan from a snapshot of the panel database, so it never
// creates a file beside the live one, and writes one result file per scope for the service to ingest.

const (
	defaultEnvFile = "/etc/servanago/servanago.env"
	failBackoff    = time.Hour // a scheduled scope that failed is not retried sooner
	resultKeep     = 14 * 24 * time.Hour
)

func dataDir() string {
	if d := os.Getenv("DATA_DIR"); d != "" {
		return d
	}
	return "/var/lib/servanago"
}

// jobPlan is a backup plan plus the schedule that applies to it.
type jobPlan struct {
	backup.Plan
	Sched string
}

type job struct {
	set     store.BackupSettings
	st      *store.Store
	key     string
	env     backup.Env
	dataDir string
	envFile string
}

// secretKey is SERVANAGO_SECRET_KEY from the environment, else read from the environment file.
func secretKey(envFile string) string {
	if k := os.Getenv("SERVANAGO_SECRET_KEY"); k != "" {
		return k
	}
	f, err := os.Open(envFile)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if k, ok := strings.CutPrefix(strings.TrimSpace(sc.Text()), "SERVANAGO_SECRET_KEY="); ok {
			return strings.Trim(k, `"'`)
		}
	}
	return ""
}

// openJob snapshots the panel database into scratch and reads the settings from the copy. cleanup removes scratch.
func openJob(dir, envFile string) (*job, func(), error) {
	scratch, err := os.MkdirTemp("", "servanago-backup-*")
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() { _ = os.RemoveAll(scratch) }
	snap := filepath.Join(scratch, "panel.db")
	if err := backup.SnapshotSQLite(filepath.Join(dir, "servanago.db"), snap, scratch); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("read the panel database: %w", err)
	}
	st, err := store.Open(snap)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	set, err := st.GetBackupSettings(context.Background())
	if err != nil {
		_ = st.Close()
		cleanup()
		return nil, nil, err
	}
	j := &job{set: set, st: st, key: secretKey(envFile), dataDir: dir, envFile: envFile}
	host, _ := os.Hostname()
	j.env = backup.Env{
		Dir: set.Dir, Scratch: scratch, Host: host, Version: "dev", Schema: store.LatestVersion(),
		Now: time.Now, Exec: backup.OsExec, Volume: backup.DockerVolume, Running: backup.DockerRunning,
		CheckRoot: helper.ValidateSiteRoot, Free: freeBytes,
		Users: backup.ContainersUsing, Stop: backup.StopContainer, Start: backup.StartContainer, IsRunning: backup.ContainerRunning,
	}
	if os.Geteuid() == 0 {
		j.env.Chown = lchownFromHeader
		j.env.VolumeChown = func(p string, h *tar.Header) error { return os.Lchown(p, h.Uid, h.Gid) } // ids inside the container, not host names
		if g, err := user.LookupGroup("servanago"); err == nil {
			if gid, err := strconv.Atoi(g.Gid); err == nil {
				j.env.Chgrp = func(p string) error { return os.Chown(p, -1, gid) }
			}
		}
	}
	return j, func() { _ = st.Close(); cleanup() }, nil
}

func lchownFromHeader(path string, h *tar.Header) error {
	uid, gid := backup.OwnerFromHeader(h)
	return os.Lchown(path, uid, gid)
}

func freeBytes(path string) (uint64, error) {
	for {
		var st syscall.Statfs_t
		err := syscall.Statfs(path, &st)
		if err == nil {
			return st.Bavail * uint64(st.Bsize), nil
		}
		parent := filepath.Dir(path)
		if parent == path || !errors.Is(err, os.ErrNotExist) {
			return 0, err
		}
		path = parent
	}
}

// unseal opens a secretbox blob; "" for nil.
func (j *job) unseal(b []byte) (string, error) {
	if b == nil {
		return "", nil
	}
	if j.key == "" {
		return "", errors.New("SERVANAGO_SECRET_KEY is not available, so sealed secrets cannot be opened")
	}
	p, err := secretbox.Open(j.key, b)
	return string(p), err
}

// passphrase is the archive passphrase from the settings.
func (j *job) passphrase() (string, error) {
	if j.set.Pass == nil {
		return "", errors.New("no backup passphrase is set (Backups page)")
	}
	return j.unseal(j.set.Pass)
}

func (j *job) keepFor(sb store.SiteBackup) (int, int) {
	keep, weekly := j.set.Keep, j.set.KeepWeekly
	if sb.Keep > 0 {
		keep = sb.Keep
	}
	if sb.KeepWeekly > 0 {
		weekly = sb.KeepWeekly
	}
	return keep, weekly
}

func (j *job) panelPlan() jobPlan {
	return jobPlan{Plan: backup.Plan{Scope: "panel", DataDir: j.dataDir, EnvFile: j.envFile, Keep: j.set.Keep, KeepWeekly: j.set.KeepWeekly}, Sched: j.set.Sched}
}

// sitePlan builds one site's plan from its rows; sealed profile secrets are opened here, in the root job only.
func (j *job) sitePlan(ctx context.Context, s store.Site) (jobPlan, error) {
	sb, err := j.st.GetSiteBackup(ctx, s.ID)
	if err != nil {
		return jobPlan{}, err
	}
	keep, weekly := j.keepFor(sb)
	p := jobPlan{Plan: backup.Plan{Scope: s.Slug, Keep: keep, KeepWeekly: weekly}, Sched: j.set.Sched}
	if sb.Sched != "" {
		p.Sched = sb.Sched
	}
	if s.Kind != "" && s.Kind != "proxy" {
		p.Root = s.StaticRoot
	}
	ps, err := j.st.ListProfiles(ctx, s.ID)
	if err != nil {
		return p, err
	}
	for _, r := range ps {
		secret, err := j.unseal(r.Secret)
		if err != nil {
			return p, fmt.Errorf("profile %s: %w", r.Name, err)
		}
		p.Profiles = append(p.Profiles, backup.Profile{Name: r.Name, Engine: r.Engine, Container: r.Container, DB: r.DB, User: r.User, Path: r.Path, Secret: secret})
	}
	if p.Volumes, err = j.st.ListVolumes(ctx, s.ID); err != nil {
		return p, err
	}
	return p, nil
}

// plans lists the enabled scopes: the panel (when on) and every site that opted in.
func (j *job) plans(ctx context.Context) ([]jobPlan, error) {
	var out []jobPlan
	if j.set.Panel {
		out = append(out, j.panelPlan())
	}
	sites, err := j.st.ListSites(ctx)
	if err != nil {
		return nil, err
	}
	for _, s := range sites {
		sb, err := j.st.GetSiteBackup(ctx, s.ID)
		if err != nil || !sb.On {
			continue
		}
		p, err := j.sitePlan(ctx, s)
		if err != nil {
			out = append(out, jobPlan{Plan: backup.Plan{Scope: s.Slug}, Sched: "error:" + err.Error()})
			continue
		}
		out = append(out, p)
	}
	return out, nil
}

func (j *job) siteBySlug(ctx context.Context, slug string) (store.Site, error) {
	sites, err := j.st.ListSites(ctx)
	if err != nil {
		return store.Site{}, err
	}
	for _, s := range sites {
		if s.Slug == slug {
			return s, nil
		}
	}
	return store.Site{}, fmt.Errorf("no site %q", slug)
}

func empty(p jobPlan) bool {
	return p.Root == "" && len(p.Profiles) == 0 && len(p.Volumes) == 0 && p.Scope != "panel"
}

func (j *job) runPlan(ctx context.Context, p jobPlan, trigger, actor string) backup.Result {
	if strings.HasPrefix(p.Sched, "error:") {
		now := time.Now().Unix()
		return backup.Result{RunID: "plan-" + p.Scope + "-" + strconv.FormatInt(now, 10), Scope: p.Scope, Trigger: trigger, Status: "failed", Error: strings.TrimPrefix(p.Sched, "error:"), Started: now, Finished: now, Actor: actor}
	}
	if empty(p) {
		now := time.Now().Unix()
		return backup.Result{RunID: "empty-" + p.Scope + "-" + strconv.FormatInt(now, 10), Scope: p.Scope, Trigger: trigger, Status: "skipped", Error: "nothing to back up: add a dump profile or a volume, or use a kind with files", Started: now, Finished: now, Actor: actor}
	}
	res := backup.RunScope(ctx, j.env, p.Plan, trigger)
	res.Actor = actor
	return res
}

// due returns the plans whose schedule says now, skipping a scope that failed within failBackoff.
func (j *job) due(ctx context.Context, now time.Time) ([]jobPlan, error) {
	all, err := j.plans(ctx)
	if err != nil {
		return nil, err
	}
	var out []jobPlan
	for _, p := range all {
		if strings.HasPrefix(p.Sched, "error:") { // reported once per backoff window like any failure
			if prev, ok := lastResult(j.set.Dir, p.Scope); !ok || prev.Status == "ok" || now.Sub(time.Unix(prev.Finished, 0)) > failBackoff {
				out = append(out, p)
			}
			continue
		}
		sc, err := backup.ParseSched(p.Sched)
		if err != nil {
			out = append(out, jobPlan{Plan: p.Plan, Sched: "error:" + err.Error()})
			continue
		}
		if !sc.Due(backup.Last(j.set.Dir, p.Scope), now) {
			continue
		}
		if prev, ok := lastResult(j.set.Dir, p.Scope); ok && prev.Status != "ok" && now.Sub(time.Unix(prev.Finished, 0)) < failBackoff {
			continue
		}
		out = append(out, p)
	}
	return out, nil
}

// resultsDir holds one JSON file per finished scope, readable by the service group.
func resultsDir(dir string) string { return filepath.Join(dir, ".runs") }

func (j *job) writeResult(r backup.Result) {
	d := resultsDir(j.set.Dir)
	if err := os.MkdirAll(d, 0o750); err != nil {
		slog.Error("backup result dir", "error", err)
		return
	}
	if j.env.Chgrp != nil {
		_ = j.env.Chgrp(j.set.Dir)
		_ = j.env.Chgrp(d)
	}
	b, _ := json.Marshal(r)
	p := filepath.Join(d, fmt.Sprintf("%d-%s.json", r.Finished, r.RunID))
	if err := os.WriteFile(p, b, 0o640); err != nil {
		slog.Error("write backup result", "error", err)
		return
	}
	if j.env.Chgrp != nil {
		_ = j.env.Chgrp(p)
	}
}

// lastResult is the newest result file of a scope.
func lastResult(dir, scope string) (backup.Result, bool) {
	ents, _ := os.ReadDir(resultsDir(dir))
	for i := len(ents) - 1; i >= 0; i-- { // names start with the finish time
		if r, ok := readResult(filepath.Join(resultsDir(dir), ents[i].Name())); ok && r.Scope == scope {
			return r, true
		}
	}
	return backup.Result{}, false
}

func readResult(path string) (backup.Result, bool) {
	var r backup.Result
	b, err := os.ReadFile(path)
	return r, err == nil && json.Unmarshal(b, &r) == nil
}

func pruneResults(dir string) {
	ents, _ := os.ReadDir(resultsDir(dir))
	for _, e := range ents {
		if fi, err := e.Info(); err == nil && time.Since(fi.ModTime()) > resultKeep {
			_ = os.Remove(filepath.Join(resultsDir(dir), e.Name()))
		}
	}
}

// notify posts a failure to the ntfy topic. The text carries the scope and a clipped error, never a secret.
func (j *job) notify(ctx context.Context, r backup.Result) {
	if j.set.Ntfy == nil {
		return
	}
	u, err := j.unseal(j.set.Ntfy)
	if err != nil || !strings.HasPrefix(u, "https://") {
		slog.Error("ntfy url unusable", "error", err)
		return
	}
	body := fmt.Sprintf("%s: %s", r.Scope, r.Error)
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Title", "ServanaGo backup "+r.Status)
	req.Header.Set("Priority", "high")
	c := http.Client{CheckRedirect: func(req *http.Request, _ []*http.Request) error {
		if req.URL.Scheme != "https" {
			return errors.New("refusing a redirect to a non-https URL")
		}
		return nil
	}}
	resp, err := c.Do(req)
	if err != nil {
		slog.Error("ntfy post", "error", err)
		return
	}
	resp.Body.Close()
}

// finish records one result: the file, the log line, and the ntfy push on a failure that is new for the scope.
func (j *job) finish(ctx context.Context, r backup.Result, prev backup.Result, hadPrev bool) {
	j.writeResult(r)
	slog.Info("backup", "scope", r.Scope, "status", r.Status, "trigger", r.Trigger, "archive", r.Archive, "bytes", r.Bytes, "error", r.Error)
	if r.Status == "failed" && (r.Trigger != "schedule" || !hadPrev || prev.Status == "ok") {
		j.notify(ctx, r)
	}
}

// execute runs a request, or the due scopes when req is nil. It reports whether anything failed.
func (j *job) execute(ctx context.Context, req *helper.BackupRequestData) (failed bool, err error) {
	if j.set.Pass == nil || !j.set.Enabled {
		return false, errors.New("backups are disabled or have no passphrase")
	}
	pass, err := j.passphrase()
	if err != nil {
		return false, err
	}
	j.env.Pass = pass
	if err := os.MkdirAll(j.set.Dir, 0o750); err != nil {
		return false, err
	}
	pruneResults(j.set.Dir)
	one := func(p jobPlan, trigger, actor string) {
		prev, had := lastResult(j.set.Dir, p.Scope)
		r := j.runPlan(ctx, p, trigger, actor)
		failed = failed || r.Status == "failed"
		j.finish(ctx, r, prev, had)
	}
	switch {
	case req == nil:
		ps, err := j.due(ctx, time.Now())
		if err != nil {
			return false, err
		}
		for _, p := range ps {
			one(p, "schedule", "")
		}
	case req.Op == "restore":
		s, err := j.siteBySlug(ctx, req.Slug)
		if err != nil {
			return false, err
		}
		p, err := j.sitePlan(ctx, s)
		if err != nil {
			return false, err
		}
		now := time.Now().Unix()
		r := backup.Result{RunID: "restore-" + strconv.FormatInt(now, 10), Scope: req.Slug, Trigger: "restore", Actor: req.Actor, Archive: req.Archive, Started: now, Status: "ok"}
		if err := backup.RestoreSite(ctx, j.env, p.Plan, req.Archive, backup.RestoreOpts{Files: req.Files, Dumps: req.Dumps, Volumes: req.Volumes}); err != nil {
			r.Status, r.Error = "failed", err.Error()
			failed = true
		}
		r.Finished = time.Now().Unix()
		prev, had := lastResult(j.set.Dir, req.Slug)
		j.finish(ctx, r, prev, had)
	default:
		trigger := "manual"
		var ps []jobPlan
		switch req.Scope {
		case "panel":
			ps = []jobPlan{j.panelPlan()}
		case "site":
			s, err := j.siteBySlug(ctx, req.Slug)
			if err != nil {
				return false, err
			}
			p, err := j.sitePlan(ctx, s)
			if err != nil {
				return false, err
			}
			ps = []jobPlan{p}
		default:
			if ps, err = j.plans(ctx); err != nil {
				return false, err
			}
		}
		for _, p := range ps {
			one(p, trigger, req.Actor)
		}
	}
	return failed, nil
}

// runBackupJob is `servanago backup-job run`: one pass over what was asked for (request.json) or what is due.
func runBackupJob(args []string) error {
	if len(args) != 1 || args[0] != "run" {
		return errors.New("usage: servanago backup-job run")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	j, cleanup, err := openJob(dataDir(), defaultEnvFile)
	if err != nil {
		return err
	}
	defer cleanup()
	var req *helper.BackupRequestData
	rp := filepath.Join(helper.BackupJobDir, helper.BackupRequestFile)
	if b, err := os.ReadFile(rp); err == nil {
		_ = os.Remove(rp) // read once: a crashed job must not repeat a restore on the next timer tick
		req = &helper.BackupRequestData{}
		if err := json.Unmarshal(b, req); err != nil {
			return fmt.Errorf("read the backup request: %w", err)
		}
	}
	if !j.set.Enabled {
		slog.Info("backups are disabled; nothing to do")
		return nil
	}
	failed, err := j.execute(ctx, req)
	if err != nil { // a setup problem is a failure too: write it so the service shows it and ntfy hears it
		now := time.Now().Unix()
		r := backup.Result{RunID: "job-" + strconv.FormatInt(now, 10), Scope: "all", Trigger: "schedule", Status: "failed", Error: err.Error(), Started: now, Finished: now}
		if req != nil {
			r.Trigger, r.Actor = "manual", req.Actor
		}
		prev, had := lastResult(j.set.Dir, "all")
		_ = os.MkdirAll(j.set.Dir, 0o750)
		j.finish(ctx, r, prev, had)
		return err
	}
	if failed {
		return errors.New("one or more backups failed; see the log above")
	}
	return nil
}

// readPassphrase reads a passphrase file ("-" = stdin), trimming one trailing newline.
func readPassphrase(path string, stdin io.Reader) (string, error) {
	var b []byte
	var err error
	if path == "-" {
		b, err = io.ReadAll(io.LimitReader(stdin, 4096))
	} else {
		b, err = os.ReadFile(path)
	}
	if err != nil {
		return "", err
	}
	p := string(bytes.TrimRight(b, "\r\n"))
	if p == "" {
		return "", errors.New("the passphrase is empty")
	}
	return p, nil
}
