// Package updatejob is the root orchestrator behind `servanago update-job`: it installs a verified release over the
// running one and puts the old one back when the new one does not come up. Every host effect goes through Env, so
// the whole sequence runs against fakes in tests.
package updatejob

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/servanago/servanago/internal/helper"
	"github.com/servanago/servanago/internal/update"
)

const (
	maxManifest = 64 << 10
	maxDeb      = 300 << 20
	appUnit     = "servanago.service"
	helperUnit  = "servanago-helper.service"
)

// Env is everything the job touches outside its own files.
type Env struct {
	Dir     string // state dir (job.json in; state.json, result.json, prev/ and new/ out)
	DataDir string // holds servanago.db
	Running string // the version of the binary running this job
	Arch    string
	Keys    []ed25519.PublicKey

	Fetch  func(url string, limit int64) ([]byte, error)
	Run    func(name string, args ...string) (string, error) // systemctl, dpkg, dpkg-deb
	Health func() error                                      // both units active and the panel answers
	Now    func() time.Time

	started time.Time
	to      string
	actor   string
	tag     string // the suffix of this run's database copy
}

// State is what the Updates page shows while the job runs.
type State struct {
	Phase   string `json:"phase"`
	Message string `json:"message,omitempty"`
	From    string `json:"from"`
	To      string `json:"to,omitempty"`
	Started string `json:"started"`
}

// Result is the job's last word. The web side turns it into an audit row at its next start.
type Result struct {
	OK         bool     `json:"ok"`
	RolledBack bool     `json:"rolledback,omitempty"`
	NeedsHands bool     `json:"needs_hands,omitempty"`
	From       string   `json:"from"`
	To         string   `json:"to,omitempty"`
	Actor      string   `json:"actor,omitempty"`
	At         string   `json:"at"`
	Error      string   `json:"error,omitempty"`
	Hands      []string `json:"hands,omitempty"` // the manual recovery commands for needs_hands
}

// Lock keeps two jobs from overlapping; the caller closes the file when done.
func Lock(dir string) (*os.File, error) {
	f, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, errors.New("another upgrade job is running")
	}
	return f, nil
}

func (e *Env) write(name string, v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	tmp := filepath.Join(e.Dir, name+".tmp")
	if os.WriteFile(tmp, b, 0o644) == nil { // the web user reads these
		_ = os.Rename(tmp, filepath.Join(e.Dir, name))
	}
}

func (e *Env) phase(p, msg string) {
	e.write("state.json", State{Phase: p, Message: msg, From: e.Running, To: e.to, Started: e.started.UTC().Format(time.RFC3339)})
}

// Do runs the whole upgrade and records the outcome in result.json.
func (e *Env) Do() Result {
	e.started = e.Now()
	_ = os.Remove(filepath.Join(e.Dir, "result.json"))
	res := e.run()
	res.From, res.To, res.Actor, res.At = e.Running, e.to, e.actor, e.Now().UTC().Format(time.RFC3339)
	phase := "done"
	if !res.OK {
		phase = "failed"
	}
	e.phase(phase, res.Error)
	e.write("result.json", res)
	return res
}

func fail(format string, a ...any) Result { return Result{Error: fmt.Sprintf(format, a...)} }

func (e *Env) run() Result {
	e.phase("verify", "checking the release")
	b, err := os.ReadFile(filepath.Join(e.Dir, helper.UpdateJobFile))
	if err != nil {
		return fail("read the job: %v", err)
	}
	var job helper.UpdateJob
	if err := json.Unmarshal(b, &job); err != nil {
		return fail("decode the job: %v", err)
	}
	e.actor = job.Actor
	if job.From != e.Running {
		return fail("the job was made for %s but this is %s", job.From, e.Running)
	}
	m, err := update.Verify(e.Keys, []byte(job.Manifest), []byte(job.Sig))
	if err != nil {
		return fail("%v", err)
	}
	e.to = m.Version
	if !update.Newer(e.Running, m.Version) {
		return fail("%s is not newer than the running %s", m.Version, e.Running)
	}
	if update.Newer(e.Running, m.MinUpgradeFrom) {
		return fail("this release cannot be installed over %s: upgrade to %s first", e.Running, m.MinUpgradeFrom)
	}
	nd, ok := m.Debs[e.Arch]
	if !ok {
		return fail("release %s has no package for %s", m.Version, e.Arch)
	}
	prevDir, newDir := filepath.Join(e.Dir, "prev"), filepath.Join(e.Dir, "new")
	for _, d := range []string{prevDir, newDir} {
		_ = os.RemoveAll(d)
		if err := os.MkdirAll(d, 0o700); err != nil {
			return fail("create %s: %v", d, err)
		}
	}

	// Without the previous package there is no way back, so there is no way forward either.
	e.phase("stage-previous", "downloading the package being replaced")
	prev, err := e.stagePrevious(prevDir)
	if err != nil {
		return fail("stage the previous version %s (no rollback possible, nothing changed): %v", e.Running, err)
	}
	e.phase("download", "downloading "+m.Version)
	next, err := e.download(nd, m.Version, newDir)
	if err != nil {
		return fail("download %s (nothing changed): %v", m.Version, err)
	}

	e.phase("backup", "stopping the services and copying the database")
	if err := e.stopUnits(); err != nil {
		return e.startAgain(fail("stop the services: %v", err))
	}
	e.tag = e.Running // an earlier copy under that name is kept, so a retry gets its own
	if _, err := os.Lstat(filepath.Join(e.DataDir, "servanago.db.pre-"+e.tag)); err == nil {
		e.tag += "-" + fmt.Sprint(e.Now().Unix())
	}
	if err := copyDB(e.DataDir, e.tag); err != nil {
		return e.startAgain(fail("copy the database (nothing changed): %v", err))
	}

	e.phase("install", "installing "+m.Version)
	if out, err := e.Run("dpkg", "--force-confold", "-i", next); err != nil {
		return e.rollback(prev, fmt.Errorf("dpkg install: %w: %s", err, tail(out)))
	}
	e.phase("start", "starting the services")
	if err := e.startUnits(); err != nil {
		return e.rollback(prev, err)
	}
	e.phase("health", "waiting for the panel")
	if err := e.Health(); err != nil {
		return e.rollback(prev, fmt.Errorf("the new version did not come up: %w", err))
	}
	return Result{OK: true}
}

func (e *Env) stagePrevious(dir string) (string, error) {
	url := update.ManifestAt(e.Running)
	mf, err := e.Fetch(url, maxManifest)
	if err != nil {
		return "", err
	}
	sig, err := e.Fetch(url+".sig", maxManifest)
	if err != nil {
		return "", err
	}
	m, err := update.Verify(e.Keys, mf, sig)
	if err != nil {
		return "", err
	}
	if m.Version != e.Running {
		return "", fmt.Errorf("that manifest is for %s", m.Version)
	}
	d, ok := m.Debs[e.Arch]
	if !ok {
		return "", fmt.Errorf("no package for %s", e.Arch)
	}
	return e.download(d, m.Version, dir)
}

// download fetches one package, then checks its size, checksum and its own idea of what it is.
func (e *Env) download(d update.Deb, version, dir string) (string, error) {
	b, err := e.Fetch(d.URL, maxDeb)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	if int64(len(b)) != d.Size || hex.EncodeToString(sum[:]) != d.SHA256 {
		return "", errors.New("the package does not match its manifest (size or checksum)")
	}
	path := filepath.Join(dir, fmt.Sprintf("servanago_%s_%s.deb", version, e.Arch))
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return "", err
	}
	out, err := e.Run("dpkg-deb", "-f", path, "Package", "Version")
	if err != nil {
		return "", fmt.Errorf("dpkg-deb: %w: %s", err, tail(out))
	}
	f := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(l, ":"); ok {
			f[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	if f["Package"] != "servanago" || f["Version"] != version {
		return "", fmt.Errorf("the package says %q %q, expected servanago %s", f["Package"], f["Version"], version)
	}
	return path, nil
}

func (e *Env) stopUnits() error {
	if out, err := e.Run("systemctl", "stop", appUnit, helperUnit); err != nil {
		return fmt.Errorf("%w: %s", err, tail(out))
	}
	return nil
}

func (e *Env) startUnits() error {
	if out, err := e.Run("systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("daemon-reload: %w: %s", err, tail(out))
	}
	for _, u := range []string{helperUnit, appUnit} { // the helper first, as postinst does
		if out, err := e.Run("systemctl", "start", u); err != nil {
			return fmt.Errorf("start %s: %w: %s", u, err, tail(out))
		}
	}
	return nil
}

// startAgain undoes a stop when nothing else changed yet.
func (e *Env) startAgain(r Result) Result {
	if err := e.startUnits(); err != nil {
		r.Error += "; starting the services again failed: " + err.Error()
	}
	return r
}

// rollback puts the previous package and the database copy back. If that does not bring the panel up the units stay
// stopped and the recovery commands are left for the admin.
func (e *Env) rollback(prev string, cause error) Result {
	e.phase("rollback", "putting "+e.Running+" back: "+cause.Error())
	r := Result{Error: cause.Error(), RolledBack: true}
	err := e.stopUnits()
	if err == nil {
		if out, derr := e.Run("dpkg", "--force-confold", "--force-downgrade", "-i", prev); derr != nil {
			err = fmt.Errorf("dpkg rollback: %w: %s", derr, tail(out))
		}
	}
	if err == nil {
		err = restoreDB(e.DataDir, e.tag)
	}
	if err == nil {
		err = e.startUnits()
	}
	if err == nil {
		err = e.Health()
	}
	if err != nil {
		_ = e.stopUnits() // a half-restored install must not keep serving
		r.RolledBack, r.NeedsHands = false, true
		r.Error += "; the rollback failed too: " + err.Error()
		r.Hands = []string{
			"systemctl stop servanago servanago-helper",
			"dpkg --force-confold --force-downgrade -i " + prev,
			fmt.Sprintf("cp -p %s/servanago.db.pre-%s %s/servanago.db  # also the -wal and -shm copies, if present", e.DataDir, e.tag, e.DataDir),
			"systemctl start servanago-helper servanago",
		}
		_ = os.WriteFile(filepath.Join(e.Dir, "NEEDS_HANDS.txt"), []byte(r.Error+"\n\n"+strings.Join(r.Hands, "\n")+"\n"), 0o644)
	}
	return r
}

func tail(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 400 {
		s = "..." + s[len(s)-400:]
	}
	return s
}
