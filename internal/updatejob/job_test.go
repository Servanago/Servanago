package updatejob

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/servanago/servanago/internal/helper"
	"github.com/servanago/servanago/internal/update"
)

type rig struct {
	t      *testing.T
	env    *Env
	pub    ed25519.PublicKey
	priv   ed25519.PrivateKey
	files  map[string][]byte // url -> body
	calls  []string
	failOn func(call string) error // by "name arg arg" of a Run call
	health []error                 // consumed one per Health call; empty = ok
	data   string
	dir    string
	badPkg string // a version whose dpkg-deb -f lies
	onDpkg func(call string)
}

var debPath = regexp.MustCompile(`servanago_(\d+\.\d+\.\d+)_`)

func manifest(r *rig, version, minFrom string, body []byte) ([]byte, []byte) {
	sum := sha256.Sum256(body)
	m := update.Manifest{Schema: 1, Version: version, Released: "2026-11-01", NotesURL: "n", MinUpgradeFrom: minFrom,
		Debs: map[string]update.Deb{"amd64": {URL: update.DebURL(version, "amd64"), SHA256: hex.EncodeToString(sum[:]), Size: int64(len(body))}}}
	mf, _ := json.Marshal(m)
	return mf, update.Sign(r.priv, mf)
}

// newRig sets up a host running 0.18.0 with 0.19.0 offered; the job file is written and signed.
func newRig(t *testing.T) *rig {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	r := &rig{t: t, pub: pub, priv: priv, files: map[string][]byte{}, data: t.TempDir(), dir: t.TempDir()}
	if err := os.WriteFile(filepath.Join(r.data, "servanago.db"), []byte("old-db"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.data, "servanago.db-wal"), []byte("old-wal"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldDeb, newDeb := []byte("old-deb"), []byte("new-deb")
	r.files[update.DebURL("0.18.0", "amd64")] = oldDeb
	r.files[update.DebURL("0.19.0", "amd64")] = newDeb
	pm, ps := manifest(r, "0.18.0", "0.5.0", oldDeb)
	r.files[update.ManifestAt("0.18.0")], r.files[update.ManifestAt("0.18.0")+".sig"] = pm, ps
	r.writeJob("0.19.0", "0.5.0", "0.18.0", newDeb)
	r.env = &Env{Dir: r.dir, DataDir: r.data, Running: "0.18.0", Arch: "amd64", Keys: []ed25519.PublicKey{pub},
		Now: func() time.Time { return time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC) },
		Fetch: func(url string, limit int64) ([]byte, error) {
			if b, ok := r.files[url]; ok {
				return b, nil
			}
			return nil, errors.New("404 " + url)
		},
		Run: func(name string, args ...string) (string, error) {
			call := name + " " + strings.Join(args, " ")
			r.calls = append(r.calls, call)
			if name == "dpkg-deb" {
				v := debPath.FindStringSubmatch(call)[1]
				if v == r.badPkg {
					return "Package: other\nVersion: " + v + "\n", nil
				}
				return "Package: servanago\nVersion: " + v + "\n", nil
			}
			if name == "dpkg" && r.onDpkg != nil {
				r.onDpkg(call)
			}
			if r.failOn != nil {
				if err := r.failOn(call); err != nil {
					return "boom", err
				}
			}
			return "", nil
		},
		Health: func() error {
			if len(r.health) == 0 {
				return nil
			}
			e := r.health[0]
			r.health = r.health[1:]
			return e
		},
	}
	return r
}

func (r *rig) writeJob(version, minFrom, from string, deb []byte) {
	mf, sig := manifest(r, version, minFrom, deb)
	b, _ := json.Marshal(helper.UpdateJob{Manifest: string(mf), Sig: string(sig), From: from, Actor: "brian"})
	if err := os.WriteFile(filepath.Join(r.dir, helper.UpdateJobFile), b, 0o600); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rig) called(prefix string) bool {
	for _, c := range r.calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

func (r *rig) read(name string) string {
	b, _ := os.ReadFile(name)
	return string(b)
}

func TestUpgradeSucceeds(t *testing.T) {
	r := newRig(t)
	res := r.env.Do()
	if !res.OK || res.Error != "" || res.To != "0.19.0" || res.Actor != "brian" {
		t.Fatalf("result %+v", res)
	}
	want := []string{
		"systemctl stop servanago.service servanago-helper.service",
		"dpkg --force-confold -i " + filepath.Join(r.dir, "new", "servanago_0.19.0_amd64.deb"),
		"systemctl daemon-reload",
		"systemctl start servanago-helper.service",
		"systemctl start servanago.service",
	}
	var got []string
	for _, c := range r.calls {
		if !strings.HasPrefix(c, "dpkg-deb") {
			got = append(got, c)
		}
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if r.read(filepath.Join(r.data, "servanago.db.pre-0.18.0")) != "old-db" || r.read(filepath.Join(r.data, "servanago.db.pre-0.18.0-wal")) != "old-wal" {
		t.Fatal("database copy missing or wrong")
	}
	var saved Result
	if err := json.Unmarshal([]byte(r.read(filepath.Join(r.dir, "result.json"))), &saved); err != nil || !saved.OK {
		t.Fatalf("result.json %v %+v", err, saved)
	}
	if !strings.Contains(r.read(filepath.Join(r.dir, "state.json")), `"phase": "done"`) {
		t.Fatal(r.read(filepath.Join(r.dir, "state.json")))
	}
}

// Nothing may change on the host when the job is refused or a download fails: no service is stopped.
func TestRefusedBeforeAnythingChanges(t *testing.T) {
	cases := []struct {
		name  string
		setup func(r *rig)
		want  string
	}{
		{"previous manifest missing", func(r *rig) { delete(r.files, update.ManifestAt("0.18.0")) }, "no rollback possible"},
		{"previous package tampered", func(r *rig) { r.files[update.DebURL("0.18.0", "amd64")] = []byte("evil") }, "no rollback possible"},
		{"new package tampered", func(r *rig) { r.files[update.DebURL("0.19.0", "amd64")] = []byte("evil") }, "does not match its manifest"},
		{"new package is another package", func(r *rig) { r.badPkg = "0.19.0" }, "expected servanago 0.19.0"},
		{"new package missing", func(r *rig) { delete(r.files, update.DebURL("0.19.0", "amd64")) }, "download 0.19.0"},
		{"same version", func(r *rig) { r.writeJob("0.18.0", "0.5.0", "0.18.0", []byte("x")) }, "not newer"},
		{"older version", func(r *rig) { r.writeJob("0.17.0", "0.5.0", "0.18.0", []byte("x")) }, "not newer"},
		{"min_upgrade_from above the running version", func(r *rig) { r.writeJob("0.19.0", "0.18.5", "0.18.0", []byte("x")) }, "cannot be installed over"},
		{"job made for another version", func(r *rig) { r.writeJob("0.19.0", "0.5.0", "0.17.0", []byte("x")) }, "was made for"},
		{"wrong signing key", func(r *rig) { other, _, _ := ed25519.GenerateKey(nil); r.env.Keys = []ed25519.PublicKey{other} }, "does not match a trusted key"},
		{"no job file", func(r *rig) { _ = os.Remove(filepath.Join(r.dir, helper.UpdateJobFile)) }, "read the job"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t)
			c.setup(r)
			res := r.env.Do()
			if res.OK || !strings.Contains(res.Error, c.want) {
				t.Fatalf("result %+v, want error containing %q", res, c.want)
			}
			if res.RolledBack || res.NeedsHands {
				t.Fatalf("nothing was changed, yet %+v", res)
			}
			if r.called("systemctl") || (r.called("dpkg ") && !r.called("dpkg-deb")) {
				t.Fatalf("host was touched: %v", r.calls)
			}
			if _, err := os.Stat(filepath.Join(r.dir, "result.json")); err != nil {
				t.Fatal("no result.json")
			}
		})
	}
}

func TestTamperedManifestInJob(t *testing.T) {
	r := newRig(t)
	var job helper.UpdateJob
	b, _ := os.ReadFile(filepath.Join(r.dir, helper.UpdateJobFile))
	_ = json.Unmarshal(b, &job)
	job.Manifest = strings.Replace(job.Manifest, "0.19.0", "0.99.0", 1)
	b, _ = json.Marshal(job)
	_ = os.WriteFile(filepath.Join(r.dir, helper.UpdateJobFile), b, 0o600)
	if res := r.env.Do(); res.OK || !strings.Contains(res.Error, "does not match a trusted key") || r.called("systemctl") {
		t.Fatalf("%+v %v", res, r.calls)
	}
}

func TestStopFailureStartsServicesAgain(t *testing.T) {
	r := newRig(t)
	first := true
	r.failOn = func(call string) error {
		if strings.HasPrefix(call, "systemctl stop") && first {
			first = false
			return errors.New("stop failed")
		}
		return nil
	}
	res := r.env.Do()
	if res.OK || res.RolledBack || res.NeedsHands || !r.called("systemctl start servanago-helper.service") || r.called("dpkg ") {
		t.Fatalf("%+v %v", res, r.calls)
	}
}

// A migration that rewrites the database and a start that fails must end with the old package and the old data.
func TestFailureRollsBack(t *testing.T) {
	cases := []struct {
		name  string
		setup func(r *rig)
		want  string
	}{
		{"dpkg install fails", func(r *rig) {
			r.failOn = func(c string) error {
				if strings.HasPrefix(c, "dpkg --force-confold -i") {
					return errors.New("exit 1")
				}
				return nil
			}
		}, "dpkg install"},
		{"new version does not start", func(r *rig) {
			r.failOn = func(c string) error {
				if c == "systemctl start servanago.service" && !r.called("dpkg --force-confold --force-downgrade") {
					return errors.New("exit 1")
				}
				return nil
			}
		}, "start servanago.service"},
		{"health check fails", func(r *rig) { r.health = []error{errors.New("/login answered 500")} }, "did not come up"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t)
			c.setup(r)
			r.onDpkg = func(call string) { // the new package's migration has already rewritten the live database
				if strings.Contains(call, "0.19.0") {
					_ = os.WriteFile(filepath.Join(r.data, "servanago.db"), []byte("new-db"), 0o600)
					_ = os.WriteFile(filepath.Join(r.data, "servanago.db-wal"), []byte("new-wal"), 0o600)
				}
			}
			res := r.env.Do()
			if res.OK || !res.RolledBack || res.NeedsHands || !strings.Contains(res.Error, c.want) {
				t.Fatalf("%+v", res)
			}
			if !r.called("dpkg --force-confold --force-downgrade -i " + filepath.Join(r.dir, "prev", "servanago_0.18.0_amd64.deb")) {
				t.Fatalf("previous package not reinstalled: %v", r.calls)
			}
			if r.read(filepath.Join(r.data, "servanago.db")) != "old-db" || r.read(filepath.Join(r.data, "servanago.db-wal")) != "old-wal" {
				t.Fatal("database not restored")
			}
			last := r.calls[len(r.calls)-1]
			if last != "systemctl start servanago.service" {
				t.Fatalf("services not running again: %v", r.calls)
			}
		})
	}
}

func TestRollbackFailureLeavesTheHostForTheAdmin(t *testing.T) {
	r := newRig(t)
	r.health = []error{errors.New("down"), errors.New("still down")}
	res := r.env.Do()
	if res.OK || res.RolledBack || !res.NeedsHands || len(res.Hands) == 0 {
		t.Fatalf("%+v", res)
	}
	if !strings.HasPrefix(r.calls[len(r.calls)-1], "systemctl stop") {
		t.Fatalf("units must be left stopped: %v", r.calls)
	}
	txt := r.read(filepath.Join(r.dir, "NEEDS_HANDS.txt"))
	if !strings.Contains(txt, "dpkg --force-confold --force-downgrade -i "+filepath.Join(r.dir, "prev")) || !strings.Contains(txt, "servanago.db.pre-0.18.0") {
		t.Fatalf("recovery text: %s", txt)
	}
}

func TestExistingDatabaseCopyIsKept(t *testing.T) {
	r := newRig(t)
	keep := filepath.Join(r.data, "servanago.db.pre-0.18.0")
	if err := os.WriteFile(keep, []byte("older copy"), 0o600); err != nil {
		t.Fatal(err)
	}
	if res := r.env.Do(); !res.OK {
		t.Fatalf("%+v", res)
	}
	if r.read(keep) != "older copy" {
		t.Fatal("an existing copy was overwritten")
	}
	m, _ := filepath.Glob(keep + "-*")
	if len(m) == 0 {
		t.Fatal("no second copy")
	}
}

func TestListenFromEnv(t *testing.T) {
	for _, c := range []struct{ file, want string }{
		{"", "127.0.0.1:8080"},
		{"A=1\nUI_LISTEN=127.0.0.1:8082\n", "127.0.0.1:8082"},
		{"UI_LISTEN=0.0.0.0:9000\n", "127.0.0.1:9000"},
		{"UI_LISTEN=127.0.0.1:1\nUI_LISTEN=\"[::]:7000\"\n", "127.0.0.1:7000"},
		{"UI_LISTEN=junk\n", "127.0.0.1:8080"},
	} {
		p := filepath.Join(t.TempDir(), "env")
		if err := os.WriteFile(p, []byte(c.file), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := ListenFromEnv(p); got != c.want {
			t.Errorf("%q: got %s want %s", c.file, got, c.want)
		}
	}
	if got := ListenFromEnv(filepath.Join(t.TempDir(), "missing")); got != "127.0.0.1:8080" {
		t.Errorf("missing file: %s", got)
	}
}

func TestHealth(t *testing.T) {
	status := http.StatusInternalServerError
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/login" {
			t.Errorf("path %s", req.URL.Path)
		}
		w.WriteHeader(status)
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")
	active := func(string, ...string) (string, error) { return "", nil }
	h := Health(addr, 50*time.Millisecond, 10*time.Millisecond, active)
	if err := h(); err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("500 must fail: %v", err)
	}
	status = http.StatusOK
	if err := h(); err != nil {
		t.Fatal(err)
	}
	down := func(_ string, args ...string) (string, error) { return "", errors.New("inactive") }
	if err := Health(addr, 20*time.Millisecond, 5*time.Millisecond, down)(); err == nil || !strings.Contains(err.Error(), "not active") {
		t.Fatalf("inactive unit must fail: %v", err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln.Addr().String()
	_ = ln.Close()
	if err := Health(dead, 20*time.Millisecond, 5*time.Millisecond, active)(); err == nil {
		t.Fatal("a closed port must fail")
	}
}

func TestLockExcludesASecondJob(t *testing.T) {
	d := t.TempDir()
	f, err := Lock(d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Lock(d); err == nil {
		t.Fatal("second lock must fail")
	}
	_ = f.Close()
	g, err := Lock(d)
	if err != nil {
		t.Fatal(err)
	}
	_ = g.Close()
}
