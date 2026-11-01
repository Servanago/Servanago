package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/servanago/servanago/internal/helper"
	"github.com/servanago/servanago/internal/update"
	"github.com/servanago/servanago/internal/updatejob"
)

type updRig struct {
	u     *updater
	out   *bytes.Buffer
	asked []helper.Spec
	dir   string
}

func newUpdRig(t *testing.T, running, latest, answer string) *updRig {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	deb := filepath.Join(t.TempDir(), "servanago_"+latest+"_amd64.deb")
	if err := os.WriteFile(deb, []byte("deb"), 0o600); err != nil {
		t.Fatal(err)
	}
	mf, err := update.Build(deb, "https://example.test/notes", "0.5.0", true, false)
	if err != nil {
		t.Fatal(err)
	}
	sig := update.Sign(priv, mf)
	r := &updRig{out: &bytes.Buffer{}, dir: t.TempDir()}
	r.u = &updater{version: running, keys: []ed25519.PublicKey{pub}, dir: r.dir, in: strings.NewReader(answer), out: r.out,
		wait: time.Millisecond, giveUp: 2 * time.Second,
		fetch: func(url string, _ int64) ([]byte, error) {
			switch url {
			case update.ManifestURL:
				return mf, nil
			case update.SigURL:
				return sig, nil
			}
			return nil, errors.New("unexpected " + url)
		},
		start: func(sp helper.Spec) error { r.asked = append(r.asked, sp); return nil }}
	return r
}

func (r *updRig) finish(t *testing.T, res updatejob.Result) {
	t.Helper()
	res.At = time.Now().UTC().Format(time.RFC3339)
	b, _ := json.Marshal(res)
	if err := os.WriteFile(filepath.Join(r.dir, "result.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestUpdateCheckOnlyChangesNothing(t *testing.T) {
	r := newUpdRig(t, "0.18.0", "0.19.0", "")
	if err := r.u.run([]string{"--check"}); err != nil {
		t.Fatal(err)
	}
	if len(r.asked) != 0 || !strings.Contains(r.out.String(), "latest 0.19.0") || !strings.Contains(r.out.String(), "database migration") {
		t.Fatalf("asked %v, output %q", r.asked, r.out)
	}
}

func TestUpdateUpToDateAndSourceBuild(t *testing.T) {
	for running, want := range map[string]string{"0.19.0": "up to date", "dev": "build from source"} {
		r := newUpdRig(t, running, "0.19.0", "y\n")
		if err := r.u.run(nil); err != nil || !strings.Contains(r.out.String(), want) || len(r.asked) != 0 {
			t.Fatalf("%s: %v %q %v", running, err, r.out, r.asked)
		}
	}
}

func TestUpdateNeedsConfirmation(t *testing.T) {
	for _, answer := range []string{"", "n\n", "maybe\n"} {
		r := newUpdRig(t, "0.18.0", "0.19.0", answer)
		if err := r.u.run(nil); err == nil || !strings.Contains(err.Error(), "not confirmed") || len(r.asked) != 0 {
			t.Fatalf("answer %q: %v %v", answer, err, r.asked)
		}
	}
}

func TestUpdateRunsAndReportsTheOutcome(t *testing.T) {
	cases := []struct {
		name string
		res  updatejob.Result
		want string // "" = success
	}{
		{"ok", updatejob.Result{OK: true, From: "0.18.0", To: "0.19.0"}, ""},
		{"rolled back", updatejob.Result{RolledBack: true, From: "0.18.0", To: "0.19.0", Error: "health"}, "put back"},
		{"needs hands", updatejob.Result{NeedsHands: true, From: "0.18.0", To: "0.19.0", Error: "x"}, "NEEDS_HANDS.txt"},
		{"refused", updatejob.Result{From: "0.18.0", To: "0.19.0", Error: "no rollback possible"}, "did not start"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newUpdRig(t, "0.18.0", "0.19.0", "")
			r.u.start = func(sp helper.Spec) error { r.asked = append(r.asked, sp); r.finish(t, c.res); return nil }
			err := r.u.run([]string{"--yes"})
			if len(r.asked) != 1 || r.asked[0].UpdateVersion != "0.19.0" || r.asked[0].Actor == "" {
				t.Fatalf("asked %+v", r.asked)
			}
			if c.want == "" && err != nil || c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}

// An earlier run's result.json must not be taken for this run's.
func TestUpdateIgnoresAnOldResult(t *testing.T) {
	r := newUpdRig(t, "0.18.0", "0.19.0", "")
	b, _ := json.Marshal(updatejob.Result{OK: true, From: "0.17.0", To: "0.18.0", At: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)})
	if err := os.WriteFile(filepath.Join(r.dir, "result.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	r.u.giveUp = 50 * time.Millisecond
	if err := r.u.run([]string{"--yes"}); err == nil || !strings.Contains(err.Error(), "no result") {
		t.Fatalf("err = %v", err)
	}
}

func TestUpdateRefusesAnUntrustedManifest(t *testing.T) {
	r := newUpdRig(t, "0.18.0", "0.19.0", "")
	other, _, _ := ed25519.GenerateKey(nil)
	r.u.keys = []ed25519.PublicKey{other}
	if err := r.u.run([]string{"--yes"}); err == nil || !strings.Contains(err.Error(), "trusted key") || len(r.asked) != 0 {
		t.Fatalf("err = %v, asked %v", err, r.asked)
	}
}

func TestUpdateStartFailureIsReported(t *testing.T) {
	r := newUpdRig(t, "0.18.0", "0.19.0", "")
	r.u.start = func(helper.Spec) error { return errors.New("a PHP build is running") }
	if err := r.u.run([]string{"--yes"}); err == nil || !strings.Contains(err.Error(), "PHP build") {
		t.Fatalf("err = %v", err)
	}
}
