package backup

import (
	"archive/tar"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// volumeEnv wires a fake Docker: containers a (running) and b (stopped) mount the volume "data".
type volumeEnv struct {
	Env
	dir             string
	stopped, starts []string
	owners          []int
	stillRunning    bool
	chownErr        error
}

func newVolumeEnv(t *testing.T) (*volumeEnv, Plan) {
	t.Helper()
	e := testEnv(t)
	v := &volumeEnv{Env: e, dir: mkdir(t, t.TempDir(), "data", "_data")}
	v.Volume = func(string) (string, error) { return v.dir, nil }
	v.Users = func(string) ([]Container, error) {
		return []Container{{ID: "aaaaaaaaaaaa", Name: "a", Running: true}, {ID: "bbbbbbbbbbbb", Name: "b"}}, nil
	}
	v.Stop = func(id string) error { v.stopped = append(v.stopped, id); return nil }
	v.Start = func(id string) error { v.starts = append(v.starts, id); return nil }
	v.IsRunning = func(string) (bool, error) { return v.stillRunning, nil }
	v.VolumeChown = func(_ string, h *tar.Header) error {
		v.owners = append(v.owners, h.Uid)
		return v.chownErr
	}
	write(t, filepath.Join(v.dir, "db", "file"), "good")
	if err := os.Symlink("/etc/absolute", filepath.Join(v.dir, "abs")); err != nil {
		t.Fatal(err)
	}
	return v, Plan{Scope: "shop", Keep: 3, KeepWeekly: 1, Volumes: []string{"data"}}
}

func (v *volumeEnv) backupThenWreck(t *testing.T, p Plan) string {
	t.Helper()
	res := RunScope(context.Background(), v.Env, p, "manual")
	if res.Status != "ok" {
		t.Fatalf("run: %+v", res)
	}
	write(t, filepath.Join(v.dir, "db", "file"), "bad")
	write(t, filepath.Join(v.dir, "stale"), "must not survive")
	return res.Archive
}

func TestVolumeRestoreReplacesContentAndRestartsOnlyWhatWasRunning(t *testing.T) {
	v, p := newVolumeEnv(t)
	archive := v.backupThenWreck(t, p)
	if err := RestoreSite(context.Background(), v.Env, p, archive, RestoreOpts{Volumes: []string{"data"}}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(v.dir, "db", "file")); string(b) != "good" {
		t.Errorf("file = %q", b)
	}
	if _, err := os.Lstat(filepath.Join(v.dir, "stale")); err == nil {
		t.Error("a file that is not in the archive survived")
	}
	if l, err := os.Readlink(filepath.Join(v.dir, "abs")); err != nil || l != "/etc/absolute" {
		t.Errorf("absolute symlink = %q %v", l, err)
	}
	if strings.Join(v.stopped, ",") != "aaaaaaaaaaaa" || strings.Join(v.starts, ",") != "aaaaaaaaaaaa" {
		t.Errorf("stopped %v started %v: only the running container is touched", v.stopped, v.starts)
	}
	if len(v.owners) == 0 {
		t.Error("VolumeChown was never called")
	}
}

func TestVolumeRestoreFailureStillRestarts(t *testing.T) {
	v, p := newVolumeEnv(t)
	archive := v.backupThenWreck(t, p)
	v.chownErr = errors.New("chown boom")
	err := RestoreSite(context.Background(), v.Env, p, archive, RestoreOpts{Volumes: []string{"data"}})
	if err == nil || !strings.Contains(err.Error(), "chown boom") || !strings.Contains(err.Error(), "pre-restore") {
		t.Fatalf("err = %v, want the failure plus a pointer to the pre-restore archive", err)
	}
	if len(v.starts) != 1 {
		t.Errorf("started %v: a failed restore must still restart", v.starts)
	}
}

func TestVolumeRestoreAbortsWhenAContainerComesBack(t *testing.T) {
	v, p := newVolumeEnv(t)
	archive := v.backupThenWreck(t, p)
	v.stillRunning = true
	if err := RestoreSite(context.Background(), v.Env, p, archive, RestoreOpts{Volumes: []string{"data"}}); err == nil {
		t.Fatal("want an error")
	}
	if b, _ := os.ReadFile(filepath.Join(v.dir, "stale")); string(b) == "" {
		t.Error("the volume was cleared although a container was running")
	}
	if len(v.starts) != 1 {
		t.Errorf("started %v: containers stopped before the abort must restart", v.starts)
	}
}

func TestVolumeRestoreRefusesBeforeStoppingAnything(t *testing.T) {
	v, p := newVolumeEnv(t)
	archive := v.backupThenWreck(t, p)
	for name, o := range map[string]RestoreOpts{
		"not opted in": {Volumes: []string{"other"}},
		"nothing":      {},
	} {
		if err := RestoreSite(context.Background(), v.Env, p, archive, o); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	p2 := p
	p2.Volumes = nil // opted out since the backup
	if err := RestoreSite(context.Background(), v.Env, p2, archive, RestoreOpts{Volumes: []string{"data"}}); err == nil {
		t.Error("a volume the site no longer backs up must be refused")
	}
	if len(v.stopped) != 0 {
		t.Errorf("stopped %v before validation passed", v.stopped)
	}
}

func TestVolumeExtractSkipsFifosAndKeepsNumericOwner(t *testing.T) {
	dest := t.TempDir()
	var uid int
	x := Extractor{Dest: dest, Volume: true, Chown: func(_ string, h *tar.Header) error { uid = h.Uid; return nil }}
	if err := x.Extract("pipe", &tar.Header{Typeflag: tar.TypeFifo, Name: "pipe"}, nil); err != nil {
		t.Fatalf("fifo: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dest, "pipe")); err == nil {
		t.Error("fifo was created")
	}
	if err := x.Extract("dev", &tar.Header{Typeflag: tar.TypeChar, Name: "dev"}, nil); err == nil {
		t.Error("device node must stay refused")
	}
	if err := (Extractor{Dest: dest}).Extract("pipe", &tar.Header{Typeflag: tar.TypeFifo, Name: "pipe"}, nil); err == nil {
		t.Error("without Volume a fifo is still refused")
	}
	h := &tar.Header{Typeflag: tar.TypeDir, Name: "d", Mode: 0o755, Uid: 999, Uname: "postgres"}
	if err := x.Extract("d", h, nil); err != nil || uid != 999 {
		t.Errorf("uid %d err %v", uid, err)
	}
}
