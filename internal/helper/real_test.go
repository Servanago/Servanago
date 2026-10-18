package helper

import (
	"os"
	"path/filepath"
	"testing"
)

// systemctl show prints properties in its own order, not the order of -p, so values are matched by key.
func TestParseShow(t *testing.T) {
	for name, out := range map[string]string{
		"asked order":    "ActiveState=active\nSubState=running\nExecMainPID=4242\n",
		"systemd order":  "ExecMainPID=4242\nSubState=running\nActiveState=active\n",
		"extra and gaps": "Foo=bar\n\nExecMainPID=4242\nActiveState=active\nSubState=running",
	} {
		t.Run(name, func(t *testing.T) {
			st, err := parseShow([]byte(out))
			if err != nil {
				t.Fatal(err)
			}
			if st.ActiveState != "active" || st.SubState != "running" || st.PID != "4242" {
				t.Errorf("parsed %+v", st)
			}
		})
	}
	// A stopped unit has PID 0 and no main process: PID is empty rather than "0".
	st, err := parseShow([]byte("ActiveState=inactive\nSubState=dead\nExecMainPID=0\n"))
	if err != nil || st.PID != "" || st.ActiveState != "inactive" {
		t.Errorf("stopped unit: %+v %v", st, err)
	}
	if _, err := parseShow([]byte("SubState=running\n")); err == nil {
		t.Error("output without ActiveState accepted")
	}
}

// Editing or toggling a site calls user-add again: an existing user is success, not a useradd error.
// "root" always exists, so this never runs useradd on the test host.
func TestRealSeamUserAddIsIdempotent(t *testing.T) {
	if err := (RealSeam{}).UserAdd("root", "/root"); err != nil {
		t.Fatalf("existing user: %v", err)
	}
}

// WriteFile must replace the file by rename, never rewrite it in place: a crash mid-write would leave a torn
// unit file. A hard link keeps the old inode reachable, so an in-place write shows up as changed content there.
func TestRealWriteFileIsAtomic(t *testing.T) {
	dir := t.TempDir()
	path, old := filepath.Join(dir, "a.service"), filepath.Join(dir, "old")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, old); err != nil {
		t.Fatal(err)
	}
	if err := (RealSeam{}).WriteFile(path, []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(old); string(b) != "old" {
		t.Errorf("old inode rewritten in place: %q", b)
	}
	if b, _ := os.ReadFile(path); string(b) != "new" {
		t.Errorf("content %q", b)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o644 {
		t.Errorf("mode %v", fi.Mode().Perm())
	}
	if es, _ := os.ReadDir(dir); len(es) != 2 {
		t.Errorf("leftover temp files: %v", es)
	}
}
