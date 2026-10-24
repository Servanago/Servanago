package backup

import (
	"archive/tar"
	"bytes"
	"context"
	"database/sql"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func mkdir(t *testing.T, p ...string) string {
	t.Helper()
	d := filepath.Join(p...)
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	return d
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func testEnv(t *testing.T) Env {
	t.Helper()
	tmp := t.TempDir()
	clock := time.Date(2026, 10, 23, 3, 0, 0, 0, time.UTC)
	return Env{
		Dir: mkdir(t, tmp, "out"), Scratch: mkdir(t, tmp, "scratch"), Pass: "correct horse battery staple", Host: "h", Version: "t", Schema: 5,
		Now: func() time.Time { clock = clock.Add(time.Minute); return clock },
		Exec: func(context.Context, Cmd, io.Reader, io.Writer) (string, error) {
			return "", errors.New("no exec in this test")
		},
		Volume:    func(string) (string, error) { return "", errors.New("no volumes") },
		Running:   func() (map[string]bool, error) { return map[string]bool{}, nil },
		CheckRoot: func(string) error { return nil },
		Free:      func(string) (uint64, error) { return 1 << 40, nil },
	}
}

func sqliteFile(t *testing.T, path string, rows ...string) {
	t.Helper()
	mkdir(t, filepath.Dir(path))
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS t(v TEXT)"); err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if _, err := db.Exec("INSERT INTO t VALUES (?)", r); err != nil {
			t.Fatal(err)
		}
	}
}

func rowsOf(t *testing.T, path string) []string {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rs, err := db.Query("SELECT v FROM t ORDER BY v")
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	var out []string
	for rs.Next() {
		var v string
		_ = rs.Scan(&v)
		out = append(out, v)
	}
	return out
}

func TestSiteRoundTripFilesSqliteAndDocker(t *testing.T) {
	e := testEnv(t)
	root := mkdir(t, t.TempDir(), "site")
	write(t, filepath.Join(root, "index.html"), "hello")
	write(t, filepath.Join(root, "sub", "a.txt"), "a")
	if err := os.Symlink("sub/a.txt", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	sqliteFile(t, filepath.Join(root, "storage", "db.sqlite"), "one", "two")
	var gotCmds []Cmd
	e.Running = func() (map[string]bool, error) { return map[string]bool{"billing-mariadb-1": true}, nil }
	e.Exec = func(_ context.Context, c Cmd, _ io.Reader, out io.Writer) (string, error) {
		gotCmds = append(gotCmds, c)
		if c.Args[len(c.Args)-5] == "mariadb-dump" && false {
			return "", nil
		}
		_, _ = io.WriteString(out, "-- dump --")
		return "", nil
	}
	p := Plan{Scope: "shop", Root: root, Keep: 3, KeepWeekly: 1, Profiles: []Profile{
		{Name: "app", Engine: "sqlite", Path: "storage/db.sqlite"},
		{Name: "bill", Engine: "mariadb", Container: "billing-mariadb-1", DB: "billing", User: "root", Secret: "s3cret"},
	}}
	res := RunScope(context.Background(), e, p, "manual")
	if res.Status != "ok" {
		t.Fatalf("run: %+v", res)
	}
	path := filepath.Join(e.Dir, "shop", res.Archive)
	if _, err := Verify(path, e.Pass); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if _, err := Verify(path, "wrong passphrase value"); err == nil {
		t.Fatal("a wrong passphrase must fail")
	}
	for _, c := range gotCmds {
		if strings.Contains(strings.Join(c.Args, " "), "s3cret") {
			t.Fatalf("password in argv: %v", c.Args)
		}
		if len(c.Env) != 1 || c.Env[0] != "MYSQL_PWD=s3cret" {
			t.Fatalf("env %v", c.Env)
		}
	}
	// wreck the site, restore it
	if err := os.RemoveAll(filepath.Join(root, "sub")); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(root, "index.html"), "vandalised")
	sqliteFile(t, filepath.Join(root, "storage", "db.sqlite"), "three")
	if err := RestoreSite(context.Background(), e, p, res.Archive, RestoreOpts{Files: true, Dumps: true}); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(root, "index.html")); string(b) != "hello" {
		t.Errorf("index.html = %q", b)
	}
	if l, err := os.Readlink(filepath.Join(root, "link")); err != nil || l != "sub/a.txt" {
		t.Errorf("symlink = %q %v", l, err)
	}
	if got := rowsOf(t, filepath.Join(root, "storage", "db.sqlite")); strings.Join(got, ",") != "one,two" {
		t.Errorf("restored rows %v", got)
	}
	if ins, _ := List(e.Dir, "shop"); len(ins) != 2 || ins[0].Manifest.Trigger != "pre-restore" {
		t.Errorf("want the run plus a pre-restore archive, newest first: %+v", ins)
	}
}

func TestRunFailureLeavesNothingListed(t *testing.T) {
	e := testEnv(t)
	root := mkdir(t, t.TempDir(), "site")
	write(t, filepath.Join(root, "f"), "x")
	p := Plan{Scope: "shop", Root: root, Keep: 3, Profiles: []Profile{{Name: "bad", Engine: "sqlite", Path: "missing.sqlite"}}}
	res := RunScope(context.Background(), e, p, "schedule")
	if res.Status != "failed" || res.Archive != "" {
		t.Fatalf("want failed, got %+v", res)
	}
	ents, _ := os.ReadDir(filepath.Join(e.Dir, "shop"))
	if len(ents) != 0 {
		t.Errorf("leftovers after a failed run: %v", ents)
	}
	// a damaged pair is reported, never counted for retention
	write(t, filepath.Join(e.Dir, "shop", "shop-20260101T000000Z.tar.zst.age"), "junk")
	if ins, _ := List(e.Dir, "shop"); len(ins) != 1 || ins[0].Damaged == "" {
		t.Errorf("list %+v", ins)
	}
}

func TestSkippedWhenDiskIsShort(t *testing.T) {
	e := testEnv(t)
	e.Free = func(string) (uint64, error) { return 1 << 20, nil }
	root := mkdir(t, t.TempDir(), "site")
	if res := RunScope(context.Background(), e, Plan{Scope: "shop", Root: root, Keep: 1}, "schedule"); res.Status != "skipped" {
		t.Errorf("%+v", res)
	}
}

func TestSqliteProfileCannotLeaveTheRoot(t *testing.T) {
	e := testEnv(t)
	base := t.TempDir()
	root := mkdir(t, base, "site")
	sqliteFile(t, filepath.Join(base, "outside.sqlite"), "secret")
	if err := os.Symlink("../outside.sqlite", filepath.Join(root, "esc.sqlite")); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"esc.sqlite", "../outside.sqlite", "/etc/passwd"} {
		p := Plan{Scope: "shop", Root: root, Keep: 1, Profiles: []Profile{{Name: "x", Engine: "sqlite", Path: path}}}
		res := RunScope(context.Background(), e, p, "manual")
		if res.Status != "failed" || !(strings.Contains(res.Error, "outside the site root") || strings.Contains(res.Error, "clean relative path")) {
			t.Errorf("%s: %+v", path, res)
		}
	}
}

func TestSnapshotSQLiteWALWithOpenWriter(t *testing.T) {
	d := t.TempDir()
	src := filepath.Join(d, "live.db")
	db, err := sql.Open("sqlite", "file:"+src)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("PRAGMA journal_mode=WAL; CREATE TABLE t(v TEXT); INSERT INTO t VALUES ('a'),('b')"); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadDir(d)
	dst := filepath.Join(t.TempDir(), "snap.db")
	if err := SnapshotSQLite(src, dst, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if got := rowsOf(t, dst); strings.Join(got, ",") != "a,b" {
		t.Errorf("rows %v", got)
	}
	if after, _ := os.ReadDir(d); len(after) != len(before) {
		t.Errorf("snapshot created files beside the source: %v -> %v", before, after)
	}
	if err := SnapshotSQLite(src, dst, t.TempDir()); err == nil {
		t.Error("an existing destination must be refused")
	}
}

func TestPanelRoundTripAndSchemaGuard(t *testing.T) {
	e := testEnv(t)
	data := mkdir(t, t.TempDir(), "data")
	sqliteFile(t, filepath.Join(data, "servanago.db"), "row")
	if _, err := sqlDo(filepath.Join(data, "servanago.db"), "PRAGMA user_version = 5"); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(data, "caddy", "certs", "a.crt"), "cert")
	write(t, filepath.Join(data, "caddy-last-good.json"), "{}")
	envf := filepath.Join(t.TempDir(), "servanago.env")
	write(t, envf, "SERVANAGO_SECRET_KEY=abc\n")
	res := RunScope(context.Background(), e, Plan{Scope: "panel", DataDir: data, EnvFile: envf, Keep: 2}, "manual")
	if res.Status != "ok" {
		t.Fatalf("%+v", res)
	}
	path := filepath.Join(e.Dir, "panel", res.Archive)
	fresh, freshEnv := filepath.Join(t.TempDir(), "d"), filepath.Join(t.TempDir(), "etc", "servanago.env")
	if err := RestorePanel(path, e.Pass, fresh, freshEnv, 4, nil); err == nil || !strings.Contains(err.Error(), "schema 5") {
		t.Fatalf("a newer schema must be refused: %v", err)
	}
	if err := RestorePanel(path, e.Pass, fresh, freshEnv, 5, nil); err != nil {
		t.Fatal(err)
	}
	if got := rowsOf(t, filepath.Join(fresh, "servanago.db")); len(got) != 1 || got[0] != "row" {
		t.Errorf("rows %v", got)
	}
	for _, f := range []string{filepath.Join(fresh, "caddy", "certs", "a.crt"), filepath.Join(fresh, "caddy-last-good.json"), freshEnv} {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("missing %s", f)
		}
	}
}

func sqlDo(path, q string) (sql.Result, error) {
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	return db.Exec(q)
}

func tarOf(t *testing.T, hs ...tar.Header) *tar.Reader {
	t.Helper()
	var buf bytes.Buffer
	w := tar.NewWriter(&buf)
	for _, h := range hs {
		h := h
		body := ""
		if h.Typeflag == tar.TypeReg {
			body = "x"
			h.Size = 1
		}
		if err := w.WriteHeader(&h); err != nil {
			return nil // the tar writer itself refuses this name (a NUL, say): nothing to extract
		}
		_, _ = io.WriteString(w, body)
	}
	_ = w.Close()
	return tar.NewReader(&buf)
}

func TestExtractRefuses(t *testing.T) {
	for _, tc := range []struct {
		name string
		hs   []tar.Header
		want string
	}{
		{"dotdot", []tar.Header{{Name: "files/../evil", Typeflag: tar.TypeReg, Mode: 0o644}}, "leaves the destination"},
		{"absolute", []tar.Header{{Name: "files//etc/evil", Typeflag: tar.TypeReg, Mode: 0o644}}, "absolute"},
		{"write through symlink", []tar.Header{{Name: "files/l", Typeflag: tar.TypeSymlink, Linkname: "/tmp"}, {Name: "files/l/evil", Typeflag: tar.TypeReg, Mode: 0o644}}, "not a directory"},
		{"device", []tar.Header{{Name: "files/dev", Typeflag: tar.TypeChar, Mode: 0o644}}, "not restored"},
		{"hardlink", []tar.Header{{Name: "files/h", Typeflag: tar.TypeLink, Linkname: "files/a"}}, "not restored"},
	} {
		dest := t.TempDir()
		err := ExtractPrefix(tarOf(t, tc.hs...), "files/", dest, nil)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err %v, want %q", tc.name, err, tc.want)
		}
		if _, e2 := os.Stat(filepath.Join(filepath.Dir(dest), "evil")); e2 == nil {
			t.Errorf("%s: wrote outside the destination", tc.name)
		}
	}
}

func TestExtractDropsSetuidAndReplacesSymlinkWithoutFollowing(t *testing.T) {
	dest := t.TempDir()
	victim := filepath.Join(t.TempDir(), "victim")
	write(t, victim, "keep")
	if err := os.Symlink(victim, filepath.Join(dest, "f")); err != nil {
		t.Fatal(err)
	}
	err := ExtractPrefix(tarOf(t, tar.Header{Name: "files/f", Typeflag: tar.TypeReg, Mode: 0o4755}), "files/", dest, nil)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Error("extraction followed an existing symlink")
	}
	fi, _ := os.Lstat(filepath.Join(dest, "f"))
	if fi.Mode()&os.ModeSetuid != 0 || fi.Mode().Perm() != 0o755 || !fi.Mode().IsRegular() {
		t.Errorf("mode %v", fi.Mode())
	}
}

func FuzzExtractNoEscape(f *testing.F) {
	for _, s := range []string{"a", "../x", "/abs", "a/../../x", "a/b/c", "..", ".", "a\x00b", "files/../../x"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		base := t.TempDir()
		dest := mkdir(t, base, "dest")
		hs := []tar.Header{{Name: "files/ln", Typeflag: tar.TypeSymlink, Linkname: "../"}, {Name: "files/" + name, Typeflag: tar.TypeReg, Mode: 0o644}}
		tr := tarOf(t, hs...)
		if tr == nil {
			return
		}
		_ = ExtractPrefix(tr, "files/", dest, nil)
		err := filepath.WalkDir(base, func(p string, d os.DirEntry, err error) error {
			if err == nil && d.Type().IsRegular() && !strings.HasPrefix(p, dest+"/") {
				t.Fatalf("file written outside the destination: %s (entry %q)", p, name)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	})
}

func TestDumpCmd(t *testing.T) {
	ok := Profile{Name: "x", Engine: "postgres", Container: "pg", DB: "app", User: "u", Secret: "pw"}
	c, err := DumpCmd(ok, "")
	if err != nil || strings.Join(c.Args, " ") != "exec -i -e PGPASSWORD pg pg_dump -U u -Fc app" || len(c.Env) != 1 {
		t.Fatalf("%v %+v", err, c)
	}
	for _, tc := range []struct {
		p    Profile
		want string
	}{
		{Profile{Name: "x", Engine: "mariadb", Container: "c", DB: "-evil", User: "u"}, "database and user"},
		{Profile{Name: "x", Engine: "mariadb", Container: "c; rm -rf /", DB: "d", User: "u"}, "container"},
		{Profile{Name: "x", Engine: "mariadb", Container: "c", DB: "d", User: "u", Secret: "a\nb"}, "line break"},
		{Profile{Name: "X", Engine: "sqlite", Path: "a"}, "profile name"},
		{Profile{Name: "x", Engine: "redis"}, "engine"},
		{Profile{Name: "x", Engine: "sqlite", Path: "../a"}, "clean relative"},
	} {
		if _, err := DumpCmd(tc.p, "mariadb-dump"); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%+v: %v, want %q", tc.p, err, tc.want)
		}
	}
}

func FuzzDumpArgvNoInjection(f *testing.F) {
	f.Add("pg", "app", "u", "pw")
	f.Add("c;x", "-d", "u u", "p\nw")
	f.Fuzz(func(t *testing.T, ctr, db, user, secret string) {
		secret = "\x01SECRET\x01" + secret // control bytes never pass the field validators, so any match in argv is a leak
		for _, eng := range []string{"mariadb", "postgres"} {
			p := Profile{Name: "x", Engine: eng, Container: ctr, DB: db, User: user, Secret: secret}
			c, err := DumpCmd(p, "mariadb-dump")
			if err != nil {
				continue
			}
			for _, a := range c.Args {
				if strings.Contains(a, "\x01SECRET\x01") {
					t.Fatalf("secret in argv %q", c.Args)
				}
			}
			if c.Name != "docker" || c.Args[0] != "exec" || strings.HasPrefix(db, "-") || strings.ContainsAny(ctr+db+user, " ;|&$`\n'\"\\") {
				t.Fatalf("unsafe argv accepted: %+v for %+v", c, p)
			}
		}
	})
}

func TestTwoRunsInOneSecondKeepBothArchives(t *testing.T) {
	e := testEnv(t)
	frozen := time.Date(2026, 10, 23, 3, 0, 0, 0, time.UTC)
	e.Now = func() time.Time { return frozen }
	root := mkdir(t, t.TempDir(), "site")
	write(t, filepath.Join(root, "f"), "x")
	p := Plan{Scope: "shop", Root: root, Keep: 5}
	a, b := RunScope(context.Background(), e, p, "manual"), RunScope(context.Background(), e, p, "pre-restore")
	if a.Status != "ok" || b.Status != "ok" || a.Archive == b.Archive {
		t.Fatalf("%+v %+v", a, b)
	}
	if ins, _ := List(e.Dir, "shop"); len(ins) != 2 {
		t.Errorf("want both archives, got %d", len(ins))
	}
}
