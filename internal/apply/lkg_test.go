package apply

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/servanago/servanago/internal/caddytest"
	"github.com/servanago/servanago/internal/store"
)

// TestLastKnownGoodStart writes a good config, breaks it (rejected render), then verifies Start
// restores the LKG file; removing it falls back to bootstrap-only.
func TestLastKnownGoodStart(t *testing.T) {
	f := newFixture(t)
	if err := f.svc.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	lkg := filepath.Join(filepath.Dir(f.svc.opts.StoragePath), "caddy-last-good.json")
	if _, err := os.ReadFile(lkg); err != nil {
		t.Fatalf("no last-known-good file after first start: %v", err)
	}

	// Break the render from the service's own options: same failure path as a poisoned DB row,
	// without needing raw SQL access from a test.
	f.svc.opts.UIHost = ""
	if err := f.svc.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if startup := f.svc.StartupError(); startup == nil || !strings.Contains(startup.Error(), "last known-good") {
		t.Fatalf("startup error %+v must report the restore", startup)
	}

	// No LKG file, and the same broken reason poisons the bootstrap render too: Start returns
	// the failure (a poisoned DB with a working setup would recover; that is the same code path).
	if err := os.Remove(lkg); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Start(context.Background()); err == nil {
		t.Fatal("Start passed with a broken render and no last-known-good file")
	}
}

// TestMutateAudits checks the system audit rows apply writes for config changes.
func TestMutateAudits(t *testing.T) {
	f := newFixture(t)
	if err := f.svc.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Mutate(context.Background(), f.addRoute("blog", "", t)); err != nil {
		t.Fatal(err)
	}
	if !auditHas(t, f, "config.changed") {
		t.Error("config.changed missing")
	}

	// A config Caddy rejects: the row says so, and the site stays out of the DB.
	f.svc.load = func([]byte, bool) error { return context.DeadlineExceeded } // pretend Caddy is unhappy
	if err := f.svc.Mutate(context.Background(), f.addRoute("blog2", "", t)); err == nil {
		t.Fatal("rejected mutate passed")
	}
	if !auditHas(t, f, "config.rejected") {
		t.Error("config.rejected missing")
	}
	sites, err := f.st.ListSites(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range sites {
		for _, h := range s.Hostnames {
			if h == "blog2.example.com" {
				t.Errorf("rejected mutate left %s in the DB", h)
			}
		}
	}
}

func auditHas(t *testing.T, f *fixture, action string) bool {
	rows, err := f.st.ListAudit(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.Action == action && r.Actor == "system" && r.Target == "caddy" {
			return true
		}
	}
	return false
}

// The LKG file holds basic-auth hashes: it must not be readable by other users.
func TestLastKnownGoodIsPrivate(t *testing.T) {
	f := newFixture(t)
	if err := f.svc.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(filepath.Dir(f.svc.opts.StoragePath), "caddy-last-good.json"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("last-known-good mode %v, want 0600", fi.Mode().Perm())
	}
}

// A crash mid-save leaves a half-written .tmp beside the real file. The next start ignores it, serves the
// stored config, and the following save replaces it.
func TestStartAfterInterruptedLKGSave(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	lkg := filepath.Join(filepath.Dir(f.svc.opts.StoragePath), "caddy-last-good.json")
	if err := os.WriteFile(lkg+".tmp", []byte(`{"apps":`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if f.svc.StartupError() != nil {
		t.Fatalf("stale temp file broke startup: %v", f.svc.StartupError())
	}
	if b, _ := os.ReadFile(lkg); !strings.Contains(string(b), uiHost) {
		t.Errorf("last-known-good not replaced: %q", b)
	}
	if _, err := os.Stat(lkg + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("temp file left behind: %v", err)
	}
}

// A torn LKG (truncated by something outside the atomic rename) plus a rejected stored config falls through to
// bootstrap-only instead of failing Start.
func TestStartWithTornLKGAndBadConfig(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.st.CreateSite(ctx, store.Site{Hostnames: []string{"bad.example.com"}, Scheme: "http",
		UpstreamHost: "127.0.0.1", UpstreamPort: 9, Enabled: true, Allowlist: "garbage"}); err != nil {
		t.Fatal(err)
	}
	lkg := filepath.Join(filepath.Dir(f.svc.opts.StoragePath), "caddy-last-good.json")
	if err := os.WriteFile(lkg, []byte(`{"apps":`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Start(ctx); err != nil {
		t.Fatalf("Start must fall back to bootstrap: %v", err)
	}
	if code, body := caddytest.Get(t, f.httpsPort, uiHost); code != 200 || body != "ui" {
		t.Fatalf("bootstrap UI site: %d %q", code, body)
	}
}
