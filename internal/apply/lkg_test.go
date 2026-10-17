package apply

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
