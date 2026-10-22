package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Notes round-trip, are capped at 10,000 characters by the schema, and every save stamps updated_at.
func TestSiteNotesAndUpdatedAt(t *testing.T) {
	st, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()

	a, err := st.CreateSite(ctx, Site{Hostnames: []string{"a.example.com"}, Scheme: "http", UpstreamHost: "127.0.0.1", UpstreamPort: 9, Notes: "owner: Brian\nrenew by hand", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if a.Notes != "owner: Brian\nrenew by hand" || a.UpdatedAt == "" {
		t.Fatalf("create: notes %q updated %q", a.Notes, a.UpdatedAt)
	}
	b, err := st.CreateSite(ctx, Site{Hostnames: []string{"b.example.com"}, Scheme: "http", UpstreamHost: "127.0.0.1", UpstreamPort: 9, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := time.Parse(time.RFC3339, b.UpdatedAt); err != nil {
		t.Fatalf("updated_at %q: %v", b.UpdatedAt, err)
	}

	// Backdate both, save only a: a moves, b stays.
	if _, err := st.db.Exec("UPDATE sites SET updated_at='2020-01-01T00:00:00Z'"); err != nil {
		t.Fatal(err)
	}
	a.Notes = "changed"
	if err := st.UpdateSite(ctx, a); err != nil {
		t.Fatal(err)
	}
	ga, _ := st.GetSite(ctx, a.ID)
	gb, _ := st.GetSite(ctx, b.ID)
	if ga.Notes != "changed" || ga.UpdatedAt == "2020-01-01T00:00:00Z" {
		t.Errorf("saved site: notes %q updated %q", ga.Notes, ga.UpdatedAt)
	}
	if gb.UpdatedAt != "2020-01-01T00:00:00Z" {
		t.Errorf("untouched site moved: %q", gb.UpdatedAt)
	}

	a.Notes = strings.Repeat("x", 10001)
	if err := st.UpdateSite(ctx, a); err == nil {
		t.Error("10,001-character notes accepted")
	}
	a.Notes = strings.Repeat("é", 10000) // characters, not bytes
	if err := st.UpdateSite(ctx, a); err != nil {
		t.Errorf("10,000 characters refused: %v", err)
	}
}
