package store

import (
	"context"
	"strings"
	"testing"
)

// TestRuntimeSiteKinds: node and php sites round-trip through the schema's kind CHECK constraints.
func TestRuntimeSiteKinds(t *testing.T) {
	st, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()

	node, err := st.CreateSite(ctx, Site{
		Hostnames: []string{"app.example.com"}, Kind: "node",
		StaticRoot: "/srv/app", UpstreamHost: "127.0.0.1", UpstreamPort: 3000,
		StartCommand: "node server.js", Enabled: true})
	if err != nil {
		t.Fatalf("create node site: %v", err)
	}
	if node.Slug == "" {
		t.Fatal("node site has no slug")
	}
	got, err := st.GetSite(ctx, node.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != "node" || got.StaticRoot != "/srv/app" || got.StartCommand != "node server.js" ||
		got.InstallCommand != "" || got.BuildCommand != "" || got.FPMVersion != "" {
		t.Errorf("node round trip: %+v", got)
	}

	php, err := st.CreateSite(ctx, Site{
		Hostnames: []string{"php.example.com"}, Kind: "php",
		StaticRoot: "/srv/php", FPMVersion: "8.2", Enabled: true})
	if err != nil {
		t.Fatalf("create php site: %v", err)
	}
	got, err = st.GetSite(ctx, php.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != "php" || got.FPMVersion != "8.2" || got.StartCommand != "" {
		t.Errorf("php round trip: %+v", got)
	}

	// CHECK violations: node without a start command, php without a version, node with an fpm version.
	for _, tt := range []struct {
		name string
		site Site
		want string
	}{
		{"node without start", Site{Hostnames: []string{"a.example.com"}, Kind: "node", StaticRoot: "/srv/a", UpstreamHost: "127.0.0.1", UpstreamPort: 3000}, "CHECK constraint"},
		{"php without version", Site{Hostnames: []string{"b.example.com"}, Kind: "php", StaticRoot: "/srv/b"}, "CHECK constraint"},
		{"node with fpm version", Site{Hostnames: []string{"c.example.com"}, Kind: "node", StaticRoot: "/srv/c", UpstreamHost: "127.0.0.1", UpstreamPort: 3001, StartCommand: "node", FPMVersion: "8.2"}, "CHECK constraint"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := st.CreateSite(ctx, tt.site); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("CreateSite(%v) = %v, want %q", tt.site.Kind, err, tt.want)
			}
		})
	}

	// Update keeps the columns.
	node.StartCommand, node.BuildCommand = "node dist/server.js", "bun build"
	if err := st.UpdateSite(ctx, node); err != nil {
		t.Fatal(err)
	}
	got, _ = st.GetSite(ctx, node.ID)
	if got.StartCommand != "node dist/server.js" || got.BuildCommand != "bun build" {
		t.Errorf("update lost commands: %+v", got)
	}
}
