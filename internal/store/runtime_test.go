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

	franken, err := st.CreateSite(ctx, Site{
		Hostnames: []string{"shop.example.com"}, Kind: "frankenphp",
		StaticRoot: "/srv/shop", UpstreamHost: "127.0.0.1", UpstreamPort: 8100, Enabled: true})
	if err != nil {
		t.Fatalf("create frankenphp site: %v", err)
	}
	if got, _ = st.GetSite(ctx, franken.ID); got.Kind != "frankenphp" || got.UpstreamPort != 8100 || !got.IsRuntime() || !got.HasUpstream() {
		t.Errorf("frankenphp round trip: %+v", got)
	}
	if _, err := st.CreateSite(ctx, Site{Hostnames: []string{"d.example.com"}, Kind: "frankenphp", StaticRoot: "/srv/d", UpstreamHost: "127.0.0.1", UpstreamPort: 8101, StartCommand: "x"}); err == nil || !strings.Contains(err.Error(), "CHECK constraint") {
		t.Errorf("frankenphp with a start command: %v", err)
	}

	// fastcgi: a host needs a port, a socket path must not have one; cgi has no upstream at all.
	for _, tt := range []struct {
		name string
		site Site
		ok   bool
	}{
		{"fastcgi socket", Site{Hostnames: []string{"f1.example.com"}, Kind: "fastcgi", StaticRoot: "/srv/f", UpstreamHost: "/run/f.sock"}, true},
		{"fastcgi tcp", Site{Hostnames: []string{"f2.example.com"}, Kind: "fastcgi", StaticRoot: "/srv/f", UpstreamHost: "10.0.0.5", UpstreamPort: 9000}, true},
		{"fastcgi host without port", Site{Hostnames: []string{"f3.example.com"}, Kind: "fastcgi", StaticRoot: "/srv/f", UpstreamHost: "10.0.0.5"}, false},
		{"fastcgi socket with port", Site{Hostnames: []string{"f4.example.com"}, Kind: "fastcgi", StaticRoot: "/srv/f", UpstreamHost: "/run/f.sock", UpstreamPort: 9000}, false},
		{"cgi", Site{Hostnames: []string{"c1.example.com"}, Kind: "cgi", StaticRoot: "/srv/c"}, true},
		{"cgi with upstream", Site{Hostnames: []string{"c2.example.com"}, Kind: "cgi", StaticRoot: "/srv/c", UpstreamHost: "127.0.0.1", UpstreamPort: 1}, false},
	} {
		if _, err := st.CreateSite(ctx, tt.site); (err == nil) != tt.ok {
			t.Errorf("%s: err=%v, want ok=%v", tt.name, err, tt.ok)
		}
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
