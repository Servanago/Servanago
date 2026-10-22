package store

import (
	"context"
	"strings"
	"testing"
)

// A site's user and public folder round-trip, a user serves one site, and each is only valid on the kinds that use it.
func TestSiteUserAndPublicDir(t *testing.T) {
	st, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()

	php, err := st.CreateSite(ctx, Site{Hostnames: []string{"luckyedward.com"}, Kind: "php", StaticRoot: "/home/luckyedward.com/public_html",
		FPMVersion: "8.4", SiteUser: "luckyedward.com", PublicDir: "public", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := st.GetSite(ctx, php.ID)
	if got.SiteUser != "luckyedward.com" || got.PublicDir != "public" || !got.IsRuntime() || got.WebRoot() != "/home/luckyedward.com/public_html/public" {
		t.Errorf("php round trip: %+v webroot %q", got, got.WebRoot())
	}
	got.PublicDir = ""
	if err := st.UpdateSite(ctx, got); err != nil {
		t.Fatal(err)
	}
	if got, _ = st.GetSite(ctx, php.ID); got.PublicDir != "" || got.WebRoot() != "/home/luckyedward.com/public_html" {
		t.Errorf("after update: %+v", got)
	}

	// a user with a static site: served by a unit, not by Caddy
	static, err := st.CreateSite(ctx, Site{Hostnames: []string{"docs.example.com"}, Kind: "static", StaticRoot: "/home/docs.example.com/public_html", SiteUser: "docs.example.com", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ = st.GetSite(ctx, static.ID); !got.IsRuntime() || got.HasUpstream() {
		t.Errorf("static with a user: %+v", got)
	}
	plain, err := st.CreateSite(ctx, Site{Hostnames: []string{"plain.example.com"}, Kind: "static", StaticRoot: "/srv/plain", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ = st.GetSite(ctx, plain.ID); got.IsRuntime() {
		t.Errorf("static without a user is Caddy's: %+v", got)
	}

	for name, s := range map[string]Site{
		"user already used": {Hostnames: []string{"two.example.com"}, Kind: "php", StaticRoot: "/home/luckyedward.com/two", FPMVersion: "8.4", SiteUser: "luckyedward.com"},
		"user on a proxy":   {Hostnames: []string{"p.example.com"}, Kind: "proxy", UpstreamHost: "h", UpstreamPort: 80, SiteUser: "bob"},
		"public on a node":  {Hostnames: []string{"n.example.com"}, Kind: "node", StaticRoot: "/srv/n", UpstreamHost: "127.0.0.1", UpstreamPort: 3000, StartCommand: "x", PublicDir: "public"},
	} {
		if _, err := st.CreateSite(ctx, s); err == nil || !strings.Contains(err.Error(), "constraint") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
