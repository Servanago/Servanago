package store

import (
	"context"
	"testing"
)

// The PHP build job runs as sg-phpbuild under servanago-phpbuild.service and servanago-phpfetch.service: a site whose
// slug were phpbuild or phpfetch would share its user and unit names.
func TestReservedSlugsAreSkipped(t *testing.T) {
	st, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	for host, want := range map[string]string{"phpbuild.example.com": "phpbuild-2", "phpfetch.example.com": "phpfetch-2", "blog.example.com": "blog"} {
		site, err := st.CreateSite(ctx, Site{Hostnames: []string{host}, Kind: "static", StaticRoot: "/srv/x", Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		if site.Slug != want {
			t.Errorf("%s got slug %q, want %q", host, site.Slug, want)
		}
	}
}
