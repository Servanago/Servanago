package store

import (
	"context"
	"reflect"
	"regexp"
	"testing"
)

func TestSiteHostnamesPrimaryFirstAndUnique(t *testing.T) {
	s, ctx := open(t), context.Background()
	r := site("a.example.com")
	r.Hostnames = []string{"a.example.com", "b.example.org"}
	r, err := s.CreateSite(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetSite(ctx, r.ID); !reflect.DeepEqual(got.Hostnames, []string{"a.example.com", "b.example.org"}) {
		t.Fatalf("hostnames: %v", got.Hostnames)
	}
	if _, err := s.CreateSite(ctx, site("b.example.org")); err == nil {
		t.Error("hostname shared by two sites accepted")
	}
	// Reordering on update moves the primary; the list always starts with it.
	r.Hostnames = []string{"b.example.org", "a.example.com"}
	if err := s.UpdateSite(ctx, r); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetSite(ctx, r.ID)
	if got.Hostnames[0] != "b.example.org" || len(got.Hostnames) != 2 {
		t.Fatalf("after reorder: %v", got.Hostnames)
	}
	// Exactly one primary row per site.
	var primaries int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM site_hostnames WHERE site_id=? AND is_primary=1`, r.ID).Scan(&primaries); err != nil || primaries != 1 {
		t.Fatalf("primaries %d %v", primaries, err)
	}
	if _, err := s.CreateSite(ctx, Site{Scheme: "http", UpstreamHost: "h", UpstreamPort: 1}); err == nil {
		t.Error("site without a hostname accepted")
	}
	if err := s.DeleteSite(ctx, r.ID); err != nil {
		t.Fatal(err)
	}
	var left int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM site_hostnames`).Scan(&left); err != nil || left != 0 {
		t.Fatalf("hostnames survived their site: %d %v", left, err)
	}
}

func TestResolveDomainLongestSuffix(t *testing.T) {
	ds := []Domain{{ID: 1, Name: "example.com"}, {ID: 2, Name: "lab.example.com"}, {ID: 3, Name: "example.co.uk"}}
	for host, want := range map[string]int64{
		"app.example.com":     1,
		"app.lab.example.com": 2, // longest suffix wins
		"example.com":         1, // the apex is a host of its own domain
		"app.example.co.uk":   3, // multi-label public suffixes need no special casing
		"a.b.example.com":     1,
	} {
		if d, ok := ResolveDomain(ds, host); !ok || d.ID != want {
			t.Errorf("%s: got %+v %v, want domain %d", host, d, ok, want)
		}
	}
	for _, host := range []string{"app.example.org", "badexample.com", "co.uk"} { // no match, and no partial-label match
		if _, ok := ResolveDomain(ds, host); ok {
			t.Errorf("%s resolved", host)
		}
	}
}

func TestSlugDerivedUniqueAndImmutable(t *testing.T) {
	s, ctx := open(t), context.Background()
	valid := regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`)
	mk := func(host string) Site {
		t.Helper()
		r, err := s.CreateSite(ctx, site(host))
		if err != nil {
			t.Fatal(err)
		}
		if !valid.MatchString(r.Slug) {
			t.Fatalf("%s: slug %q is not valid", host, r.Slug)
		}
		return r
	}
	a := mk("app.example.com")
	b := mk("app.example.org") // same first label: made unique
	if a.Slug != "app" || b.Slug != "app-2" {
		t.Fatalf("slugs %q %q", a.Slug, b.Slug)
	}
	for _, host := range []string{"1pass.example.com", "a.example.com", "x_y.example.com", "averyveryveryveryveryverylonglabelname.example.com"} {
		mk(host)
	}
	// Renaming the site never changes its slug.
	a.Hostnames = []string{"renamed.example.com"}
	if err := s.UpdateSite(ctx, a); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetSite(ctx, a.ID); got.Slug != "app" || got.Kind != "proxy" {
		t.Fatalf("after rename: slug %q kind %q", got.Slug, got.Kind)
	}
}

// DNS rows are keyed by hostname and family, so a site's several hostnames each keep their own pair.
func TestDNSRecordsPerHostname(t *testing.T) {
	s, ctx := open(t), context.Background()
	a, err := s.CreateSite(ctx, Site{Hostnames: []string{"a.example.com", "b.example.com"}, Scheme: "http", UpstreamHost: "h", UpstreamPort: 1, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	other, _ := s.CreateSite(ctx, site("c.example.com"))
	for _, rec := range []DNSRecord{
		{Hostname: "a.example.com", SiteID: a.ID, Family: FamilyA, State: "synced", Owned: true},
		{Hostname: "a.example.com", SiteID: a.ID, Family: FamilyAAAA, State: "synced", Owned: true},
		{Hostname: "b.example.com", SiteID: a.ID, Family: FamilyA, State: "pending"},
		{Hostname: "c.example.com", SiteID: other.ID, Family: FamilyA, State: "synced"},
	} {
		if err := s.UpsertDNS(ctx, rec); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := s.ListSiteDNS(ctx, a.ID)
	if err != nil || len(rows) != 3 || rows[0].Hostname != "a.example.com" || rows[2].Hostname != "b.example.com" {
		t.Fatalf("site rows: %+v %v", rows, err)
	}
	if err := s.DeleteDNSRecord(ctx, "b.example.com", FamilyA); err != nil {
		t.Fatal(err)
	}
	if rows, _ = s.ListSiteDNS(ctx, a.ID); len(rows) != 2 {
		t.Fatalf("after deleting one hostname's row: %+v", rows)
	}
	if got, err := s.GetDNS(ctx, "c.example.com", FamilyA); err != nil || got.SiteID != other.ID {
		t.Fatalf("another site's row was touched: %+v %v", got, err)
	}
}

func TestStaticSiteRoundTripAndConstraints(t *testing.T) {
	s, ctx := open(t), context.Background()
	st, err := s.CreateSite(ctx, Site{Kind: "static", StaticRoot: "/srv/www/blog", Hostnames: []string{"blog.example.com"}, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetSite(ctx, st.ID)
	if got.Kind != "static" || got.StaticRoot != "/srv/www/blog" || got.UpstreamHost != "" || got.UpstreamPort != 0 {
		t.Fatalf("static round trip: %+v", got)
	}
	p, err := s.CreateSite(ctx, site("app.example.com"))
	if err != nil || p.Kind != "proxy" || p.StaticRoot != "" {
		t.Fatalf("proxy default: %+v %v", p, err)
	}
	for name, bad := range map[string]Site{
		"static without a root":     {Kind: "static", Hostnames: []string{"a.example.com"}},
		"proxy with a root":         {Kind: "proxy", StaticRoot: "/x", Hostnames: []string{"b.example.com"}, Scheme: "http", UpstreamHost: "h", UpstreamPort: 1},
		"proxy without an upstream": {Kind: "proxy", Hostnames: []string{"c.example.com"}, Scheme: "http"},
		"unknown kind":              {Kind: "php", StaticRoot: "/x", Hostnames: []string{"d.example.com"}},
	} {
		if _, err := s.CreateSite(ctx, bad); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	got.StaticRoot = "/srv/www/blog2"
	if err := s.UpdateSite(ctx, got); err != nil {
		t.Fatal(err)
	}
	if again, _ := s.GetSite(ctx, st.ID); again.StaticRoot != "/srv/www/blog2" {
		t.Fatalf("update: %+v", again)
	}
}
