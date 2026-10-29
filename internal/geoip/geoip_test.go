package geoip

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBlockedDecisionTable(t *testing.T) {
	want := Codes("DE FR")
	cases := []struct {
		mode, country string
		blocked       bool
		why           string
	}{
		{"deny", "DE", true, "a listed country is denied"},
		{"deny", "US", false, "an unlisted country passes under deny"},
		{"deny", "", false, "unknown countries pass under deny (no record is no proof)"},
		{"allow", "DE", false, "a listed country passes under allow"},
		{"allow", "US", true, "any other country is blocked under allow"},
		{"allow", "", true, "unknown is not on the list: blocked, or the rule is meaningless"},
		{"", "DE", false, "no mode never blocks"},
		{"", "", false, "no mode and no record never blocks"},
	}
	for _, c := range cases {
		if got := Blocked(c.mode, c.country, want); got != c.blocked {
			t.Errorf("mode %q country %q = %v: want %v (%s)", c.mode, c.country, got, c.blocked, c.why)
		}
	}
	if got := Codes("de us "); got["DE"] == false || got["US"] == false || len(got) != 2 {
		t.Errorf("codes parse: %v", got)
	}
	// no path = geo off: lookup answers unknown with no error
	if c, err := New().Lookup(netip.MustParseAddr("192.168.25.10")); c != "" || err != nil {
		t.Errorf("geo off: %q %v", c, err)
	}
}

// TestLiveGeoIP runs the reader against the host's real GeoLite2-Country file (bee and v1 keep
// one under /var/lib/GeoIP; geoipupdate refreshes it) and exercises the reopen-on-swap path by
// touching the copy's mtime. Skipped on hosts without the file.
func TestLiveGeoIP(t *testing.T) {
	const installed = "/var/lib/GeoIP/GeoLite2-Country.mmdb"
	src, err := os.Stat(installed)
	if err != nil {
		t.Skip("no GeoLite2 database on this host:", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "GeoLite2-Country.mmdb")
	b, err := os.ReadFile(installed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	d := New()
	d.Use(path)
	// known public IP: 8.8.8.8 is Google, US in every edition; 2602:200::... skip, keep it simple
	if c, err := d.Lookup(netip.MustParseAddr("8.8.8.8")); err != nil || c != "US" {
		t.Fatalf("8.8.8.8 = %q %v", c, err)
	}
	// a private address has no entry
	if c, err := d.Lookup(netip.MustParseAddr("192.168.25.10")); err != nil || c != "" {
		t.Fatalf("private = %q %v", c, err)
	}
	// geoipupdate replaced the file (simulated by an mtime bump): the reader reopens, lookups keep working
	if err := os.Chtimes(path, src.ModTime().Add(time.Hour), src.ModTime().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if c, err := d.Lookup(netip.MustParseAddr("8.8.8.8")); err != nil || c != "US" {
		t.Fatalf("after reopen: %q %v", c, err)
	}
	// a path the file leaves: the error is stable (so callers can log it once per state)
	d.Use(filepath.Join(dir, "gone.mmdb"))
	c1, err1 := d.Lookup(netip.MustParseAddr("8.8.8.8"))
	c2, err2 := d.Lookup(netip.MustParseAddr("8.8.8.8"))
	if err1 == nil || err1.Error() != err2.Error() || c1 != "" {
		t.Fatalf("missing file: %q %v then %q %v", c1, err1, c2, err2)
	}
}
