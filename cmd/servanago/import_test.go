package main

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/cloudflare/cloudflare-go/v7/option"

	"github.com/servanago/servanago/internal/caddyfile"
	"github.com/servanago/servanago/internal/cfdns"
	"github.com/servanago/servanago/internal/cfdns/cftest"
	"github.com/servanago/servanago/internal/config"
	"github.com/servanago/servanago/internal/dnssync"
	"github.com/servanago/servanago/internal/store"
)

func importFx(t *testing.T) (*cftest.Fake, *store.Store, importer) {
	t.Helper()
	fake := cftest.New(t)
	fake.AddZone("example.com", "z1")
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cf := cfdns.New("tok", option.WithBaseURL(fake.URL), option.WithMaxRetries(0))
	return fake, st, importer{
		cfg: config.Config{Host: "servanago.example.com", HostIP: "10.0.0.5"},
		cf:  cf, st: st, dns: dnssync.New(cf, st),
	}
}

func TestImportSites(t *testing.T) {
	fake, st, imp := importFx(t)
	fake.Seed("kept.example.com", "10.0.0.5") // already points at us: adopted, not rewritten
	sites := []caddyfile.Site{
		{Hostname: "kept.example.com", Scheme: "http", Host: "192.168.1.9", Port: 80},
		{Hostname: "secure.example.com", Scheme: "https", Host: "192.168.1.9", Port: 443, SkipVerify: true, Stream: true, MaxBody: "2GB"},
		{Hostname: "servanago.example.com", Scheme: "http", Host: "192.168.1.9", Port: 1},
		{Hostname: "deep.sub.example.com", Scheme: "http", Host: "192.168.1.9", Port: 1},
		{Hostname: "nozone.other.org", Scheme: "http", Host: "192.168.1.9", Port: 1},
	}
	var out bytes.Buffer
	if err := imp.run(context.Background(), sites, false, &out); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ds, _ := st.ListDomains(ctx)
	if len(ds) != 1 || ds[0].Name != "example.com" || ds[0].ZoneID != "z1" || ds[0].DefaultIP != "10.0.0.5" {
		t.Fatalf("domains = %+v", ds)
	}
	rs, _ := st.ListSites(ctx)
	if len(rs) != 2 {
		t.Fatalf("routes = %+v, want kept + secure only\n%s", rs, out.String())
	}
	var secure store.Site
	for _, r := range rs {
		if r.Subdomain == "secure" {
			secure = r
		}
	}
	if secure.Scheme != "https" || !secure.TLSSkipVerify || !secure.Enabled || secure.UpstreamPort != 443 || !secure.Stream || secure.MaxBody != 2<<30 {
		t.Errorf("secure = %+v", secure)
	}
	for _, want := range []string{"servanago.example.com", "deep.sub.example.com", "nozone.other.org"} {
		if !strings.Contains(out.String(), "skip "+want) {
			t.Errorf("output lacks skip for %s:\n%s", want, out.String())
		}
	}
	if recs := fake.Records(); len(recs) != 2 { // kept (seeded) + secure (created)
		t.Errorf("cloudflare records = %+v", recs)
	}
}

func TestImportDryRunWritesNothing(t *testing.T) {
	fake, st, imp := importFx(t)
	sites := []caddyfile.Site{{Hostname: "a.example.com", Scheme: "http", Host: "192.168.1.9", Port: 80}}
	if err := imp.run(context.Background(), sites, true, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if ds, _ := st.ListDomains(context.Background()); len(ds) != 0 {
		t.Errorf("domains written: %+v", ds)
	}
	if fake.Writes() != 0 {
		t.Errorf("cloudflare writes = %d", fake.Writes())
	}
}

func TestImportIsRerunnable(t *testing.T) {
	_, st, imp := importFx(t)
	sites := []caddyfile.Site{{Hostname: "a.example.com", Scheme: "http", Host: "192.168.1.9", Port: 80}}
	for range 2 {
		if err := imp.run(context.Background(), sites, false, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
	}
	if rs, _ := st.ListSites(context.Background()); len(rs) != 1 {
		t.Errorf("routes = %+v", rs)
	}
}

func TestImportSummaryCountsParserSkips(t *testing.T) {
	_, _, imp := importFx(t)
	imp.parserSkipped = 3
	var out bytes.Buffer
	if err := imp.run(context.Background(), nil, true, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "would add 0, skipped 3") {
		t.Errorf("summary = %q", out.String())
	}
}

// import creates DNS records and looks up zones, so it needs Cloudflare; it must say so before touching anything.
func TestImportNeedsCloudflare(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SERVANAGO_HOST", "panel.example.com")
	t.Setenv("ACME_EMAIL", "me@example.com")
	t.Setenv("CLOUDFLARE_API_TOKEN", "")
	t.Setenv("DATA_DIR", dir+"/data")
	caddyfile := dir + "/Caddyfile"
	if err := os.WriteFile(caddyfile, []byte("app.example.com {\n\treverse_proxy http://10.0.0.1:80\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := runImport([]string{caddyfile}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "CLOUDFLARE_API_TOKEN") {
		t.Fatalf("want an error naming CLOUDFLARE_API_TOKEN, got %v", err)
	}
	if _, serr := os.Stat(dir + "/data"); serr == nil {
		t.Error("the data directory must not be created when import refuses to run")
	}
}
