package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/servanago/servanago/internal/caddyfile"
)

// Snippets that adapt are created and attached to the sites that import them; the rest are reported, and the
// site is still imported without them. A rerun changes nothing.
func TestImportSnippets(t *testing.T) {
	_, st, imp := importFx(t)
	imp.snippets = []caddyfile.Snippet{
		{Name: "block_sensitive", Body: "@lock path /composer.lock\nrespond @lock 404"},
		{Name: "compress", Body: "encode gzip zstd"},
		{Name: "cloudflare", Body: "tls {\ndns cloudflare x\n}"},
	}
	sites := []caddyfile.Site{
		{Hostname: "a.example.com", Scheme: "http", Host: "192.168.1.9", Port: 80, Imports: []string{"block_sensitive", "cloudflare", "compress", "undefined_one"}},
	}
	ctx := context.Background()
	var out bytes.Buffer
	if err := imp.run(ctx, sites, false, &out); err != nil {
		t.Fatal(err)
	}
	if err := imp.run(ctx, sites, false, &bytes.Buffer{}); err != nil { // a rerun changes nothing
		t.Fatal(err)
	}
	rs, _ := st.ListSites(ctx)
	if len(rs) != 1 || strings.Join(rs[0].Snippets, ",") != "block_sensitive,compress" {
		t.Fatalf("sites = %+v\n%s", rs, out.String())
	}
	if all, _ := st.ListSnippets(ctx); len(all) != 2 {
		t.Fatalf("snippets = %+v", all)
	}
	for _, want := range []string{"skip snippet cloudflare", "snippets not attached: cloudflare, undefined_one"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
}

func TestImportSnippetConflictKeepsExisting(t *testing.T) {
	_, st, imp := importFx(t)
	ctx := context.Background()
	if _, err := st.CreateSnippet(ctx, "compress", "encode gzip"); err != nil {
		t.Fatal(err)
	}
	imp.snippets = []caddyfile.Snippet{{Name: "compress", Body: "encode zstd"}}
	var out bytes.Buffer
	sites := []caddyfile.Site{{Hostname: "a.example.com", Scheme: "http", Host: "192.168.1.9", Port: 80, Imports: []string{"compress"}}}
	if err := imp.run(ctx, sites, false, &out); err != nil {
		t.Fatal(err)
	}
	all, _ := st.ListSnippets(ctx)
	if len(all) != 1 || all[0].Body != "encode gzip" || !strings.Contains(out.String(), "differs") {
		t.Fatalf("snippets %+v\n%s", all, out.String())
	}
	if rs, _ := st.ListSites(ctx); len(rs) != 1 || len(rs[0].Snippets) != 0 {
		t.Fatalf("a conflicting snippet must not be attached: %+v", rs)
	}
}
