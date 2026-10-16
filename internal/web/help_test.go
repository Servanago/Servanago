package web

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// Every hint "x" and helplink "y" used in a template must exist, so help text cannot silently go missing.
func TestTemplatesOnlyUseDefinedHelp(t *testing.T) {
	hintRE := regexp.MustCompile(`\{\{\s*hint "([a-z_]+)"`)
	linkRE := regexp.MustCompile(`helplink "([a-z-]+)"`)
	anchors := map[string]bool{}
	for _, s := range helpSections {
		anchors[s.ID] = true
	}
	found := 0
	err := fs.WalkDir(assets, "templates", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, _ := fs.ReadFile(assets, path)
		for _, m := range hintRE.FindAllStringSubmatch(string(b), -1) {
			found++
			if _, ok := hints[m[1]]; !ok {
				t.Errorf("%s uses undefined hint %q", path, m[1])
			}
		}
		for _, m := range linkRE.FindAllStringSubmatch(string(b), -1) {
			found++
			if !anchors[m[1]] {
				t.Errorf("%s links to undefined help section %q", path, m[1])
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found < 10 {
		t.Errorf("only %d hint/helplink uses found; the forms should be explained", found)
	}
}

func TestEveryHintIsPlainNonEmptyText(t *testing.T) {
	for k, v := range hints {
		if strings.TrimSpace(v) == "" || strings.ContainsAny(v, "<>") {
			t.Errorf("hint %q: empty or contains markup: %q", k, v)
		}
	}
}

func TestExplain(t *testing.T) {
	tests := []struct{ in, wantTitle string }{
		{"[x.com] solving challenges: waiting for solver certmagic.solverWrapper to be ready: timed out waiting for record to fully propagate; verify DNS provider configuration is correct - last error: <nil>", "slow"},
		{"no Cloudflare zone found for a.b.org (tried a.b.org, b.org)", "zone"},
		{"zone x.com: not found (the token cannot see it; it needs Zone:Read on that zone)", "zone"},
		{"multiple A records named oc.x.com; resolve in Cloudflare first", "More than one"},
		{`GET "https://api.cloudflare.com/client/v4/zones": 403 Forbidden {"errors":[{"code":9109,"message":"Invalid access token"}]}`, "token"},
		{"verify Cloudflare token: GET ...: 401 Unauthorized", "token"},
		{`default IP: "8.8.8.8" must be a private IPv4 address (10.0.0.0/8, ...)`, "private"},
		{"oc.x.com is the ServanaGo UI host; choose another subdomain", "own address"},
		{"x.com is a zone itself; use a subdomain such as app.x.com", "subdomain"},
		{"a.b.x.com is more than one label below x.com; a wildcard certificate would not cover it", "one level"},
		{"caddy rejected config: loading new config: invalid CIDR", "Caddy rejected"},
		{"urn:ietf:params:acme:error:rateLimited: too many certificates already issued", "rate limit"},
		{"obtaining certificate: context canceled", "interrupted"},
		{`Subdomain "oc" already exists on that domain.`, "already exists"},
	}
	for _, tt := range tests {
		e, ok := explain(tt.in)
		if !ok || !strings.Contains(strings.ToLower(e.Title), strings.ToLower(tt.wantTitle)) || e.Fix == "" {
			t.Errorf("%q -> %+v ok=%v, want title containing %q", tt.in, e, ok, tt.wantTitle)
		}
	}
	if _, ok := explain("some brand new failure"); ok {
		t.Error("unknown errors must not get an invented explanation")
	}
}

func TestCertWaitText(t *testing.T) {
	// delay + timeout is the longest Caddy waits for one DNS-01 attempt
	if got := certWait(2*60e9, 10*60e9); !strings.Contains(got, "12 minutes") {
		t.Errorf("2m+10m: %q", got)
	}
	if got := certWait(0, 0); !strings.Contains(got, "2 minutes") { // Caddy's default timeout
		t.Errorf("defaults: %q", got)
	}
}

func TestStatusHelpCoversEveryState(t *testing.T) {
	for _, k := range []string{"cert:issued", "cert:pending", "cert:error", "cert:expiring", "dns:synced", "dns:pending", "dns:conflict", "dns:error", "up:up", "up:down"} {
		if statusHelp[k].Meaning == "" {
			t.Errorf("no meaning for %s", k)
		}
	}
	for _, k := range []string{"cert:pending", "cert:error", "cert:expiring", "dns:conflict", "dns:error", "up:down"} {
		if statusHelp[k].Next == "" {
			t.Errorf("%s needs a next step", k)
		}
	}
}
