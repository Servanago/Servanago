package caddycfg

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/servanago/servanago/internal/store"
)

var update = flag.Bool("update", false, "rewrite golden files")

func opts() Options {
	return Options{
		UIHost: "servanago.example.com", UIUpstream: "127.0.0.1:8080", Email: "me@example.com",
		HTTPPort: 80, HTTPSPort: 443, StoragePath: "/data/caddy", Resolvers: []string{"1.1.1.1", "8.8.8.8"},
	}
}

var (
	dom  = store.Domain{ID: 1, Name: "example.com", CertMode: "wildcard"}
	site = store.Site{ID: 1, Hostnames: []string{"sonarr.example.com"}, Scheme: "http", UpstreamHost: "192.168.1.20", UpstreamPort: 8989, Enabled: true}
)

func with(r store.Site, f func(*store.Site)) store.Site { f(&r); return r }

// snipOpts is opts() plus the two snippets the snippet tests attach.
func snipOpts() Options {
	o := opts()
	o.Snippets = []store.Snippet{{ID: 1, Name: "block_sensitive", Body: blockSensitive}, {ID: 2, Name: "compress", Body: "encode gzip zstd"}}
	return o
}

// asStatic turns a proxy site into a static one serving root.
func asStatic(r store.Site, root string) store.Site {
	r.Kind, r.StaticRoot, r.Scheme, r.UpstreamHost, r.UpstreamPort = "static", root, "", "", 0
	return r
}

// asNode turns a proxy site into a Node.js app site on localhost:port.
func asNode(r store.Site, slug string, port int, start string) store.Site {
	r.Kind, r.Slug, r.StaticRoot, r.Scheme = "node", slug, "/srv/www/"+slug, ""
	r.UpstreamHost, r.UpstreamPort, r.StartCommand = "127.0.0.1", port, start
	return r
}

// asPHP turns a site into a PHP-FPM site on version.
func asPHP(r store.Site, slug, version string) store.Site {
	r.Kind, r.Slug, r.StaticRoot, r.Scheme = "php", slug, "/srv/www/"+slug, ""
	r.UpstreamHost, r.UpstreamPort, r.FPMVersion = "", 0, version
	return r
}

func TestRenderGolden(t *testing.T) {
	staging := opts()
	staging.Staging = true
	timed := opts()
	timed.PropagationDelay, timed.PropagationTimeout = 2*time.Minute, 10*time.Minute
	internal := opts()
	internal.Issuer, internal.HTTPPort, internal.HTTPSPort = Internal, 18080, 18443
	perHost := dom
	perHost.CertMode = "per_host"
	http01 := opts()
	http01.HTTP01 = true

	tests := []struct {
		name  string
		opts  Options
		state State
	}{
		{"bootstrap", opts(), State{}},
		{"one_route", opts(), State{[]store.Domain{dom}, []store.Site{site}}},
		{"disabled", opts(), State{[]store.Domain{dom}, []store.Site{with(site, func(r *store.Site) { r.Enabled = false })}}},
		{"allowlist", opts(), State{[]store.Domain{dom}, []store.Site{with(site, func(r *store.Site) { r.Allowlist = "192.168.0.0/16\n10.0.0.0/8" })}}},
		{"basic_auth", opts(), State{[]store.Domain{dom}, []store.Site{with(site, func(r *store.Site) { r.BasicUser, r.BasicHash = "u", "$2a$14$abc" })}}},
		{"https_skip_verify", opts(), State{[]store.Domain{dom}, []store.Site{with(site, func(r *store.Site) { r.Scheme, r.TLSSkipVerify = "https", true })}}},
		{"https_verify", opts(), State{[]store.Domain{dom}, []store.Site{with(site, func(r *store.Site) { r.Scheme = "https" })}}},
		{"stream", opts(), State{[]store.Domain{dom}, []store.Site{with(site, func(r *store.Site) { r.Stream = true })}}},
		{"max_body", opts(), State{[]store.Domain{dom}, []store.Site{with(site, func(r *store.Site) { r.MaxBody = 2 << 30 })}}},
		{"stream_max_body_basic", opts(), State{[]store.Domain{dom}, []store.Site{with(site, func(r *store.Site) {
			r.Stream, r.MaxBody, r.BasicUser, r.BasicHash = true, 2<<30, "u", "$2a$14$abc"
		})}}},
		{"staging", staging, State{}},
		{"prod_default", opts(), State{[]store.Domain{dom}, nil}},
		{"propagation_set", timed, State{}},
		{"per_host", opts(), State{[]store.Domain{perHost}, []store.Site{site, with(site, func(r *store.Site) { r.ID, r.Hostnames = 2, []string{"radarr.example.com"} })}}},
		{"per_host_one_disabled", opts(), State{[]store.Domain{perHost}, []store.Site{site, with(site, func(r *store.Site) { r.ID, r.Hostnames, r.Enabled = 2, []string{"radarr.example.com"}, false })}}},
		{"per_host_all_disabled", opts(), State{[]store.Domain{perHost}, []store.Site{with(site, func(r *store.Site) { r.Enabled = false })}}},
		{"per_host_empty", opts(), State{[]store.Domain{perHost}, nil}},
		{"internal_issuer", internal, State{[]store.Domain{dom}, []store.Site{site}}},
		{"ipv6_upstream_and_allowlist", opts(), State{[]store.Domain{dom}, []store.Site{with(site, func(r *store.Site) {
			r.UpstreamHost, r.UpstreamPort, r.Allowlist = "2001:db8::5", 8443, "2001:db8::/32\nfd00::/8\n192.168.0.0/16"
		})}}},
		// No Cloudflare: default ACME challenges. A wildcard domain cannot be validated over HTTP-01, so it renders per host.
		{"http01_bootstrap", http01, State{}},
		{"http01_wildcard_domain", http01, State{[]store.Domain{dom}, []store.Site{site, with(site, func(r *store.Site) { r.ID, r.Hostnames = 2, []string{"radarr.example.com"} }), with(site, func(r *store.Site) { r.ID, r.Hostnames, r.Enabled = 3, []string{"off.example.com"}, false })}}},
		{"http01_per_host_domain", http01, State{[]store.Domain{perHost}, []store.Site{site}}},
		// Snippets run after the access chain and before the handler, except under /.well-known/.
		{"snippets_proxy", snipOpts(), State{[]store.Domain{dom}, []store.Site{with(site, func(r *store.Site) { r.Snippets = []string{"block_sensitive", "compress"} })}}},
		{"snippets_static_gate_basic", snipOpts(), State{[]store.Domain{dom}, []store.Site{with(asStatic(site, "/srv/www/blog"), func(r *store.Site) {
			r.GateMode, r.BasicUser, r.BasicHash, r.Snippets = "acl", "u", "$2a$14$abc", []string{"compress"}
		})}}},
		{"banking_homelab", opts(), State{[]store.Domain{dom}, []store.Site{{ID: 1, Hostnames: []string{"banking.example.com"}, Scheme: "http", UpstreamHost: "192.168.25.165", UpstreamPort: 8766, Enabled: true}}}},
		{"gate_acl", opts(), State{[]store.Domain{dom}, []store.Site{with(site, func(r *store.Site) { r.GateMode = "acl" })}}},
		{"gate_open", opts(), State{[]store.Domain{dom}, []store.Site{with(site, func(r *store.Site) { r.GateMode = "open" })}}},
		{"gate_acl_allowlist", opts(), State{[]store.Domain{dom}, []store.Site{with(site, func(r *store.Site) { r.GateMode, r.Allowlist = "acl", "192.168.0.0/16" })}}},
		// Hostnames are free FQDNs. Each gets its own route; a name the wildcard cannot cover (apex, deeper label)
		// or no domain at all gets its own certificate, and a domain-less one always uses HTTP-01.
		{"multi_hostname", opts(), State{[]store.Domain{dom}, []store.Site{with(site, func(r *store.Site) { r.Hostnames = []string{"sonarr.example.com", "tv.example.com"} })}}},
		{"no_domain", opts(), State{[]store.Domain{dom}, []store.Site{with(site, func(r *store.Site) { r.Hostnames = []string{"sonarr.example.org"} })}}},
		{"no_domain_http01", http01, State{nil, []store.Site{with(site, func(r *store.Site) { r.Hostnames = []string{"sonarr.example.org"} })}}},
		// Static sites: file_server from the root (no listing, dotfiles hidden), same allowlist/auth/gate chain as a proxy.
		{"static", opts(), State{[]store.Domain{dom}, []store.Site{asStatic(site, "/srv/www/blog")}}},
		{"static_gate_basic_allowlist", opts(), State{[]store.Domain{dom}, []store.Site{with(asStatic(site, "/srv/www/blog"), func(r *store.Site) {
			r.GateMode, r.Allowlist, r.BasicUser, r.BasicHash = "acl", "192.168.0.0/16", "u", "$2a$14$abc"
		})}}},
		// Node.js sites are a reverse proxy to the app's own port; same chain as a proxy route.
		{"node", opts(), State{[]store.Domain{dom}, []store.Site{asNode(site, "app11", 3000, "node server.js")}}},
		{"node_gated", opts(), State{[]store.Domain{dom}, []store.Site{with(asNode(site, "app11", 3000, "node server.js"), func(r *store.Site) { r.GateMode = "open" })}}},
		// FrankenPHP sites are a reverse proxy to the site's own loopback port, like node.
		{"frankenphp", opts(), State{[]store.Domain{dom}, []store.Site{with(asNode(site, "shop", 8100, ""), func(r *store.Site) { r.Kind = "frankenphp" })}}},
		// FastCGI sites send every request to an admin-run upstream (socket or host:port); cgi sites run /cgi-bin/* through their own fcgiwrap socket.
		{"fastcgi_socket", opts(), State{[]store.Domain{dom}, []store.Site{with(asStatic(site, "/srv/www/app"), func(r *store.Site) { r.Kind, r.UpstreamHost = "fastcgi", "/run/app/fcgi.sock" })}}},
		{"fastcgi_tcp", opts(), State{[]store.Domain{dom}, []store.Site{with(asStatic(site, "/srv/www/app"), func(r *store.Site) { r.Kind, r.UpstreamHost, r.UpstreamPort = "fastcgi", "10.0.0.5", 9000 })}}},
		{"cgi", opts(), State{[]store.Domain{dom}, []store.Site{with(asStatic(site, "/srv/www/legacy"), func(r *store.Site) { r.Kind, r.Slug = "cgi", "legacy" })}}},
		// PHP sites render the documented php_fastcgi expansion over the per-site socket.
		{"php", opts(), State{[]store.Domain{dom}, []store.Site{asPHP(site, "blog", "8.2")}}},
		{"php_public_dir", opts(), State{[]store.Domain{dom}, []store.Site{with(asPHP(site, "blog", "8.2"), func(r *store.Site) { r.PublicDir = "public" })}}},
		{"static_user", opts(), State{[]store.Domain{dom}, []store.Site{with(asStatic(site, "/home/blog/public_html"), func(r *store.Site) { r.Slug, r.SiteUser, r.PublicDir = "blog", "blog.example.com", "public" })}}},
		{"php_gate_basic", opts(), State{[]store.Domain{dom}, []store.Site{with(asPHP(site, "blog", "8.2"), func(r *store.Site) {
			r.GateMode, r.BasicUser, r.BasicHash = "acl", "u", "$2a$14$abc"
		})}}},
		{"wildcard_uncovered_names", opts(), State{[]store.Domain{dom}, []store.Site{with(site, func(r *store.Site) {
			r.Hostnames = []string{"example.com", "a.b.example.com", "sonarr.example.com"}
		})}}},
		// Extra routes: path prefixes proxied to their own upstream ahead of the site's main handler,
		// after the dotfile guard and inside the gate chain.
		{"extra_routes", opts(), State{[]store.Domain{dom}, []store.Site{with(site, func(r *store.Site) {
			r.ExtraRoutes = "/cryptpad_websocket=127.0.0.1:3303\n/api=/run/api.sock"
		})}}},
		{"extra_routes_static", opts(), State{[]store.Domain{dom}, []store.Site{with(asStatic(site, "/srv/www/blog"), func(r *store.Site) {
			r.ExtraRoutes = "/.well-known=10.0.0.5:8080"
		})}}},
		{"extra_routes_php", opts(), State{[]store.Domain{dom}, []store.Site{with(asPHP(site, "blog", "8.2"), func(r *store.Site) {
			r.ExtraRoutes = "/ws=127.0.0.1:3303"
		})}}},
		{"extra_routes_gate", opts(), State{[]store.Domain{dom}, []store.Site{with(asNode(site, "app11", 3000, "node server.js"), func(r *store.Site) {
			r.GateMode, r.ExtraRoutes = "open", "/cryptpad_websocket=127.0.0.1:3303"
		})}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Render(tt.state, tt.opts)
			if err != nil {
				t.Fatal(err)
			}
			var buf bytes.Buffer
			if err := json.Indent(&buf, got, "", "  "); err != nil {
				t.Fatal(err)
			}
			buf.WriteByte('\n')
			path := filepath.Join("testdata", tt.name+".golden.json")
			if *update {
				if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(buf.Bytes(), want) {
				t.Errorf("output differs from %s (run with -update to accept)\n%s", path, buf.String())
			}
		})
	}
}

// issuers walks the rendered config and returns every ACME issuer object.
func acmeIssuers(t *testing.T, b []byte) []map[string]any {
	t.Helper()
	var cfg map[string]any
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	pols := cfg["apps"].(map[string]any)["tls"].(map[string]any)["automation"].(map[string]any)["policies"].([]any)
	var out []map[string]any
	for _, p := range pols {
		for _, i := range p.(map[string]any)["issuers"].([]any) {
			out = append(out, i.(map[string]any))
		}
	}
	return out
}

func TestEveryIssuerHasEmail(t *testing.T) {
	b, err := Render(State{[]store.Domain{dom}, []store.Site{site}}, opts())
	if err != nil {
		t.Fatal(err)
	}
	is := acmeIssuers(t, b)
	if len(is) < 2 { // UI policy + wildcard policy
		t.Fatalf("issuers: %d", len(is))
	}
	for _, i := range is {
		if i["email"] != "me@example.com" {
			t.Errorf("issuer without email: %v", i)
		}
	}
}

func TestEmptyEmailErrors(t *testing.T) {
	o := opts()
	o.Email = ""
	if _, err := Render(State{}, o); err == nil || !strings.Contains(err.Error(), "email") {
		t.Fatalf("want email error, got %v", err)
	}
}

func TestDeterministic(t *testing.T) {
	st := State{[]store.Domain{dom, {ID: 2, Name: "b.org", CertMode: "per_host"}}, []store.Site{
		site, with(site, func(r *store.Site) { r.ID, r.Hostnames = 2, []string{"radarr.example.com"} }),
		with(site, func(r *store.Site) { r.ID, r.Hostnames = 3, []string{"sonarr.b.org"} }),
	}}
	a, _ := Render(st, opts())
	for range 20 {
		b, _ := Render(st, opts())
		if !bytes.Equal(a, b) {
			t.Fatal("render not deterministic")
		}
	}
}

func TestNoLiteralToken(t *testing.T) {
	t.Setenv("CLOUDFLARE_API_TOKEN", "SECRET-TOKEN-XYZ")
	b, err := Render(State{[]store.Domain{dom}, []store.Site{site}}, opts())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("SECRET-TOKEN-XYZ")) {
		t.Fatal("literal token in output")
	}
	if !bytes.Contains(b, []byte("{env.CLOUDFLARE_API_TOKEN}")) {
		t.Fatal("token placeholder missing")
	}
}

func TestPropagationOnlyWhenSet(t *testing.T) {
	unset, _ := Render(State{}, opts())
	if bytes.Contains(unset, []byte("propagation_")) {
		t.Error("propagation fields emitted when unset")
	}
	o := opts()
	o.PropagationDelay = 2 * time.Minute
	onlyDelay, _ := Render(State{}, o)
	if !bytes.Contains(onlyDelay, []byte("propagation_delay")) || bytes.Contains(onlyDelay, []byte("propagation_timeout")) {
		t.Error("delay-only case wrong")
	}
}

func TestRenderUsesServanagoNames(t *testing.T) {
	got, err := Render(State{[]store.Domain{dom}, []store.Site{with(site, func(r *store.Site) { r.GateMode = "acl" })}}, opts())
	if err != nil {
		t.Fatal(err)
	}
	s := string(got)
	for _, want := range []string{`"handler":"servanago_gate"`, `"output":"servanago"`} {
		if !strings.Contains(s, want) {
			t.Errorf("rendered config lacks %s", want)
		}
	}
	if strings.Contains(strings.ToLower(s), "caretak"+"arr") { // split so a rename sweep does not rewrite it
		t.Error("rendered config still mentions the old product name")
	}
}

func TestHTTP01RendersNoDNSChallengeAndNoWildcards(t *testing.T) {
	o := opts()
	o.HTTP01 = true
	got, err := Render(State{[]store.Domain{dom}, []store.Site{site}}, o)
	if err != nil {
		t.Fatal(err)
	}
	s := string(got)
	for _, banned := range []string{"challenges", "cloudflare", "CLOUDFLARE_API_TOKEN", "propagation", `"*.example.com"`} {
		if strings.Contains(s, banned) {
			t.Errorf("HTTP-01 config must not contain %q", banned)
		}
	}
	for _, want := range []string{`"module":"acme"`, `"sonarr.example.com"`} {
		if !strings.Contains(s, want) {
			t.Errorf("HTTP-01 config lacks %s", want)
		}
	}
}

// FrankenPHP serves dotfiles (.env, .git) itself, so Caddy must answer them with 404 before the proxy is reached.
func TestFrankenPHPBlocksDotfilesBeforeProxy(t *testing.T) {
	st := with(asNode(site, "shop", 8100, ""), func(r *store.Site) { r.Kind = "frankenphp" })
	got, err := Render(State{[]store.Domain{dom}, []store.Site{st}}, opts())
	if err != nil {
		t.Fatal(err)
	}
	// JSON keys are sorted, so order in the text says nothing: find the subroute that holds the app's upstream
	// and require its first route to be the terminal dotfile 404.
	var walk func(v any) bool
	walk = func(v any) bool {
		switch x := v.(type) {
		case map[string]any:
			if routes, ok := x["routes"].([]any); ok && len(routes) == 2 && strings.Contains(fmt.Sprint(routes[1]), "127.0.0.1:8100") && routes[1].(map[string]any)["match"] == nil {
				first, _ := routes[0].(map[string]any)
				return first["terminal"] == true && strings.Contains(fmt.Sprint(first["match"]), `(^|/)\.`) && strings.Contains(fmt.Sprint(first["handle"]), "404")
			}
			for _, c := range x {
				if walk(c) {
					return true
				}
			}
		case []any:
			for _, c := range x {
				if walk(c) {
					return true
				}
			}
		}
		return false
	}
	var cfg any
	if err := json.Unmarshal(got, &cfg); err != nil {
		t.Fatal(err)
	}
	if !walk(cfg) {
		t.Errorf("frankenphp route must start with a terminal dotfile 404 ahead of the upstream:\n%s", got)
	}
}

// A public folder is what Caddy serves and what php-fpm resolves scripts against.
func TestPublicDirIsTheServedRoot(t *testing.T) {
	for name, st := range map[string]store.Site{
		"php":     with(asPHP(site, "blog", "8.2"), func(r *store.Site) { r.PublicDir = "public" }),
		"static":  with(asStatic(site, "/srv/www/blog"), func(r *store.Site) { r.Slug, r.PublicDir = "blog", "public" }),
		"fastcgi": with(asStatic(site, "/srv/www/blog"), func(r *store.Site) { r.Kind, r.UpstreamHost, r.PublicDir = "fastcgi", "/run/app/fcgi.sock", "public" }),
	} {
		got, err := Render(State{[]store.Domain{dom}, []store.Site{st}}, opts())
		if err != nil {
			t.Fatal(err)
		}
		if strings.Count(string(got), `"root":"/srv/www/blog/public"`) == 0 || strings.Contains(string(got), `"root":"/srv/www/blog"`) {
			t.Errorf("%s: the served root is not the public folder:\n%s", name, got)
		}
	}
}

// A static site with its own user is served by that user's unit over its socket; Caddy only proxies, so it
// answers dotfiles itself and has no file_server for the site.
func TestStaticWithUserProxiesToItsSocket(t *testing.T) {
	st := with(asStatic(site, "/home/docs/public_html"), func(r *store.Site) { r.Slug, r.SiteUser = "docs", "docs.example.com" })
	got, err := Render(State{[]store.Domain{dom}, []store.Site{st}}, opts())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), `"dial":"unix//run/servanago/docs.sock"`) || strings.Contains(string(got), "file_server") || !strings.Contains(string(got), `(^|/)\\.`) {
		t.Errorf("static with a user:\n%s", got)
	}
}

// The php `file` matchers resolve try_files against their root; without one that is Caddy's working directory.
func TestPHPFileMatchersUseTheSiteRoot(t *testing.T) {
	st := with(asPHP(site, "blog", "8.2"), func(r *store.Site) { r.PublicDir = "public" })
	got, err := Render(State{[]store.Domain{dom}, []store.Site{st}}, opts())
	if err != nil {
		t.Fatal(err)
	}
	var cfg any
	if err := json.Unmarshal(got, &cfg); err != nil {
		t.Fatal(err)
	}
	var files, rooted int
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if f, ok := x["file"].(map[string]any); ok {
				files++
				if f["root"] == "/srv/www/blog/public" {
					rooted++
				}
			}
			for _, c := range x {
				walk(c)
			}
		case []any:
			for _, c := range x {
				walk(c)
			}
		}
	}
	walk(cfg)
	if files != 2 || rooted != files {
		t.Errorf("%d file matchers, %d with the site root:\n%s", files, rooted, got)
	}
}
