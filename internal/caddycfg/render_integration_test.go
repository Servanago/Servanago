package caddycfg

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	_ "github.com/servanago/servanago/internal/caddygeoip"
	"github.com/servanago/servanago/internal/caddytest"
	"github.com/servanago/servanago/internal/store"
)

// TestPHPRouteLoads: the rendered php config parses and loads in-process Caddy (the pool socket
// does not need to exist for the config to load; a dial failure is a per-request 502).
func TestPHPRouteLoads(t *testing.T) {
	storage := caddytest.TempDir(t) // before Cleanup so it is removed after Caddy stops
	caddytest.Cleanup(t)
	t.Cleanup(func() { _ = caddy.Stop() })
	site := asPHP(store.Site{ID: 2, Hostnames: []string{"php.test"}, Enabled: true}, "phpt", "8.2")
	o := opts()
	o.Issuer = Internal
	o.HTTPPort, o.HTTPSPort = caddytest.FreePort(t), caddytest.FreePort(t)
	o.StoragePath = storage
	b, err := Render(State{[]store.Domain{}, []store.Site{site}}, o)
	if err != nil {
		t.Fatal(err)
	}
	if err := caddy.Load(b, false); err != nil {
		t.Fatalf("caddy rejected the php config: %v", err)
	}
}

// TestExtraRoutesServe: a proxy site's extra route answers on its own upstream while everything
// else still reaches the site's main upstream.
func TestExtraRoutesServe(t *testing.T) {
	storage := caddytest.TempDir(t)
	caddytest.Cleanup(t)
	t.Cleanup(func() { _ = caddy.Stop() })
	main, extra := caddytest.Upstream(t, "main"), caddytest.Upstream(t, "ws")
	_, mainPort, _ := net.SplitHostPort(main)
	siteR := store.Site{ID: 2, Hostnames: []string{"extra.test"}, Scheme: "http", UpstreamHost: "127.0.0.1", Enabled: true}
	n, _ := strconv.Atoi(mainPort)
	siteR.UpstreamPort = n
	site := with(siteR, func(r *store.Site) {
		r.ExtraRoutes = "/cryptpad_websocket=" + extra
	})
	o := opts()
	o.Issuer = Internal
	o.HTTPPort, o.HTTPSPort = caddytest.FreePort(t), caddytest.FreePort(t)
	o.StoragePath = storage
	b, err := Render(State{[]store.Domain{}, []store.Site{site}}, o)
	if err != nil {
		t.Fatal(err)
	}
	if err := caddy.Load(b, false); err != nil {
		t.Fatalf("caddy rejected the config: %v", err)
	}
	status, body := caddytest.GetPath(t, o.HTTPSPort, site.Hostnames[0], "/")
	if status != 200 || body != "main" {
		t.Fatalf("GET / = %d %q; want 200 main", status, body)
	}
	status, body = caddytest.GetPath(t, o.HTTPSPort, site.Hostnames[0], "/cryptpad_websocket/other?x=1")
	if status != 200 || body != "ws" {
		t.Fatalf("GET /cryptpad_websocket/other = %d %q; want 200 ws", status, body)
	}
}

// TestSnippetsServe: block_sensitive answers 404 for dotfiles and lockfiles, /.well-known/ bypasses snippets,
// and the encode snippet compresses what passes.
func TestSnippetsServe(t *testing.T) {
	storage := caddytest.TempDir(t)
	caddytest.Cleanup(t)
	t.Cleanup(func() { _ = caddy.Stop() })
	up := caddytest.Upstream(t, strings.Repeat("hello ", 200))
	_, upPort, _ := net.SplitHostPort(up)
	n, _ := strconv.Atoi(upPort)
	site := store.Site{ID: 2, Hostnames: []string{"snip.test"}, Scheme: "http", UpstreamHost: "127.0.0.1", UpstreamPort: n, Enabled: true,
		Snippets: []string{"block_sensitive", "compress"}}
	o := snipOpts()
	o.Issuer = Internal
	o.HTTPPort, o.HTTPSPort = caddytest.FreePort(t), caddytest.FreePort(t)
	o.StoragePath = storage
	b, err := Render(State{[]store.Domain{}, []store.Site{site}}, o)
	if err != nil {
		t.Fatal(err)
	}
	if err := caddy.Load(b, false); err != nil {
		t.Fatalf("caddy rejected the config: %v", err)
	}
	for path, want := range map[string]int{
		"/": 200, "/index.html": 200, "/.env": 404, "/.git/config": 404, "/composer.lock": 404, "/go.sum": 404,
		"/.well-known/security.txt": 200, "/sub/composer.lock": 200, // snippet paths are anchored at the root
	} {
		if status, _ := caddytest.GetPath(t, o.HTTPSPort, "snip.test", path); status != want {
			t.Errorf("GET %s = %d; want %d", path, status, want)
		}
	}
	for path, want := range map[string]string{"/": "zstd", "/.well-known/security.txt": ""} {
		if got := encodingOf(t, o.HTTPSPort, "snip.test", path); got != want {
			t.Errorf("GET %s Content-Encoding = %q; want %q", path, got, want)
		}
	}
}

// encodingOf requests path asking for zstd and returns the Content-Encoding the server chose.
func encodingOf(t *testing.T, httpsPort int, host, path string) string {
	t.Helper()
	c := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: host},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort("127.0.0.1", strconv.Itoa(httpsPort)))
		},
	}}
	req, _ := http.NewRequest(http.MethodGet, "https://"+host+path, nil)
	req.Header.Set("Accept-Encoding", "zstd")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.Header.Get("Content-Encoding")
}

// TestGeoRouteLoads proves the rendered country rule is a JSON Caddy loads (the module comes
// with the caddygeoip import) and that local traffic still reaches the site: the rules only
// judge public addresses, so the blocking logic itself lives in caddygeoip's own tests.
func TestGeoRouteLoads(t *testing.T) {
	storage := caddytest.TempDir(t)
	caddytest.Cleanup(t)
	t.Cleanup(func() { _ = caddy.Stop() })
	upstream := caddytest.Upstream(t, "geo")
	_, port, _ := net.SplitHostPort(upstream)
	n, _ := strconv.Atoi(port)
	site := store.Site{ID: 2, Hostnames: []string{"geo.test"}, Scheme: "http", UpstreamHost: "127.0.0.1",
		UpstreamPort: n, Enabled: true, CountryMode: "deny", Countries: "DE FR"}
	o := opts()
	o.Issuer = Internal
	o.HTTPPort, o.HTTPSPort = caddytest.FreePort(t), caddytest.FreePort(t)
	o.StoragePath = storage
	b, err := Render(State{[]store.Domain{}, []store.Site{site}}, o)
	if err != nil {
		t.Fatal(err)
	}
	if err := caddy.Load(b, false); err != nil {
		t.Fatalf("caddy rejected the geo config: %v", err)
	}
	// the site answers its upstream for a local client (the geo rule judges public addresses only)
	if status, _ := caddytest.GetPath(t, o.HTTPSPort, "geo.test", "/"); status != 200 {
		t.Errorf("local GET: %d", status)
	}
}
