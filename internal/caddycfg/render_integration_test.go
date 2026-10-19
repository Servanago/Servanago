package caddycfg

import (
	"net"
	"strconv"
	"testing"

	"github.com/caddyserver/caddy/v2"
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
