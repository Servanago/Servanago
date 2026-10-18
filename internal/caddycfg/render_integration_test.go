package caddycfg

import (
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
