package apply

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/servanago/servanago/internal/caddycfg"
	"github.com/servanago/servanago/internal/caddylog"
	"github.com/servanago/servanago/internal/caddytest"
	"github.com/servanago/servanago/internal/store"
)

// A real ACME issuer pointed at a dead CA must fail issuance and surface it in the log ring.
func TestACMEFailureAppearsInLogRing(t *testing.T) {
	t.Setenv("CLOUDFLARE_API_TOKEN", strings.Repeat("a", 40))
	storage := t.TempDir()
	caddytest.Cleanup(t)
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	svc := New(st, caddycfg.Options{
		UIHost: "ui.example.com", UIUpstream: "127.0.0.1:9", Email: "me@example.com", Issuer: caddycfg.ACME,
		CA:        "http://127.0.0.1:" + strconv.Itoa(caddytest.FreePort(t)) + "/directory", // nothing listens there
		Resolvers: []string{"127.0.0.1"}, HTTPPort: caddytest.FreePort(t), HTTPSPort: caddytest.FreePort(t), StoragePath: storage,
	})
	if err := svc.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for caddylog.Sink.LastError("ui.example.com") == "" {
		if time.Now().After(deadline) {
			t.Fatalf("no ACME error in the ring; entries: %v", caddylog.Sink.Lines())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// With no Cloudflare token the default ACME challenges are used. Real Caddy must accept that config
// (no env token, no DNS provider) and a dead CA must still surface in the log ring.
func TestHTTP01IssuerLoadsAndFailsVisibly(t *testing.T) {
	storage := t.TempDir()
	caddytest.Cleanup(t)
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	svc := New(st, caddycfg.Options{
		UIHost: "ui-http01.example.com", UIUpstream: "127.0.0.1:9", Email: "me@example.com", Issuer: caddycfg.ACME, HTTP01: true,
		CA:       "http://127.0.0.1:" + strconv.Itoa(caddytest.FreePort(t)) + "/directory", // nothing listens there
		HTTPPort: caddytest.FreePort(t), HTTPSPort: caddytest.FreePort(t), StoragePath: storage,
	})
	if err := svc.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := svc.StartupError(); err != nil {
		t.Fatalf("the HTTP-01 config was rejected, so only the bootstrap config is live: %v", err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for caddylog.Sink.LastError("ui-http01.example.com") == "" {
		if time.Now().After(deadline) {
			t.Fatalf("no ACME error in the ring; entries: %v", caddylog.Sink.Lines())
		}
		time.Sleep(20 * time.Millisecond)
	}
}
