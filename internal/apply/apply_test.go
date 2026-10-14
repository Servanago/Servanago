package apply

import (
	"context"
	"net"
	"strconv"
	"testing"

	"github.com/caddyserver/caddy/v2"

	"github.com/caretakarr/caretakarr/internal/caddycfg"
	"github.com/caretakarr/caretakarr/internal/caddytest"
	"github.com/caretakarr/caretakarr/internal/store"
)

const uiHost = "ui.example.com"

type fixture struct {
	svc       *Service
	st        *store.Store
	httpsPort int
	loads     int
	domainID  int64
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	storage := t.TempDir() // before Cleanup so it is removed after Caddy stops
	caddytest.Cleanup(t)
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	f := &fixture{st: st, httpsPort: caddytest.FreePort(t)}
	d, err := st.CreateDomain(context.Background(), store.Domain{Name: "example.com", ZoneID: "z", DefaultIP: "10.0.0.1", CertMode: "wildcard"})
	if err != nil {
		t.Fatal(err)
	}
	f.domainID = d.ID
	f.svc = New(st, caddycfg.Options{
		UIHost: uiHost, UIUpstream: caddytest.Upstream(t, "ui"), Email: "me@example.com", Issuer: caddycfg.Internal,
		HTTPPort: caddytest.FreePort(t), HTTPSPort: f.httpsPort, StoragePath: storage,
	})
	f.svc.load = func(b []byte, force bool) error { f.loads++; return caddy.Load(b, force) }
	return f
}

func (f *fixture) addRoute(sub, body string, t *testing.T) func(*store.Store) error {
	host, port := splitHostPort(t, caddytest.Upstream(t, body))
	return func(tx *store.Store) error {
		_, err := tx.CreateRoute(context.Background(), store.Route{
			DomainID: f.domainID, Subdomain: sub, Scheme: "http", UpstreamHost: host, UpstreamPort: port, Enabled: true})
		return err
	}
}

func TestMutateMakesRouteLive(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if err := f.svc.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Mutate(ctx, f.addRoute("app", "hello", t)); err != nil {
		t.Fatal(err)
	}
	if code, body := caddytest.Get(t, f.httpsPort, "app.example.com"); code != 200 || body != "hello" {
		t.Fatalf("got %d %q", code, body)
	}
	if code, body := caddytest.Get(t, f.httpsPort, uiHost); code != 200 || body != "ui" {
		t.Fatalf("ui route: %d %q", code, body)
	}
}

func TestInvalidMutationRollsBack(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if err := f.svc.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Mutate(ctx, f.addRoute("app", "hello", t)); err != nil {
		t.Fatal(err)
	}
	err := f.svc.Mutate(ctx, func(tx *store.Store) error {
		r, err := tx.CreateRoute(ctx, store.Route{DomainID: f.domainID, Subdomain: "bad", Scheme: "http",
			UpstreamHost: "127.0.0.1", UpstreamPort: 9, Enabled: true, Allowlist: "not-a-cidr"})
		_ = r
		return err
	})
	if err == nil {
		t.Fatal("Caddy accepted an invalid CIDR")
	}
	rs, _ := f.st.ListRoutes(ctx)
	if len(rs) != 1 || rs[0].Subdomain != "app" {
		t.Fatalf("db not rolled back: %+v", rs)
	}
	if code, body := caddytest.Get(t, f.httpsPort, "app.example.com"); code != 200 || body != "hello" {
		t.Fatalf("old route lost: %d %q", code, body)
	}
}

func TestCorruptStateFallsBackToBootstrap(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.st.CreateRoute(ctx, store.Route{DomainID: f.domainID, Subdomain: "bad", Scheme: "http",
		UpstreamHost: "127.0.0.1", UpstreamPort: 9, Enabled: true, Allowlist: "garbage"}); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Start(ctx); err != nil {
		t.Fatalf("bootstrap fallback must not fail Start: %v", err)
	}
	if f.svc.StartupError() == nil {
		t.Fatal("StartupError not set")
	}
	if code, body := caddytest.Get(t, f.httpsPort, uiHost); code != 200 || body != "ui" {
		t.Fatalf("bootstrap UI route: %d %q", code, body)
	}
}

func TestSameStateIsNoop(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if err := f.svc.Start(ctx); err != nil {
		t.Fatal(err)
	}
	caddytest.WaitCert(t, f.httpsPort, uiHost) // let issuance finish before storage is removed
	before := f.loads
	if err := f.svc.Mutate(ctx, func(*store.Store) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if f.loads != before {
		t.Fatalf("Load called %d extra times for unchanged state", f.loads-before)
	}
}

func splitHostPort(t *testing.T, addr string) (string, int) {
	t.Helper()
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		t.Fatal(err)
	}
	return h, n
}
