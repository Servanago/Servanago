package apply

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"golang.org/x/crypto/bcrypt"

	"github.com/servanago/servanago/internal/caddycfg"
	"github.com/servanago/servanago/internal/caddytest"
	"github.com/servanago/servanago/internal/store"
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
		_, err := tx.CreateSite(context.Background(), store.Site{
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
		t.Fatalf("ui site: %d %q", code, body)
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
		r, err := tx.CreateSite(ctx, store.Site{DomainID: f.domainID, Subdomain: "bad", Scheme: "http",
			UpstreamHost: "127.0.0.1", UpstreamPort: 9, Enabled: true, Allowlist: "not-a-cidr"})
		_ = r
		return err
	})
	if err == nil {
		t.Fatal("Caddy accepted an invalid CIDR")
	}
	rs, _ := f.st.ListSites(ctx)
	if len(rs) != 1 || rs[0].Subdomain != "app" {
		t.Fatalf("db not rolled back: %+v", rs)
	}
	if code, body := caddytest.Get(t, f.httpsPort, "app.example.com"); code != 200 || body != "hello" {
		t.Fatalf("old site lost: %d %q", code, body)
	}
}

func TestCorruptStateFallsBackToBootstrap(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.st.CreateSite(ctx, store.Site{DomainID: f.domainID, Subdomain: "bad", Scheme: "http",
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
		t.Fatalf("bootstrap UI site: %d %q", code, body)
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

func TestTwoRoutesOneDomain(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if err := f.svc.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Mutate(ctx, f.addRoute("one", "A", t)); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Mutate(ctx, f.addRoute("two", "B", t)); err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string]string{"one.example.com": "A", "two.example.com": "B"} {
		if code, body := caddytest.Get(t, f.httpsPort, host); code != 200 || body != want {
			t.Errorf("%s: %d %q", host, code, body)
		}
	}
}

// routeWith adds an "app" site with the given tweaks and returns its host.
func (f *fixture) routeWith(t *testing.T, tweak func(*store.Site)) {
	t.Helper()
	host, port := splitHostPort(t, caddytest.Upstream(t, "secret-content"))
	err := f.svc.Mutate(context.Background(), func(tx *store.Store) error {
		r := store.Site{DomainID: f.domainID, Subdomain: "app", Scheme: "http", UpstreamHost: host, UpstreamPort: port, Enabled: true}
		tweak(&r)
		_, err := tx.CreateSite(context.Background(), r)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDisabledRouteIsNotServed(t *testing.T) {
	f := newFixture(t)
	if err := f.svc.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Mutate(context.Background(), f.addRoute("other", "other-content", t)); err != nil {
		t.Fatal(err)
	}
	f.routeWith(t, func(r *store.Site) { r.Enabled = false })
	// A disabled host is not in Caddy at all: no certificate is managed for it, so even the handshake fails.
	caddytest.WaitCert(t, f.httpsPort, "other.example.com")
	if c, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", f.httpsPort), &tls.Config{InsecureSkipVerify: true, ServerName: "app.example.com"}); err == nil {
		c.Close()
		t.Fatal("disabled host completed a TLS handshake")
	}
	err := f.svc.Mutate(context.Background(), func(tx *store.Store) error {
		rs, _ := tx.ListSites(context.Background())
		rs[0].Enabled = true
		return tx.UpdateSite(context.Background(), rs[0])
	})
	if err != nil {
		t.Fatal(err)
	}
	if code, body := caddytest.Get(t, f.httpsPort, "app.example.com"); code != 200 || body != "secret-content" {
		t.Fatalf("re-enabled: %d %q", code, body)
	}
}

func TestAllowlist(t *testing.T) {
	for name, tt := range map[string]struct {
		allow string
		want  int
	}{
		"source inside range":  {"127.0.0.0/8", 200},
		"source outside range": {"10.0.0.0/8\n192.168.0.0/16", 403},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			if err := f.svc.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			f.routeWith(t, func(r *store.Site) { r.Allowlist = tt.allow })
			code, body := caddytest.Get(t, f.httpsPort, "app.example.com")
			if code != tt.want || (tt.want == 403 && body == "secret-content") {
				t.Fatalf("%d %q", code, body)
			}
		})
	}
}

func TestBasicAuth(t *testing.T) {
	f := newFixture(t)
	if err := f.svc.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("s3cret"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	f.routeWith(t, func(r *store.Site) { r.BasicUser, r.BasicHash = "alice", string(hash) })
	for _, c := range []struct {
		name, user, pass string
		want             int
	}{
		{"no credentials", "", "", 401},
		{"wrong password", "alice", "nope", 401},
		{"wrong user", "mallory", "s3cret", 401},
		{"right credentials", "alice", "s3cret", 200},
	} {
		if code, _ := caddytest.GetAs(t, f.httpsPort, "app.example.com", c.user, c.pass); code != c.want {
			t.Errorf("%s: got %d want %d", c.name, code, c.want)
		}
	}
}

func TestMaxBodyAndStreamLoad(t *testing.T) {
	f := newFixture(t)
	if err := f.svc.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.routeWith(t, func(r *store.Site) { r.Stream, r.MaxBody = true, 10 })
	if code := caddytest.Post(t, f.httpsPort, "app.example.com", "tiny"); code != 200 {
		t.Errorf("under the limit: got %d want 200", code)
	}
	if code := caddytest.Post(t, f.httpsPort, "app.example.com", "this body is longer than ten bytes"); code != 413 {
		t.Errorf("over the limit: got %d want 413", code)
	}
}
