package probe

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/servanago/servanago/internal/apply"
	"github.com/servanago/servanago/internal/caddycfg"
	"github.com/servanago/servanago/internal/caddytest"
	"github.com/servanago/servanago/internal/store"
)

func listener(t *testing.T) (string, int) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return "127.0.0.1", l.Addr().(*net.TCPAddr).Port
}

func TestTCP(t *testing.T) {
	host, port := listener(t)
	if err := TCP(context.Background(), net.JoinHostPort(host, strconv.Itoa(port)), time.Second); err != nil {
		t.Fatalf("open port: %v", err)
	}
	closed := caddytest.FreePort(t)
	if err := TCP(context.Background(), net.JoinHostPort("127.0.0.1", strconv.Itoa(closed)), time.Second); err == nil {
		t.Fatal("closed port reported up")
	}
}

func TestCertStateMapping(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	valid := CertInfo{NotAfter: now.Add(60 * 24 * time.Hour), Issuer: "Test CA"}
	soon := CertInfo{NotAfter: now.Add(3 * 24 * time.Hour), Issuer: "Test CA"}
	expired := CertInfo{NotAfter: now.Add(-time.Hour), Issuer: "Test CA"}
	tests := []struct {
		name   string
		info   CertInfo
		err    error
		logErr string
		want   string
	}{
		{"valid cert", valid, nil, "", StateIssued},
		{"expiring soon is still issued", soon, nil, "", StateIssued},
		{"expired", expired, nil, "", StateError},
		{"handshake failure, no log error", CertInfo{}, errors.New("tls: internal error"), "", StatePending},
		{"handshake failure with ACME error in log", CertInfo{}, errors.New("tls: internal error"), "dns challenge failed", StateError},
		{"valid cert wins over stale log error", valid, nil, "old failure", StateIssued},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := certStatus(tt.info, tt.err, tt.logErr, now)
			if got.State != tt.want {
				t.Fatalf("state %q, want %q (%+v)", got.State, tt.want, got)
			}
			if tt.want == StateError && got.Err == "" {
				t.Error("error state without a message")
			}
		})
	}
}

func TestSweep(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	d, _ := st.CreateDomain(ctx, store.Domain{Name: "example.com", ZoneID: "z", DefaultIP: "1.1.1.1", CertMode: "wildcard"})
	host, port := listener(t)
	mk := func(sub string, port int, enabled bool) store.Site {
		r, err := st.CreateSite(ctx, store.Site{Hostnames: []string{sub + "." + d.Name}, Scheme: "http", UpstreamHost: host, UpstreamPort: port, Enabled: enabled})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	up, down, off := mk("up", port, true), mk("down", caddytest.FreePort(t), true), mk("off", port, false)

	m := NewMonitor(st, "127.0.0.1:1")
	m.Sweep(ctx)
	if u, ok := m.Upstream(up); !ok || !u.Up {
		t.Errorf("up: %+v %v", u, ok)
	}
	if u, ok := m.Upstream(down); !ok || u.Up {
		t.Errorf("down: %+v %v", u, ok)
	}
	if _, ok := m.Upstream(off); ok {
		t.Error("disabled site was probed")
	}
}

// A static site has no upstream: the sweep must not dial anything for it.
func TestSweepSkipsStaticSites(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	r, err := st.CreateSite(ctx, store.Site{Kind: "static", StaticRoot: "/srv/www/blog", Hostnames: []string{"blog.example.com"}, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	m := NewMonitor(st, "127.0.0.1:1")
	m.Dial = func(context.Context, string, time.Duration) error { t.Error("dialed for a static site"); return nil }
	m.Sweep(ctx)
	if _, ok := m.Upstream(r); ok {
		t.Error("static site has upstream state")
	}
}

// A php site is served over its pool socket: nothing to dial at an empty host and port 0.
// A node site is dialed at its loopback port, like a proxy.
func TestSweepSkipsPHPDialsNode(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	php, err := st.CreateSite(ctx, store.Site{Kind: "php", StaticRoot: "/srv/www/blog", FPMVersion: "8.2", Hostnames: []string{"blog.example.com"}, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	node, err := st.CreateSite(ctx, store.Site{Kind: "node", StaticRoot: "/srv/www/app", UpstreamHost: "127.0.0.1", UpstreamPort: 3000,
		StartCommand: "node server.js", Hostnames: []string{"app.example.com"}, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	var dialed []string
	m := NewMonitor(st, "127.0.0.1:1")
	m.Dial = func(_ context.Context, addr string, _ time.Duration) error { dialed = append(dialed, addr); return nil }
	m.Sweep(ctx)
	if len(dialed) != 1 || dialed[0] != "127.0.0.1:3000" {
		t.Errorf("dialed %v, want only the node app", dialed)
	}
	if _, ok := m.Upstream(php); ok {
		t.Error("php site has upstream state")
	}
	if _, ok := m.Upstream(node); !ok {
		t.Error("node site has no upstream state")
	}
}

func TestCertProbeAgainstRealCaddy(t *testing.T) {
	storage := caddytest.TempDir(t)
	caddytest.Cleanup(t)
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	httpsPort := caddytest.FreePort(t)
	svc := apply.New(st, caddycfg.Options{UIHost: "ui.example.com", UIUpstream: caddytest.Upstream(t, "ui"), Email: "me@example.com",
		Issuer: caddycfg.Internal, HTTPPort: caddytest.FreePort(t), HTTPSPort: httpsPort, StoragePath: storage})
	if err := svc.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	caddytest.WaitCert(t, httpsPort, "ui.example.com")

	m := NewMonitor(st, net.JoinHostPort("127.0.0.1", strconv.Itoa(httpsPort)))
	got := m.Cert(context.Background(), "ui.example.com")
	if got.State != StateIssued || got.NotAfter.Before(time.Now()) || got.Issuer == "" {
		t.Fatalf("%+v", got)
	}
	if got := m.Cert(context.Background(), "nothing.example.net"); got.State != StatePending {
		t.Fatalf("host without cert: %+v", got)
	}
}

// SQLite reuses the highest rowid after a delete, so cached state must be tied to the upstream address.
func TestStateNotReusedWhenRouteIDIsReused(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	d, _ := st.CreateDomain(ctx, store.Domain{Name: "example.com", ZoneID: "z", DefaultIP: "1.1.1.1", CertMode: "wildcard"})
	old, _ := st.CreateSite(ctx, store.Site{Hostnames: []string{"a." + d.Name}, Scheme: "http", UpstreamHost: "127.0.0.1", UpstreamPort: caddytest.FreePort(t), Enabled: true})
	m := NewMonitor(st, "127.0.0.1:1")
	m.Sweep(ctx)
	if u, ok := m.Upstream(old); !ok || u.Up {
		t.Fatalf("setup: %+v %v", u, ok)
	}
	if err := st.DeleteSite(ctx, old.ID); err != nil {
		t.Fatal(err)
	}
	_, port := listener(t)
	fresh, _ := st.CreateSite(ctx, store.Site{Hostnames: []string{"b." + d.Name}, Scheme: "http", UpstreamHost: "127.0.0.1", UpstreamPort: port, Enabled: true})
	if fresh.ID != old.ID {
		t.Skipf("sqlite did not reuse the id (%d vs %d)", fresh.ID, old.ID)
	}
	if u, ok := m.Upstream(fresh); ok {
		t.Fatalf("stale state served for a different upstream: %+v", u)
	}
}

// P1: dials must overlap. The fake dial blocks until all routes are in flight, so a serial
// sweep deadlocks into the error path instead of passing.
func TestSweepDialsInParallel(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	d, _ := st.CreateDomain(ctx, store.Domain{Name: "example.com", ZoneID: "z", DefaultIP: "1.1.1.1", CertMode: "wildcard"})
	const n = 10
	for i := range n {
		if _, err := st.CreateSite(ctx, store.Site{Hostnames: []string{"r" + strconv.Itoa(i) + "." + d.Name}, Scheme: "http", UpstreamHost: "10.9.9.9", UpstreamPort: 1000 + i, Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	var mu sync.Mutex
	inflight, peak := 0, 0
	all := make(chan struct{})
	m := NewMonitor(st, "127.0.0.1:1")
	m.Dial = func(ctx context.Context, addr string, _ time.Duration) error {
		mu.Lock()
		inflight++
		if inflight > peak {
			peak = inflight
		}
		if inflight == n {
			close(all)
		}
		mu.Unlock()
		select {
		case <-all:
			return nil
		case <-time.After(3 * time.Second):
			return errors.New("dials never overlapped")
		}
	}
	m.Sweep(ctx)
	routes, _ := st.ListSites(ctx)
	for _, r := range routes {
		if u, ok := m.Upstream(r); !ok || !u.Up {
			t.Fatalf("%s: %+v %v (peak concurrency %d)", r.Hostnames[0], u, ok, peak)
		}
	}
}

func TestParallelBoundsConcurrency(t *testing.T) {
	var mu sync.Mutex
	cur, peak := 0, 0
	Parallel(100, func(int) {
		mu.Lock()
		cur++
		peak = max(peak, cur)
		mu.Unlock()
		time.Sleep(time.Millisecond)
		mu.Lock()
		cur--
		mu.Unlock()
	})
	if peak > maxParallel || peak < 2 {
		t.Fatalf("peak %d, want 2..%d", peak, maxParallel)
	}
}

func TestUpstreamAddrBracketsIPv6(t *testing.T) {
	cases := map[string]string{
		"192.168.1.20": "192.168.1.20:8989",
		"app.lan":      "app.lan:8989",
		"2001:db8::5":  "[2001:db8::5]:8989",
		"fd00::1":      "[fd00::1]:8989",
	}
	for host, want := range cases {
		if got := upstreamAddr(store.Site{UpstreamHost: host, UpstreamPort: 8989}); got != want {
			t.Errorf("%q: got %q, want %q", host, got, want)
		}
	}
}
