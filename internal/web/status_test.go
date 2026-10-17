package web

import (
	"context"
	"errors"
	"net"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/servanago/servanago/internal/probe"
	"github.com/servanago/servanago/internal/store"
)

func openPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l.Addr().(*net.TCPAddr).Port
}

// A static site's row shows its folder and a certificate, but no upstream status and no dial.
func TestStatusFragmentStaticSite(t *testing.T) {
	s, _, d := newDNSServer(t)
	ctx := context.Background()
	if _, err := s.deps.Store.CreateSite(ctx, store.Site{Kind: "static", StaticRoot: "/srv/www/blog", Hostnames: []string{"blog." + d.Name}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	tlsSrv := httptest.NewTLSServer(nil)
	t.Cleanup(tlsSrv.Close)
	m := probe.NewMonitor(s.deps.Store, strings.TrimPrefix(tlsSrv.URL, "https://"))
	m.Dial = func(context.Context, string, time.Duration) error { t.Error("dialed for a static site"); return nil }
	s.deps.Probe = m
	body := s.do(req{path: "/status", hdr: map[string]string{"HX-Request": "true"}}).Body.String()
	if !strings.Contains(body, "/srv/www/blog") || strings.Contains(body, "up-up") || strings.Contains(body, "up-down") || strings.Contains(body, ":0") {
		t.Fatalf("static row: %s", body)
	}
}

func TestStatusFragment(t *testing.T) {
	s, _, d := newDNSServer(t)
	ctx := context.Background()
	upPort := openPort(t)
	mk := func(sub string, port int) store.Site {
		r, err := s.deps.Store.CreateSite(ctx, store.Site{Hostnames: []string{sub + "." + d.Name}, Scheme: "http", UpstreamHost: "127.0.0.1", UpstreamPort: port, Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	mk("alive", upPort)
	mk("dead", 1)
	if _, err := s.deps.Store.CreateSite(ctx, store.Site{Hostnames: []string{"off." + d.Name}, Scheme: "http", UpstreamHost: "127.0.0.1", UpstreamPort: 1}); err != nil {
		t.Fatal(err)
	}

	// a TLS server stands in for Caddy's HTTPS listener (httptest cert is valid for years)
	tlsSrv := httptest.NewTLSServer(nil)
	t.Cleanup(tlsSrv.Close)
	m := probe.NewMonitor(s.deps.Store, strings.TrimPrefix(tlsSrv.URL, "https://"))
	s.deps.Probe = m
	m.Sweep(ctx)

	w := s.do(req{path: "/status", hdr: map[string]string{"HX-Request": "true"}})
	body := w.Body.String()
	if w.Code != 200 || strings.Contains(body, "<html") {
		t.Fatalf("want a bare fragment, got %d %.80q", w.Code, body)
	}
	row := func(host string) string {
		i := strings.Index(body, host)
		if i < 0 {
			t.Fatalf("no row for %s in %s", host, body)
		}
		end := strings.Index(body[i:], "</tr>")
		return body[i : i+end]
	}
	if r := row("alive.example.com"); !strings.Contains(r, "up") || !strings.Contains(r, "issued") || !strings.Contains(r, "expires") {
		t.Errorf("alive row: %s", r)
	}
	if r := row("dead.example.com"); !strings.Contains(r, "down") {
		t.Errorf("dead row: %s", r)
	}
	if r := row("off.example.com"); strings.Contains(r, "cert-") || strings.Contains(r, "up-") {
		t.Errorf("disabled site probed: %s", r)
	}
}

func TestCertPendingWhenNothingListens(t *testing.T) {
	s, _, d := newDNSServer(t)
	addRoute(t, s, d)
	s.deps.Probe = probe.NewMonitor(s.deps.Store, net.JoinHostPort("127.0.0.1", strconv.Itoa(1)))
	if body := s.do(req{path: "/status"}).Body.String(); !strings.Contains(body, "pending") {
		t.Errorf("want pending: %s", body)
	}
}

func TestStatusRequiresLogin(t *testing.T) {
	s := newServer(t, "pw")
	if w := s.do(req{path: "/status"}); w.Code != 303 {
		t.Fatalf("got %d", w.Code)
	}
}

// P1 at the page level: a first dashboard load with many unreachable upstreams must probe them side by side.
func TestStatusProbesUnknownRoutesInParallel(t *testing.T) {
	s, _, d := newDNSServer(t)
	const n = 8
	for i := range n {
		if _, err := s.deps.Store.CreateSite(context.Background(), store.Site{Hostnames: []string{"r" + strconv.Itoa(i) + "." + d.Name}, Scheme: "http", UpstreamHost: "10.9.9.9", UpstreamPort: 2000 + i, Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	var mu sync.Mutex
	inflight := 0
	all := make(chan struct{})
	s.deps.Probe.Dial = func(context.Context, string, time.Duration) error {
		mu.Lock()
		if inflight++; inflight == n {
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
	body := s.do(req{path: "/status"}).Body.String()
	if got := strings.Count(body, `class="up-up"`); got != n {
		t.Fatalf("%d of %d routes up; the dials were serial", got, n)
	}
}
