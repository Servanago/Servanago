package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudflare/cloudflare-go/v7/option"

	"github.com/caretakarr/caretakarr/internal/cfdns"
	"github.com/caretakarr/caretakarr/internal/cfdns/cftest"
	"github.com/caretakarr/caretakarr/internal/config"
	"github.com/caretakarr/caretakarr/internal/dnssync"
	"github.com/caretakarr/caretakarr/internal/probe"
	"github.com/caretakarr/caretakarr/internal/store"
)

// txApplier stands in for apply.Service: runs the mutation in a tx without Caddy.
type txApplier struct{ st *store.Store }

func (a txApplier) Mutate(ctx context.Context, fn func(*store.Store) error) error {
	return a.st.Tx(ctx, fn)
}
func (a txApplier) StartupError() error { return nil }

const zonesOK = `{"success":true,"errors":[],"messages":[],"result":[{"id":"zone123","name":"example.com"}],"result_info":{"page":1,"per_page":20,"count":1,"total_count":1}}`

type cfFake struct {
	calls atomic.Int32
	dns   *cftest.Fake // stateful DNS record endpoints
	zones string       // body for GET /zones
	token func(w http.ResponseWriter)
}

// domainServer returns an open-mode server wired to a fake Cloudflare.
func domainServer(t *testing.T, cf *cfFake) *Server { return cfgServer(t, cf, config.Config{}) }

// cfgServer is domainServer with an arbitrary config (the gate tests need SMTP + secret set).
func cfgServer(t *testing.T, cf *cfFake, cfg config.Config) *Server {
	t.Helper()
	cf.dns = cftest.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cf.calls.Add(1)
		if strings.Contains(r.URL.Path, "/dns_records") {
			cf.dns.Handler().ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/zones":
			_, _ = w.Write([]byte(cf.zones))
		case "/user/tokens/verify":
			cf.token(w)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	client := cfdns.New("tok", option.WithBaseURL(srv.URL), option.WithMaxRetries(0))
	mon := probe.NewMonitor(st, "127.0.0.1:1")
	mon.Dial = func(context.Context, string, time.Duration) error { return errors.New("refused") } // never touch the real network
	return New(Deps{Cfg: cfg, Store: st, Apply: txApplier{st}, CF: client, DNS: dnssync.New(client, st),
		Probe: mon})
}

func postDomain(s *Server, name, ip, mode string) *httptest.ResponseRecorder {
	v := url.Values{"name": {name}, "default_ip": {ip}, "cert_mode": {mode}}
	return s.do(req{method: "POST", path: "/domains", body: v.Encode(), hdr: htmxPost})
}

func TestAddDomain(t *testing.T) {
	cf := &cfFake{zones: zonesOK}
	s := domainServer(t, cf)
	w := postDomain(s, "example.com", "192.168.1.10", "wildcard")
	if w.Code != 204 || w.Header().Get("HX-Redirect") != "/domains" {
		t.Fatalf("%d %s %v", w.Code, w.Body.String(), w.Header())
	}
	ds, _ := s.deps.Store.ListDomains(context.Background())
	if len(ds) != 1 || ds[0].ZoneID != "zone123" || ds[0].DefaultIP != "192.168.1.10" || ds[0].CertMode != "wildcard" {
		t.Fatalf("%+v", ds)
	}
	if body := s.do(req{path: "/domains"}).Body.String(); !strings.Contains(body, "example.com") {
		t.Errorf("domain not listed: %s", body)
	}
}

func TestAddDomainValidation(t *testing.T) {
	tests := []struct{ name, domain, ip, mode, want string }{
		{"local suffix", "nas.local", "10.0.0.1", "wildcard", ".local"},
		{"ip literal", "10.0.0.1", "10.0.0.1", "wildcard", "IP literals"},
		{"bad ip", "example.com", "999.1.1.1", "wildcard", "IPv4"},
		{"ipv6", "example.com", "::1", "wildcard", "IPv4"},
		{"public ip", "example.com", "8.8.8.8", "wildcard", "private"},
		{"loopback", "example.com", "127.0.0.1", "wildcard", "private"},
		{"bad mode", "example.com", "10.0.0.1", "banana", "cert_mode"},
		{"uppercase normalised then ok-but-local", "FOO.LOCAL", "10.0.0.1", "wildcard", ".local"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cf := &cfFake{zones: zonesOK}
			s := domainServer(t, cf)
			w := postDomain(s, tt.domain, tt.ip, tt.mode)
			if w.Code != 422 || !strings.Contains(w.Body.String(), tt.want) {
				t.Fatalf("%d %q", w.Code, w.Body.String())
			}
			if cf.calls.Load() != 0 {
				t.Error("Cloudflare called for an invalid request")
			}
			if ds, _ := s.deps.Store.ListDomains(context.Background()); len(ds) != 0 {
				t.Errorf("stored: %+v", ds)
			}
		})
	}
}

func TestAddDomainZoneNotFound(t *testing.T) {
	s := domainServer(t, &cfFake{zones: `{"success":true,"errors":[],"messages":[],"result":[],"result_info":{"page":1,"per_page":20,"count":0,"total_count":0}}`})
	w := postDomain(s, "example.com", "10.0.0.1", "wildcard")
	if w.Code != 422 || !strings.Contains(w.Body.String(), "not found") {
		t.Fatalf("%d %q", w.Code, w.Body.String())
	}
}

func TestDeleteDomain(t *testing.T) {
	s := domainServer(t, &cfFake{zones: zonesOK})
	ctx := context.Background()
	postDomain(s, "example.com", "10.0.0.1", "wildcard")
	d, _ := s.deps.Store.ListDomains(ctx)
	r, _ := s.deps.Store.CreateRoute(ctx, store.Route{DomainID: d[0].ID, Subdomain: "a", Scheme: "http", UpstreamHost: "h", UpstreamPort: 1, Enabled: true})

	del := func() *httptest.ResponseRecorder {
		return s.do(req{method: "DELETE", path: "/domains/" + itoa(d[0].ID), hdr: htmxPost})
	}
	if w := del(); w.Code != 409 || !strings.Contains(w.Body.String(), "route") {
		t.Fatalf("with routes: %d %q", w.Code, w.Body.String())
	}
	if err := s.deps.Store.DeleteRoute(ctx, r.ID); err != nil {
		t.Fatal(err)
	}
	if w := del(); w.Code != 204 {
		t.Fatalf("empty domain: %d %q", w.Code, w.Body.String())
	}
	if ds, _ := s.deps.Store.ListDomains(ctx); len(ds) != 0 {
		t.Errorf("not deleted: %+v", ds)
	}
}

func TestTokenVerifyBanner(t *testing.T) {
	cf := &cfFake{zones: zonesOK, token: func(w http.ResponseWriter) {
		w.WriteHeader(401)
		_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":1000,"message":"Invalid API Token"}],"messages":[],"result":null}`))
	}}
	s := domainServer(t, cf)
	s.VerifyToken(context.Background())
	if body := s.do(req{path: "/"}).Body.String(); !strings.Contains(body, "Invalid API Token") {
		t.Fatalf("banner missing: %s", body)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
