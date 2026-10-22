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

	"github.com/servanago/servanago/internal/cfdns"
	"github.com/servanago/servanago/internal/cfdns/cftest"
	"github.com/servanago/servanago/internal/config"
	"github.com/servanago/servanago/internal/dnssync"
	"github.com/servanago/servanago/internal/probe"
	"github.com/servanago/servanago/internal/store"
)

// txApplier stands in for apply.Service: runs the mutation in a tx without Caddy.
type txApplier struct{ st *store.Store }

func (a txApplier) Mutate(ctx context.Context, fn func(*store.Store) error) error {
	return a.st.Tx(ctx, fn)
}
func (a txApplier) StartupError() error { return nil }

const zonesOK = `{"success":true,"errors":[],"messages":[],"result":[{"id":"zone123","name":"example.com"}],"result_info":{"page":1,"per_page":20,"count":1,"total_count":1}}`

type cfFake struct {
	calls     atomic.Int32
	dns       *cftest.Fake // stateful DNS record endpoints
	zones     string       // body for GET /zones
	zonesCode int          // status for GET /zones; 0 = 200
	token     func(w http.ResponseWriter)
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
			if cf.zonesCode != 0 {
				w.WriteHeader(cf.zonesCode)
			}
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
		{"loopback", "example.com", "127.0.0.1", "wildcard", "loopback"},
		{"link-local", "example.com", "169.254.1.1", "wildcard", "IPv4"},
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

func putDomain(s *Server, id int64, kv ...string) *httptest.ResponseRecorder {
	return s.do(req{method: "PUT", path: "/domains/" + itoa(id), body: form(kv...).Encode(), hdr: htmxPost})
}

func TestUpdateDomain(t *testing.T) {
	cf := &cfFake{zones: zonesOK}
	s := domainServer(t, cf)
	ctx := context.Background()
	postDomain(s, "example.com", "192.168.1.10", "wildcard")
	ds, _ := s.deps.Store.ListDomains(ctx)
	id := ds[0].ID

	w := putDomain(s, id, "default_ip", "192.168.1.20", "default_ip6", "2001:db8::1", "cert_mode", "per_host")
	if w.Code != 204 || w.Header().Get("HX-Redirect") != "/domains" {
		t.Fatalf("update: %d %s", w.Code, w.Body.String())
	}
	got, _ := s.deps.Store.GetDomain(ctx, id)
	if got.Name != "example.com" || got.ZoneID != "zone123" || got.DefaultIP != "192.168.1.20" || got.DefaultIP6 != "2001:db8::1" || got.CertMode != "per_host" {
		t.Fatalf("after update: %+v", got)
	}

	// A zone name is looked up and replaces the stored zone id; an unknown one changes nothing.
	if w := putDomain(s, id, "default_ip", "192.168.1.20", "cert_mode", "per_host", "zone", "example.com"); w.Code != 204 {
		t.Fatalf("zone update: %d %s", w.Code, w.Body.String())
	}
	got, _ = s.deps.Store.GetDomain(ctx, id) // the form replaces every field, so omitting default_ip6 cleared it
	if got.DefaultIP6 != "" {
		t.Fatalf("default_ip6 not cleared: %+v", got)
	}
	cf.zones = `{"success":true,"errors":[],"messages":[],"result":[],"result_info":{"page":1,"per_page":20,"count":0,"total_count":0}}`
	if w := putDomain(s, id, "default_ip", "192.168.1.30", "cert_mode", "wildcard", "zone", "nope.example.net"); w.Code != 422 || !strings.Contains(w.Body.String(), "not found") {
		t.Fatalf("unknown zone: %d %s", w.Code, w.Body.String())
	}
	for name, kv := range map[string][]string{
		"bad ip":   {"default_ip", "999.1.1.1", "cert_mode", "wildcard"},
		"bad ipv6": {"default_ip", "192.168.1.30", "default_ip6", "::1", "cert_mode", "wildcard"},
		"bad mode": {"default_ip", "192.168.1.30", "cert_mode", "banana"},
	} {
		if w := putDomain(s, id, kv...); w.Code != 422 {
			t.Errorf("%s: %d", name, w.Code)
		}
	}
	if again, _ := s.deps.Store.GetDomain(ctx, id); again != got {
		t.Fatalf("a rejected update changed the domain: %+v", again)
	}
	if w := putDomain(s, 999, "default_ip", "192.168.1.30", "cert_mode", "wildcard"); w.Code != 404 {
		t.Errorf("unknown domain: %d", w.Code)
	}
}

func TestUpdateDomainWithoutCloudflare(t *testing.T) {
	s := noCFServer(t)
	if code, body := addDomainNoDNS(s); code != 204 {
		t.Fatalf("%d %q", code, body)
	}
	ds, _ := s.deps.Store.ListDomains(context.Background())
	if w := putDomain(s, ds[0].ID, "cert_mode", "wildcard"); w.Code != 422 {
		t.Fatalf("wildcard needs Cloudflare: %d %s", w.Code, w.Body.String())
	}
	if w := putDomain(s, ds[0].ID, "cert_mode", "per_host", "default_ip", "10.0.0.1"); w.Code != 204 {
		t.Fatalf("per_host: %d %s", w.Code, w.Body.String())
	}
	if got, _ := s.deps.Store.GetDomain(context.Background(), ds[0].ID); got.DefaultIP != "" || got.ZoneID != "" {
		t.Fatalf("no-Cloudflare domains carry no IPs or zone: %+v", got)
	}
}

func TestDeleteDomain(t *testing.T) {
	s := domainServer(t, &cfFake{zones: zonesOK})
	ctx := context.Background()
	postDomain(s, "example.com", "10.0.0.1", "wildcard")
	d, _ := s.deps.Store.ListDomains(ctx)
	r, _ := s.deps.Store.CreateSite(ctx, store.Site{Hostnames: []string{"a." + d[0].Name}, Scheme: "http", UpstreamHost: "h", UpstreamPort: 1, Enabled: true})

	del := func() *httptest.ResponseRecorder {
		return s.do(req{method: "DELETE", path: "/domains/" + itoa(d[0].ID), hdr: htmxPost})
	}
	if w := del(); w.Code != 409 || !strings.Contains(w.Body.String(), "site") {
		t.Fatalf("with routes: %d %q", w.Code, w.Body.String())
	}
	if err := s.deps.Store.DeleteSite(ctx, r.ID); err != nil {
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
	const invalid = `{"success":false,"errors":[{"code":1000,"message":"Invalid API Token"}],"messages":[],"result":null}`
	cf := &cfFake{zones: invalid, zonesCode: 401, token: func(w http.ResponseWriter) {
		w.WriteHeader(401)
		_, _ = w.Write([]byte(invalid))
	}}
	s := domainServer(t, cf)
	s.VerifyToken(context.Background())
	if body := s.do(req{path: "/"}).Body.String(); !strings.Contains(body, "Invalid API Token") {
		t.Fatalf("banner missing: %s", body)
	}
}

// An account-owned token fails /user/tokens/verify but can list zones: no banner.
func TestTokenVerifyNoBannerForAccountToken(t *testing.T) {
	cf := &cfFake{zones: zonesOK, token: func(w http.ResponseWriter) {
		w.WriteHeader(401)
		_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":1000,"message":"Invalid API Token"}],"messages":[],"result":null}`))
	}}
	s := domainServer(t, cf)
	s.VerifyToken(context.Background())
	if body := s.do(req{path: "/"}).Body.String(); strings.Contains(body, "Cloudflare token problem") {
		t.Fatalf("banner shown for a working token: %s", body)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func TestAddDomainAcceptsPublicIP(t *testing.T) {
	s := domainServer(t, &cfFake{zones: zonesOK})
	if w := postDomain(s, "example.com", "203.0.113.20", "wildcard"); w.Code != 204 {
		t.Fatalf("a public default IP must be accepted: %d %q", w.Code, w.Body.String())
	}
	ds, _ := s.deps.Store.ListDomains(context.Background())
	if len(ds) != 1 || ds[0].DefaultIP != "203.0.113.20" {
		t.Fatalf("%+v", ds)
	}
}
