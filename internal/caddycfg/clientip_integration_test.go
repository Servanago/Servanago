package caddycfg

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/servanago/servanago/internal/caddytest"
	"github.com/servanago/servanago/internal/store"
)

// A peer outside the Cloudflare ranges cannot choose its client_ip: a forged CF-Connecting-IP
// naming an allowlisted address must not open the site.
func TestForgedCFHeaderDoesNotPassTheAllowlist(t *testing.T) {
	storage := caddytest.TempDir(t)
	caddytest.Cleanup(t)
	t.Cleanup(func() { _ = caddy.Stop() })
	up := caddytest.Upstream(t, "ok")
	upPort, _ := strconv.Atoi(strings.TrimPrefix(up, "127.0.0.1:"))
	site := with(store.Site{ID: 2, Hostnames: []string{"cf.test"}, Scheme: "http", UpstreamHost: "127.0.0.1", UpstreamPort: upPort, Enabled: true},
		func(r *store.Site) { r.Allowlist = "203.0.113.0/24" })
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
	caddytest.WaitCert(t, o.HTTPSPort, "cf.test")
	c := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "cf.test"},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, fmt.Sprintf("127.0.0.1:%d", o.HTTPSPort))
		},
	}}
	req, _ := http.NewRequest(http.MethodGet, "https://cf.test/", nil)
	req.Header.Set("CF-Connecting-IP", "203.0.113.9")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("forged header from a non-Cloudflare peer: %d; want 403", resp.StatusCode)
	}
}
