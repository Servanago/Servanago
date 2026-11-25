package caddycfg

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/servanago/servanago/internal/store"
)

// Without trusted_proxies Caddy's client_ip is the socket peer, so behind Cloudflare the WAF
// limiter, bans and allowlists would all see an edge node instead of the visitor.
func TestServerTrustsCloudflareForClientIP(t *testing.T) {
	got, err := Render(State{[]store.Domain{dom}, []store.Site{site}}, opts())
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Apps struct {
			HTTP struct {
				Servers map[string]struct {
					TrustedProxies struct {
						Source string   `json:"source"`
						Ranges []string `json:"ranges"`
					} `json:"trusted_proxies"`
					ClientIPHeaders []string `json:"client_ip_headers"`
				} `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(got, &cfg); err != nil {
		t.Fatal(err)
	}
	srv := cfg.Apps.HTTP.Servers["srv0"]
	if srv.TrustedProxies.Source != "static" || len(srv.TrustedProxies.Ranges) < 20 ||
		len(srv.ClientIPHeaders) != 1 || srv.ClientIPHeaders[0] != "CF-Connecting-IP" {
		t.Fatalf("srv0 trusted proxies = %+v, client_ip_headers = %v", srv.TrustedProxies, srv.ClientIPHeaders)
	}
}

// The allowlist and the gate's allowlist bypass must judge the visitor (client_ip), not the peer.
func TestAllowlistMatchesClientIP(t *testing.T) {
	for _, gate := range []string{"", "acl"} {
		st := with(site, func(r *store.Site) { r.Allowlist, r.GateMode = "203.0.113.0/24", gate })
		got, err := Render(State{[]store.Domain{dom}, []store.Site{st}}, opts())
		if err != nil {
			t.Fatal(err)
		}
		if s := string(got); strings.Contains(s, `"remote_ip"`) || !strings.Contains(s, `"client_ip"`) {
			t.Fatalf("gate=%q: allowlist matcher is not client_ip", gate)
		}
	}
}
