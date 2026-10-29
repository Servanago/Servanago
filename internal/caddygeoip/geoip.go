// Package caddygeoip blocks site traffic by country using the rule rendered into the JSON and
// the one GeoLite2 reader the panel has installed. Same shape as the gate module: the JSON pins
// what SQLite said at render time; the service is installed app-side.
package caddygeoip

import (
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/servanago/servanago/internal/geoip"
)

// Service is the installed lookup: one mmdb reader behind the panel, shared by every route.
type Service struct {
	Lookup func(ip netip.Addr) (string, error)
}

// FailOpen decides nothing is blocked while the service is broken or absent: a rule that cannot
// run must not take the site down.
var current atomic.Pointer[Service]

func Install(s *Service) { current.Store(s) }
func Current() *Service  { return current.Load() }

// Handler is the Caddy module config:
//
//	{"handler": "servanago_geoip", "mode": "deny", "countries": ["DE"]}
type Handler struct {
	Mode      string   `json:"mode"`
	Countries []string `json:"countries,omitempty"`
	want      map[string]bool
}

func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "http.handlers.servanago_geoip", New: func() caddy.Module { return new(Handler) }}
}

func (h *Handler) Provision(caddy.Context) error {
	h.want = geoip.Codes(strings.Join(h.Countries, " "))
	return nil
}

func init() { caddy.RegisterModule(Handler{}) }

var _ caddyhttp.MiddlewareHandler = (*Handler)(nil)

// ServeHTTP answers 403 when the client's country falls under the rule and lets everything else
// through. /.well-known/* (Let's Encrypt's HTTP-01 among others) is never blocked — the rules
// are internet-facing, so loopback, RFC1918/ULA and CGNAT clients bypass too. When the peer
// sits inside Cloudflare's published ranges (records can be proxied through the DNS pages), the
// client IP is the CF-Connecting-IP Cloudflare itself sets, so a visitor cannot forge it.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if strings.HasPrefix(r.URL.Path, "/.well-known/") {
		return next.ServeHTTP(w, r)
	}
	if ip, ok := clientOf(r); ok {
		if s := Current(); s != nil && s.Lookup != nil {
			if country, lerr := s.Lookup(ip); lerr == nil && geoip.Blocked(h.Mode, country, h.want) {
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte("Access from your location is not allowed.\n"))
				return nil
			}
		}
	}
	return next.ServeHTTP(w, r)
}

// cloudflareRanges are the address ranges https://www.cloudflare.com/ips-v4 + ips-v6 publish.
// ponytail: fixed list, refresh when Cloudflare announces new ranges.
var cloudflareRanges = []string{
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
	"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
	"2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
}

// clientOf resolves the client address; ok=false for the peers the rules never judge: loopback,
// RFC1918/ULA or CGNAT (GeoLite2 has no entry for those) and a Cloudflare peer without the
// header (its own address names a Cloudflare node, not a client).
func clientOf(r *http.Request) (netip.Addr, bool) {
	remote, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, false
	}
	ip := remote.Addr()
	if inCloudflare(ip) {
		cf, cferr := netip.ParseAddr(strings.TrimSpace(r.Header.Get("CF-Connecting-IP")))
		if cferr != nil { // CF node without the header: no client to name
			return netip.Addr{}, false
		}
		if cf.IsLoopback() || cf.IsPrivate() || !cf.IsGlobalUnicast() || cfNat(cf) {
			return netip.Addr{}, false // a forged private value changes nothing: those never block
		}
		return cf, true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || cfNat(ip) || !ip.IsGlobalUnicast() {
		return netip.Addr{}, false
	}
	return ip, true
}

// cfNat covers the shared Tailscale/CGNAT space 100.64/10: neither private nor global as netip
// classifies them.
func cfNat(ip netip.Addr) bool {
	if !ip.Is4() {
		return false
	}
	a4 := ip.As4()
	return a4[0] == 100 && a4[1] >= 64 && a4[1] < 128
}

func inCloudflare(ip netip.Addr) bool {
	for _, c := range cloudflareRanges {
		if g, err := netip.ParsePrefix(c); err == nil && g.Contains(ip) {
			return true
		}
	}
	return false
}
