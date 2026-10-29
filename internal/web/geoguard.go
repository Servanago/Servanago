// The panel's own country rule: one middleware over everything the panel serves, including /mcp.
// The sites' rules live on their routes; this one guards the WebUI. Loopback (a direct local
// request or the local stdio relay) and private peers never get judged: ServanaGo's geo rules are
// internet-facing, and a lock-out nobody can undo from inside is not worth the rule.
package web

import (
	"context"
	"log/slog"
	"net/http"
	"net/netip"

	"github.com/servanago/servanago/internal/geoip"
	"github.com/servanago/servanago/internal/store"
)

// geoRule is the settings row's country filter, cached: no settings query per request.
type geoRule struct {
	db        string
	mode      string
	countries string
}

// ShareGeo points the guard at the reader main installed into the Caddy module and seeds the
// cached rule from the settings row main just read.
func (s *Server) ShareGeo(db *geoip.DB, st store.Settings) {
	s.geo = db
	s.geoRule.Store(geoRule{db: st.GeoDB, mode: st.WebUIMode, countries: st.WebUICountries})
}

// InitGeo is the test variant of ShareGeo: it reads the row from the store itself.
func (s *Server) InitGeo(ctx context.Context) {
	st, err := s.deps.Store.GetSettings(ctx)
	if err != nil {
		slog.Error("geo settings", "error", err)
		return
	}
	s.geoRule.Store(geoRule{db: st.GeoDB, mode: st.WebUIMode, countries: st.WebUICountries})
}

func (s *Server) geoGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if gr, ok := s.geoRule.Load().(geoRule); ok && gr.db != "" && gr.mode != "" {
			ip, perr := netip.ParseAddr(clientIP(r))
			if perr == nil && !(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || isCGNat(ip) || !ip.IsGlobalUnicast()) {
				if country, err := s.geo.Lookup(ip); err == nil && geoip.Blocked(gr.mode, country, geoip.Codes(gr.countries)) {
					slog.Info("geo guard", "ip", ip, "country", country)
					w.Header().Set("Content-Type", "text/plain; charset=utf-8")
					w.WriteHeader(http.StatusForbidden)
					_, _ = w.Write([]byte("Access from your location is not allowed.\n"))
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// isCGNat covers the shared Tailscale/CGNAT space 100.64/10.
func isCGNat(ip netip.Addr) bool {
	if !ip.Is4() {
		return false
	}
	a4 := ip.As4()
	return a4[0] == 100 && a4[1] >= 64 && a4[1] < 128
}
