package web

import (
	"context"
	"net"
	"net/http"
	"strings"

	"github.com/servanago/servanago/internal/turnstile"
)

// turnstileVerifier checks Cloudflare Turnstile tokens for the panel's login (action "login"); the call itself is internal/turnstile.
type turnstileVerifier struct {
	secret, hostname, url string
}

func (s *Server) turnstile() turnstileVerifier {
	c := s.deps.Cfg
	return turnstileVerifier{secret: c.TurnstileSecret, hostname: c.Host, url: c.TurnstileBaseURL}
}

// hostOf is the lower-cased request hostname without port.
func hostOf(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		h = r.Host
	}
	return strings.ToLower(h)
}

// turnstileOn: configured, and the request came in on SERVANAGO_HOST. The UI_LISTEN recovery listener
// (reached by LAN IP or localhost) is exempt so a Cloudflare or widget-hostname problem cannot lock you out.
func (s *Server) turnstileOn(r *http.Request) bool {
	c := s.deps.Cfg
	return s.auth.enabled() && c.TurnstileSecret != "" && c.TurnstileSiteKey != "" && hostOf(r) == strings.ToLower(c.Host)
}

func (t turnstileVerifier) Verify(ctx context.Context, token, ip string) error {
	return turnstile.Verify(ctx, t.url, t.secret, token, ip, "login", t.hostname)
}
