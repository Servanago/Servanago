package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const turnstileURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

var errCaptcha = errors.New("captcha verification failed")

// turnstileVerifier checks Cloudflare Turnstile tokens. Tokens are single use. It fails closed:
// any network, decode or non-success outcome rejects.
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
	if token == "" {
		return errCaptcha
	}
	endpoint := t.url
	if endpoint == "" {
		endpoint = turnstileURL
	}
	form := url.Values{"secret": {t.secret}, "response": {token}, "remoteip": {ip}}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("turnstile siteverify: %w", err)
	}
	defer res.Body.Close()
	var out struct {
		Success  bool   `json:"success"`
		Hostname string `json:"hostname"`
		Action   string `json:"action"`
	}
	if res.StatusCode != http.StatusOK || json.NewDecoder(res.Body).Decode(&out) != nil {
		return fmt.Errorf("turnstile siteverify: status %d", res.StatusCode)
	}
	if !out.Success || out.Action != "login" || !strings.EqualFold(out.Hostname, t.hostname) {
		return errCaptcha
	}
	return nil
}
