package web

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/caretakarr/caretakarr/internal/apply"
	"github.com/caretakarr/caretakarr/internal/caddycfg"
	"github.com/caretakarr/caretakarr/internal/caddytest"
	"github.com/caretakarr/caretakarr/internal/config"
	"github.com/caretakarr/caretakarr/internal/store"
)

// The Turnstile exemption (Host == CARETAKARR_HOST), Secure cookies (X-Forwarded-Proto) and the login throttle
// (X-Forwarded-For) all depend on what Caddy's reverse_proxy hands the UI. This pins it against a real Caddy.
func TestUIBehindRealCaddyKeepsHostAndSetsForwardedHeaders(t *testing.T) {
	storage := t.TempDir() // before Cleanup so it is removed after Caddy stops
	caddytest.Cleanup(t)
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	verify := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "hostname": testHost, "action": "login"})
	}))
	t.Cleanup(verify.Close)
	cfg := config.Config{Host: testHost, AdminPassword: "pw", TurnstileSiteKey: "site", TurnstileSecret: "sec", TurnstileBaseURL: verify.URL}
	ui := httptest.NewServer(New(Deps{Cfg: cfg, Store: st}).Handler())
	t.Cleanup(ui.Close)

	httpsPort := caddytest.FreePort(t)
	svc := apply.New(st, caddycfg.Options{UIHost: testHost, UIUpstream: strings.TrimPrefix(ui.URL, "http://"),
		Email: "me@example.com", Issuer: caddycfg.Internal, HTTPPort: caddytest.FreePort(t), HTTPSPort: httpsPort, StoragePath: storage})
	if err := svc.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	caddytest.WaitCert(t, httpsPort, testHost)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: testHost},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, fmt.Sprintf("127.0.0.1:%d", httpsPort))
			},
		}}
	do := func(method, path string, form url.Values, xff string) (*http.Response, string) {
		t.Helper()
		r, err := http.NewRequest(method, "https://"+testHost+path, strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		if form != nil {
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("HX-Request", "true")
			r.Header.Set("Origin", "https://"+testHost)
		}
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		resp, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, string(b)
	}

	// Host reaches the UI unchanged: the Turnstile widget (only rendered when Host == CARETAKARR_HOST) is present.
	if _, body := do("GET", "/login", nil, ""); !strings.Contains(body, `data-sitekey="site"`) {
		t.Fatalf("UI did not see Host %s: %s", testHost, body)
	}

	// X-Forwarded-Proto is https: the session cookie is Secure. A Host mismatch would fail the CSRF Origin check here.
	resp, body := do("POST", "/login", url.Values{"password": {"pw"}, "cf-turnstile-response": {"t"}}, "")
	if resp.StatusCode != 204 {
		t.Fatalf("login via Caddy: %d %s", resp.StatusCode, body)
	}
	var secure bool
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookieName {
			secure = c.Secure
		}
	}
	if !secure {
		t.Error("session cookie is not Secure behind Caddy: X-Forwarded-Proto missing")
	}

	// X-Forwarded-For is the real client address, not a caller-supplied one: five wrong passwords, each claiming a
	// different origin, still share one throttle bucket.
	for i := range maxFailures {
		if resp, _ := do("POST", "/login", url.Values{"password": {"bad"}}, fmt.Sprintf("203.0.113.%d", i+1)); resp.StatusCode != 401 {
			t.Fatalf("attempt %d: %d", i, resp.StatusCode)
		}
	}
	if resp, _ := do("POST", "/login", url.Values{"password": {"bad"}}, "203.0.113.99"); resp.StatusCode != 429 {
		t.Fatalf("spoofed X-Forwarded-For escaped the throttle: %d", resp.StatusCode)
	}
}
