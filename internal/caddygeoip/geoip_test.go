package caddygeoip

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// next records that the request reached the rest of the chain.
func next(w *httptest.ResponseRecorder) caddyhttp.Handler {
	return caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		_, _ = w.WriteString("reached")
		return nil
	})
}

// geoReq is a request from the given address with extra headers.
func geoReq(ip string, hdr map[string]string) *http.Request {
	r := httptest.NewRequest("GET", "/page", nil)
	r.RemoteAddr = ip + ":4444"
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	return r
}

func denyDE() *Handler {
	h := &Handler{Mode: "deny", Countries: []string{"DE"}}
	_ = h.Provision(caddy.Context{})
	return h
}

func allowDE() *Handler {
	h := &Handler{Mode: "allow", Countries: []string{"DE"}}
	_ = h.Provision(caddy.Context{})
	return h
}

// installLookup answers each IP with the country a real database would: 203.0.113.9 is a German
// range in the tests' story, 8.8.4.4 is US.
func installLookup(fail bool) func() {
	Install(&Service{Lookup: func(ip netip.Addr) (string, error) {
		if fail {
			return "", errStub
		}
		if ip == netip.MustParseAddr("203.0.113.9") {
			return "DE", nil
		}
		return "US", nil
	}})
	return func() { Install(nil) }
}

var errStub = errorStub{}

type errorStub struct{}

func (errorStub) Error() string { return "db closed" }

func TestGeoHandlerDenyAndAllow(t *testing.T) {
	restore := installLookup(false)
	defer restore()

	// a listed country is denied; an unlisted one reaches the handler
	w := httptest.NewRecorder()
	if err := denyDE().ServeHTTP(w, geoReq("203.0.113.9", nil), next(w)); err != nil || w.Code != 403 {
		t.Fatalf("DE under deny: %d %q (%v)", w.Code, w.Body.String(), err)
	}
	w = httptest.NewRecorder()
	if err := denyDE().ServeHTTP(w, geoReq("8.8.4.4", nil), next(w)); err != nil || !strings.Contains(w.Body.String(), "reached") {
		t.Errorf("US under deny: %d %q (%v)", w.Code, w.Body.String(), err)
	}
	// allow mode: a listed country passes, any other is blocked
	w = httptest.NewRecorder()
	if err := allowDE().ServeHTTP(w, geoReq("203.0.113.9", nil), next(w)); err != nil || !strings.Contains(w.Body.String(), "reached") {
		t.Errorf("DE under allow: %d %q (%v)", w.Code, w.Body.String(), err)
	}
	w = httptest.NewRecorder()
	if err := allowDE().ServeHTTP(w, geoReq("8.8.4.4", nil), next(w)); err != nil || w.Code != 403 {
		t.Errorf("US under allow: %d %q (%v)", w.Code, w.Body.String(), err)
	}
}

func TestGeoHandlerWellKnownAndPrivatePeers(t *testing.T) {
	restore := installLookup(false)
	defer restore()
	// /.well-known/* always passes, even for a listed country
	for _, path := range []string{"/.well-known/acme-challenge/x", "/.well-known/mta-sts.txt"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", path, nil)
		r.RemoteAddr = "203.0.113.9:4444"
		if err := denyDE().ServeHTTP(w, r, next(w)); err != nil || !strings.Contains(w.Body.String(), "reached") {
			t.Errorf("%s blocked: %d %q", path, w.Code, w.Body.String())
		}
	}
	// loopback, RFC1918 and the CGNAT range pass
	for _, ip := range []string{"127.0.0.1", "192.168.25.10", "100.64.0.2", "10.1.2.3"} {
		w := httptest.NewRecorder()
		if err := denyDE().ServeHTTP(w, geoReq(ip, nil), next(w)); err != nil || !strings.Contains(w.Body.String(), "reached") {
			t.Errorf("%s blocked: %d %q", ip, w.Code, w.Body.String())
		}
	}
}

func TestGeoHandlerCloudflareHeader(t *testing.T) {
	// a Cloudflare peer's client is the header value (the peer's own address is a CF node)
	restore := installLookup(false)
	defer restore()
	w := httptest.NewRecorder()
	if err := denyDE().ServeHTTP(w, geoReq("108.162.192.6", map[string]string{"CF-Connecting-IP": "203.0.113.9"}), next(w)); err != nil || w.Code != 403 {
		t.Errorf("CF client DE under deny: %d %q (%v)", w.Code, w.Body.String(), err)
	}
	// the header cannot make a private address a client
	w = httptest.NewRecorder()
	if err := denyDE().ServeHTTP(w, geoReq("108.162.192.6", map[string]string{"CF-Connecting-IP": "192.168.0.5"}), next(w)); err != nil || !strings.Contains(w.Body.String(), "reached") {
		t.Errorf("CF private header passed the rule: %d %q", w.Code, w.Body.String())
	}
	// a CF peer without the header: no client, pass
	w = httptest.NewRecorder()
	if err := denyDE().ServeHTTP(w, geoReq("108.162.192.6", nil), next(w)); err != nil || !strings.Contains(w.Body.String(), "reached") {
		t.Errorf("CF peer without header: %d %q", w.Code, w.Body.String())
	}
	// a forged header on a DIRECT peer must not decide anything
	w = httptest.NewRecorder()
	if err := denyDE().ServeHTTP(w, geoReq("8.8.4.4", map[string]string{"CF-Connecting-IP": "203.0.113.9"}), next(w)); err != nil || !strings.Contains(w.Body.String(), "reached") {
		t.Errorf("forged header decided: %d %q", w.Code, w.Body.String())
	}
}

func TestGeoHandlerFailOpen(t *testing.T) {
	// no installed service = pass
	w := httptest.NewRecorder()
	if err := denyDE().ServeHTTP(w, geoReq("203.0.113.9", nil), next(w)); err != nil || !strings.Contains(w.Body.String(), "reached") {
		t.Errorf("no service: %d %q", w.Code, w.Body.String())
	}
	// a broken db = pass
	restore := installLookup(true)
	defer restore()
	w = httptest.NewRecorder()
	if err := denyDE().ServeHTTP(w, geoReq("203.0.113.9", nil), next(w)); err != nil || !strings.Contains(w.Body.String(), "reached") {
		t.Errorf("lookup error: %d %q", w.Code, w.Body.String())
	}
}
