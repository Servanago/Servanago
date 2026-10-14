package cfdns

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cloudflare/cloudflare-go/v7/option"
)

// fake serves canned Cloudflare JSON per "METHOD path" and records requests.
func fake(t *testing.T, routes map[string]func(w http.ResponseWriter, r *http.Request)) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h, ok := routes[r.Method+" "+r.URL.Path]
		if !ok {
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	return New("test-token", option.WithBaseURL(srv.URL), option.WithMaxRetries(0))
}

func reply(status int, body string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
}

const zonesOK = `{"success":true,"errors":[],"messages":[],"result":[{"id":"zone123","name":"example.com"}],"result_info":{"page":1,"per_page":20,"count":1,"total_count":1}}`

func TestZoneID(t *testing.T) {
	tests := []struct {
		name    string
		handler func(http.ResponseWriter, *http.Request)
		want    string
		errHas  string
	}{
		{"found", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("name") != "example.com" || r.Header.Get("Authorization") != "Bearer test-token" {
				t.Errorf("bad request: %s %v", r.URL, r.Header)
			}
			_, _ = w.Write([]byte(zonesOK))
		}, "zone123", ""},
		{"not found", reply(200, `{"success":true,"errors":[],"messages":[],"result":[],"result_info":{"page":1,"per_page":20,"count":0,"total_count":0}}`), "", "not found"},
		{"name mismatch", reply(200, `{"success":true,"errors":[],"messages":[],"result":[{"id":"z9","name":"other.com"}],"result_info":{"page":1,"per_page":20,"count":1,"total_count":1}}`), "", "not found"},
		{"bad token", reply(403, `{"success":false,"errors":[{"code":9109,"message":"Invalid access token"}],"messages":[],"result":null}`), "", "Invalid access token"},
		{"api error", reply(500, `{"success":false,"errors":[{"code":1000,"message":"upstream exploded"}],"messages":[],"result":null}`), "", "upstream exploded"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := fake(t, map[string]func(http.ResponseWriter, *http.Request){"GET /zones": tt.handler})
			got, err := c.ZoneID(context.Background(), "example.com")
			if tt.errHas != "" {
				if err == nil || !strings.Contains(err.Error(), tt.errHas) {
					t.Fatalf("want error containing %q, got %v", tt.errHas, err)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("got %q, %v", got, err)
			}
		})
	}
}

func TestVerifyToken(t *testing.T) {
	ok := fake(t, map[string]func(http.ResponseWriter, *http.Request){
		"GET /user/tokens/verify": reply(200, `{"success":true,"errors":[],"messages":[],"result":{"id":"abc","status":"active"}}`)})
	if err := ok.VerifyToken(context.Background()); err != nil {
		t.Fatal(err)
	}
	expired := fake(t, map[string]func(http.ResponseWriter, *http.Request){
		"GET /user/tokens/verify": reply(200, `{"success":true,"errors":[],"messages":[],"result":{"id":"abc","status":"expired"}}`)})
	if err := expired.VerifyToken(context.Background()); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("got %v", err)
	}
	bad := fake(t, map[string]func(http.ResponseWriter, *http.Request){
		"GET /user/tokens/verify": reply(401, `{"success":false,"errors":[{"code":1000,"message":"Invalid API Token"}],"messages":[],"result":null}`)})
	if err := bad.VerifyToken(context.Background()); err == nil || !strings.Contains(err.Error(), "Invalid API Token") {
		t.Fatalf("got %v", err)
	}
}
