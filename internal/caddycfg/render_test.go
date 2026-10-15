package caddycfg

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caretakarr/caretakarr/internal/store"
)

var update = flag.Bool("update", false, "rewrite golden files")

func opts() Options {
	return Options{
		UIHost: "caretakarr.example.com", UIUpstream: "127.0.0.1:8080", Email: "me@example.com",
		HTTPPort: 80, HTTPSPort: 443, StoragePath: "/data/caddy", Resolvers: []string{"1.1.1.1", "8.8.8.8"},
	}
}

var (
	dom   = store.Domain{ID: 1, Name: "example.com", CertMode: "wildcard"}
	route = store.Route{ID: 1, DomainID: 1, Subdomain: "sonarr", Scheme: "http", UpstreamHost: "192.168.1.20", UpstreamPort: 8989, Enabled: true}
)

func with(r store.Route, f func(*store.Route)) store.Route { f(&r); return r }

func TestRenderGolden(t *testing.T) {
	staging := opts()
	staging.Staging = true
	timed := opts()
	timed.PropagationDelay, timed.PropagationTimeout = 2*time.Minute, 10*time.Minute
	internal := opts()
	internal.Issuer, internal.HTTPPort, internal.HTTPSPort = Internal, 18080, 18443
	perHost := dom
	perHost.CertMode = "per_host"

	tests := []struct {
		name  string
		opts  Options
		state State
	}{
		{"bootstrap", opts(), State{}},
		{"one_route", opts(), State{[]store.Domain{dom}, []store.Route{route}}},
		{"disabled", opts(), State{[]store.Domain{dom}, []store.Route{with(route, func(r *store.Route) { r.Enabled = false })}}},
		{"allowlist", opts(), State{[]store.Domain{dom}, []store.Route{with(route, func(r *store.Route) { r.Allowlist = "192.168.0.0/16\n10.0.0.0/8" })}}},
		{"basic_auth", opts(), State{[]store.Domain{dom}, []store.Route{with(route, func(r *store.Route) { r.BasicUser, r.BasicHash = "u", "$2a$14$abc" })}}},
		{"https_skip_verify", opts(), State{[]store.Domain{dom}, []store.Route{with(route, func(r *store.Route) { r.Scheme, r.TLSSkipVerify = "https", true })}}},
		{"https_verify", opts(), State{[]store.Domain{dom}, []store.Route{with(route, func(r *store.Route) { r.Scheme = "https" })}}},
		{"stream", opts(), State{[]store.Domain{dom}, []store.Route{with(route, func(r *store.Route) { r.Stream = true })}}},
		{"max_body", opts(), State{[]store.Domain{dom}, []store.Route{with(route, func(r *store.Route) { r.MaxBody = 2 << 30 })}}},
		{"stream_max_body_basic", opts(), State{[]store.Domain{dom}, []store.Route{with(route, func(r *store.Route) {
			r.Stream, r.MaxBody, r.BasicUser, r.BasicHash = true, 2<<30, "u", "$2a$14$abc"
		})}}},
		{"staging", staging, State{}},
		{"prod_default", opts(), State{[]store.Domain{dom}, nil}},
		{"propagation_set", timed, State{}},
		{"per_host", opts(), State{[]store.Domain{perHost}, []store.Route{route, with(route, func(r *store.Route) { r.ID, r.Subdomain = 2, "radarr" })}}},
		{"per_host_one_disabled", opts(), State{[]store.Domain{perHost}, []store.Route{route, with(route, func(r *store.Route) { r.ID, r.Subdomain, r.Enabled = 2, "radarr", false })}}},
		{"per_host_all_disabled", opts(), State{[]store.Domain{perHost}, []store.Route{with(route, func(r *store.Route) { r.Enabled = false })}}},
		{"per_host_empty", opts(), State{[]store.Domain{perHost}, nil}},
		{"internal_issuer", internal, State{[]store.Domain{dom}, []store.Route{route}}},
		{"banking_homelab", opts(), State{[]store.Domain{dom}, []store.Route{{ID: 1, DomainID: 1, Subdomain: "banking", Scheme: "http", UpstreamHost: "192.168.25.165", UpstreamPort: 8766, Enabled: true}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Render(tt.state, tt.opts)
			if err != nil {
				t.Fatal(err)
			}
			var buf bytes.Buffer
			if err := json.Indent(&buf, got, "", "  "); err != nil {
				t.Fatal(err)
			}
			buf.WriteByte('\n')
			path := filepath.Join("testdata", tt.name+".golden.json")
			if *update {
				if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(buf.Bytes(), want) {
				t.Errorf("output differs from %s (run with -update to accept)\n%s", path, buf.String())
			}
		})
	}
}

// issuers walks the rendered config and returns every ACME issuer object.
func acmeIssuers(t *testing.T, b []byte) []map[string]any {
	t.Helper()
	var cfg map[string]any
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	pols := cfg["apps"].(map[string]any)["tls"].(map[string]any)["automation"].(map[string]any)["policies"].([]any)
	var out []map[string]any
	for _, p := range pols {
		for _, i := range p.(map[string]any)["issuers"].([]any) {
			out = append(out, i.(map[string]any))
		}
	}
	return out
}

func TestEveryIssuerHasEmail(t *testing.T) {
	b, err := Render(State{[]store.Domain{dom}, []store.Route{route}}, opts())
	if err != nil {
		t.Fatal(err)
	}
	is := acmeIssuers(t, b)
	if len(is) < 2 { // UI policy + wildcard policy
		t.Fatalf("issuers: %d", len(is))
	}
	for _, i := range is {
		if i["email"] != "me@example.com" {
			t.Errorf("issuer without email: %v", i)
		}
	}
}

func TestEmptyEmailErrors(t *testing.T) {
	o := opts()
	o.Email = ""
	if _, err := Render(State{}, o); err == nil || !strings.Contains(err.Error(), "email") {
		t.Fatalf("want email error, got %v", err)
	}
}

func TestDeterministic(t *testing.T) {
	st := State{[]store.Domain{dom, {ID: 2, Name: "b.org", CertMode: "per_host"}}, []store.Route{
		route, with(route, func(r *store.Route) { r.ID, r.Subdomain = 2, "radarr" }),
		with(route, func(r *store.Route) { r.ID, r.DomainID = 3, 2 }),
	}}
	a, _ := Render(st, opts())
	for range 20 {
		b, _ := Render(st, opts())
		if !bytes.Equal(a, b) {
			t.Fatal("render not deterministic")
		}
	}
}

func TestNoLiteralToken(t *testing.T) {
	t.Setenv("CLOUDFLARE_API_TOKEN", "SECRET-TOKEN-XYZ")
	b, err := Render(State{[]store.Domain{dom}, []store.Route{route}}, opts())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("SECRET-TOKEN-XYZ")) {
		t.Fatal("literal token in output")
	}
	if !bytes.Contains(b, []byte("{env.CLOUDFLARE_API_TOKEN}")) {
		t.Fatal("token placeholder missing")
	}
}

func TestPropagationOnlyWhenSet(t *testing.T) {
	unset, _ := Render(State{}, opts())
	if bytes.Contains(unset, []byte("propagation_")) {
		t.Error("propagation fields emitted when unset")
	}
	o := opts()
	o.PropagationDelay = 2 * time.Minute
	onlyDelay, _ := Render(State{}, o)
	if !bytes.Contains(onlyDelay, []byte("propagation_delay")) || bytes.Contains(onlyDelay, []byte("propagation_timeout")) {
		t.Error("delay-only case wrong")
	}
}
