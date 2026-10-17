// Package caddycfg renders the full Caddy JSON config from application state. It is pure.
package caddycfg

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/servanago/servanago/internal/store"
)

type Issuer int

const (
	ACME     Issuer = iota // Let's Encrypt (prod or staging) via Cloudflare DNS-01
	Internal               // Caddy's internal CA; tests only
)

const stagingCA = "https://acme-staging-v02.api.letsencrypt.org/directory"

type Options struct {
	UIHost, UIUpstream  string
	Email               string
	Staging             bool
	CA                  string // ACME directory URL override (tests); empty = Let's Encrypt prod or staging
	HTTPPort, HTTPSPort int
	StoragePath         string
	Issuer              Issuer
	HTTP01              bool          // no Cloudflare: default ACME challenges instead of DNS-01; wildcard domains render per host
	PropagationDelay    time.Duration // 0 = omit
	PropagationTimeout  time.Duration // 0 = omit
	Resolvers           []string
}

type State struct {
	Domains []store.Domain
	Sites   []store.Site
}

type m = map[string]any

func Render(st State, o Options) ([]byte, error) {
	if o.Issuer == ACME && o.Email == "" {
		return nil, errors.New("render: ACME email is required")
	}
	if o.UIHost == "" || o.UIUpstream == "" {
		return nil, errors.New("render: UI host and upstream are required")
	}
	domains := make(map[int64]store.Domain, len(st.Domains))
	for _, d := range st.Domains {
		domains[d.ID] = d
	}

	// One route per hostname, each with the site's handler chain: the gate pins the host it runs for.
	type hostSite struct {
		host string
		r    store.Site
	}
	var hr []hostSite
	for _, r := range st.Sites {
		if !r.Enabled { // a disabled site is not in Caddy at all: no handler, no certificate work
			continue
		}
		if len(r.Hostnames) == 0 {
			return nil, fmt.Errorf("render: site %d has no hostname", r.ID)
		}
		for _, h := range r.Hostnames {
			hr = append(hr, hostSite{h, r})
		}
	}
	sort.Slice(hr, func(i, j int) bool { return hr[i].host < hr[j].host })

	routes := []any{hostMatch(o.UIHost, m{"handler": "reverse_proxy", "upstreams": []any{m{"dial": o.UIUpstream}}})}
	own := map[int64][]string{} // hostnames that need a certificate of their own, by domain
	var orphans []string        // hostnames under no domain: HTTP-01, one certificate each
	for _, x := range hr {
		h, err := siteHandler(x.host, x.r)
		if err != nil {
			return nil, err
		}
		routes = append(routes, hostMatch(x.host, h))
		switch d, ok := store.ResolveDomain(st.Domains, x.host); {
		case !ok:
			orphans = append(orphans, x.host)
		case o.HTTP01 || d.CertMode == "per_host" || !coveredByWildcard(x.host, d.Name):
			own[d.ID] = append(own[d.ID], x.host)
		}
	}

	policies := []any{policy([]string{o.UIHost}, o)}
	ds := append([]store.Domain(nil), st.Domains...)
	sort.Slice(ds, func(i, j int) bool { return ds[i].Name < ds[j].Name })
	for _, d := range ds {
		if !o.HTTP01 && d.CertMode != "per_host" { // a wildcard cannot be validated over HTTP-01
			policies = append(policies, policy([]string{"*." + d.Name}, o))
		}
		if hosts := own[d.ID]; len(hosts) > 0 {
			policies = append(policies, policy(hosts, o))
		}
	}
	if len(orphans) > 0 { // no zone to put a DNS-01 record in
		http01 := o
		http01.HTTP01 = true
		policies = append(policies, policy(orphans, http01))
	}

	apps := m{
		"http": m{
			"http_port": o.HTTPPort, "https_port": o.HTTPSPort,
			"servers": m{"srv0": m{"listen": []string{":" + strconv.Itoa(o.HTTPSPort)}, "routes": routes}},
		},
		"tls": m{"automation": m{"policies": policies}},
	}
	if o.Issuer == Internal {
		apps["pki"] = m{"certificate_authorities": m{"local": m{"install_trust": false}}}
	}
	return json.Marshal(m{
		"admin":   m{"disabled": true, "config": m{"persist": false}},
		"storage": m{"module": "file_system", "root": o.StoragePath},
		"logging": m{"logs": m{"default": m{
			"writer": m{"output": "servanago"}, "encoder": m{"format": "json"}, "level": "INFO"}}},
		"apps": apps,
	})
}

// coveredByWildcard is true for exactly one label below the domain: *.example.com does not cover
// example.com itself or a.b.example.com.
func coveredByWildcard(host, domain string) bool {
	label, ok := strings.CutSuffix(host, "."+domain)
	return ok && !strings.Contains(label, ".")
}

func hostMatch(host string, handler any) m {
	return m{"match": []any{m{"host": []string{host}}}, "handle": []any{handler}, "terminal": true}
}

func policy(subjects []string, o Options) m {
	return m{"subjects": subjects, "issuers": []any{issuer(o)}}
}

func issuer(o Options) m {
	if o.Issuer == Internal {
		return m{"module": "internal"}
	}
	i := m{"module": "acme", "email": o.Email}
	if !o.HTTP01 { // HTTP01: Caddy's default challenges, HTTP-01 and TLS-ALPN-01
		dns := m{
			"provider":  m{"name": "cloudflare", "api_token": "{env.CLOUDFLARE_API_TOKEN}"},
			"resolvers": o.Resolvers,
		}
		if o.PropagationDelay > 0 {
			dns["propagation_delay"] = o.PropagationDelay.String()
		}
		if o.PropagationTimeout > 0 {
			dns["propagation_timeout"] = o.PropagationTimeout.String()
		}
		i["challenges"] = m{"dns": dns}
	}
	switch {
	case o.CA != "":
		i["ca"] = o.CA
	case o.Staging:
		i["ca"] = stagingCA
	}
	return i
}

func siteHandler(host string, r store.Site) (any, error) {
	proxy := m{"handler": "reverse_proxy", "upstreams": []any{m{"dial": net.JoinHostPort(r.UpstreamHost, strconv.Itoa(r.UpstreamPort))}}}
	if r.Scheme == "https" {
		tls := m{}
		if r.TLSSkipVerify {
			tls["insecure_skip_verify"] = true
		}
		proxy["transport"] = m{"protocol": "http", "tls": tls}
	}
	if r.Stream {
		proxy["flush_interval"] = -1
	}
	handlers := []any{proxy}
	if r.MaxBody > 0 {
		handlers = []any{m{"handler": "request_body", "max_size": r.MaxBody}, proxy}
	}
	if r.GateMode == "" && r.Allowlist == "" && r.BasicUser == "" && len(handlers) == 1 {
		return proxy, nil
	}

	var sub []any
	if r.GateMode != "" { // the gate leads the chain: a session must pass before anything else
		sub = append(sub, m{"handle": []any{m{"handler": "servanago_gate", "host": host, "mode": r.GateMode, "site_id": r.ID}}})
	}
	if cidrs := strings.Fields(r.Allowlist); len(cidrs) > 0 {
		sub = append(sub, m{
			"match":    []any{m{"not": []any{m{"remote_ip": m{"ranges": cidrs}}}}},
			"handle":   []any{m{"handler": "static_response", "status_code": "403"}},
			"terminal": true,
		})
	}
	if r.BasicUser != "" {
		sub = append(sub, m{"handle": []any{m{"handler": "authentication", "providers": m{"http_basic": m{
			"hash":     m{"algorithm": "bcrypt"},
			"accounts": []any{m{"username": r.BasicUser, "password": r.BasicHash}},
		}}}}})
	}
	sub = append(sub, m{"handle": handlers})
	return m{"handler": "subroute", "routes": sub}, nil
}
