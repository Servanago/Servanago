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

	"github.com/caretakarr/caretakarr/internal/store"
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
	HTTPPort, HTTPSPort int
	StoragePath         string
	Issuer              Issuer
	PropagationDelay    time.Duration // 0 = omit
	PropagationTimeout  time.Duration // 0 = omit
	Resolvers           []string
}

type State struct {
	Domains []store.Domain
	Routes  []store.Route
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

	type hostRoute struct {
		host string
		r    store.Route
	}
	var hr []hostRoute
	for _, r := range st.Routes {
		d, ok := domains[r.DomainID]
		if !ok {
			return nil, fmt.Errorf("render: route %d references unknown domain %d", r.ID, r.DomainID)
		}
		hr = append(hr, hostRoute{r.Subdomain + "." + d.Name, r})
	}
	sort.Slice(hr, func(i, j int) bool { return hr[i].host < hr[j].host })

	routes := []any{hostMatch(o.UIHost, m{"handler": "reverse_proxy", "upstreams": []any{m{"dial": o.UIUpstream}}})}
	perHost := map[int64][]string{}
	for _, x := range hr {
		h, err := routeHandler(x.r)
		if err != nil {
			return nil, err
		}
		routes = append(routes, hostMatch(x.host, h))
		if domains[x.r.DomainID].CertMode == "per_host" {
			perHost[x.r.DomainID] = append(perHost[x.r.DomainID], x.host)
		}
	}

	policies := []any{policy([]string{o.UIHost}, o)}
	ds := append([]store.Domain(nil), st.Domains...)
	sort.Slice(ds, func(i, j int) bool { return ds[i].Name < ds[j].Name })
	for _, d := range ds {
		switch d.CertMode {
		case "per_host":
			if hosts := perHost[d.ID]; len(hosts) > 0 {
				policies = append(policies, policy(hosts, o))
			}
		default:
			policies = append(policies, policy([]string{"*." + d.Name}, o))
		}
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
			"writer": m{"output": "caretakarr"}, "encoder": m{"format": "json"}, "level": "INFO"}}},
		"apps": apps,
	})
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
	i := m{"module": "acme", "email": o.Email, "challenges": m{"dns": dns}}
	if o.Staging {
		i["ca"] = stagingCA
	}
	return i
}

func routeHandler(r store.Route) (any, error) {
	if !r.Enabled {
		return m{"handler": "static_response", "status_code": "503", "body": "route disabled"}, nil
	}
	proxy := m{"handler": "reverse_proxy", "upstreams": []any{m{"dial": net.JoinHostPort(r.UpstreamHost, strconv.Itoa(r.UpstreamPort))}}}
	if r.Scheme == "https" {
		tls := m{}
		if r.TLSSkipVerify {
			tls["insecure_skip_verify"] = true
		}
		proxy["transport"] = m{"protocol": "http", "tls": tls}
	}
	if r.Allowlist == "" && r.BasicUser == "" {
		return proxy, nil
	}

	var sub []any
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
	sub = append(sub, m{"handle": []any{proxy}})
	return m{"handler": "subroute", "routes": sub}, nil
}
