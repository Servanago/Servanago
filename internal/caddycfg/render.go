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

	"github.com/servanago/servanago/internal/config"
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
	Snippets            []store.Snippet // bodies of the snippets sites attach by name; ponytail: here, not in State, to keep State's positional literals
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
		if ml := r.MLHost(); ml != "" { // the gate's own host: request form and emailed link, never the site
			hr = append(hr, hostSite{ml, r})
		}
	}
	sort.Slice(hr, func(i, j int) bool { return hr[i].host < hr[j].host })

	routes := []any{hostMatch(o.UIHost, m{"handler": "reverse_proxy", "upstreams": []any{m{"dial": o.UIUpstream}}})}
	own := map[int64][]string{} // hostnames that need a certificate of their own, by domain
	var orphans []string        // hostnames under no domain: HTTP-01, one certificate each
	bodies := map[string]string{}
	for _, x := range o.Snippets {
		bodies[x.Name] = x.Body
	}
	adapted := map[string][]any{} // each snippet is adapted once, however many sites attach it
	for _, x := range hr {
		var snip []any
		for _, n := range x.r.Snippets {
			rs, ok := adapted[n]
			if !ok {
				body, known := bodies[n]
				if !known {
					return nil, fmt.Errorf("render: site %d: unknown snippet %q", x.r.ID, n)
				}
				var err error
				if rs, err = AdaptSnippet(body); err != nil {
					return nil, fmt.Errorf("render: snippet %q: %w", n, err)
				}
				adapted[n] = rs
			}
			snip = append(snip, rs...)
		}
		h, err := siteHandler(x.host, x.r, snip)
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

// siteHandler is the site's terminal handler (reverse_proxy, file_server or the php_fastcgi
// expansion) wrapped in the shared gate, allowlist and basic-auth chain when any of them is set. snip holds the
// adapted routes of the site's snippets: they run after that chain and before the handler, except under /.well-known/.
func siteHandler(host string, r store.Site, snip []any) (any, error) {
	if host == r.MLHost() {
		return m{"handler": "servanago_gate", "host": host, "mode": r.GateMode, "site_id": r.ID, "primary": r.Hostnames[0]}, nil
	}
	var extras []any
	if r.ExtraRoutes != "" {
		var err error
		if extras, err = extraRoutes(r); err != nil {
			return nil, err
		}
	}
	var handlers []any
	switch r.Kind {
	case "static":
		// file_server lists no directories unless asked. Dotfiles and dot-directories get a 404 by request path;
		// file_server's own "hide" would also match dot-directories in the root's location.
		routes := []any{dotfile404()}
		routes = append(routes, extras...)
		if r.SiteUser != "" { // the site's own unit serves the folder as that user, over its socket
			routes = append(routes, m{"handle": []any{m{"handler": "reverse_proxy", "upstreams": []any{m{"dial": "unix//run/servanago/" + r.Slug + ".sock"}}}}})
		} else {
			routes = append(routes, m{"handle": []any{m{"handler": "file_server", "root": r.WebRoot()}}})
		}
		handlers = []any{m{"handler": "subroute", "routes": routes}}
	case "php":
		handlers = []any{phpRoute(r, extras)}
	case "fastcgi": // every request goes to the FastCGI upstream; the script path is root + the request path
		routes := []any{dotfile404()}
		routes = append(routes, extras...)
		routes = append(routes, m{"handle": []any{fastcgiProxy(fastcgiDial(r), r.WebRoot())}})
		handlers = []any{m{"handler": "subroute", "routes": routes}}
	case "cgi": // /cgi-bin/* runs through the site's own fcgiwrap; everything else is a plain file
		routes := []any{dotfile404()}
		routes = append(routes, extras...)
		routes = append(routes,
			m{"match": []any{m{"path": []any{"/cgi-bin/*"}}}, "handle": []any{fastcgiProxy("unix//run/servanago/"+r.Slug+".sock", r.WebRoot())}, "terminal": true},
			m{"handle": []any{m{"handler": "file_server", "root": r.WebRoot()}}},
		)
		handlers = []any{m{"handler": "subroute", "routes": routes}}
	default:
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
		handlers = []any{proxy}
		if r.MaxBody > 0 {
			handlers = []any{m{"handler": "request_body", "max_size": r.MaxBody}, proxy}
		}
		if r.Kind == "frankenphp" { // FrankenPHP serves .env and .git itself: answer dotfiles here, as for static and php
			routes := []any{dotfile404()}
			routes = append(routes, extras...)
			routes = append(routes, m{"handle": handlers})
			handlers = []any{m{"handler": "subroute", "routes": routes}}
		} else if len(extras) > 0 { // proxy and node: the path routes precede the catch-all proxy
			routes := make([]any, 0, len(extras)+1)
			routes = append(routes, extras...)
			routes = append(routes, m{"handle": handlers})
			handlers = []any{m{"handler": "subroute", "routes": routes}}
		}
	}
	if r.GateMode == "" && r.Allowlist == "" && r.BasicUser == "" && len(snip) == 0 && len(handlers) == 1 {
		return handlers[0], nil
	}

	var sub []any
	cidrs := strings.Fields(r.Allowlist)
	if r.GateMode != "" { // the gate leads the chain: a session must pass before anything else
		gate := m{"handle": []any{m{"handler": "servanago_gate", "host": host, "mode": r.GateMode, "site_id": r.ID, "primary": r.Hostnames[0]}}}
		if len(cidrs) > 0 { // either one gets in: an allowed address skips the gate, any other needs a link
			gate["match"] = []any{m{"not": []any{m{"remote_ip": m{"ranges": cidrs}}}}}
		}
		sub = append(sub, gate)
	}
	if len(cidrs) > 0 && r.GateMode == "" {
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
	if len(snip) > 0 { // ACME-adjacent and app well-known endpoints must never be hidden or recompressed by a snippet
		sub = append(sub, m{
			"match":  []any{m{"not": []any{m{"path": []any{"/.well-known/*"}}}}},
			"handle": []any{m{"handler": "subroute", "routes": snip}},
		})
	}
	sub = append(sub, m{"handle": handlers})
	return m{"handler": "subroute", "routes": sub}, nil
}

// dotfile404 answers any dotfile or dot-directory path (.env, .git) with 404; the upstream never sees it.
func dotfile404() m {
	return m{"match": []any{m{"path_regexp": m{"pattern": `(^|/)\.`}}}, "handle": []any{m{"handler": "static_response", "status_code": "404"}}, "terminal": true}
}

// extraRoutes renders the site's extra routes (admin-entered, config.ParseExtraRoutes): each becomes
// a path-matched reverse_proxy that answers before the site's main handler. They run after the
// dotfile guard of the kinds that have one and inside the gate, allowlist and basic-auth chain.
func extraRoutes(r store.Site) ([]any, error) {
	xs, err := config.ParseExtraRoutes(r.ExtraRoutes)
	if err != nil {
		return nil, fmt.Errorf("render: site %d extra routes: %w", r.ID, err)
	}
	var out []any
	for _, x := range xs {
		dial := x.Dial
		if strings.HasPrefix(dial, "/") {
			dial = "unix/" + dial
		}
		out = append(out, m{
			"match":    []any{m{"path": []any{x.Path, x.Path + "/*"}}},
			"handle":   []any{m{"handler": "reverse_proxy", "upstreams": []any{m{"dial": dial}}}},
			"terminal": true,
		})
	}
	return out, nil
}

// fastcgiDial is the Caddy dial string for a fastcgi site: an absolute socket path or host:port.
func fastcgiDial(r store.Site) string {
	if strings.HasPrefix(r.UpstreamHost, "/") {
		return "unix/" + r.UpstreamHost
	}
	return net.JoinHostPort(r.UpstreamHost, strconv.Itoa(r.UpstreamPort))
}

func fastcgiProxy(dial, root string) m {
	return m{"handler": "reverse_proxy", "upstreams": []any{m{"dial": dial}}, "transport": m{"protocol": "fastcgi", "root": root}}
}

// phpRoute is the JSON form of the documented php_fastcgi expansion, pointed at the site's own
// pool socket: canonical-path redirect, index.php fallback rewrite, the FastCGI proxy, and a
// plain file_server underneath (dotfiles 404 first, then any extra routes, as for static sites).
func phpRoute(r store.Site, extras []any) any {
	dial := "unix//run/servanago/" + r.Slug + ".sock"
	proxy := m{
		"handler":   "reverse_proxy",
		"upstreams": []any{m{"dial": dial}},
		"transport": m{"protocol": "fastcgi", "root": r.WebRoot(), "split_path": []any{".php"}},
	}
	root := r.WebRoot() // the file matchers look in their own root, which is Caddy's working directory when unset
	routes := []any{dotfile404()}
	routes = append(routes, extras...)
	routes = append(routes,
		m{
			"match":  []any{m{"file": m{"root": root, "try_files": []any{"{http.request.uri.path}/index.php"}}, "not": []any{m{"path": []any{"*/"}}}}},
			"handle": []any{m{"handler": "static_response", "status_code": "308", "headers": m{"Location": []any{"{http.request.orig_uri.path}/{http.request.orig_uri.prefixed_query}"}}}},
		},
		m{
			"match":  []any{m{"file": m{"root": root, "try_files": []any{"{http.request.uri.path}", "{http.request.uri.path}/index.php", "index.php"}, "try_policy": "first_exist_fallback", "split_path": []any{".php"}}}},
			"handle": []any{m{"handler": "rewrite", "uri": "{http.matchers.file.relative}"}},
		},
		m{"match": []any{m{"path": []any{"*.php"}}}, "handle": []any{proxy}},
		m{"handle": []any{m{"handler": "file_server", "root": root}}},
	)
	return m{"handler": "subroute", "routes": routes}
}
