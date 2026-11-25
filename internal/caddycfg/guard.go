package caddycfg

import (
	"html"
	"net"
	"strconv"
	"strings"

	"github.com/servanago/servanago/internal/store"
)

// guardOf is the site's protection settings; a Site built without them (tests, imports) has the defaults.
func guardOf(r store.Site) store.SiteGuard {
	if r.Guard == nil {
		return store.DefaultGuard()
	}
	return *r.Guard
}

// observer leads every enabled site's chain: it records the request once the rest of the chain returns.
func observer(r store.Site) m {
	g := guardOf(r)
	o := m{"handler": "servanago_traffic", "site": r.Slug}
	if g.BanOn {
		o["ban"] = true
	}
	if cidrs := strings.Fields(r.Allowlist); len(cidrs) > 0 {
		o["allow"] = cidrs
	}
	if g.UAMode == "auto" && g.UAAutoRPS > 0 {
		o["auto_rps"] = g.UAAutoRPS
		o["auto_cooldown_min"] = g.UACooldownMin
	}
	return o
}

// guardRoutes returns the guard handlers of one position: "ban" leads the chain after the observer, "challenge" follows the WAF,
// "paywall" follows basic auth and "queue" the paywall.
func guardHandlers(r store.Site, position string) []any {
	g := guardOf(r)
	allow := strings.Fields(r.Allowlist)
	with := func(h m) m {
		if len(allow) > 0 {
			h["allow"] = allow
		}
		return h
	}
	switch position {
	case "ban":
		if g.BanOn {
			return []any{m{"handler": "servanago_ban"}}
		}
	case "challenge":
		if g.UAMode != "" {
			h := with(m{"handler": "servanago_challenge", "site": r.Slug, "kind": g.CHKind, "difficulty": g.CHDifficulty, "ttl_min": g.CHTTLMin})
			if g.UAMode == "on" {
				h["forced"] = true
			} else {
				h["auto"] = true
			}
			return []any{h}
		}
	case "paywall":
		if len(r.X402) > 0 {
			rs := make([]any, 0, len(r.X402))
			for _, x := range r.X402 {
				rs = append(rs, m{"path": x.Path, "price": x.Price, "mode": x.Mode, "grant": x.GrantKind, "ttl_s": x.TokenTTLs})
			}
			h := with(m{"handler": "servanago_x402", "site": r.Slug, "routes": rs})
			if g.UAMode != "" {
				h["has_challenge"] = true
			}
			return []any{h}
		}
	case "queue":
		if g.QOn {
			return []any{with(m{"handler": "servanago_queue", "site": r.Slug, "capacity": g.QCapacity, "active_ttl_s": g.QActiveTTLs, "max_queue": g.QMaxQueue})}
		}
	}
	return nil
}

// catchAll answers a host no site owns: counted by the observer (and optionally fed to the ban engine), then a bare 404.
func catchAll() m {
	return m{"handle": []any{
		m{"handler": "servanago_traffic", "site": "", "unknown": true},
		m{"handler": "servanago_ban"},
		m{"handler": "static_response", "status_code": "404"},
	}, "terminal": true}
}

// backends are the site's upstreams: the main one plus the extra host:port lines, proxy sites only.
func backends(r store.Site) []any {
	ups := []any{m{"dial": net.JoinHostPort(r.UpstreamHost, itoa(r.UpstreamPort))}}
	if r.Kind != "proxy" && r.Kind != "" {
		return ups
	}
	for _, l := range strings.Fields(guardOf(r).Backends) {
		ups = append(ups, m{"dial": l})
	}
	return ups
}

// failover adds round-robin balancing with passive health to a proxy that has more than one upstream.
func failover(proxy m, ups []any) {
	if len(ups) < 2 {
		return
	}
	proxy["load_balancing"] = m{"selection_policy": m{"policy": "round_robin"}, "try_duration": "3s", "try_interval": "250ms"}
	proxy["health_checks"] = m{"passive": m{"fail_duration": "30s", "max_fails": 1, "unhealthy_status": []int{502, 503, 504}}}
}

// pageHandler renders a kind "page" site: a redirect, or a status page from the built-in template or the admin's own HTML.
func pageHandler(r store.Site) m {
	p := r.Page
	if p.Status == 0 {
		p = store.DefaultPage()
	}
	if p.IsRedirect() {
		loc := p.Target
		if p.KeepPath {
			loc = strings.TrimRight(loc, "/") + "{http.request.uri}"
		}
		return m{"handler": "static_response", "status_code": itoa(p.Status), "headers": m{"Location": []string{loc}}}
	}
	body := p.HTML
	if body == "" {
		title := p.Title
		if title == "" {
			title = "Back soon"
		}
		msg := p.Message
		if msg == "" {
			msg = "This site is not available right now."
		}
		body = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>` +
			html.EscapeString(title) + `</title><style>body{font:16px system-ui,sans-serif;margin:0;display:grid;place-items:center;min-height:100vh;background:#f6f7f8;color:#1b1f23}main{max-width:32rem;padding:2rem}@media(prefers-color-scheme:dark){body{background:#14171a;color:#e7e9ea}}</style></head><body><main><h1>` +
			html.EscapeString(title) + `</h1><p>` + html.EscapeString(msg) + `</p></main></body></html>`
	}
	// Caddy interpolates placeholders in a static body; the admin's page is served exactly as written.
	body = strings.ReplaceAll(body, "{", `\{`)
	return m{"handler": "static_response", "status_code": itoa(p.Status), "body": body,
		"headers": m{"Content-Type": []string{"text/html; charset=utf-8"}}}
}

func itoa(n int) string { return strconv.Itoa(n) }

const guardOutcomeVar = "sg_outcome"
