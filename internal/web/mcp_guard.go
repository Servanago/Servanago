package web

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/servanago/servanago/internal/store"
	"github.com/servanago/servanago/internal/trafficdb"
)

// guardArgs are the protection fields create_site and update_site take (since 0.22.0). Pointers: leaving one out keeps the stored value.
type guardArgs struct {
	BanOn         *bool    `json:"ban_on,omitempty" jsonschema:"auto-ban addresses that keep getting error responses; leaving it out keeps the stored one"`
	QueueOn       *bool    `json:"queue_on,omitempty" jsonschema:"hold visitors above the capacity in a waiting room"`
	QueueCapacity *int     `json:"queue_capacity,omitempty" jsonschema:"visitors admitted at once (1-100000)"`
	Backends      *string  `json:"backends,omitempty" jsonschema:"proxy: extra upstreams, host:port one per line, for failover; \"\" clears them"`
	X402Routes    *string  `json:"x402_routes,omitempty" jsonschema:"paywall: one line per path as: path price all|bots request|token [token seconds], e.g. /api/ 0.001 bots token 600; \"\" clears them"`
	AlertDests    *[]int64 `json:"alert_destinations,omitempty" jsonschema:"alert destination ids (list_alert_destinations) that receive this site's alerts; [] = every matching destination"`
	PageStatus    *int     `json:"page_status,omitempty" jsonschema:"page sites: HTTP status (503 maintenance, 200 parked, 301/302/303/307/308 redirect)"`
	PageTitle     *string  `json:"page_title,omitempty"`
	PageMessage   *string  `json:"page_message,omitempty"`
	PageHTML      *string  `json:"page_html,omitempty" jsonschema:"page sites: your own page, up to 64 KB, served as written"`
	PageTarget    *string  `json:"page_target,omitempty" jsonschema:"page sites with a redirect status: the target URL"`
	PageKeepPath  *bool    `json:"page_keep_path,omitempty" jsonschema:"redirects: keep the path and query"`
}

func (a guardArgs) overlayGuard(v url.Values) {
	flag := func(k string, b *bool) {
		switch {
		case b == nil:
		case *b:
			v.Set(k, "on")
		default:
			v.Del(k)
		}
	}
	str := func(k string, p *string) {
		if p != nil {
			v.Set(k, *p)
		}
	}
	flag("ban_on", a.BanOn)
	flag("q_on", a.QueueOn)
	if a.QueueCapacity != nil {
		v.Set("q_capacity", strconv.Itoa(*a.QueueCapacity))
	}
	str("backends", a.Backends)
	str("x402_routes", a.X402Routes)
	if a.AlertDests != nil {
		v.Del("alert_dest")
		for _, id := range *a.AlertDests {
			v.Add("alert_dest", strconv.FormatInt(id, 10))
		}
	}
	if a.PageStatus != nil {
		v.Set("page_status", strconv.Itoa(*a.PageStatus))
	}
	str("page_title", a.PageTitle)
	str("page_message", a.PageMessage)
	str("page_html", a.PageHTML)
	str("page_target", a.PageTarget)
	flag("page_keep_path", a.PageKeepPath)
	if a.BanOn != nil || a.QueueOn != nil || a.QueueCapacity != nil || a.Backends != nil || a.X402Routes != nil || a.AlertDests != nil {
		v.Set("protect", "1")
	}
}

// protectionView is a site's protection summary: no secrets.
type protectionView struct {
	BanOn         bool      `json:"ban_on"`
	UnderAttack   string    `json:"under_attack,omitempty"`
	Challenge     string    `json:"challenge,omitempty"`
	QueueOn       bool      `json:"queue_on"`
	QueueCapacity int       `json:"queue_capacity,omitempty"`
	Backends      []string  `json:"backends,omitempty"`
	X402Routes    []string  `json:"x402_routes,omitempty"`
	AlertDests    []int64   `json:"alert_destinations,omitempty"`
	Page          *pageView `json:"page,omitempty"`
}

type pageView struct {
	Status     int    `json:"status"`
	Title      string `json:"title,omitempty"`
	Message    string `json:"message,omitempty"`
	CustomHTML bool   `json:"custom_html,omitempty"`
	Target     string `json:"target,omitempty"`
	KeepPath   bool   `json:"keep_path,omitempty"`
}

func protectionOf(x store.Site) *protectionView {
	if x.Guard == nil {
		return nil
	}
	g := x.Guard
	p := &protectionView{BanOn: g.BanOn, UnderAttack: g.UAMode, QueueOn: g.QOn, Backends: strings.Fields(g.Backends), AlertDests: x.AlertDests}
	if g.UAMode != "" {
		p.Challenge = g.CHKind + "/" + g.CHDifficulty
	}
	if g.QOn {
		p.QueueCapacity = g.QCapacity
	}
	if t := x402Text(x.X402); t != "" {
		p.X402Routes = strings.Split(t, "\n")
	}
	if x.Kind == "page" {
		p.Page = &pageView{Status: x.Page.Status, Title: x.Page.Title, Message: x.Page.Message, CustomHTML: x.Page.HTML != "", Target: x.Page.Target, KeepPath: x.Page.KeepPath}
	}
	return p
}

type (
	trafficArgs struct {
		Site  string `json:"site,omitempty" jsonschema:"site slug (see list_sites); empty = every site"`
		Range string `json:"range,omitempty" jsonschema:"live | 1h | 24h | 7d | 90d (default live)"`
	}
	trafficOut struct {
		Site          string  `json:"site,omitempty"`
		Range         string  `json:"range"`
		Requests      uint64  `json:"requests"`
		PerSecond     float64 `json:"per_second,omitempty"`
		S2            uint64  `json:"status_2xx"`
		S3            uint64  `json:"status_3xx"`
		S4            uint64  `json:"status_4xx"`
		S5            uint64  `json:"status_5xx"`
		Blocked       uint64  `json:"blocked"`
		Challenged    uint64  `json:"challenged"`
		Queued        uint64  `json:"queued"`
		Banned        uint64  `json:"banned"`
		Paywalled     uint64  `json:"paywalled"`
		RateLimited   uint64  `json:"rate_limited"`
		P50, P95, P99 float64
		BytesOut      uint64 `json:"bytes_out"`
		ActiveBans    int    `json:"active_bans"`
		QueueActive   int    `json:"queue_active,omitempty"`
		QueueWaiting  int    `json:"queue_waiting,omitempty"`
		UnderAttack   bool   `json:"under_attack,omitempty"`
	}
	requestsArgs struct {
		Site    string `json:"site,omitempty"`
		Client  string `json:"client,omitempty"`
		Status  int    `json:"status,omitempty"`
		Outcome string `json:"outcome,omitempty" jsonschema:"pass | blocked | banned | challenged | queued | payment | ratelimited | unknown_host"`
		Path    string `json:"path,omitempty" jsonschema:"substring of the request path"`
		Errors  bool   `json:"errors_only,omitempty" jsonschema:"only requests whose upstream failed (502/504 diagnosis)"`
		Limit   int    `json:"limit,omitempty" jsonschema:"default 50, at most 500"`
	}
	banOut struct {
		Client    string `json:"client"`
		Site      string `json:"site,omitempty"`
		Source    string `json:"source"`
		Level     int    `json:"level"`
		Reason    string `json:"reason,omitempty"`
		Until     string `json:"until"`
		Active    bool   `json:"active"`
		CreatedBy string `json:"created_by,omitempty"`
	}
	destOut struct {
		ID        int64    `json:"id"`
		Name      string   `json:"name"`
		Kind      string   `json:"kind"`
		Events    []string `json:"events"`
		Enabled   bool     `json:"enabled"`
		LastError string   `json:"last_error,omitempty"`
	}
	checkOut struct {
		Address string `json:"address"`
		OK      bool   `json:"ok"`
		Stage   string `json:"failed_stage,omitempty"`
		Hint    string `json:"hint,omitempty"`
	}
)

func (s *Server) addGuardTools(srv *mcp.Server, ip string, ro *mcp.ToolAnnotations) {
	mcp.AddTool(srv, &mcp.Tool{Name: "get_traffic", Description: "Request counts, status classes, latency percentiles and protection counters for a site or every site over live, 1h, 24h, 7d or 90d, with active bans and queue state.", Annotations: ro},
		func(ctx context.Context, _ *mcp.CallToolRequest, in trafficArgs) (*mcp.CallToolResult, trafficOut, error) {
			sn := s.snapshotCtx(ctx, in.Site, in.Range)
			st := sn.Stats
			return nil, trafficOut{Site: in.Site, Range: sn.Range, Requests: st.Req, PerSecond: st.RPS, S2: st.S2, S3: st.S3, S4: st.S4, S5: st.S5,
				Blocked: st.Blocked, Challenged: st.Challenged, Queued: st.Queued, Banned: st.Banned, Paywalled: st.Paid, RateLimited: st.RateLimited,
				P50: st.P50, P95: st.P95, P99: st.P99, BytesOut: st.Bytes, ActiveBans: sn.Bans, QueueActive: sn.Queue.Active, QueueWaiting: sn.Queue.Waiting, UnderAttack: sn.UnderAttack}, nil
		})

	mcp.AddTool(srv, &mcp.Tool{Name: "list_requests", Description: "The newest requests from the request log (query strings are never stored), filtered by site, client, status, outcome or path.", Annotations: ro},
		func(ctx context.Context, _ *mcp.CallToolRequest, in requestsArgs) (*mcp.CallToolResult, struct {
			Requests []requestOut `json:"requests"`
		}, error) {
			var out struct {
				Requests []requestOut `json:"requests"`
			}
			if s.deps.Traffic == nil {
				return nil, out, fmt.Errorf("the request log is unavailable (traffic.db could not be opened)")
			}
			if in.Limit <= 0 || in.Limit > 500 {
				in.Limit = 50
			}
			rows, err := s.deps.Traffic.List(ctx, trafficdb.Filter{Site: in.Site, Client: in.Client, Status: in.Status, Outcome: in.Outcome, Path: in.Path, ErrOnly: in.Errors, Limit: in.Limit})
			for _, x := range rows {
				out.Requests = append(out.Requests, rowOut(x))
			}
			return nil, out, err
		})

	mcp.AddTool(srv, &mcp.Tool{Name: "list_bans", Description: "Bans of the last seven days: client, level, reason, until, whether still active.", Annotations: ro},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ noArgs) (*mcp.CallToolResult, struct {
			Bans []banOut `json:"bans"`
		}, error) {
			var out struct {
				Bans []banOut `json:"bans"`
			}
			now := time.Now().Unix()
			bs, err := s.deps.Store.ListBans(ctx, now-7*24*3600)
			for _, b := range bs {
				out.Bans = append(out.Bans, banOut{b.Client, b.SiteSlug, b.Source, b.Level, b.Reason, time.Unix(b.Until, 0).UTC().Format(time.RFC3339), b.Until > now, b.CreatedBy})
			}
			return nil, out, err
		})

	mcp.AddTool(srv, &mcp.Tool{Name: "create_ban", Description: "Ban an IP address or an IPv6 /64 for a number of hours. Audited as 'mcp token'."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in struct {
			Client string `json:"client" jsonschema:"IPv4 address or IPv6 /64, e.g. 203.0.113.5 or 2001:db8:1:2::/64"`
			Hours  int    `json:"hours" jsonschema:"1-8760"`
			Reason string `json:"reason,omitempty"`
		}) (*mcp.CallToolResult, banOut, error) {
			_, err := s.mcpRun(ctx, ip, s.createBan, "POST", "/bans", 0, url.Values{"client": {in.Client}, "hours": {strconv.Itoa(in.Hours)}, "reason": {in.Reason}})
			return nil, banOut{Client: in.Client, Source: "manual", Active: err == nil}, err
		})

	mcp.AddTool(srv, &mcp.Tool{Name: "delete_ban", Description: "Lift a ban and forget its escalation history (the client key as list_bans shows it)."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in struct {
			Client string `json:"client"`
		}) (*mcp.CallToolResult, banOut, error) {
			_, err := s.mcpRun(ctx, ip, s.deleteBan, "POST", "/bans/delete", 0, url.Values{"client": {in.Client}})
			return nil, banOut{Client: in.Client}, err
		})

	mcp.AddTool(srv, &mcp.Tool{Name: "set_under_attack", Description: "Switch a site's under-attack challenge: on (every visitor is challenged), off, or auto (needs the requests-per-second trigger set on the site)."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in struct {
			ID   int64  `json:"id"`
			Mode string `json:"mode" jsonschema:"on | off | auto"`
		}) (*mcp.CallToolResult, changed, error) {
			x, err := s.deps.Store.GetSite(ctx, in.ID)
			if err != nil {
				return nil, changed{}, fmt.Errorf("site %d not found", in.ID)
			}
			warn, err := s.mcpRun(ctx, ip, s.setUnderAttack, "POST", "/sites/"+strconv.FormatInt(in.ID, 10)+"/underattack", in.ID, url.Values{"mode": {in.Mode}})
			return nil, changed{ID: in.ID, Hostnames: x.Hostnames, Warnings: warn}, err
		})

	mcp.AddTool(srv, &mcp.Tool{Name: "set_queue_release", Description: "Emergency release: admit everyone to a site's waiting room for ten minutes."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in idArgs) (*mcp.CallToolResult, changed, error) {
			x, err := s.deps.Store.GetSite(ctx, in.ID)
			if err != nil {
				return nil, changed{}, fmt.Errorf("site %d not found", in.ID)
			}
			warn, err := s.mcpRun(ctx, ip, s.releaseQueue, "POST", "/sites/"+strconv.FormatInt(in.ID, 10)+"/queue/release", in.ID, nil)
			return nil, changed{ID: in.ID, Hostnames: x.Hostnames, Warnings: warn}, err
		})

	mcp.AddTool(srv, &mcp.Tool{Name: "list_alert_destinations", Description: "Alert destinations: name, kind, the events each hears, enabled, last delivery error. Addresses and secrets are never shown.", Annotations: ro},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ noArgs) (*mcp.CallToolResult, struct {
			Destinations []destOut `json:"destinations"`
		}, error) {
			var out struct {
				Destinations []destOut `json:"destinations"`
			}
			ds, err := s.deps.Store.ListAlertDests(ctx)
			for _, d := range ds {
				out.Destinations = append(out.Destinations, destOut{d.ID, d.Name, d.Kind, strings.Fields(d.Events), d.Enabled, d.LastError})
			}
			return nil, out, err
		})

	mcp.AddTool(srv, &mcp.Tool{Name: "create_alert_destination", Description: "Add an alert destination. kind ntfy | webhook | email | pushover | twilio; target is the address (webhook https URL, ntfy topic URL, email, Pushover user key, Twilio \"from,to\"); secret is the token, signing key, app token or \"SID:auth token\". events default to everything (Pushover and Twilio: under-attack and x402 only)."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in struct {
			Name   string   `json:"name"`
			Kind   string   `json:"kind"`
			Target string   `json:"target"`
			Secret string   `json:"secret,omitempty"`
			Events []string `json:"events,omitempty" jsonschema:"underattack ban queue backend x402 scan backup"`
		}) (*mcp.CallToolResult, destOut, error) {
			v := url.Values{"name": {in.Name}, "kind": {in.Kind}, "target": {in.Target}, "secret": {in.Secret}}
			for _, e := range in.Events {
				v.Add("event", e)
			}
			if _, err := s.mcpRun(ctx, ip, s.createAlertDest, "POST", "/alerts", 0, v); err != nil {
				return nil, destOut{}, err
			}
			ds, _ := s.deps.Store.ListAlertDests(ctx)
			for _, d := range ds {
				if d.Name == strings.TrimSpace(in.Name) {
					return nil, destOut{d.ID, d.Name, d.Kind, strings.Fields(d.Events), d.Enabled, d.LastError}, nil
				}
			}
			return nil, destOut{Name: in.Name}, nil
		})

	mcp.AddTool(srv, &mcp.Tool{Name: "delete_alert_destination", Description: "Delete an alert destination by id."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in idArgs) (*mcp.CallToolResult, idArgs, error) {
			_, err := s.mcpRun(ctx, ip, s.deleteAlertDest, "POST", "/alerts/"+strconv.FormatInt(in.ID, 10)+"/delete", in.ID, nil)
			return nil, in, err
		})

	mcp.AddTool(srv, &mcp.Tool{Name: "run_upstream_check", Description: "Test an upstream without saving anything: DNS lookup, TCP connection, then the TLS handshake for https. Names the failing stage and a fix hint.", Annotations: ro},
		func(ctx context.Context, _ *mcp.CallToolRequest, in struct {
			Address    string `json:"address" jsonschema:"host:port"`
			HTTPS      bool   `json:"https,omitempty"`
			SkipVerify bool   `json:"skip_verify,omitempty"`
		}) (*mcp.CallToolResult, checkOut, error) {
			stage, hint := CheckUpstream(ctx, in.Address, in.HTTPS, in.SkipVerify)
			return nil, checkOut{Address: in.Address, OK: stage == "", Stage: stage, Hint: hint}, nil
		})
}

// snapshotCtx is snapshot without an HTTP request: MCP has none.
func (s *Server) snapshotCtx(ctx context.Context, slug, rangeKey string) trafficSnap {
	return s.snapshot(ctx, slug, rangeKey)
}
