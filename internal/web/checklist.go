package web

import (
	"context"
	"html"
	"html/template"

	"github.com/servanago/servanago/internal/probe"
)

// checkItem is one line of the first-run checklist on the dashboard.
type checkItem struct {
	Label  string
	State  string        // ok | todo | bad
	Detail template.HTML // what is happening or what to do; already escaped
	Help   string        // /help section for the ? link
}

// checklist reports whether the basics work: token, the UI address (DNS + certificate), a first site.
// host is nil when SERVANAGO_HOST_IP is not configured, which hides the UI-address items.
func (s *Server) checklist(ctx context.Context, routes []routeRow, host *hostCard) []checkItem {
	items := []checkItem{s.tokenItem()}
	if host != nil {
		items = append(items, hostDNSItem(host), s.hostCertItem(ctx))
	}
	first := checkItem{Label: "Add your first site", State: "ok", Help: "sites"}
	if len(routes) == 0 {
		first.State = "todo"
		first.Detail = template.HTML(html.EscapeString("Click Add site, then enter the hostname (oc.example.com) and where the app runs: its IP address and its own port."))
	}
	return append(items, first)
}

func (s *Server) tokenItem() checkItem {
	it := checkItem{Label: "Cloudflare token works", Help: "token"}
	switch v, ok := s.cfErr.Load().(string); {
	case !ok:
		it.State, it.Detail = "todo", "Checking..."
	case v == "":
		it.State = "ok"
	default:
		it.State, it.Detail = "bad", template.HTML(errorHTML(v))
	}
	return it
}

func hostDNSItem(h *hostCard) checkItem {
	it := checkItem{Label: "UI address has its DNS record", Help: "statuses"}
	switch h.DNS.State {
	case "synced":
		it.State = "ok"
	case "conflict":
		it.State, it.Detail = "bad", template.HTML(html.EscapeString(statusHelp["dns:conflict"].Next))
	case "error":
		it.State, it.Detail = "bad", template.HTML(errorHTML(h.DNS.Error))
	default:
		it.State, it.Detail = "todo", "Syncing..."
	}
	return it
}

func (s *Server) hostCertItem(ctx context.Context) checkItem {
	it := checkItem{Label: "UI address has a valid certificate", Help: "certificates"}
	if s.deps.Probe == nil {
		it.State = "todo"
		return it
	}
	switch c := s.deps.Probe.Cert(ctx, s.deps.Cfg.Host); c.State {
	case probe.StateIssued:
		it.State = "ok"
	case probe.StateError:
		it.State, it.Detail = "bad", template.HTML(errorHTML(c.Err))
	default:
		it.State = "todo"
		it.Detail = template.HTML(html.EscapeString(certWait(s.deps.Cfg.PropagationDelay, s.deps.Cfg.PropagationTimeout)))
	}
	return it
}

func setupDone(items []checkItem) bool {
	for _, it := range items {
		if it.State != "ok" {
			return false
		}
	}
	return true
}
