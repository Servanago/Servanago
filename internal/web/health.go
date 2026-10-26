package web

import (
	"fmt"

	"github.com/servanago/servanago/internal/probe"
)

// health is the one status a dashboard row shows. Level is off, wait, ok, warn or bad.
type health struct{ Level, Label string }

// Health rolls the certificate, DNS, upstream and container states up to the worst problem, so a row needs one status.
func (r siteRow) Health() health {
	dns := r.DNSState()
	switch {
	case !r.Enabled:
		return health{"off", "Disabled"}
	case !r.Probed:
		return health{"wait", "Checking"}
	case r.Cert.State == probe.StateError:
		return health{"bad", "Certificate error"}
	case dns == "error":
		return health{"bad", "DNS error"}
	case r.Upstream == "down":
		return health{"bad", "Upstream down"}
	case r.DockerBad():
		return health{"bad", "Container down"}
	case dns == "conflict":
		return health{"warn", "DNS conflict"}
	case r.Cert.State == probe.StatePending:
		return health{"warn", "Waiting for certificate"}
	case dns == "pending":
		return health{"warn", "Waiting for DNS"}
	case r.CertSoon:
		return health{"warn", "Certificate expiring"}
	}
	return health{"ok", "Healthy"}
}

// KindLabel is the site type as the dashboard names it.
func (r siteRow) KindLabel() string {
	switch r.Kind {
	case "static":
		return "Static"
	case "node":
		return "Node.js"
	case "php":
		return "PHP"
	case "frankenphp":
		return "FrankenPHP"
	case "fastcgi":
		return "FastCGI"
	case "cgi":
		return "CGI"
	}
	return "Proxy"
}

// Target is where the site's content comes from: the upstream address, or the folder for sites Caddy serves itself.
func (r siteRow) Target() string {
	if r.HasUpstream() && r.UpstreamHost != "" {
		return fmt.Sprintf("%s:%d", r.UpstreamHost, r.UpstreamPort)
	}
	if root := r.WebRoot(); root != "" {
		return root
	}
	if r.UpstreamPort == 0 { // a fastcgi socket path
		return r.UpstreamHost
	}
	return fmt.Sprintf("%s:%d", r.UpstreamHost, r.UpstreamPort)
}

// needsAttention are the rows whose health is warn or bad, in list order.
func needsAttention(rows []siteRow) []siteRow {
	var out []siteRow
	for _, r := range rows {
		if l := r.Health().Level; l == "warn" || l == "bad" {
			out = append(out, r)
		}
	}
	return out
}
