package web

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/servanago/servanago/internal/cfdns"
	"github.com/servanago/servanago/internal/config"
	"github.com/servanago/servanago/internal/store"
)

// mcp.go: the MCP endpoint (/mcp). One server-wide bearer token (SERVANAGO_MCP_TOKEN) gates it; with the
// token unset the endpoint does not exist. Write tools do not re-implement anything: they build the form the
// UI would post and run the UI's own handlers in process, so validation, the apply path, runtime setup and
// auditing are the UI's. The audit actor is mcpActor.

// mcpActor is not a valid username, so an MCP change cannot be mistaken for an administrator's.
var mcpActor = store.User{Username: "mcp token"}

// mcpHandler serves Streamable HTTP in stateless mode: every POST stands alone, which is all a bridge or an
// agent needs and keeps no per-session state to leak or expire.
func (s *Server) mcpHandler() http.Handler {
	token := sha256.Sum256([]byte(s.deps.Cfg.MCPToken))
	h := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server { return s.mcpServer(clientIP(r)) },
		// The SDK's localhost guard refuses a non-local Host from a loopback peer, which is every request via Caddy.
		// The bearer token covers what it protects against: a rebinding page cannot send it.
		&mcp.StreamableHTTPOptions{Stateless: true, DisableLocalhostProtection: true})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Public = through Caddy (it always sets X-Forwarded-For) or from a non-loopback peer. The stdio relay
		// calls the loopback listener directly, so it passes without the flag.
		public := !loopbackPeer(r) || r.Header.Get("X-Forwarded-For") != ""
		// The allowlist is checked before the token, so a caller outside it learns nothing and spends no throttle.
		if s.deps.Cfg.MCPToken == "" || (public && (!s.deps.Cfg.MCPPublic || !s.deps.Cfg.MCPAllowed(clientIP(r)))) {
			http.NotFound(w, r)
			return
		}
		got := sha256.Sum256([]byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")))
		if subtle.ConstantTimeCompare(got[:], token[:]) != 1 {
			if !s.auth.attempt(clientIP(r)) { // the login throttle: a wrong token spends one of the IP's attempts
				http.Error(w, "too many attempts", http.StatusTooManyRequests)
				return
			}
			w.Header().Set("WWW-Authenticate", `Bearer realm="servanago"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// siteArgs are the site fields a client may set; the names are the form's. Anything left out keeps its stored
// value on update and its default on create. Access controls (gate, basic auth, upload limit) are not
// settable here and are preserved.
type siteArgs struct {
	Kind          string    `json:"kind,omitempty" jsonschema:"proxy | static | node | php | frankenphp | fastcgi | cgi"`
	Hostnames     []string  `json:"hostnames,omitempty" jsonschema:"the first is the main address"`
	StaticRoot    string    `json:"static_root,omitempty" jsonschema:"absolute folder (static, node, php, frankenphp, fastcgi, cgi)"`
	Scheme        string    `json:"scheme,omitempty" jsonschema:"proxy: http or https"`
	UpstreamHost  string    `json:"upstream_host,omitempty" jsonschema:"proxy: IP or hostname"`
	UpstreamPort  int       `json:"upstream_port,omitempty" jsonschema:"proxy: port"`
	Port          int       `json:"port,omitempty" jsonschema:"node and frankenphp: loopback port, 1024-65535"`
	StartCommand  string    `json:"start_command,omitempty" jsonschema:"node: command systemd runs as the site user"`
	InstallCmd    string    `json:"install_command,omitempty" jsonschema:"node: shown to the admin, never run"`
	BuildCmd      string    `json:"build_command,omitempty" jsonschema:"node: shown to the admin, never run"`
	FPMVersion    string    `json:"fpm_version,omitempty" jsonschema:"php: a detected php-fpm version such as 8.2"`
	FCGIAddr      string    `json:"fcgi_addr,omitempty" jsonschema:"fastcgi: absolute socket path or host:port"`
	Allowlist     string    `json:"allowlist,omitempty" jsonschema:"CIDR ranges or IPs, one per line; empty keeps the stored list"`
	Enabled       *bool     `json:"enabled,omitempty" jsonschema:"default true on create; unchanged on update when left out"`
	RecordIP      string    `json:"record_ip,omitempty" jsonschema:"IPv4 for this site's DNS record; empty = domain default"`
	RecordIPv6    string    `json:"record_ip6,omitempty"`
	TLSSkipVerify *bool     `json:"tls_skip_verify,omitempty" jsonschema:"proxy: skip verifying a self-signed https upstream"`
	Snippets      *[]string `json:"snippets,omitempty" jsonschema:"names of the snippets to attach (see list_snippets); [] detaches all, leaving it out keeps the stored ones"`
	ExtraRoutes   *string   `json:"extra_routes,omitempty" jsonschema:"paths sent to another app, one per line as path=dial (dial = host:port or absolute socket path), e.g. /api=127.0.0.1:3303; \"\" clears them, leaving it out keeps the stored ones"`
	Notes         *string   `json:"notes,omitempty" jsonschema:"admin notes shown on the Reference page, plain text, at most 10,000 characters; \"\" clears them, leaving it out keeps the stored ones"`
}

// overlay writes the fields the client set over v.
func (a siteArgs) overlay(v url.Values) {
	str := func(k, val string) {
		if val != "" {
			v.Set(k, val)
		}
	}
	num := func(k string, n int) {
		if n != 0 {
			v.Set(k, strconv.Itoa(n))
		}
	}
	flag := func(k string, b *bool) {
		switch {
		case b == nil:
		case *b:
			v.Set(k, "on")
		default:
			v.Del(k)
		}
	}
	str("kind", a.Kind)
	if len(a.Hostnames) > 0 {
		v.Set("hostnames", strings.Join(a.Hostnames, "\n"))
	}
	str("static_root", a.StaticRoot)
	str("scheme", a.Scheme)
	str("upstream_host", a.UpstreamHost)
	num("upstream_port", a.UpstreamPort)
	num("port", a.Port)
	str("start_command", a.StartCommand)
	str("install_command", a.InstallCmd)
	str("build_command", a.BuildCmd)
	str("fpm_version", a.FPMVersion)
	str("fcgi_addr", a.FCGIAddr)
	str("allowlist", a.Allowlist)
	str("record_ip", a.RecordIP)
	str("record_ip6", a.RecordIPv6)
	flag("enabled", a.Enabled)
	flag("tls_skip_verify", a.TLSSkipVerify)
	if a.Snippets != nil {
		v["snippets"] = *a.Snippets
	}
	if a.ExtraRoutes != nil {
		v.Set("extra_routes", *a.ExtraRoutes)
	}
	if a.Notes != nil {
		v.Set("notes", *a.Notes)
	}
}

// formOf is the form the UI would post to save cur unchanged: update_site overlays the client's fields on it, so
// everything the client does not mention (gate, basic auth, limits) survives. The basic-auth password is never
// read back; a blank one keeps the stored hash.
func (s *Server) formOf(ctx context.Context, cur store.Site) url.Values {
	v := url.Values{}
	v.Set("kind", cur.Kind)
	v.Set("hostnames", strings.Join(cur.Hostnames, "\n"))
	v.Set("scheme", cur.Scheme)
	v.Set("static_root", cur.StaticRoot)
	v.Set("public_dir", cur.PublicDir)
	v.Set("start_command", cur.StartCommand)
	v.Set("install_command", cur.InstallCommand)
	v.Set("build_command", cur.BuildCommand)
	v.Set("fpm_version", cur.FPMVersion)
	v["php_ext"] = strings.Fields(cur.PHPExtensions)
	v["snippets"] = cur.Snippets
	v.Set("php_health_path", cur.PHPHealthPath)
	v.Set("notes", cur.Notes)
	v.Set("extra_routes", cur.ExtraRoutes)
	v.Set("allowlist", cur.Allowlist)
	v.Set("gate_mode", cur.GateMode)
	v.Set("gate_provider", cur.GateProvider) // the sealed secret is never read back; blank keeps it
	v.Set("gate_from", cur.GateFrom)
	v.Set("gate_smtp_host", cur.GateSMTPHost)
	v.Set("gate_smtp_port", strconv.Itoa(cur.GateSMTPPort))
	v.Set("gate_smtp_user", cur.GateSMTPUser)
	v.Set("basic_user", cur.BasicUser)
	v.Set("record_ip", cur.RecordIP)
	v.Set("record_ip6", cur.RecordIP6)
	if cur.MaxBody > 0 {
		v.Set("max_body", config.FormatSize(cur.MaxBody))
	}
	for k, on := range map[string]bool{"enabled": cur.Enabled, "stream": cur.Stream, "tls_skip_verify": cur.TLSSkipVerify} {
		if on {
			v.Set(k, "on")
		}
	}
	if cur.UpstreamPort != 0 {
		v.Set("upstream_port", strconv.Itoa(cur.UpstreamPort))
		v.Set("port", strconv.Itoa(cur.UpstreamPort))
	}
	switch cur.Kind {
	case "fastcgi":
		v.Set("fcgi_addr", cur.UpstreamHost)
		if cur.UpstreamPort != 0 {
			v.Set("fcgi_addr", net.JoinHostPort(cur.UpstreamHost, strconv.Itoa(cur.UpstreamPort)))
		}
	default:
		v.Set("upstream_host", cur.UpstreamHost)
	}
	if gs, err := s.deps.Store.Grants(ctx, cur.ID); err == nil {
		v.Set("gate_acl", gateACLText(gs))
	}
	return v
}

// mcpRun runs one of the UI's own handlers as the MCP actor and reports why it refused, if it did.
func (s *Server) mcpRun(ctx context.Context, ip string, h http.HandlerFunc, method, target string, id int64, form url.Values) (warnings []string, err error) {
	r := httptest.NewRequestWithContext(ctx, method, target, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = net.JoinHostPort(ip, "0")
	r.SetPathValue("id", strconv.FormatInt(id, 10))
	w := httptest.NewRecorder()
	h(w, withUser(r, mcpActor))
	return s.mcpAnswer(w)
}

// mcpRunPath is mcpRun for handlers whose route carries named segments other than {id}
// (the DNS record pages: {zid} before {rid}); leave a segment empty when the route has none.
func (s *Server) mcpRunPath(ctx context.Context, ip string, h http.HandlerFunc, method, target string, segs [][2]string, form url.Values) (warnings []string, err error) {
	r := httptest.NewRequestWithContext(ctx, method, target, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = net.JoinHostPort(ip, "0")
	for _, kv := range segs {
		r.SetPathValue(kv[0], kv[1])
	}
	w := httptest.NewRecorder()
	h(w, withUser(r, mcpActor))
	return s.mcpAnswer(w)
}

// mcpAnswer finishes an mcpRun: flashes are warnings, a non-2xx status is the error.
func (s *Server) mcpAnswer(w *httptest.ResponseRecorder) (warnings []string, err error) {
	warnings = s.takeFlashes() // runtime setup problems are notices, not errors: the site is saved either way
	if w.Code != http.StatusOK && w.Code != http.StatusNoContent {
		return warnings, fmt.Errorf("%d: %s", w.Code, strings.TrimSpace(w.Body.String()))
	}
	return warnings, nil
}

type siteView struct {
	ID           int64     `json:"id"`
	Slug         string    `json:"slug"`
	Kind         string    `json:"kind"`
	Hostnames    []string  `json:"hostnames"`
	Enabled      bool      `json:"enabled"`
	StaticRoot   string    `json:"static_root,omitempty"`
	Upstream     string    `json:"upstream,omitempty"`
	StartCommand string    `json:"start_command,omitempty"`
	FPMVersion   string    `json:"fpm_version,omitempty"`
	Allowlist    string    `json:"allowlist,omitempty"`
	GateMode     string    `json:"gate_mode,omitempty"`
	BasicAuth    bool      `json:"basic_auth"`
	Snippets     []string  `json:"snippets,omitempty"`
	Notes        string    `json:"notes,omitempty"`
	ExtraRoutes  string    `json:"extra_routes,omitempty"`
	RecordIP     string    `json:"record_ip,omitempty"`
	RecordIPv6   string    `json:"record_ip6,omitempty"`
	DNS          []dnsView `json:"dns,omitempty"`
	UpdatedAt    string    `json:"updated_at,omitempty"`
}

// dnsView is one DNS record's sync state: what the dashboard shows per hostname.
type dnsView struct {
	Hostname string `json:"hostname"`
	Family   string `json:"family"`
	State    string `json:"state"` // pending | synced | error | conflict
	Content  string `json:"content,omitempty"`
	Error    string `json:"error,omitempty"`
}

func dnsViewOf(x store.DNSRecord) dnsView {
	return dnsView{Hostname: x.Hostname, Family: x.Family, State: x.State, Content: x.Content, Error: x.Error}
}

// viewOf drops every secret: the basic-auth hash never leaves the process.
func viewOf(x store.Site) siteView {
	v := siteView{ID: x.ID, Slug: x.Slug, Kind: x.Kind, Hostnames: x.Hostnames, Enabled: x.Enabled, StaticRoot: x.StaticRoot,
		StartCommand: x.StartCommand, FPMVersion: x.FPMVersion, Allowlist: x.Allowlist, GateMode: x.GateMode, BasicAuth: x.BasicUser != "", Snippets: x.Snippets, Notes: x.Notes, ExtraRoutes: x.ExtraRoutes, RecordIP: x.RecordIP, RecordIPv6: x.RecordIP6, UpdatedAt: x.UpdatedAt}
	switch {
	case x.UpstreamPort != 0:
		v.Upstream = net.JoinHostPort(x.UpstreamHost, strconv.Itoa(x.UpstreamPort))
	default:
		v.Upstream = x.UpstreamHost
	}
	return v
}

type snippetView struct {
	Name   string   `json:"name"`
	Body   string   `json:"body"`
	UsedBy []string `json:"used_by,omitempty"`
}

type (
	noArgs struct{}
	idArgs struct {
		ID int64 `json:"id"`
	}
	changed struct {
		ID        int64    `json:"id"`
		Hostnames []string `json:"hostnames"`
		Warnings  []string `json:"warnings,omitempty"`
	}
	updateArgs struct {
		ID int64 `json:"id"`
		siteArgs
	}
	domainArgs struct {
		ID         int64  `json:"id"`
		DefaultIP  string `json:"default_ip,omitempty" jsonschema:"IPv4 for the domain's A records; left out = keep the stored one"`
		DefaultIP6 string `json:"default_ip6,omitempty" jsonschema:"left out = keep the stored one"`
		CertMode   string `json:"cert_mode,omitempty" jsonschema:"wildcard | per_host; left out = keep the stored one"`
	}
	domainNew struct {
		Name       string `json:"name" jsonschema:"the domain name (a Cloudflare zone)"`
		DefaultIP  string `json:"default_ip,omitempty" jsonschema:"IPv4 for the domain's A records; required with a Cloudflare token"`
		DefaultIP6 string `json:"default_ip6,omitempty"`
		CertMode   string `json:"cert_mode,omitempty" jsonschema:"wildcard | per_host; empty = wildcard with Cloudflare, per_host without"`
	}
	domainDone struct {
		Name string `json:"name"`
	}
	dnsDone struct {
		ID   int64     `json:"id"`
		Rows []dnsView `json:"rows,omitempty"`
	}
	dnsZoneArgs struct {
		Zone string `json:"zone" jsonschema:"zone id or name, from list_dns_zones"`
	}
	// SRV and CAA arrive as structured args and compose their content lines server-side.
	dnsSrvArgs struct {
		Priority int    `json:"priority,omitempty"`
		Weight   int    `json:"weight,omitempty"`
		Port     int    `json:"port,omitempty"`
		Target   string `json:"target,omitempty"`
	}
	dnsCaaArgs struct {
		Flags int    `json:"flags,omitempty" jsonschema:"0 or 128"`
		Tag   string `json:"tag,omitempty" jsonschema:"issue | issuewild | iodef"`
		Value string `json:"value,omitempty"`
	}
	dnsRecordArgs struct {
		Zone     string     `json:"zone" jsonschema:"zone id or name, from list_dns_zones"`
		ID       string     `json:"id,omitempty" jsonschema:"record id, for update and delete"`
		Type     string     `json:"type,omitempty" jsonschema:"A, AAAA, CNAME, TXT, MX, SRV, CAA or NS (create required, update fixed)"`
		Name     string     `json:"name,omitempty" jsonschema:"zone-relative: www, _dmarc, *.static; @ for the zone apex"`
		Content  string     `json:"content,omitempty" jsonschema:"address for A/AAAA, hostname for CNAME/NS/MX, text for TXT; SRV/CAA compose their content lines instead"`
		TTL      int        `json:"ttl,omitempty" jsonschema:"seconds; blank or 1 = Auto"`
		Proxied  *bool      `json:"proxied,omitempty" jsonschema:"only for A, AAAA and CNAME"`
		Comment  string     `json:"comment,omitempty"`
		Priority *int       `json:"priority,omitempty" jsonschema:"MX priority 0-65535"`
		Srv      dnsSrvArgs `json:"srv,omitempty"`
		Caa      dnsCaaArgs `json:"caa,omitempty"`
	}
	dnsRecordDone struct {
		Zone string `json:"zone"`
		Type string `json:"type,omitempty"`
		Name string `json:"name,omitempty"`
	}
)

func (s *Server) mcpServer(ip string) *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{Name: "servanago", Version: "v1"}, nil)
	ro := &mcp.ToolAnnotations{ReadOnlyHint: true}
	site := func(ctx context.Context, id int64) (store.Site, error) {
		x, err := s.deps.Store.GetSite(ctx, id)
		if err != nil {
			return x, fmt.Errorf("site %d not found", id)
		}
		return x, nil
	}

	mcp.AddTool(srv, &mcp.Tool{Name: "list_sites", Description: "List every site: kind, hostnames, enabled, folder and upstream. No secrets.", Annotations: ro},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ noArgs) (*mcp.CallToolResult, struct {
			Sites []siteView `json:"sites"`
		}, error) {
			var out struct {
				Sites []siteView `json:"sites"`
			}
			rs, err := s.deps.Store.ListSites(ctx)
			for _, x := range rs {
				out.Sites = append(out.Sites, viewOf(x))
			}
			return nil, out, err
		})

	mcp.AddTool(srv, &mcp.Tool{Name: "get_site", Description: "One site by id, including its record IPs and DNS rows.", Annotations: ro},
		func(ctx context.Context, _ *mcp.CallToolRequest, in idArgs) (*mcp.CallToolResult, siteView, error) {
			x, err := site(ctx, in.ID)
			if err != nil {
				return nil, siteView{}, err
			}
			v := viewOf(x)
			rows, rerr := s.deps.Store.ListSiteDNS(ctx, in.ID)
			println("DBG get_site rows:", fmt.Sprint(rows))
			for _, r := range rows {
				v.DNS = append(v.DNS, dnsViewOf(r))
			}
			return nil, v, errors.Join(err, rerr)
		})

	mcp.AddTool(srv, &mcp.Tool{Name: "list_domains", Description: "Managed domains (Cloudflare zones) and their certificate mode.", Annotations: ro},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ noArgs) (*mcp.CallToolResult, struct {
			Domains []map[string]string `json:"domains"`
		}, error) {
			var out struct {
				Domains []map[string]string `json:"domains"`
			}
			ds, err := s.deps.Store.ListDomains(ctx)
			for _, d := range ds {
				out.Domains = append(out.Domains, map[string]string{"id": strconv.FormatInt(d.ID, 10), "name": d.Name, "default_ip": d.DefaultIP, "default_ip6": d.DefaultIP6, "cert_mode": d.CertMode})
			}
			return nil, out, err
		})

	// The domain tools run the UI's own add/edit handlers; update_domain changes no record, so resync_dns (or take_dns) converges the sites.
	mcp.AddTool(srv, &mcp.Tool{Name: "create_domain", Description: "Add a domain (a Cloudflare zone): name, default record IPs and certificate mode. The zone must be visible to the Cloudflare token; wildcard certificates need Cloudflare. Audited as 'mcp token'."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in domainNew) (*mcp.CallToolResult, domainDone, error) {
			v := url.Values{"name": {in.Name}}
			if in.DefaultIP != "" {
				v.Set("default_ip", in.DefaultIP)
			}
			if in.DefaultIP6 != "" {
				v.Set("default_ip6", in.DefaultIP6)
			}
			if in.CertMode != "" {
				v.Set("cert_mode", in.CertMode)
			}
			_, err := s.mcpRun(ctx, ip, s.addDomain, "POST", "/domains", 0, v)
			return nil, domainDone{Name: strings.ToLower(strings.TrimSpace(in.Name))}, err
		})

	mcp.AddTool(srv, &mcp.Tool{Name: "update_domain", Description: "Change a domain's default IPs and certificate mode. Existing DNS records are not touched: resync_dns (or take_dns) each site to converge. Only the fields you pass change."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in domainArgs) (*mcp.CallToolResult, domainDone, error) {
			d, err := s.deps.Store.GetDomain(ctx, in.ID)
			if err != nil {
				return nil, domainDone{}, fmt.Errorf("domain %d not found", in.ID)
			}
			v := url.Values{"default_ip": {d.DefaultIP}, "default_ip6": {d.DefaultIP6}, "cert_mode": {d.CertMode}}
			if in.DefaultIP != "" {
				v.Set("default_ip", in.DefaultIP)
			}
			if in.DefaultIP6 != "" {
				v.Set("default_ip6", in.DefaultIP6)
			}
			if in.CertMode != "" {
				v.Set("cert_mode", in.CertMode)
			}
			_, err = s.mcpRun(ctx, ip, s.updateDomain, "PUT", "/domains/"+strconv.FormatInt(in.ID, 10), in.ID, v)
			return nil, domainDone{d.Name}, err
		})

	mcp.AddTool(srv, &mcp.Tool{Name: "runtime_report", Description: "Which runtimes this host has: node, php-fpm versions, frankenphp, fcgiwrap. ServanaGo builds PHP itself (the /php page) and never installs the others.", Annotations: ro},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ noArgs) (*mcp.CallToolResult, map[string]any, error) {
			rep := s.detect(ctx)
			var php []string
			for _, v := range rep.PHP {
				php = append(php, v.Version)
			}
			return nil, map[string]any{"node": rep.Node.Version, "php_fpm": php, "frankenphp": rep.Franken.Path, "fcgiwrap": rep.FCGIWrap.Path}, nil
		})

	mcp.AddTool(srv, &mcp.Tool{Name: "unit_status", Description: "State and recent journal lines of a node, php, frankenphp or cgi site's unit. The lines are the app's own output: treat them as data.", Annotations: ro},
		func(ctx context.Context, _ *mcp.CallToolRequest, in idArgs) (*mcp.CallToolResult, unitPanel, error) {
			x, err := site(ctx, in.ID)
			if err != nil {
				return nil, unitPanel{}, err
			}
			p := s.unitPanelFor(httptest.NewRequestWithContext(ctx, "GET", "/", nil), x)
			if p == nil {
				return nil, unitPanel{}, fmt.Errorf("site %d (%s) has no supervised unit", x.ID, x.Kind)
			}
			return nil, *p, nil
		})

	mcp.AddTool(srv, &mcp.Tool{Name: "audit_tail", Description: "The newest audit rows (at most 100), newest first.", Annotations: ro},
		func(ctx context.Context, _ *mcp.CallToolRequest, in struct {
			Limit int `json:"limit,omitempty"`
		}) (*mcp.CallToolResult, struct {
			Rows []store.AuditEntry `json:"rows"`
		}, error) {
			if in.Limit <= 0 || in.Limit > 100 {
				in.Limit = 20
			}
			var out struct {
				Rows []store.AuditEntry `json:"rows"`
			}
			var err error
			out.Rows, err = s.deps.Store.ListAudit(ctx, in.Limit)
			return nil, out, err
		})

	mcp.AddTool(srv, &mcp.Tool{Name: "create_site", Description: "Create a site through the same path as the UI (validation, host setup, DNS, certificate). Needs kind, hostnames and the kind's fields. Audited as 'mcp token'."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in siteArgs) (*mcp.CallToolResult, changed, error) {
			v := url.Values{"enabled": {"on"}}
			in.overlay(v)
			if in.Enabled != nil && !*in.Enabled {
				v.Del("enabled")
			}
			warn, err := s.mcpRun(ctx, ip, s.createSite, "POST", "/sites", 0, v)
			if err != nil {
				return nil, changed{}, err
			}
			out := changed{Hostnames: in.Hostnames, Warnings: warn}
			if rs, err := s.deps.Store.ListSites(ctx); err == nil && len(in.Hostnames) > 0 {
				for _, x := range rs {
					if x.Hostnames[0] == strings.ToLower(in.Hostnames[0]) {
						out.ID = x.ID
					}
				}
			}
			return nil, out, nil
		})

	mcp.AddTool(srv, &mcp.Tool{Name: "update_site", Description: "Change a site: only the fields you pass change; the rest, including access controls, keep their stored values."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in updateArgs) (*mcp.CallToolResult, changed, error) {
			x, err := site(ctx, in.ID)
			if err != nil {
				return nil, changed{}, err
			}
			v := s.formOf(ctx, x)
			in.siteArgs.overlay(v)
			warn, err := s.mcpRun(ctx, ip, s.updateSite, "PUT", "/sites/"+strconv.FormatInt(in.ID, 10), in.ID, v)
			return nil, changed{ID: in.ID, Hostnames: strings.Fields(v.Get("hostnames")), Warnings: warn}, err
		})

	mcp.AddTool(srv, &mcp.Tool{Name: "set_site_enabled", Description: "Enable or disable a site (a supervised unit is started or stopped with it)."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in struct {
			ID      int64 `json:"id"`
			Enabled bool  `json:"enabled"`
		}) (*mcp.CallToolResult, changed, error) {
			x, err := site(ctx, in.ID)
			if err != nil || x.Enabled == in.Enabled { // already there: the toggle would flip it back
				return nil, changed{ID: in.ID, Hostnames: x.Hostnames}, err
			}
			warn, err := s.mcpRun(ctx, ip, s.toggleSite, "POST", "/sites/"+strconv.FormatInt(in.ID, 10)+"/toggle", in.ID, nil)
			return nil, changed{ID: in.ID, Hostnames: x.Hostnames, Warnings: warn}, err
		})

	mcp.AddTool(srv, &mcp.Tool{Name: "delete_site", Description: "Delete a site and tear down its unit and user. Its files are never touched. Its DNS record is kept unless delete_dns is true."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in struct {
			ID        int64 `json:"id"`
			DeleteDNS bool  `json:"delete_dns,omitempty"`
		}) (*mcp.CallToolResult, changed, error) {
			x, err := site(ctx, in.ID)
			if err != nil {
				return nil, changed{}, err
			}
			target := "/sites/" + strconv.FormatInt(in.ID, 10)
			if in.DeleteDNS {
				target += "?delete_dns=1" // DELETE bodies are not parsed as forms
			}
			warn, err := s.mcpRun(ctx, ip, s.deleteSite, "DELETE", target, in.ID, nil)
			return nil, changed{ID: in.ID, Hostnames: x.Hostnames, Warnings: warn}, err
		})

	// The site DNS tools are the dashboard's Retry and Take over buttons: the same handlers, with the
	// refreshed rows as the result. Both are no-ops on records that already match.
	dnsTool := func(name, path, desc string, h http.HandlerFunc) {
		mcp.AddTool(srv, &mcp.Tool{Name: name, Description: desc},
			func(ctx context.Context, _ *mcp.CallToolRequest, in idArgs) (*mcp.CallToolResult, dnsDone, error) {
				_, err := s.mcpRun(ctx, ip, h, "POST", "/sites/"+strconv.FormatInt(in.ID, 10)+"/dns/"+path, in.ID, nil)
				if err != nil {
					return nil, dnsDone{}, err
				}
				rows, rerr := s.deps.Store.ListSiteDNS(ctx, in.ID)
				out := dnsDone{ID: in.ID}
				for _, r := range rows {
					out.Rows = append(out.Rows, dnsViewOf(r))
				}
				return nil, out, rerr
			})
	}
	dnsTool("resync_dns", "resync",
		"Sync a site's DNS records: create missing, point owned ones at the wanted IP (record_ip, else the domain default), adopt matching ones. A conflicting record needs take_dns.", s.resyncDNS)
	dnsTool("take_dns", "takeover",
		"Take over a site's conflicting DNS records: overwrite them with the wanted IP (record_ip, else the domain default) and mark them managed. Idempotent on already-synced records.", s.takeOverDNS)

	// The DNS CRUD tools are the /dns pages over MCP: full independent record management in any
	// zone the token sees, not just the domains ServanaGo knows. They run the UI's own handlers,
	// so validation, audit and error bodies are exactly what the pages would answer.
	zoneRef := func(ctx context.Context, ref string) (cfdns.Zone, error) {
		zs, err := s.deps.CF.ListZones(ctx)
		if err != nil {
			return cfdns.Zone{}, err
		}
		for _, z := range zs {
			if z.ID == ref || strings.EqualFold(z.Name, ref) {
				return z, nil
			}
		}
		return cfdns.Zone{}, fmt.Errorf("no zone %q is visible to the Cloudflare token", ref)
	}
	type zoneView struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		Status string `json:"status"`
	}
	mcp.AddTool(srv, &mcp.Tool{Name: "list_dns_zones", Description: "Every Cloudflare zone the token can see: id, name, status. Records of any zone are manageable with the dns_record tools, not just managed domains.", Annotations: ro},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ noArgs) (*mcp.CallToolResult, struct {
			Zones []zoneView `json:"zones"`
		}, error) {
			var out struct {
				Zones []zoneView `json:"zones"`
			}
			zs, err := s.deps.CF.ListZones(ctx)
			for _, z := range zs {
				out.Zones = append(out.Zones, zoneView{ID: z.ID, Name: z.Name, Status: z.Status})
			}
			return nil, out, err
		})

	type dnsRecordView struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		Type     string `json:"type"`
		Content  string `json:"content"`
		TTL      int    `json:"ttl"`
		Proxied  bool   `json:"proxied"`
		Comment  string `json:"comment,omitempty"`
		Priority int    `json:"priority,omitempty"`
		Managed  bool   `json:"managed,omitempty"`
	}
	mcp.AddTool(srv, &mcp.Tool{Name: "list_dns_records", Description: "A zone's DNS records of every type (zone-relative name without the zone suffix possible in the type/name fields; SRV and CAA arrive as composed content lines). Marked managed when ServanaGo writes them itself.", Annotations: ro},
		func(ctx context.Context, _ *mcp.CallToolRequest, in dnsZoneArgs) (*mcp.CallToolResult, struct {
			Records []dnsRecordView `json:"records"`
		}, error) {
			z, err := zoneRef(ctx, in.Zone)
			var out struct {
				Records []dnsRecordView `json:"records"`
			}
			if err != nil {
				return nil, out, err
			}
			rs, err := s.deps.CF.ListRecords(ctx, z.ID)
			if err != nil {
				return nil, out, err
			}
			managed := s.managedCFIDs(ctx)
			for _, fr := range rs {
				out.Records = append(out.Records, dnsRecordView{ID: fr.ID, Name: fr.Name, Type: fr.Type, Content: fr.Content,
					TTL: fr.TTL, Proxied: fr.Proxied, Comment: fr.Comment, Priority: fr.Priority, Managed: managed[fr.ID]})
			}
			return nil, out, nil
		})

	// dnsRecordForm turns the tool's fields into the page form; unset fields stay blank.
	dnsRecordForm := func(in dnsRecordArgs) url.Values {
		v := url.Values{}
		set := func(k, s string) {
			if s != "" {
				v.Set(k, s)
			}
		}
		set("type", in.Type)
		set("name", in.Name)
		set("content", in.Content)
		set("comment", in.Comment)
		if in.TTL != 0 {
			v.Set("ttl", strconv.Itoa(in.TTL))
		}
		if in.Proxied != nil && *in.Proxied {
			v.Set("proxied", "on")
		}
		if in.Priority != nil {
			v.Set("priority", strconv.Itoa(*in.Priority))
		}
		if in.Srv.Priority != 0 {
			v.Set("srv_priority", strconv.Itoa(in.Srv.Priority))
		}
		if in.Srv.Weight != 0 {
			v.Set("srv_weight", strconv.Itoa(in.Srv.Weight))
		}
		if in.Srv.Port != 0 {
			v.Set("srv_port", strconv.Itoa(in.Srv.Port))
		}
		set("srv_target", in.Srv.Target)
		if in.Caa.Flags != 0 {
			v.Set("caa_flags", strconv.Itoa(in.Caa.Flags))
		}
		set("caa_tag", in.Caa.Tag)
		set("caa_value", in.Caa.Value)
		return v
	}
	mcp.AddTool(srv, &mcp.Tool{Name: "create_dns_record", Description: "Create a DNS record in a zone. Type, name required; content or the srv/caa args; ttl blank = Auto; proxied only for A, AAAA and CNAME; priority for MX. Audited as 'mcp token'."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in dnsRecordArgs) (*mcp.CallToolResult, dnsRecordDone, error) {
			z, err := zoneRef(ctx, in.Zone)
			if err != nil {
				return nil, dnsRecordDone{}, err
			}
			_, err = s.mcpRunPath(ctx, ip, s.dnsRecordCreate, "POST", "/dns/zones/"+z.ID+"/records", [][2]string{{"zid", z.ID}}, dnsRecordForm(in))
			return nil, dnsRecordDone{Zone: z.Name, Type: in.Type, Name: in.Name}, err
		})

	mcp.AddTool(srv, &mcp.Tool{Name: "update_dns_record", Description: "Change one DNS record: only the fields you pass change; the rest keeps its current value. The record id comes from list_dns_records."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in dnsRecordArgs) (*mcp.CallToolResult, dnsRecordDone, error) {
			z, err := zoneRef(ctx, in.Zone)
			if err != nil {
				return nil, dnsRecordDone{}, err
			}
			rs, err := s.deps.CF.ListRecords(ctx, z.ID)
			if err != nil {
				return nil, dnsRecordDone{}, err
			}
			v, name := url.Values{}, in.Name
			for _, fr := range rs {
				if fr.ID != in.ID {
					continue
				}
				row := recordRowOf(fr, nil)
				name = fr.Name
				v = url.Values{"type": {fr.Type}, "name": {fr.Name}, "content": {fr.Content}, "comment": {fr.Comment}}
				if fr.TTL > 1 {
					v.Set("ttl", strconv.Itoa(fr.TTL))
				}
				if fr.Proxied {
					v.Set("proxied", "on")
				}
				if fr.Priority != 0 {
					v.Set("priority", strconv.Itoa(fr.Priority))
				}
				if row.SRVPri != "" {
					v.Set("srv_priority", row.SRVPri)
					v.Set("srv_weight", row.SRVWeight)
					v.Set("srv_port", row.SRVPort)
					v.Set("srv_target", row.SRVTarget)
				}
				if row.CAATag != "" {
					v.Set("caa_flags", row.CAAFlags)
					v.Set("caa_tag", row.CAATag)
					v.Set("caa_value", row.CAAValue)
				}
			}
			if v.Get("type") == "" {
				return nil, dnsRecordDone{}, fmt.Errorf("no DNS record %q in zone %s", in.ID, z.Name)
			}
			overlay := dnsRecordForm(in)
			overlay.Del("type") // a record's type is fixed; change means delete + create
			for k := range overlay {
				v.Set(k, overlay.Get(k))
			}
			_, err = s.mcpRunPath(ctx, ip, s.dnsRecordUpdate, "PUT", "/dns/zones/"+z.ID+"/records/"+in.ID, [][2]string{{"zid", z.ID}, {"rid", in.ID}}, v)
			return nil, dnsRecordDone{Zone: z.Name, Type: in.Type, Name: name}, err
		})

	mcp.AddTool(srv, &mcp.Tool{Name: "delete_dns_record", Description: "Delete one DNS record by id (list_dns_records). A managed record re-appears at the next site save or startup."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in dnsRecordArgs) (*mcp.CallToolResult, dnsRecordDone, error) {
			z, err := zoneRef(ctx, in.Zone)
			if err != nil {
				return nil, dnsRecordDone{}, err
			}
			_, err = s.mcpRunPath(ctx, ip, s.dnsRecordDelete, "DELETE", "/dns/zones/"+z.ID+"/records/"+in.ID, [][2]string{{"zid", z.ID}, {"rid", in.ID}}, nil)
			return nil, dnsRecordDone{Zone: z.Name}, err
		})

	// The scan tools are the /scan pages over MCP: start a site scan (it runs detached) and read
	// the runs and hits, whose quarantine actions are the same buttons the pages show.
	type scanHitView struct {
		ID     int64  `json:"id"`
		Path   string `json:"path"`
		Virus  string `json:"virus"`
		Action string `json:"action"`
	}
	type scanRunView struct {
		ID         int64         `json:"id"`
		SiteID     int64         `json:"site_id"`
		Site       string        `json:"site"`
		Trigger    string        `json:"trigger"`
		State      string        `json:"state"`
		StartedAt  int64         `json:"started_at"`
		FinishedAt int64         `json:"finished_at,omitempty"`
		Files      int           `json:"files"`
		Skipped    int           `json:"skipped"`
		Error      string        `json:"error,omitempty"`
		Hits       []scanHitView `json:"hits,omitempty"`
	}
	mcp.AddTool(srv, &mcp.Tool{Name: "run_scan", Description: "Start a virus scan of a site's served folder against clamd. It runs in the background; list_scan reports it. Audited as 'mcp token'."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in idArgs) (*mcp.CallToolResult, struct {
			Site string `json:"site"`
		}, error) {
			x, err := site(ctx, in.ID)
			if err != nil {
				return nil, struct {
					Site string `json:"site"`
				}{}, err
			}
			if _, err := s.mcpRun(ctx, ip, s.startScanSite, "POST", "/scan/sites/"+strconv.FormatInt(in.ID, 10), in.ID, nil); err != nil {
				return nil, struct {
					Site string `json:"site"`
				}{}, err
			}
			return nil, struct {
				Site string `json:"site"`
			}{x.Hostnames[0]}, nil
		})
	mcp.AddTool(srv, &mcp.Tool{Name: "list_scan", Description: "Virus-scan runs, newest first (default 20; site: a site's, empty: every site's), each with its hits. Hit actions: quarantine_hit, restore_hit, ignore_hit.", Annotations: ro},
		func(ctx context.Context, _ *mcp.CallToolRequest, in struct {
			Site  int64 `json:"site,omitempty"`
			Limit int   `json:"limit,omitempty"`
		}) (*mcp.CallToolResult, struct {
			Runs []scanRunView `json:"runs"`
		}, error) {
			var out struct {
				Runs []scanRunView `json:"runs"`
			}
			if in.Limit <= 0 || in.Limit > 100 {
				in.Limit = 20
			}
			rs, err := s.deps.Store.ListScanRuns(ctx, in.Site, in.Limit)
			if err != nil {
				return nil, out, err
			}
			ids := make([]int64, len(rs))
			for i, r := range rs {
				ids[i] = r.ID
			}
			hitsMap, _ := s.deps.Store.ListRunsHits(ctx, ids)
			names := map[int64]string{}
			if st, err := s.deps.Store.ListSites(ctx); err == nil {
				for _, x := range st {
					names[x.ID] = x.Hostnames[0]
				}
			}
			for _, r := range rs {
				v := scanRunView{ID: r.ID, SiteID: r.SiteID, Site: names[r.SiteID], Trigger: r.Trigger, State: r.State,
					StartedAt: r.StartedAt, FinishedAt: r.FinishedAt, Files: r.Files, Skipped: r.Skipped, Error: r.Error}
				for _, h := range hitsMap[r.ID] {
					v.Hits = append(v.Hits, scanHitView{ID: h.ID, Path: h.Path, Virus: h.Virus, Action: h.Action})
				}
				out.Runs = append(out.Runs, v)
			}
			return nil, out, nil
		})
	hitTool := func(name, verb, desc string) {
		mcp.AddTool(srv, &mcp.Tool{Name: name, Description: desc},
			func(ctx context.Context, _ *mcp.CallToolRequest, in idArgs) (*mcp.CallToolResult, scanHitView, error) {
				if _, err := s.mcpRunPath(ctx, ip, s.scanHitAction, "POST", "/scan/hits/"+strconv.FormatInt(in.ID, 10)+"/"+verb,
					[][2]string{{"hid", strconv.FormatInt(in.ID, 10)}, {"do", verb}}, nil); err != nil {
					return nil, scanHitView{}, err
				}
				h, err := s.deps.Store.GetScanHit(ctx, in.ID)
				return nil, scanHitView{ID: h.ID, Path: h.Path, Virus: h.Virus, Action: h.Action}, err
			})
	}
	hitTool("quarantine_hit", "quarantine",
		"Move a hit's file into the quarantine (the scan page's Quarantine button). Only a file still in the site can move.")
	hitTool("restore_hit", "restore",
		"Move a quarantined file back to its site folder. Refused when the original path is occupied again.")
	hitTool("ignore_hit", "ignore",
		"Stop alarming about a quarantined file: it stays in the quarantine and future scans do not list it again as a decision to make.")

	mcp.AddTool(srv, &mcp.Tool{Name: "list_snippets", Description: "Caddyfile snippets sites can attach (update_site snippets): name, directives and the sites using each.", Annotations: ro},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ noArgs) (*mcp.CallToolResult, struct {
			Snippets []snippetView `json:"snippets"`
		}, error) {
			var out struct {
				Snippets []snippetView `json:"snippets"`
			}
			all, err := s.deps.Store.ListSnippets(ctx)
			for _, x := range all {
				users, uerr := s.deps.Store.SnippetUsers(ctx, x.ID)
				err = errors.Join(err, uerr)
				out.Snippets = append(out.Snippets, snippetView{Name: x.Name, Body: x.Body, UsedBy: users})
			}
			return nil, out, err
		})

	// snippet runs a snippet handler for the named snippet (create passes id 0).
	snippet := func(ctx context.Context, h http.HandlerFunc, method, name, body string) error {
		var id int64
		if method != "POST" {
			all, err := s.deps.Store.ListSnippets(ctx)
			if err != nil {
				return err
			}
			for _, x := range all {
				if x.Name == name {
					id = x.ID
				}
			}
			if id == 0 {
				return fmt.Errorf("snippet %q not found", name)
			}
		}
		_, err := s.mcpRun(ctx, ip, h, method, "/snippets", id, url.Values{"name": {name}, "body": {body}})
		return err
	}
	type snippetArgs struct {
		Name string `json:"name" jsonschema:"lowercase letters, digits, _ and -"`
		Body string `json:"body" jsonschema:"Caddyfile directives: named matchers with respond, error, redir, header, request_header, request_body, encode"`
	}
	type snippetDone struct {
		Name string `json:"name"`
	}
	mcp.AddTool(srv, &mcp.Tool{Name: "create_snippet", Description: "Add a snippet. Directives that serve, proxy or authenticate are refused."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in snippetArgs) (*mcp.CallToolResult, snippetDone, error) {
			return nil, snippetDone{in.Name}, snippet(ctx, s.addSnippet, "POST", in.Name, in.Body)
		})
	mcp.AddTool(srv, &mcp.Tool{Name: "update_snippet", Description: "Replace a snippet's directives; every site that uses it picks the change up at once."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in snippetArgs) (*mcp.CallToolResult, snippetDone, error) {
			return nil, snippetDone{in.Name}, snippet(ctx, s.updateSnippet, "PUT", in.Name, in.Body)
		})
	mcp.AddTool(srv, &mcp.Tool{Name: "delete_snippet", Description: "Delete a snippet that no site uses."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in struct {
			Name string `json:"name"`
		}) (*mcp.CallToolResult, snippetDone, error) {
			return nil, snippetDone{in.Name}, snippet(ctx, s.deleteSnippet, "DELETE", in.Name, "")
		})
	s.addBackupTools(srv, ip, ro)
	return srv
}
