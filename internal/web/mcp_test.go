package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/servanago/servanago/internal/config"
	"github.com/servanago/servanago/internal/store"
)

const mcpToken = "0123456789abcdef0123456789abcdef"

type bearer struct{ token string }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	if b.token != "" {
		r.Header.Set("Authorization", "Bearer "+b.token)
	}
	return http.DefaultTransport.RoundTrip(r)
}

// mcpSession serves the full handler tree over HTTP and connects an MCP client with the given token.
func mcpSession(t *testing.T, s *Server, token string) *mcp.ClientSession {
	t.Helper()
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	c := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "v1"}, nil)
	sess, err := c.Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: ts.URL + "/mcp", HTTPClient: &http.Client{Transport: bearer{token}}}, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })
	return sess
}

// call runs a tool and decodes its structured result into out (nil to ignore); a tool error comes back as err.
func call(t *testing.T, sess *mcp.ClientSession, name string, args map[string]any, out any) error {
	t.Helper()
	res, err := sess.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		return err
	}
	if res.IsError {
		msg := ""
		for _, c := range res.Content {
			if tc, ok := c.(*mcp.TextContent); ok {
				msg += tc.Text
			}
		}
		return &toolError{msg}
	}
	if out != nil {
		b, _ := json.Marshal(res.StructuredContent)
		if err := json.Unmarshal(b, out); err != nil {
			t.Fatalf("%s result %s: %v", name, b, err)
		}
	}
	return nil
}

type toolError struct{ s string }

func (e *toolError) Error() string { return e.s }

func TestMCPEndpointAuth(t *testing.T) {
	s, _ := runtimeServer(t)
	post := func(auth string) int {
		r := httptest.NewRequest("POST", "/mcp", strings.NewReader(`{}`))
		r.RemoteAddr = "127.0.0.1:5555" // the local relay; public callers are TestMCPPublicIsOptIn's
		if auth != "" {
			r.Header.Set("Authorization", auth)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w.Code
	}
	if c := post("Bearer " + mcpToken); c != 404 { // no token configured: the endpoint does not exist
		t.Fatalf("disabled endpoint answered %d", c)
	}
	s.deps.Cfg.MCPToken = mcpToken
	if c := post(""); c != 401 {
		t.Errorf("no token: %d", c)
	}
	if c := post("Bearer wrong"); c != 401 {
		t.Errorf("wrong token: %d", c)
	}
	if c := post("Basic " + mcpToken); c != 401 {
		t.Errorf("wrong scheme: %d", c)
	}
	for i := 0; i < 8; i++ { // the login throttle applies to wrong tokens
		post("Bearer wrong")
	}
	if c := post("Bearer wrong"); c != 429 {
		t.Errorf("guessing was not throttled: %d", c)
	}
}

func TestMCPSiteLifecycle(t *testing.T) {
	s, _ := runtimeServer(t)
	s.deps.Cfg.MCPToken = mcpToken
	sess := mcpSession(t, s, mcpToken)
	root := t.TempDir()

	tools, err := sess.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, tl := range tools.Tools {
		have[tl.Name] = true
	}
	for _, want := range []string{"list_sites", "get_site", "list_domains", "runtime_report", "unit_status", "audit_tail", "create_site", "update_site", "set_site_enabled", "delete_site"} {
		if !have[want] {
			t.Errorf("tool %s missing (have %v)", want, have)
		}
	}

	// A site made in the UI with access controls: an MCP edit must not drop them.
	f := form("kind", "proxy", "scheme", "http", "upstream_host", "192.168.1.20", "upstream_port", "9200", "hostnames", "guarded.example.com",
		"allowlist", "10.0.0.0/8", "basic_user", "bob", "basic_password", "secret", "stream", "on", "max_body", "5MB", "enabled", "on")
	if w := s.do(req{method: "POST", path: "/sites", body: f.Encode(), hdr: htmxPost}); w.Code != 204 {
		t.Fatalf("ui create: %d %q", w.Code, w.Body.String())
	}
	guarded, _ := s.deps.Store.ListSites(context.Background())
	id := guarded[0].ID
	if err := call(t, sess, "update_site", map[string]any{"id": id, "upstream_port": 9300}, nil); err != nil {
		t.Fatalf("update_site: %v", err)
	}
	got, _ := s.deps.Store.GetSite(context.Background(), id)
	if got.UpstreamPort != 9300 || got.UpstreamHost != "192.168.1.20" || got.Allowlist != "10.0.0.0/8" || got.BasicUser != "bob" || got.BasicHash != guarded[0].BasicHash || !got.Stream || got.MaxBody != 5<<20 || !got.Enabled {
		t.Fatalf("update dropped stored settings:\nbefore %+v\nafter  %+v", guarded[0], got)
	}

	// create, read back, disable, delete.
	var made changed
	if err := call(t, sess, "create_site", map[string]any{"kind": "static", "static_root": root, "hostnames": []string{"new.example.com"}}, &made); err != nil || made.ID == 0 {
		t.Fatalf("create_site: %+v %v", made, err)
	}
	var list struct{ Sites []siteView }
	if err := call(t, sess, "list_sites", nil, &list); err != nil || len(list.Sites) != 2 {
		t.Fatalf("list_sites: %+v %v", list, err)
	}
	if err := call(t, sess, "set_site_enabled", map[string]any{"id": made.ID, "enabled": false}, nil); err != nil {
		t.Fatal(err)
	}
	if err := call(t, sess, "set_site_enabled", map[string]any{"id": made.ID, "enabled": false}, nil); err != nil { // already off: must not flip back on
		t.Fatal(err)
	}
	if x, _ := s.deps.Store.GetSite(context.Background(), made.ID); x.Enabled {
		t.Errorf("site is enabled after set_site_enabled false twice")
	}
	if err := call(t, sess, "delete_site", map[string]any{"id": made.ID}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.deps.Store.GetSite(context.Background(), made.ID); err == nil {
		t.Errorf("site survived delete_site")
	}

	// Changes are audited as the token, and no secret is readable.
	rows, _ := s.deps.Store.ListAudit(context.Background(), 20)
	seen := map[string]bool{}
	for _, r := range rows {
		if r.Actor == "mcp token" {
			seen[r.Action] = true
		}
	}
	for _, a := range []string{"site.updated", "site.created", "site.toggled", "site.deleted"} {
		if !seen[a] {
			t.Errorf("no %q audit row by 'mcp token': %+v", a, rows)
		}
	}
	res, err := sess.CallTool(context.Background(), &mcp.CallToolParams{Name: "get_site", Arguments: map[string]any{"id": id}})
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := json.Marshal(res); strings.Contains(string(b), "$2a$") || strings.Contains(string(b), got.BasicHash) {
		t.Errorf("get_site leaked the password hash: %s", b)
	}
}

func TestMCPToolErrors(t *testing.T) {
	s, host := runtimeServer(t)
	s.deps.Cfg.MCPToken = mcpToken
	sess := mcpSession(t, s, mcpToken)
	for name, args := range map[string]map[string]any{
		"bad kind":       {"kind": "ruby", "hostnames": []string{"a.example.com"}},
		"missing folder": {"kind": "static", "static_root": "/does/not/exist", "hostnames": []string{"a.example.com"}},
		"no hostnames":   {"kind": "static", "static_root": t.TempDir()},
	} {
		if err := call(t, sess, "create_site", args, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := call(t, sess, "get_site", map[string]any{"id": 999}, nil); err == nil {
		t.Error("unknown site id accepted")
	}
	if err := call(t, sess, "unit_status", map[string]any{"id": 999}, nil); err == nil {
		t.Error("unit_status of an unknown site accepted")
	}
	if rs, _ := s.deps.Store.ListSites(context.Background()); len(rs) != 0 || host.log() != "" {
		t.Errorf("refused calls left state: sites=%v helper=%q", rs, host.log())
	}
}

// A domain-less hostname (no zone in Cloudflare) still needs a possible host IP: the create path
// validates SERVANAGO_HOST_IP when Cloudflare is on. newDNSServer with that IP, plus the fake again.
func mcpDnsServer(t *testing.T) (*Server, *cfFake, store.Domain) {
	t.Helper()
	cf := &cfFake{zones: zonesOK}
	s := cfgServer(t, cf, config.Config{Host: "panel.example.com", HostIP: "203.0.113.10", HostIP6: "2001:db8::10"})
	d, err := s.deps.Store.CreateDomain(context.Background(), store.Domain{Name: "example.com", ZoneID: "zone123", DefaultIP: "10.0.0.1", CertMode: "wildcard"})
	if err != nil {
		t.Fatal(err)
	}
	return s, cf, d
}

// getSite decodes get_site into a fresh struct: unmarshalling into a reused
// one merges old field values in (encoding/json reuses existing slice
// elements), and every siteView field is omitempty.
func getSite(t *testing.T, sess *mcp.ClientSession, id int64) siteView {
	t.Helper()
	var out siteView
	if err := call(t, sess, "get_site", map[string]any{"id": id}, &out); err != nil {
		t.Fatalf("get_site %d: %v", id, err)
	}
	return out
}

// The DNS tools run the UI's own resync/takeover/domain handlers: a conflict
// is only solvable by take_dns, resync does not unsettle it, an update_domain
// changes no record, and a site whose record_ip is not mentioned keeps it.
func TestMCPDnsTools(t *testing.T) {
	s, cf, d := mcpDnsServer(t)
	s.deps.Cfg.MCPToken = mcpToken
	sess := mcpSession(t, s, mcpToken)

	tools, err := sess.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, tl := range tools.Tools {
		have[tl.Name] = true
	}
	for _, want := range []string{"take_dns", "resync_dns", "update_domain", "create_domain"} {
		if !have[want] {
			t.Errorf("tool %s missing (have %v)", want, have)
		}
	}

	x := addRoute(t, s, d) // syncs sonarr.example.com to 10.0.0.1
	v := getSite(t, sess, x.ID)
	if v.RecordIP != "" || v.RecordIPv6 != "" || len(v.DNS) != 1 ||
		v.DNS[0] != (dnsView{Hostname: "sonarr.example.com", Family: "A", State: "synced", Content: "10.0.0.1"}) {
		t.Fatalf("get_site DNS view wrong: %+v", v)
	}

	// record_ip works like the form's DNS record IP field, and survives an update that omits it.
	if err := call(t, sess, "update_site", map[string]any{"id": x.ID, "record_ip": "10.0.0.5"}, nil); err != nil {
		t.Fatalf("update_site record_ip: %v", err)
	}
	v = getSite(t, sess, x.ID)
	recs := cf.dns.Records()
	if v.RecordIP != "10.0.0.5" || len(recs) != 1 || recs[0].Content != "10.0.0.5" {
		t.Fatalf("record_ip not applied: %+v %v", v, recs)
	}
	if err := call(t, sess, "update_site", map[string]any{"id": x.ID, "notes": "kept"}, nil); err != nil {
		t.Fatalf("update_site notes: %v", err)
	}
	if v := getSite(t, sess, x.ID); v.RecordIP != "10.0.0.5" {
		t.Fatalf("update_site dropped record_ip: %+v", v)
	}

	// A Cloudflare record pointing elsewhere, unowned: conflict until take_dns.
	root := t.TempDir()
	cf.dns.Seed("tv.example.com", "9.9.9.9")
	var made changed
	if err := call(t, sess, "create_site", map[string]any{"kind": "static", "static_root": root, "hostnames": []string{"tv.example.com"}}, &made); err != nil {
		t.Fatalf("create_site: %v", err)
	}
	if v := getSite(t, sess, made.ID); len(v.DNS) != 1 || v.DNS[0].State != "conflict" || !strings.Contains(v.DNS[0].Error, "9.9.9.9") {
		t.Fatalf("conflict not visible: %+v", v)
	}
	if err := call(t, sess, "resync_dns", map[string]any{"id": made.ID}, nil); err != nil {
		t.Fatalf("resync_dns: %v", err)
	}
	if v := getSite(t, sess, made.ID); len(v.DNS) != 1 || v.DNS[0].State != "conflict" {
		t.Fatalf("resync must leave a conflict alone: %+v", v)
	}
	if err := call(t, sess, "take_dns", map[string]any{"id": made.ID}, nil); err != nil {
		t.Fatalf("take_dns: %v", err)
	}
	row, _ := s.deps.Store.GetDNS(context.Background(), "tv.example.com", store.FamilyA)
	cfContent := ""
	for _, rec := range cf.dns.Records() { // Records() is unordered (a map)
		if rec.Name == "tv.example.com" {
			cfContent = rec.Content
		}
	}
	if v := getSite(t, sess, made.ID); len(v.DNS) != 1 || v.DNS[0].State != "synced" || v.DNS[0].Content != "10.0.0.1" || !row.Owned || cfContent != "10.0.0.1" {
		t.Fatalf("takeover not applied: %+v %+v %q", v, row, cfContent)
	}

	// Idempotent: a second takeover rewrites nothing.
	before := cf.dns.Writes()
	if err := call(t, sess, "take_dns", map[string]any{"id": made.ID}, nil); err != nil {
		t.Fatalf("take_dns again: %v", err)
	}
	if cf.dns.Writes() != before {
		t.Errorf("idempotent takeover wrote DNS: %d -> %d", before, cf.dns.Writes())
	}

	// Refusals.
	if err := call(t, sess, "take_dns", map[string]any{"id": 999}, nil); err == nil {
		t.Error("take_dns accepted an unknown site")
	}
	if err := call(t, sess, "resync_dns", map[string]any{"id": 999}, nil); err == nil {
		t.Error("resync_dns accepted an unknown site")
	}

	// A hostname with no domain has no rows, and resync on it is a clean no-op.
	var solo changed
	if err := call(t, sess, "create_site", map[string]any{"kind": "static", "static_root": root, "hostnames": []string{"solo.example.org"}}, &solo); err != nil {
		t.Fatalf("create_site solo: %v", err)
	}
	if v := getSite(t, sess, solo.ID); len(v.DNS) != 0 {
		t.Errorf("domain-less hostnames grew DNS rows: %+v", v.DNS)
	}
	if err := call(t, sess, "resync_dns", map[string]any{"id": solo.ID}, nil); err != nil {
		t.Errorf("resync_dns on a domain-less site: %v", err)
	}

	rows, _ := s.deps.Store.ListAudit(context.Background(), 30)
	seen := map[string]bool{}
	for _, r := range rows {
		if r.Actor == "mcp token" {
			seen[r.Action] = true
		}
	}
	for _, a := range []string{"site.dns_taken_over", "site.dns_resynced"} {
		if !seen[a] {
			t.Errorf("no %q audit row by 'mcp token': %+v", a, rows)
		}
	}
}

// The domain tools run the UI's own add/update handlers. create completes the
// headless flow; update changes no record — resync_dns converges the sites.
func TestMCPDomainTools(t *testing.T) {
	cf := &cfFake{zones: zonesOK}
	s := cfgServer(t, cf, config.Config{})
	s.deps.Cfg.MCPToken = mcpToken
	sess := mcpSession(t, s, mcpToken)
	root := t.TempDir()

	var made domainDone
	if err := call(t, sess, "create_domain", map[string]any{"name": "Example.com", "default_ip": "203.0.113.1"}, &made); err != nil || made.Name != "example.com" {
		t.Fatalf("create_domain: %+v %v", made, err)
	}
	var list struct {
		Domains []map[string]string `json:"domains"`
	}
	if err := call(t, sess, "list_domains", nil, &list); err != nil || len(list.Domains) != 1 || list.Domains[0]["default_ip"] != "203.0.113.1" {
		t.Fatalf("list_domains: %+v %v", list, err)
	}

	var site changed
	if err := call(t, sess, "create_site", map[string]any{"kind": "static", "static_root": root, "hostnames": []string{"app.example.com"}}, &site); err != nil {
		t.Fatalf("create_site under the domain: %v", err)
	}
	if recs := cf.dns.Records(); len(recs) != 1 || recs[0].Content != "203.0.113.1" {
		t.Fatalf("site did not pick up the domain default: %+v", recs)
	}

	before := cf.dns.Writes() // Writes is cumulative; only the delta counts
	if err := call(t, sess, "update_domain", map[string]any{"id": 1, "default_ip": "203.0.113.9", "cert_mode": "per_host"}, nil); err != nil {
		t.Fatalf("update_domain: %v", err)
	}
	if err := call(t, sess, "list_domains", nil, &list); err != nil || list.Domains[0]["default_ip"] != "203.0.113.9" || list.Domains[0]["cert_mode"] != "per_host" {
		t.Fatalf("list_domains after update: %+v %v", list, err)
	}
	if cf.dns.Writes() != before {
		t.Errorf("update_domain wrote DNS records")
	}
	if recs := cf.dns.Records(); len(recs) != 1 || recs[0].Content != "203.0.113.1" {
		t.Fatalf("update_domain touched records: %+v", recs)
	}
	if err := call(t, sess, "resync_dns", map[string]any{"id": site.ID}, nil); err != nil {
		t.Fatalf("resync after update: %v", err)
	}
	if recs := cf.dns.Records(); len(recs) != 1 || recs[0].Content != "203.0.113.9" {
		t.Fatalf("resync did not converge to the new default: %+v", recs)
	}

	for name, args := range map[string]map[string]any{
		"unseeable zone": {"name": "elsewhere.example"},
		"unknown id":     {"id": 999},
		"bad ipv6":       {"id": 1, "default_ip6": "notanip"},
	} {
		if err := call(t, sess, map[string]string{"unseeable zone": "create_domain", "unknown id": "update_domain", "bad ipv6": "update_domain"}[name], args, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Caddy forwards from loopback with the public Host header: the SDK's localhost DNS-rebinding guard would
// refuse every real request. The bearer token already stops a rebinding page, which cannot send it.
func TestMCPAcceptsPublicHostBehindProxy(t *testing.T) {
	s, _ := runtimeServer(t)
	s.deps.Cfg.MCPToken = mcpToken
	ts := httptest.NewServer(s.Handler()) // the client connects from loopback, like Caddy
	t.Cleanup(ts.Close)
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`
	r, _ := http.NewRequest("POST", ts.URL+"/mcp", strings.NewReader(body))
	r.Host = "panel.example.com"
	r.Header.Set("Authorization", "Bearer "+mcpToken)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("public Host header refused: %d", resp.StatusCode)
	}
}

// Without SERVANAGO_MCP_PUBLIC, /mcp answers only a direct loopback caller (the stdio relay): a request that came
// through Caddy (X-Forwarded-For) or from a non-loopback peer gets the same 404 as a disabled endpoint, even with
// the right token.
func TestMCPPublicIsOptIn(t *testing.T) {
	s, _ := runtimeServer(t)
	s.deps.Cfg.MCPToken = mcpToken
	post := func(peer, xff string) int {
		r := httptest.NewRequest("POST", "/mcp", strings.NewReader(`{}`))
		r.RemoteAddr = peer
		r.Header.Set("Authorization", "Bearer "+mcpToken)
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w.Code
	}
	if c := post("127.0.0.1:5555", ""); c == 404 {
		t.Errorf("relay on loopback refused: %d", c)
	}
	for name, got := range map[string]int{
		"via caddy":        post("127.0.0.1:5555", "203.0.113.9"),
		"non-loopback":     post("203.0.113.9:5555", ""),
		"non-loopback+xff": post("203.0.113.9:5555", "198.51.100.1"),
	} {
		if got != 404 {
			t.Errorf("%s: %d, want 404", name, got)
		}
	}
	s.deps.Cfg.MCPPublic = true
	if c := post("127.0.0.1:5555", "203.0.113.9"); c == 404 {
		t.Errorf("via caddy with the flag on: %d", c)
	}
	if c := post("203.0.113.9:5555", ""); c == 404 {
		t.Errorf("non-loopback with the flag on: %d", c)
	}
}

// With the flag on, SERVANAGO_MCP_ALLOWLIST limits public callers by their real address (X-Forwarded-For via
// Caddy); others get 404 before the token is looked at, so guessing from outside the list spends no throttle.
func TestMCPAllowlistLimitsPublicCallers(t *testing.T) {
	s, _ := runtimeServer(t)
	s.deps.Cfg.MCPToken = mcpToken
	s.deps.Cfg.MCPPublic = true
	s.deps.Cfg.MCPAllowlist = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
	post := func(peer, xff string) int {
		r := httptest.NewRequest("POST", "/mcp", strings.NewReader(`{}`))
		r.RemoteAddr = peer
		r.Header.Set("Authorization", "Bearer "+mcpToken)
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w.Code
	}
	if c := post("127.0.0.1:5555", "203.0.113.9"); c == 404 {
		t.Errorf("listed address via caddy: %d", c)
	}
	if c := post("127.0.0.1:5555", "198.51.100.1"); c != 404 {
		t.Errorf("unlisted address via caddy: %d, want 404", c)
	}
	if c := post("198.51.100.1:5555", ""); c != 404 {
		t.Errorf("unlisted direct peer: %d, want 404", c)
	}
	if c := post("127.0.0.1:5555", ""); c == 404 { // the local relay is not a public caller
		t.Errorf("local relay refused: %d", c)
	}
}
