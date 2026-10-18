package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
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
