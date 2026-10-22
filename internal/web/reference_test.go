package web

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/servanago/servanago/internal/probe"
	"github.com/servanago/servanago/internal/store"
)

// Notes are written and read through MCP, survive an update that does not mention them, and can be cleared with "".
func TestMCPNotes(t *testing.T) {
	s, _ := runtimeServer(t)
	s.deps.Cfg.MCPToken = mcpToken
	sess := mcpSession(t, s, mcpToken)
	ctx := context.Background()

	var made changed
	if err := call(t, sess, "create_site", map[string]any{"kind": "static", "static_root": t.TempDir(), "hostnames": []string{"n.example.com"}, "notes": "owner: Brian"}, &made); err != nil {
		t.Fatalf("create_site: %v", err)
	}
	if got, _ := s.deps.Store.GetSite(ctx, made.ID); got.Notes != "owner: Brian" {
		t.Fatalf("create dropped notes: %q", got.Notes)
	}
	if err := call(t, sess, "update_site", map[string]any{"id": made.ID, "enabled": true}, nil); err != nil {
		t.Fatalf("update_site: %v", err)
	}
	if got, _ := s.deps.Store.GetSite(ctx, made.ID); got.Notes != "owner: Brian" {
		t.Fatalf("update_site without notes cleared them: %q", got.Notes)
	}
	if err := call(t, sess, "update_site", map[string]any{"id": made.ID, "notes": "renews by hand"}, nil); err != nil {
		t.Fatalf("update notes: %v", err)
	}
	var v siteView
	if err := call(t, sess, "get_site", map[string]any{"id": made.ID}, &v); err != nil || v.Notes != "renews by hand" || v.UpdatedAt == "" {
		t.Fatalf("get_site: %+v %v", v, err)
	}
	if err := call(t, sess, "update_site", map[string]any{"id": made.ID, "notes": ""}, nil); err != nil {
		t.Fatalf("clear notes: %v", err)
	}
	if got, _ := s.deps.Store.GetSite(ctx, made.ID); got.Notes != "" {
		t.Fatalf("empty notes did not clear: %q", got.Notes)
	}
	if err := call(t, sess, "update_site", map[string]any{"id": made.ID, "notes": strings.Repeat("x", 10001)}, nil); err == nil || !strings.Contains(err.Error(), "10,000") {
		t.Fatalf("over-long notes: %v", err)
	}
}

// healthOf names every reason a site needs attention; a disabled site is never an issue, and an unreadable
// status counts as one.
func TestHealthOf(t *testing.T) {
	site := func(kind string, enabled bool) siteRow {
		return siteRow{Site: store.Site{Kind: kind, Enabled: enabled}}
	}
	down := site("proxy", true)
	down.Upstream = "down"
	badCert := site("proxy", true)
	badCert.Cert = probe.CertStatus{State: probe.StateError}
	pendingCert := site("proxy", true)
	pendingCert.Cert = probe.CertStatus{State: probe.StatePending}
	badDNS := site("proxy", true)
	badDNS.DNS = []store.DNSRecord{{State: "synced"}, {State: "conflict"}}
	offDown := site("proxy", false)
	offDown.Upstream = "down"

	for _, c := range []struct {
		name    string
		row     siteRow
		unit    string
		unitErr error
		rootErr error
		health  string
		want    string // substring of the issues
	}{
		{"healthy proxy", site("proxy", true), "", nil, nil, "ok", ""},
		{"upstream down", down, "", nil, nil, "issue", "upstream down"},
		{"certificate error", badCert, "", nil, nil, "issue", "certificate"},
		{"certificate pending is not an issue", pendingCert, "", nil, nil, "ok", ""},
		{"dns conflict", badDNS, "", nil, nil, "issue", "DNS"},
		{"folder unreadable", site("php", true), "active", nil, errors.New("permission denied"), "issue", "folder"},
		{"unit failed", site("node", true), "failed", nil, nil, "issue", "unit failed"},
		{"unit active", site("node", true), "active", nil, nil, "ok", ""},
		{"status unavailable counts", site("php", true), "", errors.New("no helper"), nil, "issue", "status unavailable"},
		{"proxy ignores the helper", site("proxy", true), "", errors.New("no helper"), nil, "ok", ""},
		{"disabled is not an issue", offDown, "", nil, nil, "disabled", ""},
	} {
		health, issues := healthOf(c.row, c.unit, c.unitErr, c.rootErr)
		if health != c.health || (c.want != "" && !strings.Contains(strings.Join(issues, "; "), c.want)) {
			t.Errorf("%s: got %q %v, want %q containing %q", c.name, health, issues, c.health, c.want)
		}
	}
}

func TestReferenceRequiresSignIn(t *testing.T) {
	s := newServer(t, "pw")
	if w := s.do(req{path: "/reference"}); w.Code != 303 || w.Header().Get("Location") != "/login" {
		t.Fatalf("signed out: %d %q", w.Code, w.Header().Get("Location"))
	}
}

// One card per site linking to its edit view; notes are escaped; the basic-auth hash never leaves the server;
// a disabled site is listed and labelled; hostile query parameters change nothing.
func TestReferencePage(t *testing.T) {
	s, _ := siteServer(t)
	ctx := context.Background()
	mk := func(x store.Site) store.Site {
		t.Helper()
		got, err := s.deps.Store.CreateSite(ctx, x)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	proxy := mk(store.Site{Hostnames: []string{"app.example.com"}, Scheme: "http", UpstreamHost: "127.0.0.1", UpstreamPort: 9, Enabled: true,
		BasicUser: "alice", BasicHash: "$2a$10$HASHHASHHASHHASHHASHHASHHASHHASH", Notes: "<script>alert(1)</script>\nsecond line"})
	static := mk(store.Site{Hostnames: []string{"files.example.com"}, Kind: "static", StaticRoot: t.TempDir(), Enabled: true})
	off := mk(store.Site{Hostnames: []string{"old.example.com"}, Scheme: "http", UpstreamHost: "127.0.0.1", UpstreamPort: 9})

	w := s.do(req{path: "/reference?sort=bogus&kind=%3Cscript%3Ealert(2)%3C/script%3E&view=%22%3E"})
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	body := w.Body.String()
	for _, x := range []store.Site{proxy, static, off} {
		if !strings.Contains(body, `href="/sites/`+itoa(x.ID)+`"`) {
			t.Errorf("no edit link for %s", x.Hostnames[0])
		}
	}
	if n := strings.Count(body, `<article id="`); n != 3 {
		t.Errorf("%d cards, want 3", n)
	}
	if strings.Contains(body, "HASHHASH") {
		t.Error("basic-auth hash leaked into the page")
	}
	if !strings.Contains(body, "Basic auth</dt><dd>on") {
		t.Error("basic auth not shown as on")
	}
	if strings.Contains(body, "<script>alert") {
		t.Errorf("notes or query not escaped:\n%s", body)
	}
	if !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("escaped notes missing")
	}
	if !strings.Contains(body, `data-health="disabled"`) {
		t.Error("disabled site not labelled")
	}
}

func TestReferenceEmptyAndHelperDown(t *testing.T) {
	s, _ := siteServer(t)
	if body := s.do(req{path: "/reference"}).Body.String(); !strings.Contains(body, "No sites yet") {
		t.Fatalf("empty page: %s", body)
	}
	if _, err := s.deps.Store.CreateSite(context.Background(), store.Site{Hostnames: []string{"n.example.com"}, Kind: "node", StaticRoot: t.TempDir(),
		StartCommand: "node x.js", UpstreamHost: "127.0.0.1", UpstreamPort: 3000, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	s.deps.HelperSocket = t.TempDir() + "/none.sock"
	w := s.do(req{path: "/reference"})
	body := w.Body.String()
	if w.Code != 200 || !strings.Contains(body, "Status unavailable") || !strings.Contains(body, `data-health="issue"`) {
		t.Fatalf("helper down: %d %s", w.Code, body)
	}
}
