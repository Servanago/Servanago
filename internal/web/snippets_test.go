package web

import (
	"context"
	"strings"
	"testing"
)

func snippetReq(s *Server, method, path string, kv ...string) (int, string) {
	w := s.do(req{method: method, path: path, body: form(kv...).Encode(), hdr: htmxPost})
	return w.Code, w.Body.String()
}

// With no snippets yet the page must still offer the add form (a `with` on the empty list hid everything).
func TestSnippetsPageEmptyHasAddForm(t *testing.T) {
	s, _ := siteServer(t)
	if body := s.do(req{path: "/snippets"}).Body.String(); !strings.Contains(body, "Add snippet") {
		t.Fatalf("empty page has no add form:\n%s", body)
	}
}

func TestSnippetsCRUDAndRefusals(t *testing.T) {
	s, _ := siteServer(t)
	ctx := context.Background()
	for _, tc := range []struct {
		name, body string
		code       int
		want       string
	}{
		{"block_sensitive", "@lock path /composer.lock\nrespond @lock 404", 204, ""},
		{"compress", "encode gzip zstd", 204, ""},
		{"compress", "encode gzip", 422, "UNIQUE"},
		{"Bad Name", "encode gzip", 422, "snippet name"},
		{"proxy_it", "reverse_proxy 127.0.0.1:9", 422, "not allowed"},
		{"imports", "import /etc/hosts", 422, "import"},
	} {
		code, body := snippetReq(s, "POST", "/snippets", "name", tc.name, "body", tc.body)
		if code != tc.code || !strings.Contains(body, tc.want) {
			t.Errorf("add %q: %d %q; want %d containing %q", tc.name, code, body, tc.code, tc.want)
		}
	}
	all, _ := s.deps.Store.ListSnippets(ctx)
	if len(all) != 2 {
		t.Fatalf("stored %+v; rejected snippets must leave nothing behind", all)
	}
	if w := s.do(req{path: "/snippets"}); w.Code != 200 || !strings.Contains(w.Body.String(), "block_sensitive") {
		t.Fatalf("page: %d", w.Code)
	}

	// Attach through the site form; an unknown name is refused.
	if code, body := postSite(s, siteForm("hostnames", "a.example.com")); code != 204 {
		t.Fatalf("site: %d %q", code, body)
	}
	rs, _ := s.deps.Store.ListSites(ctx)
	f := siteForm("hostnames", "a.example.com")
	f["snippets"] = []string{"nope"}
	if w := s.do(req{method: "PUT", path: "/sites/" + itoa(rs[0].ID), body: f.Encode(), hdr: htmxPost}); w.Code != 422 || !strings.Contains(w.Body.String(), "unknown snippet") {
		t.Fatalf("unknown: %d %q", w.Code, w.Body.String())
	}
	f["snippets"] = []string{"compress", "block_sensitive"}
	if w := s.do(req{method: "PUT", path: "/sites/" + itoa(rs[0].ID), body: f.Encode(), hdr: htmxPost}); w.Code != 200 {
		t.Fatalf("attach: %d %q", w.Code, w.Body.String())
	}
	if got, _ := s.deps.Store.GetSite(ctx, rs[0].ID); strings.Join(got.Snippets, ",") != "block_sensitive,compress" {
		t.Fatalf("attached %v", got.Snippets)
	}

	// A bad edit changes nothing; delete is refused while in use, then works.
	id := itoa(all[1].ID)
	if code, _ := snippetReq(s, "PUT", "/snippets/"+id, "body", "file_server"); code != 422 {
		t.Errorf("bad edit: %d", code)
	}
	if code, body := snippetReq(s, "DELETE", "/snippets/"+id); code != 409 || !strings.Contains(body, "a.example.com") {
		t.Errorf("delete in use: %d %q", code, body)
	}
	f["snippets"] = []string{""} // the sentinel the snippets form posts to clear
	if w := s.do(req{method: "PUT", path: "/sites/" + itoa(rs[0].ID), body: f.Encode(), hdr: htmxPost}); w.Code != 200 {
		t.Fatalf("detach: %d", w.Code)
	}
	if code, body := snippetReq(s, "DELETE", "/snippets/"+id); code != 204 {
		t.Errorf("delete: %d %q", code, body)
	}
}

// The snippets tab lists the site's snippets as checkboxes and keeps the ones already attached.
func TestSnippetsTabShowsAttachments(t *testing.T) {
	s, _ := siteServer(t)
	ctx := context.Background()
	if code, body := snippetReq(s, "POST", "/snippets", "name", "compress", "body", "encode gzip"); code != 204 {
		t.Fatalf("%d %q", code, body)
	}
	if code, body := postSite(s, siteForm("hostnames", "a.example.com")); code != 204 {
		t.Fatalf("%d %q", code, body)
	}
	rs, _ := s.deps.Store.ListSites(ctx)
	rs[0].Snippets = []string{"compress"}
	if err := s.deps.Store.UpdateSite(ctx, rs[0]); err != nil {
		t.Fatal(err)
	}
	body := s.do(req{path: "/sites/" + itoa(rs[0].ID) + "/snippets"}).Body.String()
	if !strings.Contains(body, `name="snippets" value="compress" checked`) {
		t.Errorf("checkbox missing or unchecked:\n%s", body)
	}
}

// MCP: snippet tools run through the UI handlers, and an update_site that does not mention snippets keeps them.
func TestMCPSnippets(t *testing.T) {
	s, _ := runtimeServer(t)
	s.deps.Cfg.MCPToken = mcpToken
	sess := mcpSession(t, s, mcpToken)
	ctx := context.Background()

	if err := call(t, sess, "create_snippet", map[string]any{"name": "compress", "body": "encode gzip zstd"}, nil); err != nil {
		t.Fatalf("create_snippet: %v", err)
	}
	if err := call(t, sess, "create_snippet", map[string]any{"name": "evil", "body": "reverse_proxy 127.0.0.1:9"}, nil); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("create evil: %v", err)
	}
	var made changed
	if err := call(t, sess, "create_site", map[string]any{"kind": "static", "static_root": t.TempDir(), "hostnames": []string{"s.example.com"}, "snippets": []string{"compress"}}, &made); err != nil {
		t.Fatalf("create_site: %v", err)
	}
	if err := call(t, sess, "update_site", map[string]any{"id": made.ID, "enabled": true}, nil); err != nil {
		t.Fatalf("update_site: %v", err)
	}
	if got, _ := s.deps.Store.GetSite(ctx, made.ID); strings.Join(got.Snippets, ",") != "compress" {
		t.Fatalf("update_site dropped snippets: %v", got.Snippets)
	}
	var list struct {
		Snippets []snippetView `json:"snippets"`
	}
	if err := call(t, sess, "list_snippets", nil, &list); err != nil || len(list.Snippets) != 1 || len(list.Snippets[0].UsedBy) != 1 {
		t.Fatalf("list_snippets: %+v %v", list, err)
	}
	if err := call(t, sess, "delete_snippet", map[string]any{"name": "compress"}, nil); err == nil || !strings.Contains(err.Error(), "s.example.com") {
		t.Fatalf("delete in use: %v", err)
	}
	if err := call(t, sess, "update_site", map[string]any{"id": made.ID, "snippets": []string{}}, nil); err != nil {
		t.Fatalf("detach: %v", err)
	}
	if err := call(t, sess, "delete_snippet", map[string]any{"name": "compress"}, nil); err != nil {
		t.Fatalf("delete: %v", err)
	}
}
