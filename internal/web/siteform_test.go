package web

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/servanago/servanago/internal/store"
)

func staticForm(root string, kv ...string) []string {
	return append([]string{"kind", "static", "static_root", root, "hostnames", "blog.example.com", "enabled", "on"}, kv...)
}

func TestCreateStaticSite(t *testing.T) {
	s, _ := routeServer(t)
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	s.deps.Cfg.DataDir = t.TempDir()
	w := s.do(req{method: "POST", path: "/sites", body: form(staticForm(root, "stream", "on", "max_body", "1GB", "upstream_host", "ignored")...).Encode(), hdr: htmxPost})
	if w.Code != 204 {
		t.Fatalf("create: %d %q", w.Code, w.Body.String())
	}
	rs, _ := s.deps.Store.ListSites(context.Background())
	if len(rs) != 1 {
		t.Fatalf("%+v", rs)
	}
	got := rs[0]
	resolved, _ := filepath.EvalSymlinks(root)
	if got.Kind != "static" || got.StaticRoot != resolved || got.UpstreamHost != "" || got.UpstreamPort != 0 || got.Stream || got.MaxBody != 0 {
		t.Fatalf("static site carries proxy-only settings or an unresolved root: %+v", got)
	}
	body := s.do(req{path: "/"}).Body.String()
	if !strings.Contains(body, resolved) || strings.Contains(body, ":0<") {
		t.Errorf("dashboard row for a static site: %s", body)
	}
	edit := s.do(req{path: "/sites/" + itoa(got.ID)}).Body.String()
	if !strings.Contains(edit, `value="static" selected`) || !strings.Contains(edit, `value="`+resolved+`"`) || strings.Contains(edit, "cannot read") {
		t.Errorf("edit page: %s", edit)
	}
}

func TestStaticSiteRootIsValidated(t *testing.T) {
	s, _ := routeServer(t)
	dataDir, allowed, other := t.TempDir(), t.TempDir(), t.TempDir()
	s.deps.Cfg.DataDir, s.deps.Cfg.StaticRoots = dataDir, []string{allowed}
	file := filepath.Join(allowed, "f.txt")
	_ = os.WriteFile(file, nil, 0o644)
	for name, root := range map[string]string{
		"empty": "", "relative": "srv/www", "missing": filepath.Join(allowed, "nope"), "a file": file,
		"/etc": "/etc", "outside the allowlist": other, "the data dir": dataDir,
	} {
		w := s.do(req{method: "POST", path: "/sites", body: form(staticForm(root)...).Encode(), hdr: htmxPost})
		if w.Code != 422 || !strings.Contains(w.Body.String(), "static folder") {
			t.Errorf("%s: %d %q", name, w.Code, w.Body.String())
		}
	}
	if rs, _ := s.deps.Store.ListSites(context.Background()); len(rs) != 0 {
		t.Fatalf("a rejected root stored a site: %+v", rs)
	}
}

func TestStaticEditPageReportsUnreadableRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads everything")
	}
	s, _ := routeServer(t)
	root := t.TempDir()
	r, err := s.deps.Store.CreateSite(context.Background(), store.Site{Kind: "static", StaticRoot: root, Hostnames: []string{"blog.example.com"}, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0o755) })
	if body := s.do(req{path: "/sites/" + itoa(r.ID)}).Body.String(); !strings.Contains(body, "cannot read this folder") {
		t.Fatalf("unreadable root not reported: %s", body)
	}
}

func TestHostnamesBoxAddsRemovesAndReordersAndSaveStaysOnPage(t *testing.T) {
	s, cf, d := newDNSServer(t)
	ctx := context.Background()
	r := addRoute(t, s, d, "hostnames", "sonarr.example.com\nalias.example.com")
	if len(r.Hostnames) != 2 || r.Hostnames[1] != "alias.example.com" {
		t.Fatalf("created: %+v", r.Hostnames)
	}
	if body := s.do(req{path: "/"}).Body.String(); !strings.Contains(body, "alias.example.com") {
		t.Errorf("dashboard lacks the alias: %s", body)
	}
	save := func(hostnames string) (int, string) {
		w := s.do(req{method: "PUT", path: "/sites/" + itoa(r.ID), body: form("hostnames", hostnames, "enabled", "on").Encode(), hdr: htmxPost})
		return w.Code, w.Body.String()
	}

	// Save answers in place, not with a redirect.
	code, body := save("sonarr.example.com\nalias.example.com\nthird.example.com")
	if code != 200 || !strings.Contains(body, "Saved and applied") {
		t.Fatalf("save: %d %q", code, body)
	}
	got, _ := s.deps.Store.GetSite(ctx, r.ID)
	if len(got.Hostnames) != 3 || got.Hostnames[2] != "third.example.com" {
		t.Fatalf("added: %v", got.Hostnames)
	}
	// Removing a name and making another primary: the DNS record follows the primary.
	if code, body = save("alias.example.com\nsonarr.example.com"); code != 200 {
		t.Fatalf("reorder: %d %q", code, body)
	}
	got, _ = s.deps.Store.GetSite(ctx, r.ID)
	if len(got.Hostnames) != 2 || got.Hostnames[0] != "alias.example.com" || got.Slug != r.Slug {
		t.Fatalf("after reorder: %v slug %q (was %q)", got.Hostnames, got.Slug, r.Slug)
	}
	// Every hostname has its own record; the dropped third one's owned record is deleted, the others stay.
	recs := map[string]bool{}
	for _, rec := range cf.dns.Records() {
		recs[rec.Name] = true
	}
	if len(recs) != 2 || !recs["alias.example.com"] || !recs["sonarr.example.com"] {
		t.Fatalf("records after dropping the third hostname: %v", recs)
	}
	// A name another site owns is refused, and nothing changes.
	addRoute(t, s, d, "hostnames", "other.example.com")
	if code, _ = save("alias.example.com\nother.example.com"); code != 409 {
		t.Fatalf("shared hostname: %d", code)
	}
	if again, _ := s.deps.Store.GetSite(ctx, r.ID); len(again.Hostnames) != 2 {
		t.Fatalf("a refused save changed the site: %v", again.Hostnames)
	}
	// The edit page shows every hostname in the box.
	if page := s.do(req{path: "/sites/" + itoa(r.ID)}).Body.String(); !strings.Contains(page, "alias.example.com\nsonarr.example.com") {
		t.Errorf("hostnames box: %s", page)
	}
}

// With several hostnames the DNS column and the delete dialog say which record belongs to which name.
func TestDashboardAndDialogNameTheHostnameOfEachRecord(t *testing.T) {
	s, _, d := newDNSServer(t)
	addRoute(t, s, d, "hostnames", "sonarr.example.com\nalias.example.com")
	body := s.do(req{path: "/"}).Body.String()
	if !strings.Contains(body, `data-dns-ip="sonarr.example.com A 10.0.0.1, alias.example.com A 10.0.0.1"`) &&
		!strings.Contains(body, `data-dns-ip="alias.example.com A 10.0.0.1, sonarr.example.com A 10.0.0.1"`) {
		t.Errorf("delete dialog summary lacks hostnames: %s", body)
	}
	if strings.Count(body, `<small class="alias">alias.example.com</small> <span class="dns-synced"`) != 1 {
		t.Errorf("DNS cell does not label the alias's record: %s", body)
	}
	// One hostname keeps the short form.
	s2, _, d2 := newDNSServer(t)
	addRoute(t, s2, d2)
	if b := s2.do(req{path: "/"}).Body.String(); !strings.Contains(b, `data-dns-ip="10.0.0.1"`) || strings.Contains(b, `<small class="alias">sonarr.example.com</small> <span`) {
		t.Errorf("single hostname should stay unlabeled: %s", b)
	}
}

func TestSwitchingKindOnEdit(t *testing.T) {
	s, _ := routeServer(t)
	ctx := context.Background()
	s.deps.Cfg.DataDir = t.TempDir()
	root := t.TempDir()
	w := s.do(req{method: "POST", path: "/sites", body: form("enabled", "on", "stream", "on").Encode(), hdr: htmxPost})
	if w.Code != 204 {
		t.Fatalf("%d %q", w.Code, w.Body.String())
	}
	rs, _ := s.deps.Store.ListSites(ctx)
	id := itoa(rs[0].ID)
	if w := s.do(req{method: "PUT", path: "/sites/" + id, body: form(staticForm(root, "hostnames", "sonarr.example.com")...).Encode(), hdr: htmxPost}); w.Code != 200 {
		t.Fatalf("to static: %d %q", w.Code, w.Body.String())
	}
	got, _ := s.deps.Store.GetSite(ctx, rs[0].ID)
	if got.Kind != "static" || got.UpstreamHost != "" || got.Stream {
		t.Fatalf("after switching to static: %+v", got)
	}
	if w := s.do(req{method: "PUT", path: "/sites/" + id, body: form("enabled", "on").Encode(), hdr: htmxPost}); w.Code != 200 {
		t.Fatalf("back to proxy: %d %q", w.Code, w.Body.String())
	}
	if got, _ = s.deps.Store.GetSite(ctx, rs[0].ID); got.Kind != "proxy" || got.StaticRoot != "" || got.UpstreamPort != 8989 {
		t.Fatalf("after switching back: %+v", got)
	}
}

// Editing a gated site must keep (and update) its allowlist: saving once wiped the grants because the gate
// mode was read before the access controls had set it.
func TestEditingGatedSiteKeepsAndChangesItsAllowlist(t *testing.T) {
	s := gateServer(t)
	ctx := context.Background()
	if _, err := s.deps.Store.CreateDomain(ctx, store.Domain{Name: "example.com", ZoneID: "z", DefaultIP: "10.0.0.1", CertMode: "wildcard"}); err != nil {
		t.Fatal(err)
	}
	c := sessionCookie(t, login(s, "pw", nil, ""))
	post := func(method, path string, kv ...string) int {
		return s.do(req{method: method, path: path, body: form(kv...).Encode(), hdr: htmxPost, cookies: []*http.Cookie{c}}).Code
	}
	if code := post("POST", "/sites", "enabled", "on", "gate_mode", "acl", "gate_acl", "alice@example.com"); code != 204 {
		t.Fatalf("create: %d", code)
	}
	rs, _ := s.deps.Store.ListSites(ctx)
	id := "/sites/" + itoa(rs[0].ID)
	if code := post("PUT", id, "enabled", "on", "gate_mode", "acl", "gate_acl", "alice@example.com\n@dev.example"); code != 200 {
		t.Fatalf("edit: %d", code)
	}
	if gs, _ := s.deps.Store.Grants(ctx, rs[0].ID); len(gs) != 2 {
		t.Fatalf("grants after edit: %+v", gs)
	}
	if code := post("PUT", id, "enabled", "on", "gate_mode", "acl", "gate_acl", ""); code != 422 {
		t.Fatalf("an empty allowlist must be refused, got %d", code)
	}
	if gs, _ := s.deps.Store.Grants(ctx, rs[0].ID); len(gs) != 2 {
		t.Fatalf("a refused edit changed the grants: %+v", gs)
	}
	if code := post("PUT", id, "enabled", "on", "gate_mode", ""); code != 200 {
		t.Fatalf("gate off: %d", code)
	}
	if gs, _ := s.deps.Store.Grants(ctx, rs[0].ID); len(gs) != 0 {
		t.Fatalf("turning the gate off must clear the grants: %+v", gs)
	}
}

func TestEditPageShowsStatusChipsAndPrefillWorks(t *testing.T) {
	s, _, d := newDNSServer(t)
	r := addRoute(t, s, d)
	body := s.do(req{path: "/sites/" + itoa(r.ID)}).Body.String()
	for _, want := range []string{"<h1>sonarr.example.com", "chip", "aria-describedby", `id="hint-hostnames"`, "Advanced", "Delete site"} {
		if !strings.Contains(body, want) {
			t.Errorf("edit page missing %q", want)
		}
	}
	pre := s.do(req{path: "/sites/new?hostname=Oc.Example.com&host=nas&port=9200"}).Body.String()
	for _, want := range []string{">oc.example.com</textarea>", `name="upstream_host" value="nas"`, `value="9200"`} {
		if !strings.Contains(pre, want) {
			t.Errorf("prefill missing %q", want)
		}
	}
}
