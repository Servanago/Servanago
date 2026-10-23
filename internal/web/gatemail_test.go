package web

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/servanago/servanago/internal/secretbox"
	"github.com/servanago/servanago/internal/store"
)

// gatedSite creates a gated site with its own SMTP provider through the form and returns its id and the session.
func gatedSite(t *testing.T) (*Server, int64, *http.Cookie) {
	t.Helper()
	s := gateServer(t)
	ctx := context.Background()
	if _, err := s.deps.Store.CreateDomain(ctx, store.Domain{Name: "example.com", ZoneID: "z", DefaultIP: "10.0.0.1", CertMode: "wildcard"}); err != nil {
		t.Fatal(err)
	}
	c := sessionCookie(t, login(s, "pw", nil, ""))
	body := form(append([]string{"enabled", "on", "gate_mode", "acl", "gate_acl", "alice@example.com"}, gateMail...)...).Encode()
	if w := s.do(req{method: "POST", path: "/sites", body: body, hdr: htmxPost, cookies: []*http.Cookie{c}}); w.Code != 204 {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	rs, _ := s.deps.Store.ListSites(ctx)
	return s, rs[0].ID, c
}

func TestGateRowsAddRemoveAndSurviveSiteSave(t *testing.T) {
	s, id, c := gatedSite(t)
	ctx := context.Background()
	do := func(method, path string, kv ...string) int {
		return s.do(req{method: method, path: path, body: form(kv...).Encode(), hdr: htmxPost, cookies: []*http.Cookie{c}}).Code
	}
	base := "/sites/" + itoa(id)
	if code := do("POST", base+"/gate/grants", "rule", "@Dev.Example"); code != 204 {
		t.Fatalf("add: %d", code)
	}
	gs, _ := s.deps.Store.Grants(ctx, id)
	if len(gs) != 2 {
		t.Fatalf("rows: %+v", gs)
	}
	for _, g := range gs {
		if g.Mode == "domain" && (g.Value != "dev.example" || g.AddedBy != "admin" || g.AddedAt == "") {
			t.Fatalf("row metadata: %+v", g)
		}
	}
	if code := do("POST", base+"/gate/grants", "rule", "a@x.test\nb@x.test"); code != 422 {
		t.Fatalf("two rules in one add must be refused, got %d", code)
	}
	// The site form on an edit page has no gate_acl field: saving it must not touch the rows.
	if code := do("PUT", base, append([]string{"enabled", "on", "gate_mode", "acl"}, gateMail...)...); code != 200 {
		t.Fatalf("save: %d", code)
	}
	if gs, _ := s.deps.Store.Grants(ctx, id); len(gs) != 2 {
		t.Fatalf("a form save without gate_acl changed the rows: %+v", gs)
	}
	// A session that only this row admitted dies with the row.
	if err := s.deps.Store.UpsertIdentity(ctx, "carol@dev.example", "n1", "h1", "2026-10-15T10:00:00Z", time.Hour); err != nil {
		t.Fatal(err)
	}
	if code := do("POST", base+"/gate/grants/delete", "mode", "domain", "value", "dev.example"); code != 204 {
		t.Fatalf("remove: %d", code)
	}
	if gs, _ := s.deps.Store.Grants(ctx, id); len(gs) != 1 || gs[0].Value != "alice@example.com" {
		t.Fatalf("after remove: %+v", gs)
	}
	if ids, _ := s.deps.Store.GateIdentities(ctx); len(ids) != 0 {
		t.Fatalf("session survived its row: %+v", ids)
	}
}

// The edit page of a gated site with access rows once stopped rendering at the first row (a template error
// answered 200 with half a page), so the Save button was missing.
func TestGatedSiteEditPageRendersToTheEnd(t *testing.T) {
	s, id, c := gatedSite(t) // one row: alice@example.com
	w := s.do(req{path: "/sites/" + itoa(id), cookies: []*http.Cookie{c}})
	body := w.Body.String()
	if w.Code != 200 {
		t.Fatalf("edit page: %d", w.Code)
	}
	for _, want := range []string{"alice@example.com", "/gate/grants/delete", "Add entry", "Send test", ">Save</button>", "</form>"} {
		if !strings.Contains(body, want) {
			t.Errorf("edit page of a gated site lacks %q (page cut short?)", want)
		}
	}
}

func TestGateMailSecretSealedAndKept(t *testing.T) {
	s, id, c := gatedSite(t)
	ctx := context.Background()
	put := func(kv ...string) int {
		return s.do(req{method: "PUT", path: "/sites/" + itoa(id), body: form(kv...).Encode(), hdr: htmxPost, cookies: []*http.Cookie{c}}).Code
	}
	pm := []string{"enabled", "on", "gate_mode", "open", "gate_provider", "postmark", "gate_from", "Access@Example.com", "gate_secret", "server-token-1"}
	if code := put(pm...); code != 200 {
		t.Fatalf("save postmark: %d", code)
	}
	got, _ := s.deps.Store.GetSite(ctx, id)
	if got.GateProvider != "postmark" || got.GateFrom != "access@example.com" || !got.GateMailReady() {
		t.Fatalf("site: %+v", got)
	}
	if strings.Contains(string(got.GateSecret), "server-token-1") {
		t.Fatal("token stored in the clear")
	}
	if b, err := secretbox.Open(s.deps.Cfg.SecretKey, got.GateSecret); err != nil || string(b) != "server-token-1" {
		t.Fatalf("unseal: %q %v", b, err)
	}
	// A blank secret on a later save keeps the sealed one.
	if code := put("enabled", "on", "gate_mode", "open", "gate_provider", "postmark", "gate_from", "access@example.com"); code != 200 {
		t.Fatalf("resave: %d", code)
	}
	if again, _ := s.deps.Store.GetSite(ctx, id); string(again.GateSecret) != string(got.GateSecret) {
		t.Fatal("blank secret replaced the stored one")
	}
	// The edit page never prints it.
	if page := s.do(req{path: "/sites/" + itoa(id), cookies: []*http.Cookie{c}}).Body.String(); strings.Contains(page, "server-token-1") {
		t.Fatal("edit page shows the secret")
	}
	if code := put("enabled", "on", "gate_mode", "open", "gate_provider", "carrier-pigeon"); code != 422 {
		t.Fatalf("unknown provider: %d", code)
	}
}

func TestGateMailTestRefusedWithoutProvider(t *testing.T) {
	s, id, c := gatedSite(t)
	s2 := s.deps.Store
	rt, _ := s2.GetSite(context.Background(), id)
	rt.GateProvider = ""
	if err := s2.UpdateSite(context.Background(), rt); err != nil {
		t.Fatal(err)
	}
	w := s.do(req{method: "POST", path: "/sites/" + itoa(id) + "/gate/test", body: form("to", "me@x.test").Encode(), hdr: htmxPost, cookies: []*http.Cookie{c}})
	if w.Code != 422 || !strings.Contains(w.Body.String(), "mail provider") {
		t.Fatalf("test mail: %d %s", w.Code, w.Body.String())
	}
}

func TestGatedSiteMLHostIsReserved(t *testing.T) {
	s, _, c := gatedSite(t)
	// Another site already answers on the name the gated site's magic-link host needs.
	other := form("hostnames", "ml.sonarr.example.com").Encode()
	if w := s.do(req{method: "POST", path: "/sites", body: other, hdr: htmxPost, cookies: []*http.Cookie{c}}); w.Code != 204 {
		t.Fatalf("other site: %d %s", w.Code, w.Body.String())
	}
	body := form(append([]string{"enabled", "on", "gate_mode", "open"}, gateMail...)...).Encode()
	w := s.do(req{method: "POST", path: "/sites", body: body, hdr: htmxPost, cookies: []*http.Cookie{c}})
	if w.Code != 409 || !strings.Contains(w.Body.String(), "ml.sonarr.example.com") {
		t.Fatalf("ml collision: %d %s", w.Code, w.Body.String())
	}
}

func TestFormOfKeepsGateMailBlock(t *testing.T) {
	s, id, _ := gatedSite(t)
	ctx := context.Background()
	rt, _ := s.deps.Store.GetSite(ctx, id)
	rt.GateSecret = []byte("sealed")
	v := s.formOf(ctx, rt)
	base := rt
	base.GateProvider, base.GateFrom, base.GateSMTPHost = "", "", ""
	if err := s.applyGateMail(&base, v); err != nil {
		t.Fatal(err)
	}
	if base.GateProvider != "smtp" || base.GateFrom != rt.GateFrom || base.GateSMTPHost != rt.GateSMTPHost || base.GateSMTPPort != rt.GateSMTPPort || string(base.GateSecret) != "sealed" {
		t.Fatalf("mcp round trip lost the mail block: %+v", base)
	}
}
