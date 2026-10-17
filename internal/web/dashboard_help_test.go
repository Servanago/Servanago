package web

import (
	"context"
	"html"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/servanago/servanago/internal/store"
)

func rowHTML(t *testing.T, body, host string) string {
	t.Helper()
	i := strings.Index(body, host)
	if i < 0 {
		t.Fatalf("no row for %s in %s", host, body)
	}
	end := strings.Index(body[i:], "</tr>")
	return html.UnescapeString(body[i : i+end]) // compare against what the user reads, not &#39;
}

func TestStatusesExplainThemselves(t *testing.T) {
	s, _, d := newDNSServer(t)
	addRoute(t, s, d) // sonarr.example.com; fake dial refuses, cert handshake fails
	row := rowHTML(t, s.do(req{path: "/status"}).Body.String(), "sonarr.example.com")
	for _, want := range []string{
		statusHelp["up:down"].Meaning, statusHelp["up:down"].Next, // backend unreachable
		statusHelp["cert:pending"].Meaning, // tooltip
		"up to 2 minutes",                  // Caddy's default wait when no propagation settings are configured
		statusHelp["dns:synced"].Meaning,
	} {
		if !strings.Contains(row, want) {
			t.Errorf("row missing %q:\n%s", want, row)
		}
	}
}

func TestCertWaitUsesConfiguredPropagation(t *testing.T) {
	s, _, d := newDNSServer(t)
	s.deps.Cfg.PropagationDelay, s.deps.Cfg.PropagationTimeout = 2*60e9, 10*60e9
	addRoute(t, s, d)
	if row := rowHTML(t, s.do(req{path: "/status"}).Body.String(), "sonarr.example.com"); !strings.Contains(row, "up to 12 minutes") {
		t.Errorf("wait not derived from settings:\n%s", row)
	}
}

func TestConflictAndErrorGetNextSteps(t *testing.T) {
	s, cf, d := newDNSServer(t)
	cf.dns.Seed("sonarr.example.com", "9.9.9.9")
	addRoute(t, s, d)
	row := rowHTML(t, s.do(req{path: "/status"}).Body.String(), "sonarr.example.com")
	if !strings.Contains(row, "Press Take over") || !strings.Contains(row, statusHelp["dns:conflict"].Meaning) {
		t.Errorf("conflict help missing:\n%s", row)
	}

	s2, cf2, d2 := newDNSServer(t)
	cf2.dns.FailWith("Invalid access token")
	addRoute(t, s2, d2)
	row = rowHTML(t, s2.do(req{path: "/status"}).Body.String(), "sonarr.example.com")
	if !strings.Contains(row, "Cloudflare rejected the API token") || !strings.Contains(row, "Invalid access token") {
		t.Errorf("explained error with raw text missing:\n%s", row)
	}
}

func TestCertErrorIsExplained(t *testing.T) {
	s, _, d := newDNSServer(t)
	s.deps.Probe.LogError = func(string) string {
		return "solving challenges: timed out waiting for record to fully propagate"
	}
	addRoute(t, s, d)
	row := rowHTML(t, s.do(req{path: "/status"}).Body.String(), "sonarr.example.com")
	if !strings.Contains(row, "slow to publish the verification record") || !strings.Contains(row, "ACME_PROPAGATION_TIMEOUT") {
		t.Errorf("cert error not explained:\n%s", row)
	}
}

func TestChecklist(t *testing.T) {
	s, _, d := newDNSServer(t)
	ctx := context.Background()
	get := func() []checkItem { return s.checklist(ctx, nil, nil) }
	state := func(items []checkItem, label string) string {
		for _, it := range items {
			if strings.Contains(it.Label, label) {
				return it.State
			}
		}
		t.Fatalf("no checklist item %q in %+v", label, items)
		return ""
	}

	// token: unknown until VerifyToken has run, then ok or bad
	if got := state(get(), "Cloudflare token"); got != "todo" {
		t.Errorf("token before verify: %s", got)
	}
	s.cfErr.Store("")
	if got := state(get(), "Cloudflare token"); got != "ok" {
		t.Errorf("token ok: %s", got)
	}
	s.cfErr.Store("Invalid access token")
	if got := state(get(), "Cloudflare token"); got != "bad" {
		t.Errorf("token bad: %s", got)
	}

	// The UI address's DNS record item appears only with a host card (Cloudflare configured);
	// its certificate item is always shown.
	for _, it := range get() {
		if strings.Contains(it.Label, "DNS record") {
			t.Error("DNS record item shown without a host card")
		}
	}
	if got := state(get(), "valid certificate"); got == "" {
		t.Error("the UI address certificate item must show without DNS management")
	}
	for want, card := range map[string]*hostCard{
		"ok":   {DNS: []store.DNSRecord{statusRecord("synced")}},
		"todo": {DNS: []store.DNSRecord{statusRecord("pending")}},
		"bad":  {DNS: []store.DNSRecord{statusRecord("conflict")}},
	} {
		if got := state(s.checklist(ctx, nil, card), "UI address"); got != want {
			t.Errorf("host %s: got %s", want, got)
		}
	}

	// first site
	if got := state(get(), "first site"); got != "todo" {
		t.Errorf("no sites: %s", got)
	}
	addRoute(t, s, d)
	rows, _ := s.siteRows(newReq(t))
	if got := state(s.checklist(ctx, rows, nil), "first site"); got != "ok" {
		t.Errorf("with a site: %s", got)
	}
}

func TestChecklistShownUntilEverythingIsDone(t *testing.T) {
	s, _, _ := newDNSServer(t)
	if body := s.do(req{path: "/"}).Body.String(); !strings.Contains(body, "Getting started") || !strings.Contains(body, "Add your first site") {
		t.Errorf("checklist missing on a fresh install: %s", body)
	}
}

func TestEmptyDashboardExplainsTheFirstStep(t *testing.T) {
	s, _, _ := newDNSServer(t)
	body := s.do(req{path: "/"}).Body.String()
	if !strings.Contains(body, "No sites yet") || !strings.Contains(body, "Add site") {
		t.Errorf("empty state unhelpful: %s", body)
	}
}

func TestHelpPage(t *testing.T) {
	s, _, _ := newDNSServer(t)
	w := s.do(req{path: "/help"})
	body := html.UnescapeString(w.Body.String())
	if w.Code != 200 {
		t.Fatalf("%d", w.Code)
	}
	for _, sec := range helpSections {
		if !strings.Contains(body, `id="`+sec.ID+`"`) {
			t.Errorf("section %s missing", sec.ID)
		}
	}
	for _, k := range statusOrder {
		if !strings.Contains(body, statusHelp[k].Label) {
			t.Errorf("glossary lacks %s", k)
		}
	}
	for _, e := range errTable {
		if !strings.Contains(body, e.Title) {
			t.Errorf("troubleshooting lacks %q", e.Title)
		}
	}
	if !strings.Contains(s.do(req{path: "/"}).Body.String(), `href="/help"`) {
		t.Error("no nav link to Help")
	}
}

func TestHelpRequiresLogin(t *testing.T) {
	s := newServer(t, "pw")
	if w := s.do(req{path: "/help"}); w.Code != 303 {
		t.Errorf("%d", w.Code)
	}
}

func TestErrorsReachTheUserExplained(t *testing.T) {
	s, _ := siteServer(t)
	s.deps.Cfg.Host = "oc.example.com"
	_, body := postSite(s, siteForm("hostnames", "oc.example.com"))
	if !strings.Contains(body, "own address") || !strings.Contains(body, "UI host") {
		t.Errorf("explanation plus raw error expected: %s", body)
	}
}

func TestBannerExplainsTokenProblem(t *testing.T) {
	s, _, _ := newDNSServer(t)
	s.cfErr.Store("verify Cloudflare token: 401 Invalid API Token")
	body := s.do(req{path: "/"}).Body.String()
	if !strings.Contains(body, "Cloudflare rejected the API token") || !strings.Contains(body, `href="/help#token"`) {
		t.Errorf("banner: %s", body)
	}
}

func statusRecord(state string) store.DNSRecord { return store.DNSRecord{State: state} }

func newReq(t *testing.T) *http.Request {
	t.Helper()
	return httptest.NewRequest("GET", "/", nil)
}
