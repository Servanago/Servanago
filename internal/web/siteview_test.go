package web

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/servanago/servanago/internal/store"
)

// siteTabsAll is the tab rail of the site view, settings first (it lives on /sites/{id} itself).
var siteTabsAll = []string{"settings", "dns", "ssl", "scan", "backups", "mail", "snippets", "runtime", "gate", "routes", "countries"}

// signedIn makes a server with one static site full of facts and returns the admin's cookies.
func signedIn(t *testing.T) (*Server, int64, []*http.Cookie) {
	t.Helper()
	s := newServer(t, "pw")
	w := login(s, "pw", map[string]string{"X-Forwarded-Proto": "https"}, "")
	if w.Code != 204 {
		t.Fatalf("login: %d", w.Code)
	}
	rt, err := s.deps.Store.CreateSite(context.Background(), store.Site{
		Hostnames:   []string{"tabs.example.com", "www.tabs.example.com"},
		Kind:        "static",
		StaticRoot:  "/srv/www/tabs",
		Enabled:     true,
		ExtraRoutes: "/api=127.0.0.1:3011\n/old=127.0.0.1:3012",
		CountryMode: "deny",
		Countries:   "RU IR",
		GateMode:    "open",
		Notes:       "note body",
	})
	if err != nil {
		t.Fatal(err)
	}
	return s, rt.ID, cookiesOf(t, w)
}

// wantTab asserts each tab path renders its panel.
func TestSiteTabsRender(t *testing.T) {
	s, id, ck := signedIn(t)
	want := map[string]string{
		"dns":       "panel-dns", // without Cloudflare the tab explains itself
		"ssl":       "panel-ssl",
		"scan":      "panel-scan",
		"backups":   "panel-backups",
		"mail":      "panel-mail",
		"snippets":  "panel-snippets",
		"runtime":   "panel-runtime",
		"gate":      "panel-gate",
		"routes":    "127.0.0.1:3011",
		"countries": "RU, IR",
	}
	for _, tab := range siteTabsAll {
		if tab == "settings" {
			continue
		}
		w := s.do(req{path: fmt.Sprintf("/sites/%d/%s", id, tab), cookies: ck})
		if w.Code != 200 {
			t.Errorf("%s: %d", tab, w.Code)
			continue
		}
		if !strings.Contains(w.Body.String(), "panel-"+tab) {
			t.Errorf("%s: panel marker missing:\n%s", tab, w.Body.String())
		}
		if mark := want[tab]; mark != "" && !strings.Contains(w.Body.String(), mark) {
			t.Errorf("%s: marker %q missing", tab, mark)
		}
	}
}

// TestSiteEditorHasTheRail keeps the full editor on /sites/{id} with the tabs above it.
func TestSiteEditorHasTheRail(t *testing.T) {
	s, id, ck := signedIn(t)
	body := s.do(req{path: fmt.Sprintf("/sites/%d", id), cookies: ck}).Body.String()
	for _, tab := range siteTabsAll {
		if !strings.Contains(body, `href="/sites/`+fmt.Sprint(id)+`/`+tab+`"`) {
			t.Errorf("settings page: no link to %s", tab)
		}
	}
	for _, mark := range []string{"Save</button>", "</form>", "panel-settings"} {
		if !strings.Contains(body, mark) {
			t.Errorf("settings page: %q missing", mark)
		}
	}
}

func TestSiteTabUnknownOrMissingFails(t *testing.T) {
	s, id, ck := signedIn(t)
	for _, path := range []string{"/sites/" + fmt.Sprint(id) + "/nope", "/sites/999/dns", "/sites/0x/dns", "/sites/new/dns"} {
		if w := s.do(req{path: path, cookies: ck}); w.Code != http.StatusNotFound {
			t.Errorf("%s: got %d", path, w.Code)
		}
	}
}

// TestBackRedirectOfActions only changes redirect targets: with back the row lands on the calling tab.
func TestBackRedirectOfActions(t *testing.T) {
	s, id, ck := signedIn(t)

	w := s.do(req{method: "POST", path: fmt.Sprintf("/sites/%d/gate/grants", id), cookies: ck,
		hdr: htmxPost, body: url.Values{"rule": {"alice@example.com"}, "back": {"/sites/" + fmt.Sprint(id) + "/gate"}}.Encode()})
	if got := w.Header().Get("HX-Redirect"); got != "/sites/"+fmt.Sprint(id)+"/gate" {
		t.Errorf("grant add back redirect: %q", got)
	}
	w = s.do(req{method: "POST", path: fmt.Sprintf("/sites/%d/gate/grants", id), cookies: ck,
		hdr: htmxPost, body: url.Values{"rule": {"bob@example.com"}}.Encode()})
	if got := w.Header().Get("HX-Redirect"); got != fmt.Sprintf("/sites/%d", id) {
		t.Errorf("grant add default redirect: %q", got)
	}

	w = s.do(req{method: "POST", path: fmt.Sprintf("/backups/sites/%d", id), cookies: ck,
		hdr: htmxPost, body: url.Values{"on": {"1"}, "back": {"/sites/" + fmt.Sprint(id) + "/backups"}}.Encode()})
	if got := w.Header().Get("HX-Redirect"); got != "/sites/"+fmt.Sprint(id)+"/backups" {
		t.Errorf("backup save back redirect: %q", got)
	}
	if _, err := s.deps.Store.GetSiteBackup(context.Background(), id); err != nil {
		t.Errorf("backup row: %v", err)
	}
	w = s.do(req{method: "POST", path: fmt.Sprintf("/backups/sites/%d", id), cookies: ck,
		hdr: htmxPost, body: url.Values{"s sched": {"on"}}.Encode()})
	if got := w.Header().Get("HX-Redirect"); got != "/backups" {
		t.Errorf("backup save default redirect: %q", got)
	}
}
