package web

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/servanago/servanago/internal/store"
)

func TestSiteEditorIsSectionedWithFeaturesClosedUntilUsed(t *testing.T) {
	s, _, d := newDNSServer(t)
	body := s.do(req{path: "/sites/new"}).Body.String()
	for _, want := range []string{`id="sec-basics"`, `id="sec-access"`, `id="sec-behaviour"`, `class="toc"`, `class="savebar"`, `id="preview"`, `name="enabled"`, ">Add site</button>", "</form>", "</html>"} {
		if !strings.Contains(body, want) {
			t.Errorf("new-site editor lacks %q", want)
		}
	}
	if n := strings.Count(body, `<details class="feature">`); n != 4 {
		t.Errorf("want 4 closed access features (gate, allowlist, basic auth, country filter), got %d", n)
	}
	if strings.Contains(body, `id="sec-danger"`) {
		t.Error("a new site has nothing to delete")
	}

	site, err := s.deps.Store.CreateSite(context.Background(), store.Site{Hostnames: []string{"acl." + d.Name}, Scheme: "http", UpstreamHost: "10.9.9.9", UpstreamPort: 8000, Enabled: true, Allowlist: "10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	body = s.do(req{path: "/sites/" + itoa(site.ID)}).Body.String()
	for _, want := range []string{`id="panel-settings"`, `href="/sites/` + itoa(site.ID) + `/gate">Gate</a>`, `id="sec-danger"`, "Delete site", ">Save</button>", "</form>"} {
		if !strings.Contains(body, want) {
			t.Errorf("edit page lacks %q", want)
		}
	}
	if strings.Contains(body, `<details class="feature"`) {
		t.Error("access features live on the Gate tab now, not in the editor")
	}
	if !strings.Contains(body, `id="panel-settings"`) {
		t.Error("edit page lost the settings panel")
	}
	gate := s.do(req{path: "/sites/" + itoa(site.ID) + "/gate"}).Body.String()
	if !strings.Contains(gate, `<textarea name="allowlist"`) || !strings.Contains(gate, "Save allowlist and basic auth") {
		t.Errorf("gate tab lacks the editable access controls: %q", gate)
	}
}

// With the session key set the Gate tab carries the gate mode too, the Mail tab the provider form.
func TestGateTabAndMailTabCarryTheirControls(t *testing.T) {
	s := gateServer(t)
	site, err := s.deps.Store.CreateSite(context.Background(), store.Site{Hostnames: []string{"gt.example.com"}, Kind: "static", StaticRoot: "/srv/www/gt", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	ck := sessionCookie(t, login(s, "pw", nil, ""))
	body := s.do(req{path: "/sites/" + itoa(site.ID) + "/gate", cookies: []*http.Cookie{ck}}).Body.String()
	for _, want := range []string{`name="gate_mode"`, "Save gate", "Who may ask for a link"} {
		if !strings.Contains(body, want) {
			t.Errorf("gate tab lacks %q", want)
		}
	}
	mail := s.do(req{path: "/sites/" + itoa(site.ID) + "/mail", cookies: []*http.Cookie{ck}}).Body.String()
	for _, want := range []string{`name="gate_provider"`, "Save mail"} {
		if !strings.Contains(mail, want) {
			t.Errorf("mail tab lacks %q", want)
		}
	}
}
