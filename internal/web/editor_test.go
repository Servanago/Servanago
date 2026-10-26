package web

import (
	"context"
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
	if n := strings.Count(body, `<details class="feature">`); n != 3 {
		t.Errorf("want 3 closed access features, got %d", n)
	}
	if strings.Contains(body, `id="sec-danger"`) {
		t.Error("a new site has nothing to delete")
	}

	site, err := s.deps.Store.CreateSite(context.Background(), store.Site{Hostnames: []string{"acl." + d.Name}, Scheme: "http", UpstreamHost: "10.9.9.9", UpstreamPort: 8000, Enabled: true, Allowlist: "10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	body = s.do(req{path: "/sites/" + itoa(site.ID)}).Body.String()
	if n := strings.Count(body, `<details class="feature" open>`); n != 1 {
		t.Errorf("only the allowlist feature is in use and should be open, got %d open", n)
	}
	for _, want := range []string{`id="sec-danger"`, "Delete site", ">Save</button>", "</form>"} {
		if !strings.Contains(body, want) {
			t.Errorf("edit page lacks %q", want)
		}
	}
}
