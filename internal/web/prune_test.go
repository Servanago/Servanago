package web

import (
	"strings"
	"testing"
)

// ServanaGo is not an arr-stack front end: no preset picker, no Docker discovery panel.
func TestFormsHaveNoPresetOrDockerPanel(t *testing.T) {
	site, _ := siteServer(t)
	route, _, _ := newDNSServer(t) // has a domain, so /routes/new renders the form
	for path, s := range map[string]*Server{"/sites/new": site, "/routes/new": route} {
		body := s.do(req{path: path}).Body.String()
		if !strings.Contains(body, "<form") {
			t.Fatalf("%s rendered no form", path)
		}
		for _, banned := range []string{"Preset", `name="preset"`, "Docker containers", "Sonarr", "Radarr"} {
			if strings.Contains(body, banned) {
				t.Errorf("%s still contains %q", path, banned)
			}
		}
	}
}

func TestHelpTextIsNotContainerSpecific(t *testing.T) {
	for k, v := range hints {
		if strings.Contains(strings.ToLower(v), "docker") {
			t.Errorf("hint %q mentions Docker: %q", k, v)
		}
	}
	for _, sec := range helpSections {
		if strings.Contains(strings.ToLower(string(sec.Body)), "docker") {
			t.Errorf("help section %q mentions Docker", sec.ID)
		}
	}
}
