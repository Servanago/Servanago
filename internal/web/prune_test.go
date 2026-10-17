package web

import (
	"strings"
	"testing"
)

// ServanaGo is not an arr-stack front end: no preset picker, no Docker discovery panel.
func TestFormsHaveNoPresetOrDockerPanel(t *testing.T) {
	s, _ := siteServer(t)
	body := s.do(req{path: "/sites/new"}).Body.String()
	if !strings.Contains(body, "<form") {
		t.Fatal("/sites/new rendered no form")
	}
	for _, banned := range []string{"Preset", `name="preset"`, "Docker containers", "Sonarr", "Radarr"} {
		if strings.Contains(body, banned) {
			t.Errorf("/sites/new still contains %q", banned)
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

// The sign-in pages are served to visitors who are not signed in: no app navigation, no Sign out.
func TestLoginPageHasNoAppNavigation(t *testing.T) {
	s := newServer(t, "secret")
	body := s.do(req{path: "/login"}).Body.String()
	if !strings.Contains(body, `name="password"`) {
		t.Fatalf("not the login form: %s", body)
	}
	for _, banned := range []string{"Sign out", `href="/domains"`, `href="/logs"`, `href="/security"`, `href="/sites/new"`} {
		if strings.Contains(body, banned) {
			t.Errorf("login page shows %q to an unauthenticated visitor", banned)
		}
	}
}
