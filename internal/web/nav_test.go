package web

import (
	"regexp"
	"strings"
	"testing"
)

// current returns the labels of nav links marked aria-current="page".
func current(body string) []string {
	re := regexp.MustCompile(`<a [^>]*aria-current="page"[^>]*>(?:<svg.*?</svg>)?([^<]+)</a>`)
	var out []string
	for _, m := range re.FindAllStringSubmatch(body, -1) {
		out = append(out, strings.TrimSpace(m[1]))
	}
	return out
}

func TestTopbarNavMarksCurrentPage(t *testing.T) {
	s := newServer(t, "pw")
	ck := cookiesOf(t, login(s, "pw", nil, ""))

	body := s.do(req{path: "/", cookies: ck}).Body.String()
	for _, want := range []string{"class=\"topbar\"", `href="/domains"`, "usermenu", `href="/settings"`, `href="/users"`, `href="/audit"`, `href="/security"`, `href="/sites/new"`} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard lacks %q", want)
		}
	}
	if strings.Contains(body, "<aside") {
		t.Error("the app still renders a sidebar")
	}
	if got := current(body); len(got) != 1 || got[0] != "Sites" {
		t.Errorf("dashboard current = %v, want [Sites]", got)
	}
	for path, label := range map[string]string{"/domains": "Domains", "/snippets": "Snippets", "/reference": "Reference", "/php": "PHP", "/backups": "Backups", "/audit": "Audit trail", "/settings": "Settings", "/help": "Help", "/users": "Users", "/scan": "Scan", "/mail": "Mail"} {
		if got := current(s.do(req{path: path, cookies: ck}).Body.String()); len(got) != 1 || got[0] != label {
			t.Errorf("%s current = %v, want [%s]", path, got, label)
		}
	}
	if got := current(s.do(req{path: "/sites/new", cookies: ck}).Body.String()); len(got) != 1 || got[0] != "Sites" {
		t.Errorf("site form current = %v, want [Sites]", got)
	}
}

func TestOpenModeHidesAccountLinks(t *testing.T) {
	s, _ := siteServer(t)
	body := s.do(req{path: "/"}).Body.String()
	for _, gone := range []string{`href="/users"`, `href="/audit"`, `href="/security"`, "Sign out", "usermenu"} {
		if strings.Contains(body, gone) {
			t.Errorf("open UI shows %q", gone)
		}
	}
}

func TestSignInPagesHaveNoAppShell(t *testing.T) {
	s := newServer(t, "pw")
	if body := s.do(req{path: "/login"}).Body.String(); strings.Contains(body, "<aside") || strings.Contains(body, "topbar") || strings.Contains(body, "toasts") {
		t.Error("sign-in page renders the app shell")
	}
}
