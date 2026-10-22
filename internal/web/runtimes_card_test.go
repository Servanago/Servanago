package web

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// bareExec is a host with no node and no PHP at all.
type bareExec struct{}

func (bareExec) LookupPath(string) (string, error) { return "", errors.New("none") }
func (bareExec) Run(context.Context, string, ...string) ([]byte, error) {
	return nil, errors.New("none")
}
func (bareExec) Glob(string) ([]string, error) { return nil, nil }

// ServanaGo builds PHP itself, so a host without PHP is pointed at the PHP page, never at apt.
func TestRuntimesCardPointsAtPHPPage(t *testing.T) {
	s, _ := phpServer(t)
	s.deps.Exec = bareExec{}
	for _, path := range []string{"/", "/sites/new"} {
		body := s.do(req{path: path}).Body.String()
		if strings.Contains(body, "apt install php") {
			t.Errorf("%s still tells the admin to apt install PHP", path)
		}
		if strings.Contains(body, "detects these and never installs them") {
			t.Errorf("%s still says ServanaGo never installs any runtime", path)
		}
		if !strings.Contains(body, `<a href="/php">PHP page</a>`) {
			t.Errorf("%s has no link to the PHP page", path)
		}
	}
}

// Source builds and the distro's php-fpm are listed apart.
func TestRuntimesCardSplitsSourceAndDistroPHP(t *testing.T) {
	s, _ := phpServer(t) // two ServanaGo builds of 8.4 and the distro's php-fpm 8.2
	body := s.do(req{path: "/"}).Body.String()
	for _, want := range []string{"ServanaGo builds", "8.4.27-1", "distro", "8.2"} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard lacks %q", want)
		}
	}
}
