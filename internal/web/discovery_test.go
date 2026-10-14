package web

import (
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caretakarr/caretakarr/internal/discovery"
)

func fakeDocker(t *testing.T, status int, body string) *discovery.Client {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "docker.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return discovery.New(sock)
}

const containersJSON = `[{"Names":["/sonarr"],"Image":"sonarr","Ports":[{"PrivatePort":8989,"Type":"tcp"}],"NetworkSettings":{"Networks":{"media":{}}}},
{"Names":["/plex"],"Image":"plex","Ports":[{"PrivatePort":32400,"Type":"tcp"},{"PrivatePort":8324,"Type":"tcp"}],"NetworkSettings":{"Networks":{}}}]`

func TestDockerPanelAndPrefill(t *testing.T) {
	s, _, _ := newDNSServer(t)
	s.deps.Docker = fakeDocker(t, 200, containersJSON)
	body := s.do(req{path: "/routes/new"}).Body.String()
	for _, want := range []string{"Docker containers", "sonarr", "host=sonarr", "port=8989", "port=32400", "port=8324", "shared Docker network"} {
		if !strings.Contains(body, want) {
			t.Errorf("panel missing %q", want)
		}
	}
	pre := s.do(req{path: "/routes/new?sub=sonarr&host=sonarr&port=8989"}).Body.String()
	for _, want := range []string{`value="sonarr"`, `value="8989"`} {
		if strings.Count(pre, want) < 1 {
			t.Errorf("prefill missing %q", want)
		}
	}
	if !strings.Contains(pre, `name="upstream_host" value="sonarr"`) {
		t.Errorf("upstream host not prefilled")
	}
}

func TestDockerPanelHiddenWithoutSocket(t *testing.T) {
	s, _, _ := newDNSServer(t)
	if body := s.do(req{path: "/routes/new"}).Body.String(); strings.Contains(body, "Docker containers") {
		t.Error("panel shown with no Docker client")
	}
	s.deps.Docker = discovery.New(filepath.Join(t.TempDir(), "absent.sock"))
	if body := s.do(req{path: "/routes/new"}).Body.String(); strings.Contains(body, "Docker containers") {
		t.Error("panel shown for a missing socket")
	}
}

func TestDockerErrorDoesNotBreakThePage(t *testing.T) {
	s, _, _ := newDNSServer(t)
	s.deps.Docker = fakeDocker(t, 500, `{"message":"daemon exploded"}`)
	w := s.do(req{path: "/routes/new"})
	if w.Code != 200 || !strings.Contains(w.Body.String(), "daemon exploded") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}
