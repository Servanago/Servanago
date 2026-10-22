package web

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/servanago/servanago/internal/helper"
	"github.com/servanago/servanago/internal/store"
)

func ctr(name, state, health string, ip string, pub int) helper.Container {
	return helper.Container{Name: name, ID: "abc123def456", Image: "img/" + name + ":1", State: state, Health: health, Status: state,
		Ports: []helper.DockerPort{{IP: ip, Private: 80, Public: pub, Proto: "tcp"}}, Networks: []string{name + "_default"},
		Project: name, Service: "app", WorkingDir: "/opt/" + name, ConfigFiles: "/opt/" + name + "/compose.yml"}
}

// dockerHost serves docker-list from d on a temp socket and counts the calls.
func dockerHost(t *testing.T, s *Server, d helper.DockerData) *atomic.Int32 {
	t.Helper()
	ln, err := net.Listen("unix", filepath.Join(t.TempDir(), "h.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var calls atomic.Int32
	go helper.Serve(ln, func(helper.Peer) bool { return true }, map[string]helper.Action{
		helper.ActionDockerList: func(helper.Request) helper.Response {
			calls.Add(1)
			return helper.Response{OK: true, Docker: &d}
		},
	})
	s.deps.HelperSocket = ln.Addr().String()
	return &calls
}

func proxySite(t *testing.T, s *Server, host, up string, port int) store.Site {
	t.Helper()
	x, err := s.deps.Store.CreateSite(context.Background(), store.Site{Hostnames: []string{host}, Scheme: "http", UpstreamHost: up, UpstreamPort: port, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	return x
}

// A proxy site is matched to the one container publishing its upstream port on this host; anything else is no match.
func TestMatchContainer(t *testing.T) {
	s, _ := siteServer(t) // HostIP 192.168.25.165
	one := []helper.Container{ctr("ntfy", "running", "", "127.0.0.1", 6910)}
	for _, c := range []struct {
		name string
		site store.Site
		cs   []helper.Container
		want string
	}{
		{"loopback", store.Site{Kind: "proxy", UpstreamHost: "127.0.0.1", UpstreamPort: 6910}, one, "ntfy"},
		{"localhost", store.Site{Kind: "proxy", UpstreamHost: "localhost", UpstreamPort: 6910}, one, "ntfy"},
		{"host ip", store.Site{Kind: "proxy", UpstreamHost: "192.168.25.165", UpstreamPort: 6910}, []helper.Container{ctr("ntfy", "running", "", "192.168.25.165", 6910)}, "ntfy"},
		{"loopback-only publish is not reachable by host ip", store.Site{Kind: "proxy", UpstreamHost: "192.168.25.165", UpstreamPort: 6910}, one, ""},
		{"published on all interfaces", store.Site{Kind: "proxy", UpstreamHost: "127.0.0.1", UpstreamPort: 6910}, []helper.Container{ctr("ntfy", "running", "", "0.0.0.0", 6910)}, "ntfy"},
		{"other port", store.Site{Kind: "proxy", UpstreamHost: "127.0.0.1", UpstreamPort: 6911}, one, ""},
		{"container network ip", store.Site{Kind: "proxy", UpstreamHost: "172.18.0.2", UpstreamPort: 80}, one, ""},
		{"remote host", store.Site{Kind: "proxy", UpstreamHost: "10.0.0.9", UpstreamPort: 6910}, one, ""},
		{"published on another address", store.Site{Kind: "proxy", UpstreamHost: "127.0.0.1", UpstreamPort: 6910}, []helper.Container{ctr("x", "running", "", "10.1.1.1", 6910)}, ""},
		{"two containers", store.Site{Kind: "proxy", UpstreamHost: "127.0.0.1", UpstreamPort: 6910}, append(one, ctr("dup", "running", "", "127.0.0.1", 6910)), ""},
		{"not a proxy", store.Site{Kind: "node", UpstreamHost: "127.0.0.1", UpstreamPort: 6910}, one, ""},
	} {
		got := s.matchContainer(c.site, c.cs)
		if (got == nil && c.want != "") || (got != nil && got.Name != c.want) {
			t.Errorf("%s: got %v, want %q", c.name, got, c.want)
		}
	}
}

func TestDockerIssuesFeedHealth(t *testing.T) {
	row := func(c *helper.Container, errd bool) siteRow {
		return siteRow{Site: store.Site{Kind: "proxy", Enabled: true}, Docker: c, DockerErr: errd}
	}
	for _, c := range []struct {
		name   string
		row    siteRow
		health string
		want   string
	}{
		{"running", row(&helper.Container{State: "running", Health: "healthy"}, false), "ok", ""},
		{"exited", row(&helper.Container{State: "exited"}, false), "issue", "container exited"},
		{"restarting", row(&helper.Container{State: "restarting"}, false), "issue", "container restarting"},
		{"unhealthy", row(&helper.Container{State: "running", Health: "unhealthy"}, false), "issue", "container unhealthy"},
		{"starting is fine", row(&helper.Container{State: "running", Health: "starting"}, false), "ok", ""},
		{"docker unreadable", row(nil, true), "issue", "docker status unavailable"},
		{"no container", row(nil, false), "ok", ""},
	} {
		health, issues := healthOf(c.row, "", nil, nil, dockerIssues(c.row)...)
		if health != c.health || (c.want != "" && !strings.Contains(strings.Join(issues, "; "), c.want)) {
			t.Errorf("%s: got %q %v, want %q containing %q", c.name, health, issues, c.health, c.want)
		}
	}
}

func TestReferenceAndDashboardShowContainer(t *testing.T) {
	s, _ := siteServer(t)
	calls := dockerHost(t, s, helper.DockerData{Present: true, Containers: []helper.Container{
		ctr("ntfy", "exited", "", "127.0.0.1", 6910), ctr("fine", "running", "healthy", "127.0.0.1", 6920)}})
	proxySite(t, s, "ntfy.example.com", "127.0.0.1", 6910)
	proxySite(t, s, "fine.example.com", "127.0.0.1", 6920)
	proxySite(t, s, "none.example.com", "127.0.0.1", 6999)

	ref := s.do(req{path: "/reference"}).Body.String()
	for _, want := range []string{"img/ntfy:1", "/opt/ntfy/compose.yml", "ntfy_default", "container exited", `data-compose="ntfy"`, `data-compose="-"`} {
		if !strings.Contains(ref, want) {
			t.Errorf("reference lacks %q", want)
		}
	}
	dash := s.do(req{path: "/"}).Body.String()
	if !strings.Contains(dash, "container exited") {
		t.Error("dashboard lacks the stopped container's badge")
	}
	if strings.Contains(dash, "container running") || strings.Count(dash, "container exited") != 1 {
		t.Errorf("only the stopped container is flagged on the dashboard:\n%s", dash)
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("%d docker-list calls for two pages inside the cache window, want 1", n)
	}
}

func TestDockerAbsentAndUnreachable(t *testing.T) {
	s, _ := siteServer(t)
	dockerHost(t, s, helper.DockerData{}) // no Docker on the host
	proxySite(t, s, "a.example.com", "127.0.0.1", 6910)
	body := s.do(req{path: "/reference"}).Body.String()
	if strings.Contains(body, "docker status unavailable") || strings.Contains(body, "Container</dt>") {
		t.Errorf("a host without Docker shows Docker output:\n%s", body)
	}

	s2, _ := siteServer(t)
	s2.deps.HelperSocket = t.TempDir() + "/none.sock" // helper down
	proxySite(t, s2, "b.example.com", "127.0.0.1", 6910)
	proxySite(t, s2, "remote.example.com", "10.0.0.9", 6910)
	body = s2.do(req{path: "/reference"}).Body.String()
	if n := strings.Count(body, "docker status unavailable"); n != 1 { // b.example.com only: a remote upstream cannot be a local container
		t.Errorf("%d sites flagged, want 1", n)
	}
	if strings.Contains(s2.do(req{path: "/"}).Body.String(), "docker status unavailable") {
		t.Error("dashboard shows the Docker error")
	}
}
