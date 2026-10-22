package helper

import (
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

const dockerJSON = `[
 {"Id":"ceeffbff52a5aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","Names":["/ntfy-ntfy-1"],"Image":"binwiederhier/ntfy:v2","State":"running","Status":"Up 19 minutes (healthy)",
  "Ports":[{"IP":"127.0.0.1","PrivatePort":80,"PublicPort":6910,"Type":"tcp"},{"PrivatePort":443,"Type":"tcp"}],
  "Labels":{"com.docker.compose.project":"ntfy","com.docker.compose.service":"ntfy","com.docker.compose.project.working_dir":"/opt/ntfy","com.docker.compose.project.config_files":"/opt/ntfy/compose.yml","secret":"nope"},
  "NetworkSettings":{"Networks":{"ntfy_default":{"IPAddress":"172.18.0.2"}}},
  "Env":["PASSWORD=hunter2"]},
 {"Id":"1234","Names":["/old"],"Image":"x","State":"exited","Status":"Exited (1) 3 hours ago","Ports":[],"Labels":null,"NetworkSettings":{"Networks":{}}},
 {"Id":"5678","Names":["/sick"],"Image":"y","State":"running","Status":"Up 2 hours (unhealthy)"}
]`

func TestParseDockerList(t *testing.T) {
	cs, err := parseDockerList([]byte(dockerJSON))
	if err != nil || len(cs) != 3 {
		t.Fatalf("parse: %v %+v", err, cs)
	}
	n := cs[0]
	if n.Name != "ntfy-ntfy-1" || n.ID != "ceeffbff52a5" || n.Image != "binwiederhier/ntfy:v2" || n.State != "running" || n.Health != "healthy" {
		t.Errorf("ntfy: %+v", n)
	}
	if len(n.Ports) != 2 || n.Ports[0] != (DockerPort{IP: "127.0.0.1", Private: 80, Public: 6910, Proto: "tcp"}) {
		t.Errorf("ports: %+v", n.Ports)
	}
	if n.Project != "ntfy" || n.Service != "ntfy" || n.WorkingDir != "/opt/ntfy" || n.ConfigFiles != "/opt/ntfy/compose.yml" || len(n.Networks) != 1 || n.Networks[0] != "ntfy_default" {
		t.Errorf("compose/networks: %+v", n)
	}
	if cs[1].State != "exited" || cs[1].Health != "" || cs[2].Health != "unhealthy" {
		t.Errorf("states: %+v %+v", cs[1], cs[2])
	}
	// Nothing outside the fixed fields survives: no env values, no other labels.
	if got := strings.Join([]string{n.Name, n.Image, n.Status, n.Project}, "|"); strings.Contains(got, "hunter2") || strings.Contains(got, "nope") {
		t.Errorf("leaked: %s", got)
	}
	if _, err := parseDockerList([]byte("{not json")); err == nil {
		t.Error("bad JSON accepted")
	}
}

// dockerList talks HTTP over the socket, reports a missing socket as "no Docker", and refuses an oversized answer.
func TestDockerListOverSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "docker.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var path string
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.RequestURI()
		_, _ = w.Write([]byte(dockerJSON))
	})}
	go srv.Serve(ln) //nolint:errcheck // closed below
	t.Cleanup(func() { _ = srv.Close() })

	d, err := dockerList(sock)
	if err != nil || !d.Present || len(d.Containers) != 3 {
		t.Fatalf("list: %+v %v", d, err)
	}
	if path != "/containers/json?all=1" {
		t.Errorf("requested %q", path)
	}
	d, err = dockerList(filepath.Join(t.TempDir(), "absent.sock"))
	if err != nil || d.Present {
		t.Errorf("missing socket: %+v %v", d, err)
	}
}

func TestDockerListAction(t *testing.T) {
	seam := newFakeSeam()
	seam.docker = DockerData{Present: true, Containers: []Container{{Name: "a", State: "running"}}}
	req, err := DecodeRequest([]byte(`{"action":"docker-list","spec":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	resp := NewActions(seam).DockerList(req)
	if !resp.OK || resp.Docker == nil || len(resp.Docker.Containers) != 1 {
		t.Fatalf("resp: %+v", resp)
	}
	// The action takes no input: a field is refused at decode.
	if _, err := DecodeRequest([]byte(`{"action":"docker-list","spec":{"slug":"x","extra":"y"}}`)); err == nil {
		t.Error("unknown spec field accepted")
	}
}
