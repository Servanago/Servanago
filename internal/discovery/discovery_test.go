package discovery

import (
	"context"
	"net"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// fakeDocker serves body at /containers/json on a unix socket and returns the socket path.
func fakeDocker(t *testing.T, status int, body string) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "docker.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/containers/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return sock
}

func TestList(t *testing.T) {
	tests := []struct {
		name string
		body string
		want []Container
	}{
		{"typical", `[{"Names":["/sonarr"],"Image":"lscr.io/linuxserver/sonarr","Ports":[{"PrivatePort":8989,"PublicPort":8989,"Type":"tcp"}],"NetworkSettings":{"Networks":{"media":{}}}}]`,
			[]Container{{Name: "sonarr", Image: "lscr.io/linuxserver/sonarr", Ports: []int{8989}, Networks: []string{"media"}}}},
		{"no ports", `[{"Names":["/worker"],"Image":"busybox","Ports":[],"NetworkSettings":{"Networks":{}}}]`,
			[]Container{{Name: "worker", Image: "busybox"}}},
		{"multiple ports sorted, deduped, udp ignored", `[{"Names":["/plex"],"Image":"plex","Ports":[{"PrivatePort":32400,"Type":"tcp"},{"PrivatePort":1900,"Type":"udp"},{"PrivatePort":8324,"Type":"tcp"},{"PrivatePort":32400,"PublicPort":1,"Type":"tcp"}],"NetworkSettings":{"Networks":{"b":{},"a":{}}}}]`,
			[]Container{{Name: "plex", Image: "plex", Ports: []int{8324, 32400}, Networks: []string{"a", "b"}}}},
		{"link alias names skipped", `[{"Names":["/web/db","/db"],"Image":"pg","Ports":[],"NetworkSettings":{"Networks":{}}}]`,
			[]Container{{Name: "db", Image: "pg"}}},
		{"sorted by name", `[{"Names":["/zeta"],"Image":"i","Ports":[],"NetworkSettings":{"Networks":{}}},{"Names":["/alpha"],"Image":"i","Ports":[],"NetworkSettings":{"Networks":{}}}]`,
			[]Container{{Name: "alpha", Image: "i"}, {Name: "zeta", Image: "i"}}},
		{"empty", `[]`, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := New(fakeDocker(t, 200, tt.body))
			got, err := c.List(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %+v\nwant %+v", got, tt.want)
			}
		})
	}
}

func TestListErrors(t *testing.T) {
	if _, err := New(fakeDocker(t, 500, `{"message":"daemon exploded"}`)).List(context.Background()); err == nil || !strings.Contains(err.Error(), "daemon exploded") {
		t.Errorf("status error not surfaced: %v", err)
	}
	if _, err := New(fakeDocker(t, 200, `not json`)).List(context.Background()); err == nil {
		t.Error("bad json accepted")
	}
}

func TestAvailable(t *testing.T) {
	if !New(fakeDocker(t, 200, `[]`)).Available() {
		t.Error("existing socket reported absent")
	}
	if New(filepath.Join(t.TempDir(), "nope.sock")).Available() {
		t.Error("missing socket reported present")
	}
	if New("").Available() {
		t.Error("empty path reported present")
	}
}
