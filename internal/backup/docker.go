package backup

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

const dockerSock = "/var/run/docker.sock"

func dockerGet(path string) ([]byte, error) {
	return dockerDo(http.MethodGet, path, 10*time.Second, http.StatusOK)
}

func dockerDo(method, path string, timeout time.Duration, ok ...int) ([]byte, error) {
	if _, err := os.Stat(dockerSock); err != nil {
		return nil, fmt.Errorf("docker is not available: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c := http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", dockerSock)
	}}}
	req, err := http.NewRequestWithContext(ctx, method, "http://docker"+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if !slices.Contains(ok, resp.StatusCode) {
		return nil, fmt.Errorf("docker: %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 4<<20))
}

// Container is one container that mounts a volume.
type Container struct {
	ID, Name string
	Running  bool
}

var volumeDirRE = regexp.MustCompile(`^/var/lib/docker/volumes/[^/]+/_data$`)
var containerIDRE = regexp.MustCompile(`^[0-9a-f]{12,64}$`)

// ContainersUsing lists the containers (running or not) that mount the named volume.
func ContainersUsing(volume string) ([]Container, error) {
	if !ValidVolume(volume) {
		return nil, fmt.Errorf("volume %q is not a valid volume name", volume)
	}
	f, _ := json.Marshal(map[string][]string{"volume": {volume}})
	b, err := dockerGet("/containers/json?all=1&filters=" + url.QueryEscape(string(f)))
	if err != nil {
		return nil, err
	}
	var cs []struct {
		ID    string
		Names []string
		State string
	}
	if err := json.Unmarshal(b, &cs); err != nil {
		return nil, err
	}
	out := make([]Container, 0, len(cs))
	for _, c := range cs {
		n := c.ID
		if len(c.Names) > 0 {
			n = strings.TrimPrefix(c.Names[0], "/")
		}
		out = append(out, Container{ID: c.ID, Name: n, Running: c.State == "running"})
	}
	return out, nil
}

// StopContainer stops a container (30 s grace). Docker then keeps it down despite its restart policy.
func StopContainer(id string) error {
	if !containerIDRE.MatchString(id) {
		return fmt.Errorf("container id %q is not valid", id)
	}
	_, err := dockerDo(http.MethodPost, "/containers/"+id+"/stop?t=30", 70*time.Second, http.StatusNoContent, http.StatusNotModified)
	return err
}

// StartContainer starts a container.
func StartContainer(id string) error {
	if !containerIDRE.MatchString(id) {
		return fmt.Errorf("container id %q is not valid", id)
	}
	_, err := dockerDo(http.MethodPost, "/containers/"+id+"/start", 30*time.Second, http.StatusNoContent, http.StatusNotModified)
	return err
}

// ContainerRunning reports whether the container is running now.
func ContainerRunning(id string) (bool, error) {
	if !containerIDRE.MatchString(id) {
		return false, fmt.Errorf("container id %q is not valid", id)
	}
	b, err := dockerGet("/containers/" + id + "/json")
	if err != nil {
		return false, err
	}
	var c struct{ State struct{ Running bool } }
	if err := json.Unmarshal(b, &c); err != nil {
		return false, err
	}
	return c.State.Running, nil
}

// DockerVolume resolves a volume's directory through the Docker API; the name is never joined into a path.
func DockerVolume(name string) (string, error) {
	if !ValidVolume(name) {
		return "", fmt.Errorf("volume %q is not a valid volume name", name)
	}
	b, err := dockerGet("/volumes/" + url.PathEscape(name))
	if err != nil {
		return "", fmt.Errorf("volume %s: %w", name, err)
	}
	var v struct{ Mountpoint string }
	if err := json.Unmarshal(b, &v); err != nil {
		return "", err
	}
	if c := filepath.Clean(v.Mountpoint); c != v.Mountpoint || !volumeDirRE.MatchString(c) {
		return "", fmt.Errorf("volume %s: mountpoint %q is not /var/lib/docker/volumes/NAME/_data", name, v.Mountpoint)
	}
	return v.Mountpoint, nil
}

// DockerRunning lists the names of running containers.
func DockerRunning() (map[string]bool, error) {
	b, err := dockerGet("/containers/json")
	if err != nil {
		return nil, err
	}
	var cs []struct{ Names []string }
	if err := json.Unmarshal(b, &cs); err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, c := range cs {
		for _, n := range c.Names {
			out[strings.TrimPrefix(n, "/")] = true
		}
	}
	return out, nil
}
