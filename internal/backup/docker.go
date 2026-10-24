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
	"strings"
	"time"
)

const dockerSock = "/var/run/docker.sock"

func dockerGet(path string) ([]byte, error) {
	if _, err := os.Stat(dockerSock); err != nil {
		return nil, fmt.Errorf("docker is not available: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c := http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", dockerSock)
	}}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("docker: %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 4<<20))
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
	if c := filepath.Clean(v.Mountpoint); c != v.Mountpoint || !strings.HasPrefix(c, "/var/lib/docker/volumes/") {
		return "", fmt.Errorf("volume %s: mountpoint %q is outside /var/lib/docker/volumes", name, v.Mountpoint)
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
