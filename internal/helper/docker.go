package helper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"
)

// docker.go: docker-list, a read-only view of the containers on this host. The helper reads Docker's socket so the
// web process never has to (membership of the docker group is root on the host). Only the fixed fields below leave
// here: no environment, no mounts, no commands, and only the four compose labels.

const (
	dockerSocket    = "/var/run/docker.sock"
	maxDockerBody   = 4 << 20
	maxContainers   = 500
	maxDockerString = 512
)

// Container is what the web UI shows for one container.
type Container struct {
	Name        string       `json:"name"`
	ID          string       `json:"id"`
	Image       string       `json:"image"`
	State       string       `json:"state"`  // running | exited | restarting | paused | created | dead
	Status      string       `json:"status"` // Docker's own text, such as "Up 19 minutes (healthy)"
	Health      string       `json:"health,omitempty"`
	Ports       []DockerPort `json:"ports,omitempty"`
	Networks    []string     `json:"networks,omitempty"`
	Volumes     []string     `json:"volumes,omitempty"` // names of the named volumes it mounts (backup restore lists the users of a volume)
	Project     string       `json:"project,omitempty"` // compose labels
	Service     string       `json:"service,omitempty"`
	WorkingDir  string       `json:"working_dir,omitempty"`
	ConfigFiles string       `json:"config_files,omitempty"`
}

// DockerPort is one port mapping; Public is 0 when the port is not published.
type DockerPort struct {
	IP      string `json:"ip,omitempty"`
	Private int    `json:"private"`
	Public  int    `json:"public,omitempty"`
	Proto   string `json:"proto,omitempty"`
}

// DockerData is the docker-list answer. Present is false on a host without Docker.
type DockerData struct {
	Present    bool        `json:"present"`
	Containers []Container `json:"containers,omitempty"`
}

// DockerList reports the containers; it takes no input.
func (a Actions) DockerList(Request) Response {
	d, err := a.s.DockerList()
	if err != nil {
		return Response{Error: err.Error()}
	}
	return Response{OK: true, Docker: &d}
}

func (RealSeam) DockerList() (DockerData, error) { return dockerList(dockerSocket) }

// dockerList asks the daemon on sock for every container. A missing socket means no Docker, not a failure.
func dockerList(sock string) (DockerData, error) {
	if _, err := os.Stat(sock); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return DockerData{}, nil
		}
		return DockerData{}, fmt.Errorf("docker socket: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c := http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/containers/json?all=1", nil)
	if err != nil {
		return DockerData{}, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return DockerData{}, fmt.Errorf("docker: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return DockerData{}, fmt.Errorf("docker: %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDockerBody+1))
	if err != nil {
		return DockerData{}, fmt.Errorf("docker: %w", err)
	}
	if len(body) > maxDockerBody {
		return DockerData{}, fmt.Errorf("docker: answer over %d bytes", maxDockerBody)
	}
	cs, err := parseDockerList(body)
	return DockerData{Present: true, Containers: cs}, err
}

// parseDockerList keeps the fixed fields of Docker's /containers/json answer. Everything in it is the
// container's own text, so each string is clipped.
func parseDockerList(body []byte) ([]Container, error) {
	var raw []struct {
		ID, Image, State, Status string
		Names                    []string
		Ports                    []struct {
			IP          string
			PrivatePort int
			PublicPort  int
			Type        string
		}
		Labels          map[string]string
		NetworkSettings struct{ Networks map[string]json.RawMessage }
		Mounts          []struct{ Type, Name string }
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("docker: %w", err)
	}
	if len(raw) > maxContainers {
		raw = raw[:maxContainers]
	}
	out := make([]Container, 0, len(raw))
	for _, r := range raw {
		c := Container{ID: clip(r.ID, 12), Image: clip(r.Image, maxDockerString), State: clip(r.State, 32), Status: clip(r.Status, maxDockerString),
			Project: clip(r.Labels["com.docker.compose.project"], maxDockerString), Service: clip(r.Labels["com.docker.compose.service"], maxDockerString),
			WorkingDir: clip(r.Labels["com.docker.compose.project.working_dir"], maxDockerString), ConfigFiles: clip(r.Labels["com.docker.compose.project.config_files"], maxDockerString)}
		if len(r.Names) > 0 {
			c.Name = clip(strings.TrimPrefix(r.Names[0], "/"), maxDockerString)
		}
		for _, m := range r.Mounts {
			if m.Type == "volume" && m.Name != "" {
				c.Volumes = append(c.Volumes, clip(m.Name, maxDockerString))
			}
		}
		switch s := r.Status; {
		case strings.Contains(s, "(unhealthy)"):
			c.Health = "unhealthy"
		case strings.Contains(s, "(healthy)"):
			c.Health = "healthy"
		case strings.Contains(s, "(health: starting)"):
			c.Health = "starting"
		}
		for _, p := range r.Ports {
			c.Ports = append(c.Ports, DockerPort{IP: clip(p.IP, 45), Private: p.PrivatePort, Public: p.PublicPort, Proto: clip(p.Type, 8)})
		}
		for n := range r.NetworkSettings.Networks {
			c.Networks = append(c.Networks, clip(n, maxDockerString))
		}
		slices.Sort(c.Networks) // map order is random
		out = append(out, c)
	}
	return out, nil
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
