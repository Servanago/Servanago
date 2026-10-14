// Package discovery lists Docker containers over the Docker socket (opt-in).
package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
)

type Container struct {
	Name     string
	Image    string
	Ports    []int // exposed private TCP ports, ascending
	Networks []string
}

type Client struct {
	sock string
	http *http.Client
}

// New talks to the Docker daemon at sock with stdlib HTTP, avoiding the moby client dependency tree.
func New(sock string) *Client {
	return &Client{sock: sock, http: &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
	}}}
}

// Available reports whether the socket exists, i.e. whether the user mounted it.
func (c *Client) Available() bool {
	if c.sock == "" {
		return false
	}
	fi, err := os.Stat(c.sock)
	return err == nil && fi.Mode()&os.ModeSocket != 0
}

type apiContainer struct {
	Names []string
	Image string
	Ports []struct {
		PrivatePort int
		Type        string
	}
	NetworkSettings struct{ Networks map[string]json.RawMessage }
}

func (c *Client) List(ctx context.Context) ([]Container, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/containers/json", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("docker socket %s: %w", c.sock, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("docker: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var raw []apiContainer
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("decode docker response: %w", err)
	}
	var out []Container
	for _, r := range raw {
		out = append(out, Container{Name: containerName(r.Names), Image: r.Image, Ports: tcpPorts(r), Networks: networkNames(r)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// containerName picks the container's own name: "/name", not a link alias like "/other/name".
func containerName(names []string) string {
	for _, n := range names {
		if n = strings.TrimPrefix(n, "/"); n != "" && !strings.Contains(n, "/") {
			return n
		}
	}
	if len(names) > 0 {
		return strings.TrimPrefix(names[0], "/")
	}
	return ""
}

func tcpPorts(r apiContainer) []int {
	seen := map[int]bool{}
	var ports []int
	for _, p := range r.Ports {
		if p.Type == "tcp" && p.PrivatePort > 0 && !seen[p.PrivatePort] {
			seen[p.PrivatePort] = true
			ports = append(ports, p.PrivatePort)
		}
	}
	sort.Ints(ports)
	return ports
}

func networkNames(r apiContainer) []string {
	var nets []string
	for n := range r.NetworkSettings.Networks {
		nets = append(nets, n)
	}
	sort.Strings(nets)
	return nets
}
