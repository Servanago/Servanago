package web

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/servanago/servanago/internal/helper"
	"github.com/servanago/servanago/internal/store"
)

// docker.go: which container a proxy site points at. The helper lists the containers (docker-list); a site matches
// the one container that publishes its upstream port on this host. Container-network addresses, remote upstreams and
// ambiguous ports match nothing: showing no container beats showing the wrong one.

const dockerCacheFor = 5 * time.Second // the dashboard polls every 10 s and the Reference page adds its own load

type dockerCache struct {
	mu   sync.Mutex
	at   time.Time
	data helper.DockerData
	err  error
}

// dockerData is the helper's container list, fetched at most once per dockerCacheFor, failures included.
func (s *Server) dockerData(ctx context.Context) (helper.DockerData, error) {
	c := &s.docker
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.at.IsZero() && time.Since(c.at) < dockerCacheFor {
		return c.data, c.err
	}
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	resp, err := s.helperClient().Call(cctx, helper.ActionDockerList, helper.Spec{})
	c.at, c.data, c.err = time.Now(), helper.DockerData{}, err
	if err == nil && resp.Docker != nil {
		c.data = *resp.Docker
	}
	return c.data, c.err
}

// localUpstream is true for a proxy site whose upstream is a port on this machine.
func (s *Server) localUpstream(rt store.Site) bool {
	return rt.Kind == "proxy" && (slices.Contains([]string{"127.0.0.1", "localhost", "::1", "0.0.0.0"}, rt.UpstreamHost) ||
		rt.UpstreamHost != "" && rt.UpstreamHost == s.deps.Cfg.HostIP)
}

// matchContainer is the one container publishing the site's upstream port on an address the upstream reaches, or nil.
func (s *Server) matchContainer(rt store.Site, cs []helper.Container) *helper.Container {
	if !s.localUpstream(rt) {
		return nil
	}
	var found *helper.Container
	for i := range cs {
		for _, p := range cs[i].Ports {
			if p.Public != rt.UpstreamPort || !s.reachable(p.IP, rt.UpstreamHost) {
				continue
			}
			if found != nil && found != &cs[i] {
				return nil // two containers on one port: do not guess
			}
			found = &cs[i]
		}
	}
	return found
}

// reachable is true when a port published on pub answers at the upstream host.
func (s *Server) reachable(pub, upstream string) bool {
	switch pub {
	case "", "0.0.0.0", "::":
		return true
	case "127.0.0.1", "::1":
		return upstream != s.deps.Cfg.HostIP || s.deps.Cfg.HostIP == ""
	}
	return pub == upstream
}

// dockerIssues are the reasons the container (or the failure to read it) makes the site an issue.
func dockerIssues(r siteRow) []string {
	var out []string
	switch {
	case r.DockerErr:
		out = append(out, "docker status unavailable")
	case r.Docker != nil:
		if r.Docker.State != "running" {
			out = append(out, "container "+r.Docker.State)
		} else if r.Docker.Health == "unhealthy" {
			out = append(out, "container unhealthy")
		}
	}
	return out
}

// DockerBad is true when the dashboard should flag the container: stopped, restarting or unhealthy.
func (r siteRow) DockerBad() bool {
	return r.Docker != nil && (r.Docker.State != "running" || r.Docker.Health == "unhealthy")
}

// attachContainers fills Docker on every row that can have a container. Docker being absent leaves the rows alone;
// Docker being unreadable marks the rows that could have matched.
func (s *Server) attachContainers(ctx context.Context, rows []siteRow) {
	if !slices.ContainsFunc(rows, func(r siteRow) bool { return s.localUpstream(r.Site) }) {
		return
	}
	d, err := s.dockerData(ctx)
	for i := range rows {
		switch {
		case !s.localUpstream(rows[i].Site):
		case err != nil:
			rows[i].DockerErr = true
		case d.Present:
			rows[i].Docker = s.matchContainer(rows[i].Site, d.Containers)
		}
	}
}
