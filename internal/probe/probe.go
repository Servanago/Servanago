// Package probe checks upstream reachability and certificate state.
package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/servanago/servanago/internal/store"
)

const (
	StateIssued  = "issued"
	StatePending = "pending"
	StateError   = "error"
)

// TCP reports nil when addr accepts a connection within timeout.
func TCP(ctx context.Context, addr string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	return c.Close()
}

type CertInfo struct {
	NotAfter time.Time
	Issuer   string
}

type CertStatus struct {
	State    string
	NotAfter time.Time
	Issuer   string
	Err      string
}

// certStatus maps a handshake outcome to a UI state. logErr is the latest ACME/issuance error
// logged for the host ("" if none); it only matters when there is no usable certificate.
func certStatus(info CertInfo, handshakeErr error, logErr string, now time.Time) CertStatus {
	switch {
	case handshakeErr == nil && now.Before(info.NotAfter):
		return CertStatus{State: StateIssued, NotAfter: info.NotAfter, Issuer: info.Issuer}
	case handshakeErr == nil:
		return CertStatus{State: StateError, NotAfter: info.NotAfter, Issuer: info.Issuer, Err: "certificate expired"}
	case logErr != "":
		return CertStatus{State: StateError, Err: logErr}
	default:
		return CertStatus{State: StatePending}
	}
}

type Upstream struct {
	Up      bool
	Checked time.Time
	addr    string // site ids are reused by SQLite, so state is only valid for the address it probed
}

// Monitor keeps upstream state in memory and probes certificates on demand.
type Monitor struct {
	store     *store.Store
	httpsAddr string // where Caddy serves TLS, e.g. 127.0.0.1:443
	// Dial checks one upstream address; tests replace it to stay off the real network.
	Dial func(ctx context.Context, addr string, timeout time.Duration) error
	// LogError returns the latest logged issuance error mentioning host, or "". Optional.
	LogError func(host string) string

	mu sync.Mutex
	up map[int64]Upstream

	backends backendState
	// OnBackend, when set, hears every failover backend going down or coming back (the alerts layer).
	OnBackend func(slug, addr string, up bool)
}

func NewMonitor(st *store.Store, httpsAddr string) *Monitor {
	return &Monitor{store: st, httpsAddr: httpsAddr, up: map[int64]Upstream{}, Dial: TCP}
}

const dialTimeout = 2 * time.Second

func (m *Monitor) dialSite(ctx context.Context, r store.Site) Upstream {
	addr := upstreamAddr(r)
	return Upstream{Up: m.Dial(ctx, addr, dialTimeout) == nil, Checked: time.Now(), addr: addr}
}

// Check probes one site now, so a new site shows a real state before the next sweep.
func (m *Monitor) Check(ctx context.Context, r store.Site) Upstream {
	u := m.dialSite(ctx, r)
	if ctx.Err() != nil {
		return u // cancelled, not a real result: do not cache "down"
	}
	m.mu.Lock()
	m.up[r.ID] = u
	m.mu.Unlock()
	return u
}

// Sweep dials every enabled site's upstream once.
func (m *Monitor) Sweep(ctx context.Context) {
	routes, err := m.store.ListSites(ctx)
	if err != nil {
		return
	}
	var enabled []store.Site
	for _, r := range routes {
		if r.Enabled && r.HasUpstream() { // static and php sites have no upstream to dial
			enabled = append(enabled, r)
		}
	}
	results := make([]Upstream, len(enabled))
	Parallel(len(enabled), func(i int) { results[i] = m.dialSite(ctx, enabled[i]) })
	next := make(map[int64]Upstream, len(enabled))
	for i, r := range enabled {
		next[r.ID] = results[i]
	}
	m.mu.Lock()
	m.up = next
	m.mu.Unlock()
	if m.OnBackend != nil {
		m.WatchBackends(ctx, routes, m.OnBackend)
	}
}

// Run sweeps immediately and then every interval until ctx ends.
func (m *Monitor) Run(ctx context.Context, interval time.Duration) {
	m.Sweep(ctx)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.Sweep(ctx)
		}
	}
}

// Upstream returns the last probe of r's current upstream address, if there is one.
func (m *Monitor) Upstream(r store.Site) (Upstream, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.up[r.ID]
	return u, ok && u.addr == upstreamAddr(r)
}

func upstreamAddr(r store.Site) string {
	return net.JoinHostPort(r.UpstreamHost, strconv.Itoa(r.UpstreamPort))
}

// Cert handshakes with the local Caddy using host as SNI and reads the leaf certificate.
func (m *Monitor) Cert(ctx context.Context, host string) CertStatus {
	info, err := leaf(ctx, m.httpsAddr, host)
	logErr := ""
	if err != nil && m.LogError != nil {
		logErr = m.LogError(host)
	}
	return certStatus(info, err, logErr, time.Now())
}

func leaf(ctx context.Context, addr, host string) (CertInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	d := tls.Dialer{Config: &tls.Config{ServerName: host, InsecureSkipVerify: true}} // we read the cert, not trust it
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return CertInfo{}, err
	}
	defer c.Close()
	certs := c.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return CertInfo{}, errors.New("no certificate presented")
	}
	return CertInfo{NotAfter: certs[0].NotAfter, Issuer: certs[0].Issuer.CommonName}, nil
}

const maxParallel = 16

// Parallel runs fn(0..n-1) with at most maxParallel in flight and waits for all of them.
// Probes spend their time waiting on dials, so serial loops scale with the slowest upstream times N.
func Parallel(n int, fn func(i int)) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxParallel)
	for i := range n {
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() { <-sem; wg.Done() }()
			fn(i)
		}()
	}
	wg.Wait()
}

// backendState remembers the last state of every probed upstream address (the site's own and its extra backends), by slug|addr.
type backendState struct {
	mu   sync.Mutex
	last map[string]bool
}

// WatchBackends probes each enabled proxy site's upstreams (the main one and the extra failover backends) and calls
// notify on a change: the first sighting of a dead one, and every later up/down transition.
func (m *Monitor) WatchBackends(ctx context.Context, sites []store.Site, notify func(slug, addr string, up bool)) {
	type probeJob struct {
		slug, addr string
	}
	var jobs []probeJob
	seen := map[string]bool{}
	for _, r := range sites {
		if !r.Enabled || (r.Kind != "proxy" && r.Kind != "") || r.Guard == nil || r.Guard.Backends == "" {
			continue // only sites with failover backends: a single upstream has the dashboard's own health column
		}
		for _, a := range append([]string{upstreamAddr(r)}, strings.Fields(r.Guard.Backends)...) {
			if k := r.Slug + "|" + a; !seen[k] {
				seen[k] = true
				jobs = append(jobs, probeJob{r.Slug, a})
			}
		}
	}
	up := make([]bool, len(jobs))
	Parallel(len(jobs), func(i int) { up[i] = m.Dial(ctx, jobs[i].addr, dialTimeout) == nil })
	if ctx.Err() != nil {
		return
	}
	m.backends.mu.Lock()
	defer m.backends.mu.Unlock()
	if m.backends.last == nil {
		m.backends.last = map[string]bool{}
	}
	now := map[string]bool{}
	for i, j := range jobs {
		k := j.slug + "|" + j.addr
		prev, known := m.backends.last[k]
		now[k] = up[i]
		if (known && prev != up[i]) || (!known && !up[i]) {
			notify(j.slug, j.addr, up[i])
		}
	}
	m.backends.last = now
}
