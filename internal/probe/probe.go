// Package probe checks upstream reachability and certificate state.
package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/caretakarr/caretakarr/internal/store"
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
	addr    string // route ids are reused by SQLite, so state is only valid for the address it probed
}

// Monitor keeps upstream state in memory and probes certificates on demand.
type Monitor struct {
	store     *store.Store
	httpsAddr string // where Caddy serves TLS, e.g. 127.0.0.1:443
	// LogError returns the latest logged issuance error mentioning host, or "". Optional.
	LogError func(host string) string

	mu sync.Mutex
	up map[int64]Upstream
}

func NewMonitor(st *store.Store, httpsAddr string) *Monitor {
	return &Monitor{store: st, httpsAddr: httpsAddr, up: map[int64]Upstream{}}
}

const dialTimeout = 2 * time.Second

func dialRoute(ctx context.Context, r store.Route) Upstream {
	addr := upstreamAddr(r)
	return Upstream{Up: TCP(ctx, addr, dialTimeout) == nil, Checked: time.Now(), addr: addr}
}

// Check probes one route now, so a new route shows a real state before the next sweep.
func (m *Monitor) Check(ctx context.Context, r store.Route) Upstream {
	u := dialRoute(ctx, r)
	if ctx.Err() != nil {
		return u // cancelled, not a real result: do not cache "down"
	}
	m.mu.Lock()
	m.up[r.ID] = u
	m.mu.Unlock()
	return u
}

// Sweep dials every enabled route's upstream once.
func (m *Monitor) Sweep(ctx context.Context) {
	routes, err := m.store.ListRoutes(ctx)
	if err != nil {
		return
	}
	next := make(map[int64]Upstream, len(routes))
	for _, r := range routes {
		if r.Enabled {
			next[r.ID] = dialRoute(ctx, r)
		}
	}
	m.mu.Lock()
	m.up = next
	m.mu.Unlock()
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
func (m *Monitor) Upstream(r store.Route) (Upstream, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.up[r.ID]
	return u, ok && u.addr == upstreamAddr(r)
}

func upstreamAddr(r store.Route) string {
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
