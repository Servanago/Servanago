// Package caddyguard holds the Caddy handler modules of the protection layers. Each is a thin shell: the JSON pins the
// site's slug and the settings SQLite had at render time, the work happens in the guard.Service the app installed.
// With no service installed every module passes the request on (fail open).
package caddyguard

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/servanago/servanago/internal/caddygeoip"
	"github.com/servanago/servanago/internal/guard"
)

func init() {
	caddy.RegisterModule(Traffic{})
	caddy.RegisterModule(Ban{})
	caddy.RegisterModule(Challenge{})
	caddy.RegisterModule(Queue{})
	caddy.RegisterModule(X402{})
}

// clientString is the address the request is attributed to: Caddy's client_ip (already the visitor behind Cloudflare), else the peer.
// clientOf resolves the visitor the layers judge (public unicast only). SetClientOf is a test seam, since every test peer is loopback.
var clientFn atomic.Pointer[func(*http.Request) (netip.Addr, bool)]

func init() { SetClientOf(nil) }

// SetClientOf replaces the resolver; nil restores the real one.
func SetClientOf(f func(*http.Request) (netip.Addr, bool)) {
	if f == nil {
		f = caddygeoip.ClientOf
	}
	clientFn.Store(&f)
}

func ClientOf(r *http.Request) (netip.Addr, bool) { return (*clientFn.Load())(r) }

func clientString(r *http.Request) string {
	if v, ok := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string); ok && v != "" {
		if h, _, err := net.SplitHostPort(v); err == nil {
			return h
		}
		return v
	}
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}

func prefixes(in []string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range in {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p)
		} else if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return out
}

// obsWriter counts bytes and keeps the first status; it buffers nothing and passes Flush and Hijack through.
type obsWriter struct {
	http.ResponseWriter
	status, bytes int
}

func (w *obsWriter) WriteHeader(c int) {
	if w.status == 0 && (c >= 200 || c == http.StatusSwitchingProtocols) {
		w.status = c
	}
	w.ResponseWriter.WriteHeader(c)
}

func (w *obsWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, err
}

func (w *obsWriter) Flush() { _ = http.NewResponseController(w.ResponseWriter).Flush() }

func (w *obsWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return http.NewResponseController(w.ResponseWriter).Hijack()
}

func (w *obsWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Traffic is the observer: it leads every site's chain and records the request once the chain returns.
type Traffic struct {
	Site         string   `json:"site"`
	BanOn        bool     `json:"ban,omitempty"`
	Unknown      bool     `json:"unknown,omitempty"` // the catch-all route for hosts no site owns
	Allow        []string `json:"allow,omitempty"`
	AutoRPS      int      `json:"auto_rps,omitempty"`
	AutoCooldown int      `json:"auto_cooldown_min,omitempty"`
}

func (Traffic) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "http.handlers.servanago_traffic", New: func() caddy.Module { return new(Traffic) }}
}

func (t *Traffic) Provision(caddy.Context) error {
	if s := guard.Current(); s != nil {
		s.Register(guard.SiteCfg{Slug: t.Site, BanOn: t.BanOn, UnknownHost: t.Unknown, AutoRPS: t.AutoRPS,
			AutoCooldown: time.Duration(t.AutoCooldown) * time.Minute, Allow: prefixes(t.Allow)})
	}
	return nil
}

func (t *Traffic) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	s := guard.Current()
	if s == nil {
		return next.ServeHTTP(w, r)
	}
	start := time.Now()
	ow := &obsWriter{ResponseWriter: w}
	err := next.ServeHTTP(ow, r)
	status := ow.status
	var he caddyhttp.HandlerError
	if errors.As(err, &he) && status == 0 {
		status = he.StatusCode
	}
	if status == 0 {
		status = http.StatusOK
	}
	outcome, _ := caddyhttp.GetVar(r.Context(), guard.OutcomeVar).(string)
	switch {
	case t.Unknown:
		outcome = guard.OutUnknownHost
	case outcome == "" && errors.As(err, &he) && he.StatusCode == http.StatusForbidden:
		outcome = guard.OutBlocked // the WAF interrupts through a handler error
	case outcome == "":
		outcome = guard.OutPass
	}
	rec := guard.Record{Site: t.Site, Host: clip(r.Host, 255), Client: clientString(r), Method: r.Method, Path: clip(r.URL.Path, 500), Status: status,
		Bytes: ow.bytes, Dur: time.Since(start), Outcome: outcome, UA: clip(r.UserAgent(), 200), Ref: originOf(r.Referer())}
	if err != nil {
		rec.Err = clip(err.Error(), 200)
	}
	addr, ok := ClientOf(r)
	s.Observe(rec, guard.ClientRef(addr, ok))
	return err
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// originOf reduces a referrer to scheme://host: paths and queries can carry secrets.
func originOf(ref string) string {
	i := strings.Index(ref, "://")
	if i < 0 {
		return ""
	}
	rest := ref[i+3:]
	if j := strings.IndexAny(rest, "/?#"); j >= 0 {
		rest = rest[:j]
	}
	return clip(ref[:i+3]+rest, 200)
}

// Ban refuses a banned client.
type Ban struct{}

func (Ban) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "http.handlers.servanago_ban", New: func() caddy.Module { return new(Ban) }}
}

func (b *Ban) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	s := guard.Current()
	if s == nil || strings.HasPrefix(r.URL.Path, "/.well-known/") {
		return next.ServeHTTP(w, r)
	}
	if addr, ok := ClientOf(r); ok && s.Banned(guard.Key(addr)) {
		guard.SetOutcome(r, guard.OutBanned)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("Forbidden\n"))
		return nil
	}
	return next.ServeHTTP(w, r)
}

// Challenge is the under-attack layer.
type Challenge struct {
	Site       string   `json:"site"`
	Forced     bool     `json:"forced,omitempty"`
	Auto       bool     `json:"auto,omitempty"`
	Kind       string   `json:"kind,omitempty"`
	Difficulty string   `json:"difficulty,omitempty"`
	TTLMin     int      `json:"ttl_min,omitempty"`
	Allow      []string `json:"allow,omitempty"`
	allow      []netip.Prefix
}

func (Challenge) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "http.handlers.servanago_challenge", New: func() caddy.Module { return new(Challenge) }}
}

func (c *Challenge) Provision(caddy.Context) error { c.allow = prefixes(c.Allow); return nil }

func (c *Challenge) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	s := guard.Current()
	if s == nil {
		return next.ServeHTTP(w, r)
	}
	addr, ok := ClientOf(r)
	cfg := guard.ChallengeCfg{Slug: c.Site, Forced: c.Forced, Auto: c.Auto, Kind: c.Kind, Difficulty: c.Difficulty, TTLMin: c.TTLMin, Allow: c.allow}
	if s.Challenge(w, r, cfg, clientString(r), addr, ok) {
		return nil
	}
	return next.ServeHTTP(w, r)
}

// Queue is the access queue (waiting room).
type Queue struct {
	Site      string   `json:"site"`
	Capacity  int      `json:"capacity"`
	ActiveTTL int      `json:"active_ttl_s"`
	MaxQueue  int      `json:"max_queue"`
	Allow     []string `json:"allow,omitempty"`
	allow     []netip.Prefix
}

func (Queue) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "http.handlers.servanago_queue", New: func() caddy.Module { return new(Queue) }}
}

func (q *Queue) Provision(caddy.Context) error { q.allow = prefixes(q.Allow); return nil }

func (q *Queue) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	s := guard.Current()
	if s == nil {
		return next.ServeHTTP(w, r)
	}
	addr, ok := ClientOf(r)
	if s.Queue(w, r, guard.QueueCfg{Slug: q.Site, Capacity: q.Capacity, ActiveTTL: q.ActiveTTL, MaxQueue: q.MaxQueue, Allow: q.allow}, addr, ok) {
		return nil
	}
	return next.ServeHTTP(w, r)
}

// X402 is the paywall.
type X402 struct {
	Site         string      `json:"site"`
	Routes       []X402Route `json:"routes"`
	HasChallenge bool        `json:"has_challenge,omitempty"`
	Allow        []string    `json:"allow,omitempty"`
	allow        []netip.Prefix
}

// X402Route mirrors guard.X402Route in the module JSON.
type X402Route struct {
	Path  string `json:"path"`
	Price string `json:"price"`
	Mode  string `json:"mode"`
	Grant string `json:"grant"`
	TTL   int    `json:"ttl_s"`
}

func (X402) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "http.handlers.servanago_x402", New: func() caddy.Module { return new(X402) }}
}

func (x *X402) Provision(caddy.Context) error { x.allow = prefixes(x.Allow); return nil }

func (x *X402) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	s := guard.Current()
	if s == nil {
		return next.ServeHTTP(w, r)
	}
	cfg := guard.X402Cfg{Slug: x.Site, HasChallenge: x.HasChallenge, Allow: x.allow}
	for _, rt := range x.Routes {
		cfg.Routes = append(cfg.Routes, guard.X402Route{Path: rt.Path, Price: rt.Price, Mode: rt.Mode, Grant: rt.Grant, TTL: rt.TTL})
	}
	addr, ok := ClientOf(r)
	ww, handled := s.X402(w, r, cfg, clientString(r), addr, ok)
	if handled {
		return nil
	}
	return next.ServeHTTP(ww, r)
}

var (
	_ caddyhttp.MiddlewareHandler = (*Traffic)(nil)
	_ caddyhttp.MiddlewareHandler = (*Ban)(nil)
	_ caddyhttp.MiddlewareHandler = (*Challenge)(nil)
	_ caddyhttp.MiddlewareHandler = (*Queue)(nil)
	_ caddyhttp.MiddlewareHandler = (*X402)(nil)
	_ caddy.Provisioner           = (*Traffic)(nil)
)
