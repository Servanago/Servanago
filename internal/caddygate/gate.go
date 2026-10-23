// Package caddygate is the Caddy handler module putting a magic-link gate in front of gated
// routes. The module is thin: the flow lives on Service, which is installed per process before
// the first caddy.Load (same pattern as caddylog.Sink) and talks straight to the store, with
// no HTTP hop. Fail closed everywhere (DESIGN.md §18).
package caddygate

import (
	"context"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/servanago/servanago/internal/gatelogic"
	"github.com/servanago/servanago/internal/postmark"
	"github.com/servanago/servanago/internal/secretbox"
	"github.com/servanago/servanago/internal/smtpx"
	"github.com/servanago/servanago/internal/store"
)

const (
	CookieName = "servanago_gate"
	Prefix     = "/_gate"
	tokenTTL   = 15 * time.Minute
)

// Mailer sends the magic link; smtpx.Dialer is the production implementation.
type Mailer interface {
	Send(from, to, subject, body string) error
}

// SettingsSource returns the site's own mail setup from app state; ok=false means cannot deliver
// right now. Wired at boot: reads the site row in SQLite and opens its sealed credential.
type SettingsSource func(siteID int64) (Mailer, string, bool)

// SiteMailer builds the site's mailer and sender from its row, unsealing the credential with the secret key.
func SiteMailer(key string, r store.Site) (Mailer, string, error) {
	if !r.GateMailReady() {
		return nil, "", fmt.Errorf("site %d has no mail provider set up", r.ID)
	}
	var secret string
	if r.GateSecret != nil {
		b, err := secretbox.Open(key, r.GateSecret)
		if err != nil {
			return nil, "", fmt.Errorf("unseal the mail credential: %w", err)
		}
		secret = string(b)
	}
	if r.GateProvider == "postmark" {
		return postmark.Client{Token: secret}, r.GateFrom, nil
	}
	return smtpx.Dialer{Host: r.GateSMTPHost, Port: r.GateSMTPPort, User: r.GateSMTPUser, Pass: secret}, r.GateFrom, nil
}

func init() { caddy.RegisterModule(Handler{}) }

// Handler is the Caddy module config. It carries the route's host, mode and id, so the
// rendered JSON pins them to what SQLite said at render time.
type Handler struct {
	SiteID int64  `json:"site_id"`
	Host   string `json:"host"`
	Mode   string `json:"mode"` // acl | open, never empty when rendered
	// Primary is the site's main hostname. Set, the route runs in one of three roles by Host: the primary (serves the
	// site, holds the session), "ml."+Primary (request form and link only, hands the session to the primary) or an
	// alias (redirects to the primary). Empty = a single host that does everything.
	Primary string `json:"primary,omitempty"`
}

func (h Handler) mlHost() string { return "ml." + h.Primary }

// linkHost is where the emailed link opens.
func (h Handler) linkHost() string {
	if h.Primary == "" {
		return h.Host
	}
	return h.mlHost()
}

func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "http.handlers.servanago_gate", New: func() caddy.Module { return new(Handler) }}
}

// nextFunc is the rest of the route chain: the Caddy handler returns errors, plain handlers do not.
type nextFunc func(http.ResponseWriter, *http.Request) error

// Handler.ServeHTTP delegates to the installed Service; nothing is ever proxied through when
// the process forgot to install one (fail closed).
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	s := Current()
	if s == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return nil
	}
	return s.handle(w, r, func(w http.ResponseWriter, r *http.Request) error { return next.ServeHTTP(w, r) }, *h)
}

var _ caddyhttp.MiddlewareHandler = (*Handler)(nil)

// current is the installed Service. Set by Install before the first caddy.Load.
var current atomic.Pointer[Service]

func Install(s *Service) { current.Store(s) }

func Current() *Service {
	return current.Load()
}

type Service struct {
	st     *store.Store
	src    SettingsSource
	secret string // SERVANAGO_SECRET_KEY; empty = issuance disabled, sessions still check
	port   int    // HTTPS listen port; 443 = default, shown in magic links otherwise

	lim limiter
	now func() time.Time
}

// New builds the service. All optional pieces degrade to refusing issuance, never to opening.
func New(st *store.Store, src SettingsSource, secret string, port int) *Service {
	return &Service{st: st, src: src, secret: secret, port: port, now: time.Now}
}

// Wrap turns a Handler config into a plain http.Handler for tests.
func (s *Service) Wrap(h Handler, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = s.handle(w, r, func(w http.ResponseWriter, r *http.Request) error { next.ServeHTTP(w, r); return nil }, h)
	})
}

func (s *Service) ctx(r *http.Request) (context.Context, string) { // ctx and the RFC3339 now string
	return r.Context(), s.now().UTC().Format(time.RFC3339)
}

// origin is the scheme, host and non-default port a visitor's browser must use for host.
func (s *Service) origin(host string) string {
	if s.port != 443 {
		return fmt.Sprintf("https://%s:%d", host, s.port)
	}
	return "https://" + host
}

func (s *Service) handle(w http.ResponseWriter, r *http.Request, next nextFunc, h Handler) error {
	switch {
	case h.Primary != "" && h.Host != h.Primary && h.Host != h.mlHost(): // alias: one place holds the session
		http.Redirect(w, r, s.origin(h.Primary)+r.URL.RequestURI(), http.StatusFound)
		return nil
	case h.Primary != "" && h.Host == h.mlHost() && strings.HasPrefix(r.URL.Path, Prefix+"/verify/"):
		s.verifyML(w, r, h)
		return nil
	case h.Primary != "" && h.Host == h.mlHost() && r.URL.Path != Prefix+"/request":
		http.NotFound(w, r) // the ml host never serves the site
		return nil
	case r.URL.Path == Prefix+"/request":
		if r.Method == http.MethodPost {
			s.request(w, r, h)
			return nil
		}
		s.page(w, pageData{Title: "Site access", Heading: "Request access to " + h.Host, Form: true})
		return nil
	case strings.HasPrefix(r.URL.Path, Prefix+"/verify/"):
		s.verify(w, r, h)
		return nil
	default:
		return s.guarded(w, r, next, h)
	}
}

// guarded passes a valid session with a grant on this route; anything else gets the portal.
func (s *Service) guarded(w http.ResponseWriter, r *http.Request, next nextFunc, h Handler) error {
	ctx, at := s.ctx(r)
	if c, err := r.Cookie(CookieName); err == nil && c.Value != "" {
		email, ok, err := s.st.Session(ctx, sha256hex(c.Value), at)
		if err != nil {
			slog.Error("gate session lookup failed", "host", h.Host, "error", err)
			w.WriteHeader(http.StatusServiceUnavailable) // fail closed
			return nil
		}
		if ok {
			good := h.Mode == "open"
			if !good {
				grants, gerr := s.st.Grants(ctx, h.SiteID)
				if gerr != nil {
					slog.Error("gate grants lookup failed", "host", h.Host, "error", gerr)
					w.WriteHeader(http.StatusServiceUnavailable)
					return nil
				}
				good = gatelogic.Qualify(email, grantsToRules(grants))
			}
			if good {
				_ = s.st.TouchSession(ctx, sha256hex(c.Value), at, gatelogic.Window(h.Mode))
				return next(w, r)
			}
		}
	}
	s.page(w, pageData{Title: "Site access", Heading: "Request access to " + h.Host, Form: true})
	return nil
}

func (s *Service) request(w http.ResponseWriter, r *http.Request, h Handler) {
	ip := clientIP(r)
	if !s.lim.allow("ip:"+ip, 20, time.Hour, s.now()) {
		s.page(w, pageData{Title: "Site access", Heading: "Too many requests", Note: "Try again later."})
		return
	}
	email, err := gatelogic.NormalizeEmail(r.PostFormValue("email"))
	if err != nil {
		s.page(w, pageData{Title: "Site access", Heading: "Enter your email address", Form: true, Invalid: "That does not look like an email address. Try again."})
		return
	}
	if !s.lim.allow("email:"+sha256hex(email), 5, time.Hour, s.now()) {
		s.page(w, pageData{Title: "Site access", Heading: "Too many requests", Note: "Try again later."})
		return
	}
	ctx, at := s.ctx(r)
	if h.Mode == "acl" { // open routes issue for any parseable address
		grants, gerr := s.st.Grants(ctx, h.SiteID)
		if gerr != nil {
			slog.Error("gate grants lookup failed", "host", h.Host, "error", gerr)
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if !gatelogic.Qualify(email, grantsToRules(grants)) {
			s.page(w, pageData{Title: "Check your email", Heading: "Check your email"}) // identical: no enumeration
			return
		}
	}
	mailer, from, ok := s.src(h.SiteID)
	if !ok || s.secret == "" {
		slog.Error("gate issuance refused: mail or secret key not configured", "host", h.Host)
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	raw := newToken()
	if err := s.st.IssueToken(ctx, sha256hex(raw), h.linkHost(), email, at, tokenTTL); err != nil {
		slog.Error("gate token issue failed", "host", h.Host, "error", err)
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	go s.deliver(email, h.Host, s.origin(h.linkHost()), raw, mailer, from)
	s.page(w, pageData{Title: "Check your email", Heading: "Check your email"})
}

// deliver is detached: a slow SMTP server must not strand the token or stall the response.
func (s *Service) deliver(email, host, origin, token string, mailer Mailer, from string) {
	body := "A link to open " + host + " is below.\n\n" +
		origin + Prefix + "/verify/" + token + "\n\n" +
		"It expires in 15 minutes and works once. If you did not ask for this, ignore it:\n" +
		"forwarding the link would give away access."
	if err := mailer.Send(from, email, "Access link for "+host, body); err != nil {
		slog.Error("gate mail send failed", "host", host, "error", err)
		return
	}
	slog.Info("gate link sent", "event", "gate.link", "host", host)
}

// verifyML consumes the emailed link on the ml host and hands the visitor to the primary with a fresh
// one-time code (a minute, bound to the primary host), which the primary's verify turns into the cookie.
func (s *Service) verifyML(w http.ResponseWriter, r *http.Request, h Handler) {
	ip := clientIP(r)
	if !s.lim.allow("tok:"+ip, 30, time.Hour, s.now()) {
		s.page(w, pageData{Title: "Site access", Heading: "Too many requests", Note: "Try again later."})
		return
	}
	ctx, at := s.ctx(r)
	email, ok, err := s.st.ConsumeToken(ctx, sha256hex(strings.TrimPrefix(r.URL.Path, Prefix+"/verify/")), h.Host, at)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable) // fail closed
		return
	}
	if !ok || s.secret == "" {
		s.page(w, pageData{Title: "Link expired", Heading: "This link has expired or was already used.", Note: "Request a new one from the site."})
		return
	}
	code := newToken()
	if err := s.st.IssueToken(ctx, sha256hex(code), h.Primary, email, at, time.Minute); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	http.Redirect(w, r, s.origin(h.Primary)+Prefix+"/verify/"+code, http.StatusSeeOther)
}

// verify consumes the link and mints the session cookie for this host.
func (s *Service) verify(w http.ResponseWriter, r *http.Request, h Handler) {
	ip := clientIP(r)
	if !s.lim.allow("tok:"+ip, 30, time.Hour, s.now()) {
		s.page(w, pageData{Title: "Site access", Heading: "Too many requests", Note: "Try again later."})
		return
	}
	token := strings.TrimPrefix(r.URL.Path, Prefix+"/verify/")
	ctx, at := s.ctx(r)
	email, ok, err := s.st.ConsumeToken(ctx, sha256hex(token), h.Host, at)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable) // fail closed
		return
	}
	if !ok || s.secret == "" {
		s.page(w, pageData{Title: "Link expired", Heading: "This link has expired or was already used.", Note: "Request a new one from the site."})
		return
	}
	nonce, err := s.st.IdentityNonce(ctx, email)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	if nonce == "" {
		nonce = newToken()[:24]
	}
	win := gatelogic.Window(h.Mode)
	secret := s.sessionSecret(email, nonce)
	value := base64.RawURLEncoding.EncodeToString([]byte(secret)) // exactly what the cookie carries
	if err := s.st.UpsertIdentity(ctx, email, nonce, sha256hex(value), at, win); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	_ = s.st.TouchSession(ctx, sha256hex(value), at, win)
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: value,
		Path: "/", MaxAge: int(win / time.Second), HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: r.TLS != nil})
	slog.Info("gate session", "event", "gate.verified", "host", h.Host)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// sessionSecret derives the (never-stored, deterministically recoverable) session secret for
// an identity: HKDF over the operator secret key, the email and the identity's random nonce.
func (s *Service) sessionSecret(email, nonce string) string {
	master := sha256.Sum256([]byte(s.secret))
	d, err := hkdf.Key(sha256.New, master[:], []byte("servanago-gate"), "gate|"+email+"|"+nonce, 32)
	if err != nil { // only fails when keyLength exceeds 255*hash size
		panic(err)
	}
	return string(d)
}

func sha256hex(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func newToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func grantsToRules(gs []store.Grant) []gatelogic.Rule {
	out := make([]gatelogic.Rule, len(gs))
	for i, g := range gs {
		out[i] = gatelogic.Rule{Mode: g.Mode, Value: g.Value}
	}
	return out
}

// clientIP is the TCP peer. The gate runs before reverse_proxy rewrites X-Forwarded-For and
// no proxy sits in front of Caddy, so the header is attacker-controlled here.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// limiter is the in-memory bucket: per key, timestamped hits inside a sliding window.
type limiter struct {
	mu   sync.Mutex
	hits map[string][]time.Time
}

func (l *limiter) allow(key string, max int, win time.Duration, at time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	keep := at.Add(-win)
	var fresh []time.Time
	for _, t := range l.hits[key] {
		if t.After(keep) {
			fresh = append(fresh, t)
		}
	}
	if len(fresh) >= max {
		l.hits[key] = fresh
		return false
	}
	if l.hits == nil {
		l.hits = map[string][]time.Time{}
	}
	l.hits[key] = append(fresh, at)
	return true
}

// pageData drives the three portal pages and the two terminal ones.
type pageData struct {
	Title   string
	Heading string
	Note    string
	Form    bool
	Invalid string
}

var portal = template.Must(template.New("p").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}</title>
<style>
body{display:grid;place-items:center;min-height:100vh;margin:0;font:16px system-ui,sans-serif;background:#0f1720;color:#e2e8f0}
main{max-width:26rem;padding:2.5rem 2rem;background:#18202b;border:1px solid #2b3648;border-radius:.75rem;text-align:center}
h1{font-size:1.1rem;margin:.2rem 0 1rem}form{display:grid;gap:.75rem;margin-top:1rem}
input,button{font:inherit;padding:.55rem .75rem;border-radius:.4rem;border:1px solid #2b3648}
input{background:#0f1720;color:#e2e8f0}small{color:#93a3b5}button{background:#08b3c6;color:#06222a;border:0;font-weight:600}
</style></head><body>
<main><h1>{{.Heading}}</h1>
{{if .Note}}<p>{{.Note}}</p>{{end}}
{{if .Invalid}}<p>{{.Invalid}}</p>{{end}}
{{if .Form}}<form method="post" action="/_gate/request"><input type="email" name="email" placeholder="you@example.com" required><button type="submit">Send me a link</button></form>
<small>A single-use link lands in your inbox and works for 15 minutes.</small>{{end}}
</main></body></html>`))

// page writes one portal page; always a 200/2xx so nothing hints at ACL state.
func (s *Service) page(w http.ResponseWriter, d pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if err := portal.Execute(w, d); err != nil {
		slog.Error("gate page", "error", err)
	}
}
