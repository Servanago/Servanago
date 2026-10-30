package web

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"golang.org/x/crypto/bcrypt"

	"github.com/servanago/servanago/internal/store"
)

const (
	sessionCookieName = "servanago_session"
	pendingCookieName = "servanago_pending"
	sessionTTL        = 12 * time.Hour
	maxFailures       = 5
	throttleWindow    = 15 * time.Minute
	pendingTTL        = 5 * time.Minute // password accepted, second factor still owed
	maxPendingTries   = 5
	ceremonyTTL       = 5 * time.Minute
	maxCeremonies     = 64 // unauthenticated begin calls allocate state: bound it

	levelFull   = "f"
	levelEnroll = "e" // REQUIRE_2FA and no TOTP or passkey yet: only /security until one is set up
)

type pending struct {
	uid   int64 // the user whose password was accepted
	exp   time.Time
	tries int
}

type ceremony struct {
	data webauthn.SessionData
	kind string
	exp  time.Time
}

type authn struct {
	on     atomic.Bool // at least one user exists; otherwise the UI is open
	key    []byte      // per boot: a restart logs everyone out
	now    func() time.Time
	lookup func(id int64) (store.User, bool) // the session's user, as stored now

	mu         sync.Mutex
	failures   map[string][]time.Time // attempts per bucket (client IP, or "pk:"+IP) within throttleWindow
	lastSweep  time.Time
	pendings   map[string]*pending // in memory: a restart just restarts the login
	ceremonies map[string]ceremony
}

func newAuthn() *authn {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err) // no entropy: cannot sign sessions safely
	}
	return &authn{key: key, now: time.Now,
		lookup:   func(int64) (store.User, bool) { return store.User{}, false },
		failures: map[string][]time.Time{}, pendings: map[string]*pending{}, ceremonies: map[string]ceremony{}}
}

func (a *authn) enabled() bool { return a.on.Load() }

func (a *authn) sign(exp string) string {
	m := hmac.New(sha256.New, a.key)
	m.Write([]byte(exp))
	return hex.EncodeToString(m.Sum(nil))
}

func randToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// newCookie signs "expiry:level:uid:epoch" so a limited (enroll) session cannot be upgraded by editing the cookie,
// and so ending a user's sessions (epoch bump, removal) invalidates every cookie issued to them.
func (a *authn) newCookie(secure bool, level string, u store.User) *http.Cookie {
	p := strconv.FormatInt(a.now().Add(sessionTTL).Unix(), 10) + ":" + level + ":" + strconv.FormatInt(u.ID, 10) + ":" + strconv.FormatInt(u.SessionEpoch, 10)
	return &http.Cookie{Name: sessionCookieName, Value: p + "." + a.sign(p), Path: "/",
		MaxAge: int(sessionTTL.Seconds()), HttpOnly: true, Secure: secure, SameSite: http.SameSiteStrictMode}
}

// newPending starts the second-factor step for a login whose password was verified for user uid.
func (a *authn) newPending(uid int64) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	for k, p := range a.pendings {
		if !now.Before(p.exp) {
			delete(a.pendings, k)
		}
	}
	tok := randToken()
	a.pendings[tok] = &pending{uid: uid, exp: now.Add(pendingTTL)}
	return tok
}

// pendingUser is the user a live pending login belongs to.
func (a *authn) pendingUser(tok string) (int64, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	p, ok := a.pendings[tok]
	if !ok || !a.now().Before(p.exp) || p.tries >= maxPendingTries {
		return 0, false
	}
	return p.uid, true
}

func (a *authn) pendingLive(tok string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	p, ok := a.pendings[tok]
	return ok && a.now().Before(p.exp) && p.tries < maxPendingTries
}

// tryPending spends one guess; false when the token is unknown, expired or out of guesses.
func (a *authn) tryPending(tok string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	p, ok := a.pendings[tok]
	if !ok || !a.now().Before(p.exp) || p.tries >= maxPendingTries {
		return false
	}
	p.tries++
	return true
}

func (a *authn) endPending(tok string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.pendings, tok)
}

// putCeremony stores single-use WebAuthn state; false when too many are outstanding.
func (a *authn) putCeremony(kind string, sd webauthn.SessionData) (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	for k, c := range a.ceremonies {
		if !now.Before(c.exp) {
			delete(a.ceremonies, k)
		}
	}
	if len(a.ceremonies) >= maxCeremonies {
		return "", false
	}
	id := randToken()
	a.ceremonies[id] = ceremony{data: sd, kind: kind, exp: now.Add(ceremonyTTL)}
	return id, true
}

func (a *authn) takeCeremony(id, kind string) (webauthn.SessionData, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	c, ok := a.ceremonies[id]
	delete(a.ceremonies, id)
	if !ok || c.kind != kind || !a.now().Before(c.exp) {
		return webauthn.SessionData{}, false
	}
	return c.data, true
}

// secureRequest reports whether the browser reached us over TLS: directly, or via Caddy on loopback.
// Marking cookies Secure on plain HTTP would make the browser drop them and break the UI_LISTEN recovery listener.
func secureRequest(r *http.Request) bool {
	return r.TLS != nil || (loopbackPeer(r) && r.Header.Get("X-Forwarded-Proto") == "https")
}

// session returns the session's level and its user, or "" when there is no valid session: bad signature, expired,
// or the user is gone or has had their sessions ended since the cookie was issued (epoch mismatch).
func (a *authn) session(r *http.Request) (string, store.User) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return "", store.User{}
	}
	p, sig, ok := strings.Cut(c.Value, ".")
	if !ok || subtle.ConstantTimeCompare([]byte(sig), []byte(a.sign(p))) != 1 {
		return "", store.User{}
	}
	f := strings.Split(p, ":")
	if len(f) != 4 || (f[1] != levelFull && f[1] != levelEnroll) {
		return "", store.User{}
	}
	exp, err1 := strconv.ParseInt(f[0], 10, 64)
	uid, err2 := strconv.ParseInt(f[2], 10, 64)
	epoch, err3 := strconv.ParseInt(f[3], 10, 64)
	if err1 != nil || err2 != nil || err3 != nil || a.now().Unix() >= exp {
		return "", store.User{}
	}
	u, ok := a.lookup(uid)
	if !ok || u.SessionEpoch != epoch {
		return "", store.User{}
	}
	return f[1], u
}

// level returns levelFull, levelEnroll, or "" for no valid session.
func (a *authn) level(r *http.Request) string {
	l, _ := a.session(r)
	return l
}

// dummyHash makes a login for an unknown username cost one bcrypt comparison, like a wrong password does.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("servanago-no-such-user"), bcrypt.DefaultCost)

// checkPassword compares pw with the user's hash; with ok=false it still burns one comparison. Passwords are
// stored trimmed, so stray whitespace from a paste is forgiven; the text exactly as typed is tried first so an
// account whose password was set with edge whitespace (before that rule) still signs in.
func checkPassword(u store.User, found bool, pw string) bool {
	hash := []byte(dummyHash)
	if found {
		hash = []byte(u.PasswordHash)
	}
	ok := bcrypt.CompareHashAndPassword(hash, []byte(pw)) == nil
	if t := strings.TrimSpace(pw); !ok && t != pw {
		ok = bcrypt.CompareHashAndPassword(hash, []byte(t)) == nil
	}
	return ok && found
}

type userCtxKey struct{}

// currentUser is the signed-in admin of this request; ok=false in open mode (no users exist).
func currentUser(r *http.Request) (store.User, bool) {
	u, ok := r.Context().Value(userCtxKey{}).(store.User)
	return u, ok
}

func withUser(r *http.Request, u store.User) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), userCtxKey{}, u))
}

// attempt reserves one login attempt for ip and reports whether the budget allowed it. Checking and
// recording happen under one lock, so parallel requests cannot all slip past the limit.
func (a *authn) attempt(ip string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	cutoff := now.Add(-throttleWindow)
	if now.Sub(a.lastSweep) >= time.Minute { // drop IPs that never came back
		for k, ts := range a.failures {
			if len(ts) == 0 || !ts[len(ts)-1].After(cutoff) {
				delete(a.failures, k)
			}
		}
		a.lastSweep = now
	}
	recent := a.failures[ip][:0]
	for _, t := range a.failures[ip] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	if len(recent) >= maxFailures {
		a.failures[ip] = recent
		return false
	}
	a.failures[ip] = append(recent, now)
	return true
}

// clear forgets ip's attempts after a successful login.
func (a *authn) clear(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.failures, ip)
}

func loopbackPeer(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// clientIP trusts X-Forwarded-For only from a loopback peer (Caddy in this process).
func clientIP(r *http.Request) string {
	if loopbackPeer(r) {
		if first, _, _ := strings.Cut(r.Header.Get("X-Forwarded-For"), ","); strings.TrimSpace(first) != "" {
			return strings.TrimSpace(first)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) protected(h http.HandlerFunc) http.Handler { return s.gate(h, false) }

// gate requires a session. Limited (enroll) sessions pass only where allowEnroll is set.
func (s *Server) gate(h http.HandlerFunc, allowEnroll bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.auth.enabled() {
			lvl, u := s.auth.session(r)
			if lvl == "" {
				redirect(w, r, "/login", http.StatusUnauthorized)
				return
			}
			if lvl == levelEnroll && !allowEnroll {
				redirect(w, r, "/security", http.StatusForbidden)
				return
			}
			r = withUser(r, u)
		} else if ip := net.ParseIP(clientIP(r)); ip == nil || !ip.IsLoopback() {
			// Open mode: whoever gets in first creates the first account, so only this machine may.
			http.Error(w, "No administrator exists yet. Create one on this machine: servanago user add NAME, or set ADMIN_PASSWORD and restart.", http.StatusForbidden)
			return
		}
		h(w, r)
	})
}

// redirect sends htmx callers an HX-Redirect with status, everyone else a plain 303.
func redirect(w http.ResponseWriter, r *http.Request, to string, hxStatus int) {
	if r.Header.Get("HX-Request") != "" {
		w.Header().Set("HX-Redirect", to)
		w.WriteHeader(hxStatus)
		return
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}

func (s *Server) setSession(w http.ResponseWriter, r *http.Request, level string, u store.User) {
	http.SetCookie(w, s.auth.newCookie(secureRequest(r), level, u))
	if err := s.deps.Store.TouchLogin(r.Context(), u.ID, s.auth.now().UTC().Format(time.RFC3339)); err != nil {
		slog.Error("record login time", "user", u.Username, "error", err)
	}
}

func (s *Server) setPending(w http.ResponseWriter, r *http.Request, tok string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: pendingCookieName, Value: tok, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: secureRequest(r), SameSite: http.SameSiteStrictMode})
}

func hxRedirect(w http.ResponseWriter, to string) {
	w.Header().Set("HX-Redirect", to)
	w.WriteHeader(http.StatusNoContent)
}

// backOf is where an action's caller wants to land: forms on a site tab send back=/sites/<id>/<tab>,
// everything else keeps the endpoint's own page. Values outside the site tree are ignored.
func backOf(r *http.Request, def string) string {
	if v := r.PostFormValue("back"); strings.HasPrefix(v, "/sites/") && !strings.ContainsAny(v, " \r\n\t") {
		return v
	}
	return def
}

// csrf: SameSite=Strict covers cookies; additionally non-GET needs HX-Request and a same-host Origin.
func (s *Server) csrf(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if r.Header.Get("HX-Request") == "" {
				http.Error(w, "forbidden: missing HX-Request", http.StatusForbidden)
				return
			}
			if o := r.Header.Get("Origin"); o != "" {
				u, err := url.Parse(o)
				if err != nil || u.Host != r.Host {
					http.Error(w, "forbidden: origin mismatch", http.StatusForbidden)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	if !s.auth.enabled() {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	d := loginData{}
	if s.turnstileOn(r) {
		d.SiteKey = s.deps.Cfg.TurnstileSiteKey
	}
	d.Passkeys = s.passkeysOffered(r)
	s.render(w, "login", http.StatusOK, page{Title: "Sign in", Data: d})
}

type loginData struct {
	SiteKey  string // set = render the Turnstile widget
	Passkeys bool   // set = show "Sign in with passkey"
}

func (s *Server) loginSubmit(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !s.auth.attempt(ip) {
		http.Error(w, "Too many attempts. Try again later.", http.StatusTooManyRequests)
		return
	}
	if s.turnstileOn(r) {
		if err := s.turnstile().Verify(r.Context(), r.PostFormValue("cf-turnstile-response"), ip); err != nil {
			slog.Warn("login rejected", "event", "turnstile", "ip", ip, "error", err)
			http.Error(w, "Captcha check failed. Reload the page and try again.", http.StatusUnauthorized)
			return
		}
	}
	name := normalizeUsername(r.PostFormValue("username"))
	u, found, err := s.deps.Store.GetUserByName(r.Context(), name)
	if err != nil {
		slog.Error("login: read user", "error", err)
		http.Error(w, "Internal error.", http.StatusInternalServerError)
		return
	}
	if !checkPassword(u, found, r.PostFormValue("password")) { // same cost and answer for an unknown name
		slog.Warn("login failed", "event", "login", "method", "password", "user", name, "ip", ip)
		s.auditAs(r, name, "login.failed", "password")
		http.Error(w, "Wrong username or password.", http.StatusUnauthorized)
		return
	}
	t, enrolled, err := s.deps.Store.GetTOTP(r.Context(), u.ID)
	if err != nil {
		slog.Error("login: read totp", "error", err)
		http.Error(w, "Internal error.", http.StatusInternalServerError)
		return
	}
	if enrolled && t.Enabled {
		s.setPending(w, r, s.auth.newPending(u.ID), int(pendingTTL.Seconds()))
		hxRedirect(w, "/login/totp")
		return
	}
	if s.deps.Cfg.Require2FA {
		ps, err := s.deps.Store.ListPasskeys(r.Context(), u.ID)
		if err != nil {
			slog.Error("login: read passkeys", "error", err)
			http.Error(w, "Internal error.", http.StatusInternalServerError)
			return
		}
		if len(ps) > 0 { // a passkey is their factor: the password alone opens nothing; same answer as a wrong password
			slog.Warn("login failed", "event", "login", "method", "password", "user", name, "ip", ip, "why", "passkey required")
			s.auditAs(r, name, "login.failed", "password: passkey required")
			http.Error(w, "Wrong username or password.", http.StatusUnauthorized)
			return
		}
	}
	s.auth.clear(ip)
	if s.deps.Cfg.Require2FA {
		slog.Info("login", "event", "login", "method", "password", "session", "enroll-only", "user", u.Username, "ip", ip)
		s.auditAs(r, u.Username, "login", "password")
		s.setSession(w, r, levelEnroll, u)
		hxRedirect(w, "/security")
		return
	}
	slog.Info("login", "event", "login", "method", "password", "user", u.Username, "ip", ip)
	s.auditAs(r, u.Username, "login", "password")
	s.setSession(w, r, levelFull, u)
	hxRedirect(w, "/")
}

// normalizeUsername is the form usernames are stored and compared in.
func normalizeUsername(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if _, u := s.auth.session(r); u.Username != "" {
		s.auditAs(r, u.Username, "logout", "")
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Path: "/", MaxAge: -1, HttpOnly: true, Secure: secureRequest(r), SameSite: http.SameSiteStrictMode})
	hxRedirect(w, "/login")
}
