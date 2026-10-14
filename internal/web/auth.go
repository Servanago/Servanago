package web

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	sessionCookieName = "caretakarr_session"
	sessionTTL        = 12 * time.Hour
	maxFailures       = 5
	throttleWindow    = 15 * time.Minute
)

type authn struct {
	passHash [32]byte
	on       bool
	key      []byte // per boot: a restart logs everyone out
	now      func() time.Time

	mu        sync.Mutex
	failures  map[string][]time.Time // attempts per client IP within throttleWindow
	lastSweep time.Time
}

func newAuthn(password string) *authn {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err) // no entropy: cannot sign sessions safely
	}
	return &authn{passHash: sha256.Sum256([]byte(password)), on: password != "", key: key, now: time.Now,
		failures: map[string][]time.Time{}}
}

func (a *authn) enabled() bool { return a.on }

func (a *authn) sign(exp string) string {
	m := hmac.New(sha256.New, a.key)
	m.Write([]byte(exp))
	return hex.EncodeToString(m.Sum(nil))
}

func (a *authn) newCookie(secure bool) *http.Cookie {
	exp := strconv.FormatInt(a.now().Add(sessionTTL).Unix(), 10)
	return &http.Cookie{Name: sessionCookieName, Value: exp + "." + a.sign(exp), Path: "/",
		MaxAge: int(sessionTTL.Seconds()), HttpOnly: true, Secure: secure, SameSite: http.SameSiteStrictMode}
}

// secureRequest reports whether the browser reached us over TLS: directly, or via Caddy on loopback.
// Marking cookies Secure on plain HTTP would make the browser drop them and break the UI_LISTEN recovery listener.
func secureRequest(r *http.Request) bool {
	return r.TLS != nil || (loopbackPeer(r) && r.Header.Get("X-Forwarded-Proto") == "https")
}

func (a *authn) valid(r *http.Request) bool {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return false
	}
	exp, sig, ok := strings.Cut(c.Value, ".")
	if !ok || subtle.ConstantTimeCompare([]byte(sig), []byte(a.sign(exp))) != 1 {
		return false
	}
	n, err := strconv.ParseInt(exp, 10, 64)
	return err == nil && a.now().Unix() < n
}

func (a *authn) checkPassword(p string) bool {
	h := sha256.Sum256([]byte(p))
	return subtle.ConstantTimeCompare(h[:], a.passHash[:]) == 1
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

func (s *Server) protected(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.auth.enabled() && !s.auth.valid(r) {
			if r.Header.Get("HX-Request") != "" {
				w.Header().Set("HX-Redirect", "/login")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		h(w, r)
	})
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
	s.render(w, "login", http.StatusOK, page{Title: "Sign in"})
}

func (s *Server) loginSubmit(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !s.auth.attempt(ip) {
		http.Error(w, "Too many attempts. Try again later.", http.StatusTooManyRequests)
		return
	}
	if !s.auth.checkPassword(r.PostFormValue("password")) {
		http.Error(w, "Wrong password.", http.StatusUnauthorized)
		return
	}
	s.auth.clear(ip)
	http.SetCookie(w, s.auth.newCookie(secureRequest(r)))
	w.Header().Set("HX-Redirect", "/")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Path: "/", MaxAge: -1, HttpOnly: true, Secure: secureRequest(r), SameSite: http.SameSiteStrictMode})
	w.Header().Set("HX-Redirect", "/login")
	w.WriteHeader(http.StatusNoContent)
}
