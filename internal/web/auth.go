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

	mu       sync.Mutex
	failures map[string][]time.Time
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

func (a *authn) newCookie() *http.Cookie {
	exp := strconv.FormatInt(a.now().Add(sessionTTL).Unix(), 10)
	return &http.Cookie{Name: sessionCookieName, Value: exp + "." + a.sign(exp), Path: "/",
		MaxAge: int(sessionTTL.Seconds()), HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode}
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

// blocked reports whether ip has used up its failed-attempt budget in the window.
func (a *authn) blocked(ip string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	cutoff := a.now().Add(-throttleWindow)
	recent := a.failures[ip][:0]
	for _, t := range a.failures[ip] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	a.failures[ip] = recent
	return len(recent) >= maxFailures
}

func (a *authn) fail(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.failures[ip] = append(a.failures[ip], a.now())
}

// clientIP trusts X-Forwarded-For only from a loopback peer (Caddy in this process).
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		if first, _, _ := strings.Cut(r.Header.Get("X-Forwarded-For"), ","); strings.TrimSpace(first) != "" {
			return strings.TrimSpace(first)
		}
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
	if s.auth.blocked(ip) {
		http.Error(w, "Too many attempts. Try again later.", http.StatusTooManyRequests)
		return
	}
	if !s.auth.checkPassword(r.PostFormValue("password")) {
		s.auth.fail(ip)
		http.Error(w, "Wrong password.", http.StatusUnauthorized)
		return
	}
	http.SetCookie(w, s.auth.newCookie())
	w.Header().Set("HX-Redirect", "/")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	w.Header().Set("HX-Redirect", "/login")
	w.WriteHeader(http.StatusNoContent)
}
