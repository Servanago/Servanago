package guard

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"html"
	"math/bits"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Challenge cookie and the panel-owned paths every guard layer lets through.
const (
	PassCookie    = "sg_pass"
	ChallengePath = "/__servanago/challenge"
	PanelPrefix   = "/__servanago/"
	maxPuzzleAge  = 120 // seconds
)

// ChallengeCfg is the provision-time challenge setting of a site.
type ChallengeCfg struct {
	Slug       string
	Forced     bool   // ua_mode on
	Auto       bool   // ua_mode auto
	Kind       string // pow | turnstile
	Difficulty string
	TTLMin     int
	Allow      []netip.Prefix
}

// PowBits maps the difficulty names to leading zero bits.
func PowBits(d string) int {
	switch d {
	case "low":
		return 14
	case "high":
		return 18
	}
	return 16
}

// Puzzle is the signed work a visitor must solve; the signature binds it to the site and the client.
type Puzzle struct {
	Salt string
	Bits int
	TS   int64
	Sig  string
}

func (s *Service) NewPuzzle(slug, client string, nbits int) Puzzle {
	p := Puzzle{Salt: randHex(12), Bits: nbits, TS: s.now().Unix()}
	p.Sig = s.mac("challenge-pow", slug, client, p.Salt, itoa(p.Bits), strconv.FormatInt(p.TS, 10))
	return p
}

var errPuzzle = errors.New("challenge failed")

// CheckPuzzle verifies the signature, the age and the proof of work. counter is the solver's decimal answer.
func (s *Service) CheckPuzzle(slug, client string, p Puzzle, counter string) error {
	want := s.mac("challenge-pow", slug, client, p.Salt, itoa(p.Bits), strconv.FormatInt(p.TS, 10))
	if !macEqual(want, p.Sig) || p.Bits < 8 || p.Bits > 30 {
		return errPuzzle
	}
	if age := s.now().Unix() - p.TS; age < 0 || age > maxPuzzleAge {
		return errPuzzle
	}
	if len(counter) == 0 || len(counter) > 12 {
		return errPuzzle
	}
	if _, err := strconv.ParseUint(counter, 10, 64); err != nil {
		return errPuzzle
	}
	if leadingZeroBits(sha256.Sum256([]byte(p.Salt+counter))) < p.Bits {
		return errPuzzle
	}
	return nil
}

func leadingZeroBits(h [32]byte) int {
	n := 0
	for _, b := range h {
		if b == 0 {
			n += 8
			continue
		}
		return n + bits.LeadingZeros8(b)
	}
	return n
}

// SetPass issues the pass cookie: valid for ttl, bound to the site and the client.
func (s *Service) SetPass(w http.ResponseWriter, r *http.Request, slug, client string, ttl time.Duration) {
	exp := s.now().Add(ttl).Unix()
	v := strconv.FormatInt(exp, 10) + "." + s.mac("challenge-pass", slug, client, strconv.FormatInt(exp, 10))
	http.SetCookie(w, &http.Cookie{Name: PassCookie, Value: v, Path: "/", MaxAge: int(ttl.Seconds()), HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode})
}

// HasPass is true for a valid, unexpired pass cookie of this site and client.
func (s *Service) HasPass(r *http.Request, slug, client string) bool {
	c, err := r.Cookie(PassCookie)
	if err != nil {
		return false
	}
	exp, mac, ok := strings.Cut(c.Value, ".")
	if !ok {
		return false
	}
	n, err := strconv.ParseInt(exp, 10, 64)
	if err != nil || n <= s.now().Unix() {
		return false
	}
	return macEqual(s.mac("challenge-pass", slug, client, exp), mac)
}

// SafeReturn keeps a post-challenge redirect on this host: a path, never a scheme, host or backslash trick.
func SafeReturn(p string) string {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.ContainsAny(p, "\\\r\n\x00") {
		return "/"
	}
	return p
}

// challengeActive: forced, or auto mode inside its cooldown.
func (s *Service) challengeActive(cfg ChallengeCfg) bool {
	return cfg.Forced || (cfg.Auto && s.site(cfg.Slug).auto.Load() > s.now().Unix())
}

// Challenge decides one request. It returns true when it answered (the module must not call next).
// client is the raw client string, caddyAddr its parsed form when public.
func (s *Service) Challenge(w http.ResponseWriter, r *http.Request, cfg ChallengeCfg, client string, addr netip.Addr, public bool) bool {
	if r.URL.Path == ChallengePath {
		s.solve(w, r, cfg, client)
		SetOutcome(r, OutChallenged)
		return true
	}
	if strings.HasPrefix(r.URL.Path, PanelPrefix) || strings.HasPrefix(r.URL.Path, "/.well-known/") {
		return false
	}
	if !s.challengeActive(cfg) || (public && inPrefixes(cfg.Allow, addr)) || s.HasPass(r, cfg.Slug, client) {
		return false
	}
	SetOutcome(r, OutChallenged)
	s.page(w, r, cfg, client)
	return true
}

func (s *Service) solve(w http.ResponseWriter, r *http.Request, cfg ChallengeCfg, client string) {
	if r.Method != http.MethodPost || r.ParseForm() != nil {
		http.Error(w, "challenge: POST the solved form", http.StatusMethodNotAllowed)
		return
	}
	back := SafeReturn(r.PostFormValue("return"))
	if cfg.Kind == "turnstile" {
		if s.Turnstile == nil {
			http.Error(w, "Challenge unavailable", http.StatusServiceUnavailable)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		host := r.Host
		if i := strings.LastIndexByte(host, ':'); i > 0 && !strings.Contains(host[i:], "]") {
			host = host[:i]
		}
		if err := s.Turnstile(ctx, r.PostFormValue("cf-turnstile-response"), client, host); err != nil {
			s.page(w, r, cfg, client)
			return
		}
	} else {
		nb, err := strconv.Atoi(r.PostFormValue("bits"))
		ts, err2 := strconv.ParseInt(r.PostFormValue("ts"), 10, 64)
		p := Puzzle{Salt: r.PostFormValue("salt"), Bits: nb, TS: ts, Sig: r.PostFormValue("sig")}
		if err != nil || err2 != nil || s.CheckPuzzle(cfg.Slug, client, p, r.PostFormValue("counter")) != nil {
			s.page(w, r, cfg, client)
			return
		}
	}
	ttl := time.Duration(cfg.TTLMin) * time.Minute
	if ttl <= 0 {
		ttl = time.Hour
	}
	s.SetPass(w, r, cfg.Slug, client, ttl)
	http.Redirect(w, r, back, http.StatusSeeOther)
}

func (s *Service) page(w http.ResponseWriter, r *http.Request, cfg ChallengeCfg, client string) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Robots-Tag", "noindex")
	back := r.URL.RequestURI()
	if r.URL.Path == ChallengePath {
		back = "/"
	}
	back = html.EscapeString(SafeReturn(back))
	if cfg.Kind == "turnstile" {
		h.Set("X-ServanaGo-Challenge", "turnstile")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, turnstilePage, html.EscapeString(s.TurnstileSiteKey), back)
		return
	}
	h.Set("X-ServanaGo-Challenge", "pow")
	p := s.NewPuzzle(cfg.Slug, client, PowBits(cfg.Difficulty))
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintf(w, powPage, ChallengePath, p.Salt, p.Bits, p.TS, p.Sig, back, p.Salt, p.Bits)
}

// SetOutcome tells the observer which layer answered.
func SetOutcome(r *http.Request, outcome string) { caddyhttp.SetVar(r.Context(), OutcomeVar, outcome) }

const powPage = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Checking your browser</title><style>body{font:16px system-ui,sans-serif;margin:0;display:grid;place-items:center;min-height:100vh;background:#f6f7f8;color:#1b1f23}
main{max-width:30rem;padding:2rem}progress{width:100%%}@media(prefers-color-scheme:dark){body{background:#14171a;color:#e7e9ea}}</style></head>
<body><main><h1>Checking your browser</h1><p id="m">This takes a moment. JavaScript is required.</p><progress></progress>
<noscript><p>This site needs JavaScript to prove you are not a bot. Enable it and reload.</p></noscript>
<form id="f" method="post" action="%s"><input type="hidden" name="salt" value="%s"><input type="hidden" name="bits" value="%d"><input type="hidden" name="ts" value="%d"><input type="hidden" name="sig" value="%s"><input type="hidden" name="return" value="%s"><input type="hidden" name="counter" id="c"></form>
<script>
(function(){var salt="%s",bits=%d;
var src='onmessage=async function(e){var s=e.data.s,b=e.data.b,enc=new TextEncoder();for(var n=0;;n++){var h=new Uint8Array(await crypto.subtle.digest("SHA-256",enc.encode(s+n)));var z=0;for(var i=0;i<h.length;i++){if(h[i]===0){z+=8;continue}z+=Math.clz32(h[i])-24;break}if(z>=b){postMessage(n);return}}}';
try{var w=new Worker(URL.createObjectURL(new Blob([src])));w.onmessage=function(e){document.getElementById("c").value=e.data;document.getElementById("f").submit()};w.postMessage({s:salt,b:bits})}
catch(x){document.getElementById("m").textContent="Your browser cannot run the check."}})();
</script></main></body></html>`

const turnstilePage = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Checking your browser</title><script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
<style>body{font:16px system-ui,sans-serif;margin:0;display:grid;place-items:center;min-height:100vh;background:#f6f7f8;color:#1b1f23}main{max-width:30rem;padding:2rem}@media(prefers-color-scheme:dark){body{background:#14171a;color:#e7e9ea}}</style></head>
<body><main><h1>Checking your browser</h1><form method="post" action="/__servanago/challenge"><div class="cf-turnstile" data-sitekey="%s" data-action="challenge" data-callback="done"></div>
<input type="hidden" name="return" value="%s"><noscript><p>JavaScript is required.</p></noscript></form>
<script>function done(){document.forms[0].submit()}</script></main></body></html>`

// evaluate runs the under-attack auto trigger for one site.
func (s *Service) evaluate(st *siteState, now time.Time) {
	cfg := st.cfg.Load()
	if cfg == nil || cfg.AutoRPS <= 0 {
		return
	}
	st.mu.Lock()
	n := len(st.ring)
	var rate uint64
	if n > 10 {
		rate = st.ring[n-1].req - st.ring[n-11].req
	}
	st.mu.Unlock()
	if rate >= uint64(cfg.AutoRPS)*10 {
		cool := cfg.AutoCooldown
		if cool <= 0 {
			cool = 10 * time.Minute
		}
		st.auto.Store(now.Add(cool).Unix())
	}
	active := st.auto.Load() > now.Unix()
	was := st.autoWasOn.Swap(active)
	switch {
	case active && !was:
		s.audit("underattack.auto-on", st.slug)
		s.alert("underattack", st.slug, fmt.Sprintf("Under-attack mode switched on: %d requests per second over the last 10 s", rate/10))
	case !active && was:
		s.audit("underattack.auto-off", st.slug)
		s.alert("underattack", st.slug, "Under-attack mode switched off: traffic is back under the limit")
	}
}

// AutoActive reports whether the site's auto challenge is running now.
func (s *Service) AutoActive(slug string) bool { return s.site(slug).auto.Load() > s.now().Unix() }
