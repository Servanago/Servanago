package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"
	"github.com/pquerna/otp/totp"

	"github.com/servanago/servanago/internal/config"
	"github.com/servanago/servanago/internal/store"
)

const (
	testKey  = "0123456789abcdef0123456789abcdef"
	testHost = "servanago.example.com"
)

var (
	secretRE = regexp.MustCompile(`<code>([A-Z2-7]+)</code>`)
	backupRE = regexp.MustCompile(`<code>([a-z0-9]{5}-[a-z0-9]{5})</code>`)
	httpsHdr = map[string]string{"X-Forwarded-Proto": "https"}
)

func cfg2fa() config.Config {
	return config.Config{Host: testHost, AdminPassword: "pw", SecretKey: testKey}
}

// newServerCfg returns a server with a controllable clock.
func newServerCfg(t *testing.T, cfg config.Config) (*Server, *time.Time) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	s := New(Deps{Cfg: cfg, Store: st})
	now := time.Unix(1_800_000_000, 0)
	s.auth.now = func() time.Time { return now }
	return s, &now
}

func merge(ms ...map[string]string) map[string]string {
	out := map[string]string{}
	for _, m := range ms {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

func postForm(s *Server, path string, form url.Values, cookies []*http.Cookie, hdr ...map[string]string) *httptest.ResponseRecorder {
	return s.do(req{method: "POST", path: path, body: form.Encode(), hdr: merge(append([]map[string]string{htmxPost}, hdr...)...), cookies: cookies})
}

func cookieNamed(w *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == name && c.MaxAge >= 0 {
			return c
		}
	}
	return nil
}

func sessionOf(t *testing.T, s *Server) []*http.Cookie {
	t.Helper()
	w := login(s, "pw", nil, "")
	if w.Code != 204 {
		t.Fatalf("login: %d %s", w.Code, w.Body)
	}
	return []*http.Cookie{sessionCookie(t, w)}
}

func levelOf(s *Server, ck ...*http.Cookie) string {
	r := httptest.NewRequest("GET", "/", nil)
	for _, c := range ck {
		r.AddCookie(c)
	}
	return s.auth.level(r)
}

// enrollTOTP runs begin + confirm on the session and returns the seed, backup codes and any upgraded cookie.
func enrollTOTP(t *testing.T, s *Server, now *time.Time, ck []*http.Cookie) (secret string, codes []string, upgraded *http.Cookie) {
	t.Helper()
	w := postForm(s, "/security/totp/begin", url.Values{"password": {"pw"}}, ck)
	m := secretRE.FindStringSubmatch(w.Body.String())
	if w.Code != 200 || m == nil || !strings.Contains(w.Body.String(), "data:image/png;base64,") {
		t.Fatalf("begin: %d %s", w.Code, w.Body)
	}
	secret = m[1]
	code, _ := totp.GenerateCode(secret, *now)
	w = postForm(s, "/security/totp/confirm", url.Values{"code": {code}}, ck)
	if w.Code != 200 {
		t.Fatalf("confirm: %d %s", w.Code, w.Body)
	}
	for _, m := range backupRE.FindAllStringSubmatch(w.Body.String(), -1) {
		codes = append(codes, m[1])
	}
	if len(codes) != backupCount {
		t.Fatalf("backup codes: %d", len(codes))
	}
	*now = now.Add(30 * time.Second) // the confirming step is spent
	return secret, codes, cookieNamed(w, sessionCookieName)
}

func pendingOf(t *testing.T, w *httptest.ResponseRecorder) []*http.Cookie {
	t.Helper()
	if w.Code != 204 || w.Header().Get("HX-Redirect") != "/login/totp" || cookieNamed(w, sessionCookieName) != nil {
		t.Fatalf("want pending step, got %d %v", w.Code, w.Header())
	}
	c := cookieNamed(w, pendingCookieName)
	if c == nil || !c.HttpOnly {
		t.Fatal("no pending cookie")
	}
	return []*http.Cookie{c}
}

func TestTOTPEnrollAndLogin(t *testing.T) {
	s, now := newServerCfg(t, cfg2fa())
	secret, backups, _ := enrollTOTP(t, s, now, sessionOf(t, s))

	pend := pendingOf(t, login(s, "pw", nil, ""))
	if w := postForm(s, "/login/totp", url.Values{"code": {"abcdefghij"}}, pend); w.Code != 401 {
		t.Fatalf("wrong code: %d", w.Code)
	}
	code, _ := totp.GenerateCode(secret, *now)
	w := postForm(s, "/login/totp", url.Values{"code": {code}}, pend)
	if w.Code != 204 || w.Header().Get("HX-Redirect") != "/" {
		t.Fatalf("good code: %d %v", w.Code, w.Header())
	}
	if levelOf(s, cookieNamed(w, sessionCookieName)) != levelFull {
		t.Fatal("not a full session")
	}
	if w := postForm(s, "/login/totp", url.Values{"code": {code}}, pend); w.Code != 401 {
		t.Fatalf("pending token reused: %d", w.Code)
	}

	// the same step cannot log in twice
	pend = pendingOf(t, login(s, "pw", nil, ""))
	if w := postForm(s, "/login/totp", url.Values{"code": {code}}, pend); w.Code != 401 {
		t.Fatalf("replayed code: %d", w.Code)
	}

	// backup code: once
	pend = pendingOf(t, login(s, "pw", nil, ""))
	if w := postForm(s, "/login/totp", url.Values{"code": {strings.ToUpper(backups[0])}}, pend); w.Code != 204 {
		t.Fatalf("backup code: %d", w.Code)
	}
	pend = pendingOf(t, login(s, "pw", nil, ""))
	if w := postForm(s, "/login/totp", url.Values{"code": {backups[0]}}, pend); w.Code != 401 {
		t.Fatalf("backup code reused: %d", w.Code)
	}
}

func TestPendingLoginDiesAfterFiveGuesses(t *testing.T) {
	s, now := newServerCfg(t, cfg2fa())
	secret, _, _ := enrollTOTP(t, s, now, sessionOf(t, s))
	pend := pendingOf(t, login(s, "pw", map[string]string{"X-Forwarded-For": "10.9.0.1"}, ""))
	for i := range maxPendingTries { // a distinct IP each time keeps the per-IP throttle out of the way
		w := postForm(s, "/login/totp", url.Values{"code": {"abcdefghij"}}, pend, map[string]string{"X-Forwarded-For": "10.9.1." + string(rune('0'+i))})
		if w.Code != 401 {
			t.Fatalf("guess %d: %d", i, w.Code)
		}
	}
	code, _ := totp.GenerateCode(secret, *now)
	if w := postForm(s, "/login/totp", url.Values{"code": {code}}, pend, map[string]string{"X-Forwarded-For": "10.9.2.1"}); w.Code != 401 || w.Header().Get("HX-Redirect") != "/login" {
		t.Fatalf("right code after 5 wrong: %d %v", w.Code, w.Header())
	}
}

func TestPendingLoginExpires(t *testing.T) {
	s, now := newServerCfg(t, cfg2fa())
	secret, _, _ := enrollTOTP(t, s, now, sessionOf(t, s))
	pend := pendingOf(t, login(s, "pw", nil, ""))
	*now = now.Add(pendingTTL + time.Second)
	code, _ := totp.GenerateCode(secret, *now)
	if w := postForm(s, "/login/totp", url.Values{"code": {code}}, pend); w.Code != 401 {
		t.Fatalf("expired: %d", w.Code)
	}
	if w := s.do(req{path: "/login/totp", cookies: pend}); w.Code != 303 {
		t.Fatalf("page with expired token: %d", w.Code)
	}
}

func TestTOTPNeedsSecretKey(t *testing.T) {
	cfg := cfg2fa()
	cfg.SecretKey = ""
	s, _ := newServerCfg(t, cfg)
	w := postForm(s, "/security/totp/begin", url.Values{"password": {"pw"}}, sessionOf(t, s))
	if w.Code != 422 || !strings.Contains(w.Body.String(), "SERVANAGO_SECRET_KEY") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

func TestEnrollRequiresPasswordAndDisableRequiresBoth(t *testing.T) {
	s, now := newServerCfg(t, cfg2fa())
	ck := sessionOf(t, s)
	if w := postForm(s, "/security/totp/begin", url.Values{"password": {"nope"}}, ck); w.Code != 401 {
		t.Fatalf("begin wrong password: %d", w.Code)
	}
	secret, _, _ := enrollTOTP(t, s, now, ck)
	code, _ := totp.GenerateCode(secret, *now)
	for name, f := range map[string]url.Values{
		"no code":        {"password": {"pw"}},
		"wrong password": {"password": {"x"}, "code": {code}},
		"wrong code":     {"password": {"pw"}, "code": {"abcdefghij"}},
	} {
		if w := postForm(s, "/security/totp/disable", f, ck); w.Code != 401 {
			t.Errorf("%s: %d", name, w.Code)
		}
	}
	if w := postForm(s, "/security/totp/disable", url.Values{"password": {"pw"}, "code": {code}}, ck); w.Code != 204 {
		t.Fatalf("disable: %d %s", w.Code, w.Body)
	}
	if w := login(s, "pw", nil, ""); w.Header().Get("HX-Redirect") != "/" {
		t.Fatalf("login after disable: %v", w.Header())
	}
}

func TestRequire2FALimitedSession(t *testing.T) {
	cfg := cfg2fa()
	cfg.Require2FA = true
	s, now := newServerCfg(t, cfg)
	w := login(s, "pw", nil, "")
	if w.Code != 204 || w.Header().Get("HX-Redirect") != "/security" {
		t.Fatalf("%d %v", w.Code, w.Header())
	}
	ck := []*http.Cookie{sessionCookie(t, w)}
	if levelOf(s, ck...) != levelEnroll {
		t.Fatal("not limited")
	}
	if w := s.do(req{path: "/domains", cookies: ck}); w.Code != 303 || w.Header().Get("Location") != "/security" {
		t.Fatalf("limited session reached /domains: %d %v", w.Code, w.Header())
	}
	if w := s.do(req{path: "/security", cookies: ck}); w.Code != 200 {
		t.Fatalf("/security: %d", w.Code)
	}
	if w := postForm(s, "/security/passkeys/begin", url.Values{"password": {"pw"}}, ck, httpsHdr); w.Code != 200 {
		t.Fatalf("passkey begin in limited session: %d", w.Code)
	}
	_, _, up := enrollTOTP(t, s, now, ck)
	if up == nil || levelOf(s, up) != levelFull {
		t.Fatal("confirm did not upgrade the session")
	}
	if w := s.do(req{path: "/domains", cookies: []*http.Cookie{up}}); w.Code != 200 {
		t.Fatalf("/domains after upgrade: %d", w.Code)
	}
	if w := postForm(s, "/security/totp/disable", url.Values{"password": {"pw"}}, []*http.Cookie{up}); w.Code != 403 {
		t.Fatalf("disable under REQUIRE_2FA: %d", w.Code)
	}
	// a password login now owes the code instead of getting a limited session
	pendingOf(t, login(s, "pw", nil, ""))
}

func TestSessionCookieCannotBeUpgraded(t *testing.T) {
	cfg := cfg2fa()
	cfg.Require2FA = true
	s, _ := newServerCfg(t, cfg)
	c := sessionCookie(t, login(s, "pw", nil, ""))
	forged := *c
	p, sig, _ := strings.Cut(c.Value, ".")
	forged.Value = strings.Replace(p, ":"+levelEnroll, ":"+levelFull, 1) + "." + sig
	if levelOf(s, &forged) != "" {
		t.Fatal("edited cookie accepted")
	}
}

func TestUnreadableSeedStillAllowsBackupCodes(t *testing.T) {
	s, now := newServerCfg(t, cfg2fa())
	secret, backups, _ := enrollTOTP(t, s, now, sessionOf(t, s))
	other := cfg2fa()
	other.SecretKey = strings.Repeat("z", 32)
	s2 := New(Deps{Cfg: other, Store: s.deps.Store})
	s2.auth.now = func() time.Time { return *now }
	code, _ := totp.GenerateCode(secret, *now)
	pend := pendingOf(t, login(s2, "pw", nil, ""))
	if w := postForm(s2, "/login/totp", url.Values{"code": {code}}, pend); w.Code != 503 || !strings.Contains(w.Body.String(), "2fa-reset") {
		t.Fatalf("unreadable seed: %d %s", w.Code, w.Body)
	}
	pend = pendingOf(t, login(s2, "pw", nil, ""))
	if w := postForm(s2, "/login/totp", url.Values{"code": {backups[1]}}, pend); w.Code != 204 {
		t.Fatalf("backup code with wrong key: %d", w.Code)
	}
}

func TestRegenerateBackupCodesInvalidatesOld(t *testing.T) {
	s, now := newServerCfg(t, cfg2fa())
	secret, old, _ := enrollTOTP(t, s, now, sessionOf(t, s))
	pend := pendingOf(t, login(s, "pw", nil, ""))
	code, _ := totp.GenerateCode(secret, *now)
	w := postForm(s, "/login/totp", url.Values{"code": {code}}, pend)
	ck := []*http.Cookie{cookieNamed(w, sessionCookieName)}
	*now = now.Add(30 * time.Second)
	code, _ = totp.GenerateCode(secret, *now)
	w = postForm(s, "/security/backup-codes", url.Values{"password": {"pw"}, "code": {code}}, ck)
	fresh := backupRE.FindAllStringSubmatch(w.Body.String(), -1)
	if w.Code != 200 || len(fresh) != backupCount {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	pend = pendingOf(t, login(s, "pw", nil, ""))
	if w := postForm(s, "/login/totp", url.Values{"code": {old[2]}}, pend); w.Code != 401 {
		t.Fatalf("old backup code still works: %d", w.Code)
	}
	pend = pendingOf(t, login(s, "pw", nil, ""))
	if w := postForm(s, "/login/totp", url.Values{"code": {fresh[0][1]}}, pend); w.Code != 204 {
		t.Fatalf("new backup code: %d", w.Code)
	}
}

func TestSecurityRoutesAbsentWhenUIOpen(t *testing.T) {
	s, _ := newServerCfg(t, config.Config{Host: testHost, SecretKey: testKey})
	if w := s.do(req{path: "/security"}); w.Code != 404 {
		t.Fatalf("/security on open UI: %d", w.Code)
	}
	if w := postForm(s, "/security/totp/begin", url.Values{"password": {""}}, nil); w.Code != 404 {
		t.Fatalf("totp begin on open UI: %d", w.Code)
	}
}

func TestTurnstileOnPasswordStep(t *testing.T) {
	verify := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostFormValue("secret") != "sec" {
			t.Error("secret not sent")
		}
		out := map[string]any{"success": true, "hostname": testHost, "action": "login"}
		switch r.PostFormValue("response") {
		case "badhost":
			out["hostname"] = "evil.example.com"
		case "badaction":
			out["action"] = "other"
		case "fail":
			out["success"] = false
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	defer verify.Close()
	cfg := cfg2fa()
	cfg.TurnstileSiteKey, cfg.TurnstileSecret, cfg.TurnstileBaseURL = "site", "sec", verify.URL
	s, _ := newServerCfg(t, cfg)

	submit := func(token, host string) *httptest.ResponseRecorder {
		f := url.Values{"username": {"admin"}, "password": {"pw"}}
		if token != "" {
			f.Set("cf-turnstile-response", token)
		}
		h := map[string]string{"HX-Request": "true"}
		if host != "" {
			h["Origin"] = "http://" + host
		} else {
			h["Origin"] = "https://" + testHost
		}
		return s.do(req{method: "POST", path: "/login", body: f.Encode(), hdr: h, host: host})
	}
	for name, token := range map[string]string{"missing": "", "wrong hostname": "badhost", "wrong action": "badaction", "rejected": "fail"} {
		if w := submit(token, ""); w.Code != 401 {
			t.Errorf("%s: %d", name, w.Code)
		}
	}
	if w := submit("good", ""); w.Code != 204 {
		t.Fatalf("good token: %d %s", w.Code, w.Body)
	}
	if w := submit("", "192.168.1.5:8080"); w.Code != 204 {
		t.Fatalf("recovery listener must be exempt: %d", w.Code)
	}
	if b := s.do(req{path: "/login"}).Body.String(); !strings.Contains(b, `data-sitekey="site"`) {
		t.Error("widget missing on the HTTPS host")
	}
	if b := s.do(req{path: "/login", host: "192.168.1.5:8080"}).Body.String(); strings.Contains(b, "data-sitekey") {
		t.Error("widget shown on the recovery listener")
	}
}

func TestTurnstileNetworkErrorFailsClosed(t *testing.T) {
	cfg := cfg2fa()
	cfg.TurnstileSiteKey, cfg.TurnstileSecret, cfg.TurnstileBaseURL = "site", "sec", "http://127.0.0.1:1"
	s, _ := newServerCfg(t, cfg)
	w := s.do(req{method: "POST", path: "/login", body: url.Values{"password": {"pw"}, "cf-turnstile-response": {"x"}}.Encode(), hdr: htmxPost})
	if w.Code != 401 {
		t.Fatalf("%d", w.Code)
	}
}

func TestPasskeys(t *testing.T) {
	s, now := newServerCfg(t, cfg2fa())
	ck := sessionOf(t, s)
	secret, _, _ := enrollTOTP(t, s, now, ck) // TOTP on: passkey login must still skip it

	rp := virtualwebauthn.RelyingParty{Name: "ServanaGo", ID: testHost, Origin: "https://" + testHost}
	authn := virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{})
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	begin := func(path string, f url.Values, cookies []*http.Cookie, host string) (int, string, string) {
		h := merge(htmxPost, httpsHdr)
		if host != "" {
			h["Origin"] = "https://" + host
		}
		w := s.do(req{method: "POST", path: path, body: f.Encode(), host: host, cookies: cookies, hdr: h})
		var out struct {
			ID      string          `json:"id"`
			Options json.RawMessage `json:"options"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out.ID, string(out.Options)
	}
	finish := func(path, id, name string, body string, cookies []*http.Cookie) *httptest.ResponseRecorder {
		q := "?id=" + url.QueryEscape(id)
		if name != "" {
			q += "&name=" + url.QueryEscape(name)
		}
		return s.do(req{method: "POST", path: path + q, body: body, cookies: cookies, hdr: merge(htmxPost, httpsHdr)})
	}

	// registration re-authenticates with password and code
	code, _ := totp.GenerateCode(secret, *now)
	if c, _, _ := begin("/security/passkeys/begin", url.Values{"password": {"bad"}, "code": {code}}, ck, ""); c != 401 {
		t.Fatalf("bad password: %d", c)
	}
	if c, _, _ := begin("/security/passkeys/begin", url.Values{"password": {"pw"}}, ck, ""); c != 401 {
		t.Fatalf("missing code: %d", c)
	}
	if c, _, _ := begin("/security/passkeys/begin", url.Values{"password": {"pw"}, "code": {code}}, ck, "evil.example.com"); c != 422 {
		t.Fatalf("foreign host: %d", c)
	}
	status, id, opts := begin("/security/passkeys/begin", url.Values{"password": {"pw"}, "code": {code}}, ck, "")
	if status != 200 {
		t.Fatalf("begin: %d", status)
	}
	ao, err := virtualwebauthn.ParseAttestationOptions(opts)
	if err != nil {
		t.Fatalf("%v: %s", err, opts)
	}
	authn.Options.UserHandle = []byte(ao.UserID)
	attest := virtualwebauthn.CreateAttestationResponse(rp, authn, cred, *ao)
	if w := finish("/security/passkeys/finish", "bogus", "laptop", attest, ck); w.Code != 401 {
		t.Fatalf("unknown ceremony: %d", w.Code)
	}
	if w := finish("/security/passkeys/finish", id, "laptop", attest, ck); w.Code != 204 {
		t.Fatalf("finish: %d %s", w.Code, w.Body)
	}
	if w := finish("/security/passkeys/finish", id, "laptop", attest, ck); w.Code != 401 {
		t.Fatalf("ceremony replay: %d", w.Code)
	}
	authn.AddCredential(cred)

	assert := func(origin string) (string, string) {
		_, id, opts := begin("/login/passkey/begin", nil, nil, "")
		o, err := virtualwebauthn.ParseAssertionOptions(opts)
		if err != nil {
			t.Fatalf("%v: %s", err, opts)
		}
		r := rp
		r.Origin = origin
		return id, virtualwebauthn.CreateAssertionResponse(r, authn, cred, *o)
	}
	id, bad := assert("https://evil.example.com")
	if w := finish("/login/passkey/finish", id, "", bad, nil); w.Code != 401 || cookieNamed(w, sessionCookieName) != nil {
		t.Fatalf("wrong origin: %d", w.Code)
	}
	id, good := assert(rp.Origin)
	w := finish("/login/passkey/finish", id, "", good, nil)
	if w.Code != 204 || levelOf(s, cookieNamed(w, sessionCookieName)) != levelFull {
		t.Fatalf("passkey login (TOTP is on, must be skipped): %d %s", w.Code, w.Body)
	}
	if w := finish("/login/passkey/finish", id, "", good, nil); w.Code != 401 {
		t.Fatalf("assertion replay: %d", w.Code)
	}
	id, again := assert(rp.Origin)
	*now = now.Add(ceremonyTTL + time.Second)
	if w := finish("/login/passkey/finish", id, "", again, nil); w.Code != 401 {
		t.Fatalf("expired ceremony: %d", w.Code)
	}

	// listing and delete
	w = s.do(req{path: "/security", cookies: ck, hdr: httpsHdr})
	m := regexp.MustCompile(`/security/passkeys/([0-9a-f]{32})`).FindStringSubmatch(w.Body.String())
	if w.Code != 200 || m == nil || !strings.Contains(w.Body.String(), "laptop") {
		t.Fatalf("security page: %d", w.Code)
	}
	if w := s.do(req{method: "DELETE", path: "/security/passkeys/" + m[1], cookies: ck, hdr: htmxPost}); w.Code != 204 {
		t.Fatalf("delete: %d", w.Code)
	}
	if w := s.do(req{method: "DELETE", path: "/security/passkeys/" + m[1], cookies: ck, hdr: htmxPost}); w.Code != 404 {
		t.Fatalf("delete twice: %d", w.Code)
	}
}

func TestPasskeysUnavailableOnPlainHTTPHost(t *testing.T) {
	s, _ := newServerCfg(t, cfg2fa())
	// SERVANAGO_HOST over plain HTTP (no forwarded https) and an unknown host are both refused
	for _, host := range []string{testHost, "192.168.1.5:8080"} {
		w := s.do(req{method: "POST", path: "/login/passkey/begin", host: host, hdr: map[string]string{"HX-Request": "true", "Origin": "http://" + host}})
		if w.Code != 404 {
			t.Errorf("%s: %d", host, w.Code)
		}
	}
	// localhost is a secure context even over http
	w := s.do(req{method: "POST", path: "/login/passkey/begin", host: "localhost:8080", hdr: map[string]string{"HX-Request": "true", "Origin": "http://localhost:8080"}})
	if w.Code != 200 {
		t.Errorf("localhost: %d %s", w.Code, w.Body)
	}
}

func addPasskeyFor(t *testing.T, s *Server, name, id string) {
	t.Helper()
	u, ok, err := s.deps.Store.GetUserByName(context.Background(), name)
	if err != nil || !ok {
		t.Fatalf("user %s: %v", name, err)
	}
	if err := s.deps.Store.AddPasskey(context.Background(), u.ID, store.Passkey{ID: id, RPID: "h", CredentialID: []byte(id), Credential: "{}", Name: id}); err != nil {
		t.Fatal(err)
	}
}

func TestPasswordAloneOpensNothingWithAPasskey(t *testing.T) {
	cfg := cfg2fa()
	cfg.Require2FA = true
	s, _ := newServerCfg(t, cfg)
	addPasskeyFor(t, s, "admin", "k1")
	w := login(s, "pw", nil, "")
	if w.Code != 401 || cookieNamed(w, sessionCookieName) != nil {
		t.Fatalf("password login with a passkey: %d %v", w.Code, w.Header())
	}
	cfg.Require2FA = false
	s2, _ := newServerCfg(t, cfg)
	addPasskeyFor(t, s2, "admin", "k1")
	if w := login(s2, "pw", nil, ""); w.Code != 204 {
		t.Fatalf("opt-out: %d", w.Code)
	}
}

func TestLastFactorCannotBeRemoved(t *testing.T) {
	cfg := cfg2fa()
	cfg.Require2FA = true
	s, now := newServerCfg(t, cfg)
	_, _, up := enrollTOTP(t, s, now, sessionOf(t, s)) // enroll-only session, upgraded by TOTP
	ck := []*http.Cookie{up}
	addPasskeyFor(t, s, "admin", "k1")
	del := func(id string) int {
		return s.do(req{method: "DELETE", path: "/security/passkeys/" + id, hdr: htmxPost, cookies: ck}).Code
	}
	if c := del("k1"); c != 204 {
		t.Fatalf("delete passkey while TOTP is on: %d", c)
	}
	if w := postForm(s, "/security/totp/disable", url.Values{"password": {"pw"}}, ck); w.Code != 403 {
		t.Fatalf("disable the last factor: %d", w.Code)
	}
	addPasskeyFor(t, s, "admin", "k2")
	// with a passkey left the guard passes and the request reaches re-auth (no code sent: 401, not 403)
	if w := postForm(s, "/security/totp/disable", url.Values{"password": {"pw"}}, ck); w.Code != 401 {
		t.Fatalf("disable with a passkey left: %d %s", w.Code, w.Body)
	}
}

func TestPasskeyLiftsTheEnrollOnlyLimit(t *testing.T) {
	cfg := cfg2fa()
	cfg.Require2FA = true
	s, _ := newServerCfg(t, cfg)
	ck := []*http.Cookie{sessionCookie(t, login(s, "pw", nil, ""))}
	if levelOf(s, ck...) != levelEnroll {
		t.Fatal("not limited")
	}
	h := merge(htmxPost, httpsHdr)
	w := s.do(req{method: "POST", path: "/security/passkeys/begin", body: url.Values{"password": {"pw"}}.Encode(), cookies: ck, hdr: h})
	var out struct {
		ID      string          `json:"id"`
		Options json.RawMessage `json:"options"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || w.Code != 200 {
		t.Fatalf("begin: %d %s", w.Code, w.Body)
	}
	ao, err := virtualwebauthn.ParseAttestationOptions(string(out.Options))
	if err != nil {
		t.Fatal(err)
	}
	rp := virtualwebauthn.RelyingParty{Name: "ServanaGo", ID: testHost, Origin: "https://" + testHost}
	authn := virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{UserHandle: []byte(ao.UserID)})
	attest := virtualwebauthn.CreateAttestationResponse(rp, authn, virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2), *ao)
	w = s.do(req{method: "POST", path: "/security/passkeys/finish?id=" + url.QueryEscape(out.ID), body: attest, cookies: ck, hdr: h})
	up := cookieNamed(w, sessionCookieName)
	if w.Code != 204 || up == nil || levelOf(s, up) != levelFull {
		t.Fatalf("finish did not upgrade: %d %v", w.Code, w.Header())
	}
}
