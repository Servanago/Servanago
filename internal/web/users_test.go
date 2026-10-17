package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"

	"github.com/servanago/servanago/internal/config"
	"github.com/servanago/servanago/internal/store"
)

// addUser creates another admin directly in the store (cheap bcrypt cost for tests).
func addUser(t *testing.T, s *Server, name, password string) store.User {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	u, err := s.deps.Store.CreateUser(context.Background(), name, string(h))
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func cookiesOf(t *testing.T, w *httptest.ResponseRecorder) []*http.Cookie {
	t.Helper()
	return []*http.Cookie{sessionCookie(t, w)}
}

func TestFirstAdminIsSeededOnceAndTheEnvIsIgnoredAfter(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	s := New(Deps{Cfg: config.Config{AdminUser: "Boss", AdminPassword: "first"}, Store: st})
	if w := loginAs(s, "boss", "first", nil, ""); w.Code != 204 {
		t.Fatalf("seeded admin cannot sign in: %d %s", w.Code, w.Body)
	}
	// A restart with a different env password must not add or change anyone.
	s2 := New(Deps{Cfg: config.Config{AdminUser: "other", AdminPassword: "second"}, Store: st})
	if n, _ := st.CountUsers(context.Background()); n != 1 {
		t.Fatalf("users after restart: %d", n)
	}
	if w := loginAs(s2, "boss", "second", nil, ""); w.Code != 401 {
		t.Fatalf("env password took over: %d", w.Code)
	}
	if w := loginAs(s2, "boss", "first", nil, ""); w.Code != 204 {
		t.Fatalf("stored password stopped working: %d", w.Code)
	}
}

func TestLoginNeedsAKnownUser(t *testing.T) {
	s := newServer(t, "pw")
	addUser(t, s, "bob", "bobs-password")
	for name, tc := range map[string]struct{ user, pw string }{
		"unknown user":    {"nobody", "pw"},
		"wrong password":  {"admin", "bobs-password"},
		"empty user":      {"", "pw"},
		"password of bob": {"admin", "bobs-password"},
	} {
		w := loginAs(s, tc.user, tc.pw, nil, "")
		if w.Code != 401 || !strings.Contains(w.Body.String(), "Wrong username or password.") {
			t.Errorf("%s: %d %q", name, w.Code, w.Body.String())
		}
	}
	// Names are case-insensitive and trimmed; each user signs in with their own password.
	if w := loginAs(s, " BOB ", "bobs-password", nil, ""); w.Code != 204 {
		t.Errorf("bob: %d", w.Code)
	}
	if w := loginAs(s, "Admin", "pw", nil, ""); w.Code != 204 {
		t.Errorf("admin: %d", w.Code)
	}
	// The unknown-name answer is the wrong-password answer: nothing tells them apart.
	a, b := loginAs(s, "nobody", "x", nil, ""), loginAs(s, "admin", "x", nil, "")
	if a.Code != b.Code || a.Body.String() != b.Body.String() {
		t.Errorf("unknown user and wrong password differ: %d %q vs %d %q", a.Code, a.Body, b.Code, b.Body)
	}
}

func TestSessionEndsWhenTheUserIsRemovedOrTheirSessionsAreEnded(t *testing.T) {
	s := newServer(t, "pw")
	ctx := context.Background()
	bob := addUser(t, s, "bob", "bobs-password")
	bobCk := cookiesOf(t, loginAs(s, "bob", "bobs-password", nil, ""))
	adminCk := cookiesOf(t, login(s, "pw", nil, ""))
	if w := s.do(req{path: "/", cookies: bobCk}); w.Code != 200 {
		t.Fatalf("bob's session: %d", w.Code)
	}

	// Ending one user's sessions leaves everyone else's alone.
	if err := s.deps.Store.BumpEpoch(ctx, bob.ID); err != nil {
		t.Fatal(err)
	}
	if w := s.do(req{path: "/", cookies: bobCk}); w.Code != 303 {
		t.Fatalf("bob's old session after the epoch bump: %d", w.Code)
	}
	if w := s.do(req{path: "/", cookies: adminCk}); w.Code != 200 {
		t.Fatalf("admin's session ended with bob's: %d", w.Code)
	}

	// A password change ends that user's sessions too.
	bobCk = cookiesOf(t, loginAs(s, "bob", "bobs-password", nil, ""))
	if err := s.deps.Store.SetPassword(ctx, bob.ID, "$2a$10$irrelevant"); err != nil {
		t.Fatal(err)
	}
	if w := s.do(req{path: "/", cookies: bobCk}); w.Code != 303 {
		t.Fatalf("session survived a password change: %d", w.Code)
	}

	// A removed user's cookie is dead.
	if err := s.deps.Store.DeleteUser(ctx, bob.ID); err != nil {
		t.Fatal(err)
	}
	if w := s.do(req{path: "/", cookies: bobCk}); w.Code != 303 {
		t.Fatalf("removed user's session: %d", w.Code)
	}
}

func TestOpenModeWhenThereAreNoUsers(t *testing.T) {
	s := newServer(t, "")
	if w := s.do(req{path: "/"}); w.Code != 200 {
		t.Fatalf("open UI: %d", w.Code)
	}
	if w := s.do(req{path: "/login"}); w.Code != 303 {
		t.Fatalf("login page in open mode: %d", w.Code)
	}
	if w := s.do(req{path: "/security"}); w.Code != 404 {
		t.Fatalf("security page in open mode: %d", w.Code)
	}
}

// Two admins hold independent authenticators and backup codes: a code, or a TOTP step, never works for the other.
func TestTwoAdminsHaveIndependentTOTPAndBackupCodes(t *testing.T) {
	s, now := newServerCfg(t, cfg2fa())
	addUser(t, s, "bob", "pw")
	adminCk := cookiesOf(t, login(s, "pw", nil, ""))
	bobCk := cookiesOf(t, loginAs(s, "bob", "pw", nil, ""))
	secretA, backupsA, _ := enrollTOTP(t, s, now, adminCk)
	secretB, backupsB, _ := enrollTOTP(t, s, now, bobCk)
	if secretA == secretB {
		t.Fatal("two users share a TOTP secret")
	}
	n := 0
	fresh := func() map[string]string { // a new client IP per call keeps the login throttle out of the way
		n++
		return map[string]string{"X-Forwarded-For": "10.9.0." + strconv.Itoa(n)}
	}
	step := func(user, secret string) *httptest.ResponseRecorder {
		code, _ := totp.GenerateCode(secret, *now)
		h := fresh()
		return postForm(s, "/login/totp", url.Values{"code": {code}}, pendingOf(t, loginAs(s, user, "pw", h, "")), h)
	}
	if w := step("admin", secretB); w.Code != 401 {
		t.Fatalf("bob's TOTP code signed admin in: %d", w.Code)
	}
	if w := step("bob", secretA); w.Code != 401 {
		t.Fatalf("admin's TOTP code signed bob in: %d", w.Code)
	}
	if w := step("admin", secretA); w.Code != 204 {
		t.Fatalf("admin's own code: %d", w.Code)
	}
	*now = now.Add(30 * time.Second)
	if w := step("bob", secretB); w.Code != 204 {
		t.Fatalf("bob's own code: %d", w.Code)
	}
	withBackup := func(code string) *httptest.ResponseRecorder {
		h := fresh()
		return postForm(s, "/login/totp", url.Values{"code": {code}}, pendingOf(t, loginAs(s, "bob", "pw", h, "")), h)
	}
	if w := withBackup(backupsA[0]); w.Code != 401 {
		t.Fatalf("admin's backup code signed bob in: %d", w.Code)
	}
	if w := withBackup(backupsB[0]); w.Code != 204 {
		t.Fatalf("bob's own backup code: %d", w.Code)
	}

	// Resetting one user's factors leaves the other's in place.
	bob, _, _ := s.deps.Store.GetUserByName(context.Background(), "bob")
	if _, _, _, err := s.deps.Store.ResetAuth(context.Background(), bob.ID); err != nil {
		t.Fatal(err)
	}
	if w := loginAs(s, "bob", "pw", fresh(), ""); w.Code != 204 || w.Header().Get("HX-Redirect") != "/" {
		t.Fatalf("bob after reset signs in with the password alone: %d %v", w.Code, w.Header())
	}
	pendingOf(t, loginAs(s, "admin", "pw", fresh(), "")) // admin still owes a code
}

// A passkey signs in the user it belongs to, and a credential never works under another user's handle.
func TestPasskeyLoginPicksTheOwner(t *testing.T) {
	s, _ := newServerCfg(t, cfg2fa())
	addUser(t, s, "bob", "pw")
	rp := virtualwebauthn.RelyingParty{Name: "ServanaGo", ID: testHost, Origin: "https://" + testHost}
	post := func(path string, f url.Values, ck []*http.Cookie) *httptest.ResponseRecorder {
		return s.do(req{method: "POST", path: path, body: f.Encode(), cookies: ck, hdr: merge(htmxPost, httpsHdr)})
	}
	options := func(w *httptest.ResponseRecorder) (string, string) {
		var out struct {
			ID      string          `json:"id"`
			Options json.RawMessage `json:"options"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return out.ID, string(out.Options)
	}
	type holder struct {
		name  string
		ck    []*http.Cookie
		authn virtualwebauthn.Authenticator
		cred  virtualwebauthn.Credential
	}
	register := func(name string, ck []*http.Cookie) holder {
		h := holder{name: name, ck: ck, authn: virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{}),
			cred: virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)}
		w := post("/security/passkeys/begin", url.Values{"password": {"pw"}}, ck)
		id, opts := options(w)
		ao, err := virtualwebauthn.ParseAttestationOptions(opts)
		if err != nil {
			t.Fatalf("%s: %v: %s", name, err, opts)
		}
		h.authn.Options.UserHandle = []byte(ao.UserID)
		attest := virtualwebauthn.CreateAttestationResponse(rp, h.authn, h.cred, *ao)
		fin := s.do(req{method: "POST", path: "/security/passkeys/finish?id=" + url.QueryEscape(id) + "&name=key", body: attest, cookies: ck, hdr: merge(htmxPost, httpsHdr)})
		if fin.Code != 204 {
			t.Fatalf("%s register: %d %s", name, fin.Code, fin.Body)
		}
		h.authn.AddCredential(h.cred)
		return h
	}
	admin := register("admin", cookiesOf(t, login(s, "pw", nil, "")))
	bob := register("bob", cookiesOf(t, loginAs(s, "bob", "pw", nil, "")))
	if string(admin.authn.Options.UserHandle) == string(bob.authn.Options.UserHandle) {
		t.Fatal("two users got the same WebAuthn handle")
	}

	signIn := func(h holder) *httptest.ResponseRecorder {
		id, opts := options(post("/login/passkey/begin", nil, nil))
		o, err := virtualwebauthn.ParseAssertionOptions(opts)
		if err != nil {
			t.Fatalf("%v: %s", err, opts)
		}
		resp := virtualwebauthn.CreateAssertionResponse(rp, h.authn, h.cred, *o)
		return s.do(req{method: "POST", path: "/login/passkey/finish?id=" + url.QueryEscape(id), body: resp, hdr: merge(htmxPost, httpsHdr)})
	}
	for _, h := range []holder{admin, bob} {
		w := signIn(h)
		if w.Code != 204 {
			t.Fatalf("%s passkey login: %d %s", h.name, w.Code, w.Body)
		}
		if _, u := s.auth.session(&http.Request{Header: http.Header{"Cookie": {sessionCookie(t, w).String()}}}); u.Username != h.name {
			t.Fatalf("passkey of %s signed in as %q", h.name, u.Username)
		}
	}
	// Bob's credential presented under the admin's user handle is refused.
	forged := bob
	forged.authn = virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{UserHandle: admin.authn.Options.UserHandle})
	forged.authn.AddCredential(bob.cred)
	if w := signIn(forged); w.Code != 401 {
		t.Fatalf("a credential under another user's handle was accepted: %d", w.Code)
	}
}
