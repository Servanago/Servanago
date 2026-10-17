package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/pquerna/otp/totp"

	"github.com/servanago/servanago/internal/store"
)

func userID(t *testing.T, s *Server, name string) int64 {
	t.Helper()
	u, ok, err := s.deps.Store.GetUserByName(context.Background(), name)
	if err != nil || !ok {
		t.Fatalf("no user %s: %v", name, err)
	}
	return u.ID
}

// act posts a user-management form as the signed-in admin; "password" is the admin's own (re-auth).
func act(s *Server, path string, ck []*http.Cookie, kv ...string) *httptest.ResponseRecorder {
	f := url.Values{"password": {"pw"}}
	for i := 0; i < len(kv); i += 2 {
		f.Set(kv[i], kv[i+1])
	}
	return postForm(s, path, f, ck)
}

func TestAddUser(t *testing.T) {
	s := newServer(t, "pw")
	ck := cookiesOf(t, login(s, "pw", nil, ""))
	if w := act(s, "/users", ck, "username", "Bob", "new_password", "bobs-password"); w.Code != 204 || w.Header().Get("HX-Redirect") != "/users" {
		t.Fatalf("add: %d %s", w.Code, w.Body)
	}
	if w := loginAs(s, "bob", "bobs-password", nil, ""); w.Code != 204 {
		t.Fatalf("the new admin cannot sign in: %d", w.Code)
	}
	for name, tc := range map[string]struct {
		kv   []string
		want int
	}{
		"duplicate, any case": {[]string{"username", "BOB", "new_password", "another-password"}, 409},
		"short password":      {[]string{"username", "carol", "new_password", "short"}, 422},
		"bad username":        {[]string{"username", "no spaces", "new_password", "long-enough-pw"}, 422},
		"empty username":      {[]string{"username", "", "new_password", "long-enough-pw"}, 422},
		"wrong own password":  {[]string{"username", "carol", "new_password", "long-enough-pw", "password", "nope"}, 401},
	} {
		if w := act(s, "/users", ck, tc.kv...); w.Code != tc.want {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
	}
	if n, _ := s.deps.Store.CountUsers(context.Background()); n != 2 {
		t.Errorf("rejected requests left users behind: %d", n)
	}
}

func TestUserActionsNeedASessionAndReauth(t *testing.T) {
	s := newServer(t, "pw")
	addUser(t, s, "bob", "bobs-password")
	bob := strconv.FormatInt(userID(t, s, "bob"), 10)
	for _, path := range []string{"/users", "/users/" + bob + "/password", "/users/" + bob + "/reset-2fa", "/users/" + bob + "/delete"} {
		if w := postForm(s, path, url.Values{"password": {"pw"}}, nil); w.Code != 401 {
			t.Errorf("%s without a session: %d", path, w.Code)
		}
	}
	if w := s.do(req{path: "/users"}); w.Code != 303 {
		t.Errorf("users page without a session: %d", w.Code)
	}
	ck := cookiesOf(t, login(s, "pw", nil, ""))
	for _, path := range []string{"/users", "/users/" + bob + "/password", "/users/" + bob + "/reset-2fa", "/users/" + bob + "/delete"} {
		if w := postForm(s, path, url.Values{"username": {"x"}, "new_password": {"long-enough-pw"}}, ck); w.Code != 401 {
			t.Errorf("%s without re-auth: %d", path, w.Code)
		}
	}
	if n, _ := s.deps.Store.CountUsers(context.Background()); n != 2 {
		t.Errorf("an unauthenticated action changed users: %d", n)
	}
}

func TestSetAnotherUsersPasswordEndsTheirSessions(t *testing.T) {
	s := newServer(t, "pw")
	addUser(t, s, "bob", "old-password")
	bobCk := cookiesOf(t, loginAs(s, "bob", "old-password", nil, ""))
	ck := cookiesOf(t, login(s, "pw", nil, ""))
	id := strconv.FormatInt(userID(t, s, "bob"), 10)
	if w := act(s, "/users/"+id+"/password", ck, "new_password", "short"); w.Code != 422 {
		t.Fatalf("weak password: %d", w.Code)
	}
	if w := act(s, "/users/"+id+"/password", ck, "new_password", "brand-new-password"); w.Code != 204 {
		t.Fatalf("set: %d %s", w.Code, w.Body)
	}
	if w := s.do(req{path: "/", cookies: bobCk}); w.Code != 303 {
		t.Fatalf("bob's old session survived: %d", w.Code)
	}
	if w := loginAs(s, "bob", "old-password", nil, ""); w.Code != 401 {
		t.Fatalf("old password still works: %d", w.Code)
	}
	if w := loginAs(s, "bob", "brand-new-password", nil, ""); w.Code != 204 {
		t.Fatalf("new password: %d", w.Code)
	}
	if w := s.do(req{path: "/", cookies: ck}); w.Code != 200 {
		t.Fatalf("the acting admin's session ended: %d", w.Code)
	}
	if w := act(s, "/users/999/password", ck, "new_password", "brand-new-password"); w.Code != 404 {
		t.Fatalf("unknown user: %d", w.Code)
	}
}

func TestChangingYourOwnPasswordKeepsYouSignedIn(t *testing.T) {
	s := newServer(t, "pw")
	ck := cookiesOf(t, login(s, "pw", nil, ""))
	other := cookiesOf(t, login(s, "pw", map[string]string{"X-Forwarded-For": "10.1.1.1"}, "")) // a second device
	id := strconv.FormatInt(userID(t, s, "admin"), 10)
	w := act(s, "/users/"+id+"/password", ck, "new_password", "my-new-password")
	if w.Code != 204 {
		t.Fatalf("change: %d %s", w.Code, w.Body)
	}
	fresh := cookiesOf(t, w)
	if w := s.do(req{path: "/", cookies: fresh}); w.Code != 200 {
		t.Fatalf("this browser was signed out by its own change: %d", w.Code)
	}
	if w := s.do(req{path: "/", cookies: ck}); w.Code != 303 {
		t.Fatalf("the old cookie still works: %d", w.Code)
	}
	if w := s.do(req{path: "/", cookies: other}); w.Code != 303 {
		t.Fatalf("another device stayed signed in: %d", w.Code)
	}
	if w := login(s, "pw", nil, ""); w.Code != 401 {
		t.Fatalf("old password still works: %d", w.Code)
	}
	if w := login(s, "my-new-password", map[string]string{"X-Forwarded-For": "10.2.2.2"}, ""); w.Code != 204 {
		t.Fatalf("new password: %d", w.Code)
	}
}

func TestSecurityPageOffersPasswordChange(t *testing.T) {
	s := newServer(t, "pw")
	ck := cookiesOf(t, login(s, "pw", nil, ""))
	body := s.do(req{path: "/security", cookies: ck}).Body.String()
	want := `hx-post="/users/` + strconv.FormatInt(userID(t, s, "admin"), 10) + `/password"`
	if !strings.Contains(body, want) || !strings.Contains(body, `name="new_password"`) {
		t.Errorf("security page lacks the password form (%s)", want)
	}
}

func TestResetAnotherUsersSecondFactor(t *testing.T) {
	s, now := newServerCfg(t, cfg2fa())
	addUser(t, s, "bob", "pw")
	adminCk := cookiesOf(t, login(s, "pw", nil, ""))
	bobCk := cookiesOf(t, loginAs(s, "bob", "pw", nil, ""))
	secretA, _, upgraded := enrollTOTP(t, s, now, adminCk)
	if upgraded != nil {
		adminCk = []*http.Cookie{upgraded}
	}
	enrollTOTP(t, s, now, bobCk)
	bob := userID(t, s, "bob")

	// The acting admin now has TOTP, so re-auth needs a code as well as the password.
	if w := act(s, "/users/"+strconv.FormatInt(bob, 10)+"/reset-2fa", adminCk); w.Code != 401 {
		t.Fatalf("reset without the admin's own code: %d", w.Code)
	}
	code, _ := totp.GenerateCode(secretA, *now)
	if w := act(s, "/users/"+strconv.FormatInt(bob, 10)+"/reset-2fa", adminCk, "code", code); w.Code != 204 {
		t.Fatalf("reset: %d %s", w.Code, w.Body)
	}
	if _, ok, _ := s.deps.Store.GetTOTP(context.Background(), bob); ok {
		t.Error("bob's authenticator survived the reset")
	}
	if _, ok, _ := s.deps.Store.GetTOTP(context.Background(), userID(t, s, "admin")); !ok {
		t.Error("the reset removed the acting admin's own authenticator")
	}
	if w := s.do(req{path: "/", cookies: bobCk}); w.Code != 303 {
		t.Fatalf("bob's session survived the reset: %d", w.Code)
	}
	if w := loginAs(s, "bob", "pw", map[string]string{"X-Forwarded-For": "10.3.3.3"}, ""); w.Code != 204 || w.Header().Get("HX-Redirect") != "/" {
		t.Fatalf("bob signs in with the password alone after the reset: %d %v", w.Code, w.Header())
	}

	// Your own second factor is managed on the Security page, not here.
	*now = now.Add(30 * 1e9)
	code, _ = totp.GenerateCode(secretA, *now)
	self := strconv.FormatInt(userID(t, s, "admin"), 10)
	if w := act(s, "/users/"+self+"/reset-2fa", adminCk, "code", code); w.Code != 422 {
		t.Fatalf("self reset: %d", w.Code)
	}
}

func TestRemoveUser(t *testing.T) {
	s := newServer(t, "pw")
	addUser(t, s, "bob", "bobs-password")
	bobCk := cookiesOf(t, loginAs(s, "bob", "bobs-password", nil, ""))
	ck := cookiesOf(t, login(s, "pw", nil, ""))
	self := strconv.FormatInt(userID(t, s, "admin"), 10)
	if w := act(s, "/users/"+self+"/delete", ck); w.Code != 422 {
		t.Fatalf("removing yourself: %d", w.Code)
	}
	id := strconv.FormatInt(userID(t, s, "bob"), 10)
	if w := act(s, "/users/"+id+"/delete", ck, "password", "wrong"); w.Code != 401 {
		t.Fatalf("without re-auth: %d", w.Code)
	}
	if w := act(s, "/users/"+id+"/delete", ck); w.Code != 204 {
		t.Fatalf("remove: %d %s", w.Code, w.Body)
	}
	if _, ok, _ := s.deps.Store.GetUserByName(context.Background(), "bob"); ok {
		t.Error("bob still exists")
	}
	if w := s.do(req{path: "/", cookies: bobCk}); w.Code != 303 {
		t.Fatalf("a removed user's session still works: %d", w.Code)
	}
	if w := act(s, "/users/"+id+"/delete", ck); w.Code != 404 {
		t.Fatalf("removing twice: %d", w.Code)
	}
	if n, _ := s.deps.Store.CountUsers(context.Background()); n != 1 {
		t.Errorf("users left: %d", n)
	}
}

func TestUsersPageListsEveryAdminAndTheirFactors(t *testing.T) {
	s, now := newServerCfg(t, cfg2fa())
	addUser(t, s, "bob", "pw")
	ck := cookiesOf(t, login(s, "pw", nil, ""))
	enrollTOTP(t, s, now, ck)
	bob, _, _ := s.deps.Store.GetUserByName(context.Background(), "bob")
	if err := s.deps.Store.AddPasskey(context.Background(), bob.ID, store.Passkey{ID: "p", RPID: "h", CredentialID: []byte{9}, Credential: "{}", Name: "key"}); err != nil {
		t.Fatal(err)
	}
	body := s.do(req{path: "/users", cookies: ck}).Body.String()
	for _, want := range []string{"admin", "bob", "(you)", "authenticator", "1 passkey", `hx-post="/users"`} {
		if !strings.Contains(body, want) {
			t.Errorf("users page missing %q", want)
		}
	}
	if strings.Count(body, "/delete") != 1 { // you cannot remove yourself, so only bob's row offers it
		t.Errorf("remove offered %d times, want once", strings.Count(body, "/delete"))
	}
}
