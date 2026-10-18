package web

import (
	"crypto/tls"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// S1: the budget must hold under parallel attempts (check-then-record raced).
func TestThrottleHoldsUnderParallelAttempts(t *testing.T) {
	s := newServer(t, "pw")
	const n = 60
	codes := make([]int, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes[i] = login(s, "wrong", nil, "").Code
		}()
	}
	wg.Wait()
	got := map[int]int{}
	for _, c := range codes {
		got[c]++
	}
	if got[401] != maxFailures || got[429] != n-maxFailures {
		t.Fatalf("want exactly %d x 401 and %d x 429, got %v", maxFailures, n-maxFailures, got)
	}
}

func TestSuccessfulLoginClearsBudget(t *testing.T) {
	s := newServer(t, "pw")
	for range maxFailures - 1 {
		login(s, "bad", nil, "")
	}
	if w := login(s, "pw", nil, ""); w.Code != 204 {
		t.Fatalf("login: %d", w.Code)
	}
	for i := range maxFailures {
		if w := login(s, "bad", nil, ""); w.Code != 401 {
			t.Fatalf("attempt %d after a good login: %d (budget should have reset)", i, w.Code)
		}
	}
}

// S3: entries for IPs that never come back must not accumulate.
func TestThrottleMapIsPruned(t *testing.T) {
	s := newServer(t, "pw")
	now := time.Unix(2_000_000, 0)
	s.auth.now = func() time.Time { return now }
	for i := range 50 {
		login(s, "bad", map[string]string{"X-Forwarded-For": "9.9.9." + string(rune('0'+i%10)) + string(rune('0'+i/10))}, "")
	}
	if n := len(s.auth.failures); n != 50 {
		t.Fatalf("setup: %d entries", n)
	}
	now = now.Add(throttleWindow + 2*time.Minute)
	login(s, "bad", map[string]string{"X-Forwarded-For": "8.8.8.8"}, "") // a different IP triggers the sweep
	if n := len(s.auth.failures); n != 1 {
		t.Fatalf("expired entries kept: %d", n)
	}
}

// S2: Secure only when the browser connection is TLS, so the plain-HTTP recovery listener can log in.
func TestCookieSecureFollowsTransport(t *testing.T) {
	s := newServer(t, "pw")
	cases := []struct {
		name   string
		peer   string
		hdr    map[string]string
		secure bool
	}{
		{"behind Caddy over https", "127.0.0.1:1", map[string]string{"X-Forwarded-Proto": "https"}, true},
		{"behind Caddy over plain http", "127.0.0.1:1", map[string]string{"X-Forwarded-Proto": "http"}, false},
		{"direct plain http (recovery listener)", "192.168.1.50:5555", nil, false},
		{"forged proto from a non-loopback peer is ignored", "192.168.1.50:5555", map[string]string{"X-Forwarded-Proto": "https"}, false},
		{"loopback with no proto header", "127.0.0.1:1", nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := login(s, "pw", c.hdr, c.peer)
			if w.Code != 204 {
				t.Fatalf("login: %d", w.Code)
			}
			ck := sessionCookie(t, w)
			if ck.Secure != c.secure || !ck.HttpOnly {
				t.Errorf("Secure=%v HttpOnly=%v, want Secure=%v", ck.Secure, ck.HttpOnly, c.secure)
			}
		})
	}
}

func TestSecureRequestWhenServedOverTLS(t *testing.T) {
	r := httptest.NewRequest("POST", "/login", nil)
	r.TLS = &tls.ConnectionState{}
	if !secureRequest(r) {
		t.Fatal("TLS request not treated as secure")
	}
}

// Stray whitespace around a password (a paste, a trailing newline) must not lock anyone out. The stored hash may be of
// the trimmed text (every password set now) or, for an older account, of the text exactly as typed: both still sign in.
func TestPasswordWhitespaceIsForgiven(t *testing.T) {
	s := newServer(t, "pw-pw-pw-pw")
	for n, pw := range map[string]string{"trimmed": "pw-pw-pw-pw", "pasted": " pw-pw-pw-pw\r\n"} {
		if w := login(s, pw, map[string]string{"X-Forwarded-For": "10.9.0." + map[string]string{"trimmed": "1", "pasted": "2"}[n]}, ""); w.Code != 204 {
			t.Errorf("%s sign-in: %d", n, w.Code)
		}
	}
	addUser(t, s, "oldie", " spaced pw ") // hash of the text with its spaces, as before this rule
	if w := loginAs(s, "oldie", " spaced pw ", map[string]string{"X-Forwarded-For": "10.9.0.3"}, ""); w.Code != 204 {
		t.Errorf("legacy untrimmed password: %d", w.Code)
	}
	if w := loginAs(s, "oldie", "spaced pw", map[string]string{"X-Forwarded-For": "10.9.0.4"}, ""); w.Code == 204 {
		t.Error("a different password signed in")
	}
}

// A password set with whitespace around it is stored trimmed, so it signs in however it is typed later.
func TestSetPasswordTrims(t *testing.T) {
	w := httptest.NewRecorder()
	h, ok := hashPassword(w, "  new-password-1 \n")
	if !ok || bcrypt.CompareHashAndPassword([]byte(h), []byte("new-password-1")) != nil {
		t.Errorf("hash is not of the trimmed password (ok=%v)", ok)
	}
	if _, ok := hashPassword(httptest.NewRecorder(), "   short  "); ok {
		t.Error("length rule must apply to the trimmed text")
	}
}
