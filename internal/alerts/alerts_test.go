package alerts

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestWebhookIsSignedAndNtfyCarriesToken(t *testing.T) {
	var gotSig, gotTS, gotBody, gotAuth, gotPrio string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotSig, gotTS, gotBody, gotAuth, gotPrio = r.Header.Get("X-ServanaGo-Signature"), r.Header.Get("X-ServanaGo-Timestamp"), string(b), r.Header.Get("Authorization"), r.Header.Get("Priority")
	}))
	defer srv.Close()
	s := &Sender{AllowLocal: true}
	if err := s.Send(context.Background(), Dest{Kind: "webhook", Target: srv.URL, Secret: "k"}, Event{Kind: "ban", Site: "a", Text: "x"}); err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, []byte("k"))
	mac.Write([]byte(gotTS + "." + gotBody))
	if gotSig != "sha256="+hex.EncodeToString(mac.Sum(nil)) {
		t.Errorf("signature %q does not verify", gotSig)
	}
	if err := s.Send(context.Background(), Dest{Kind: "ntfy", Target: srv.URL, Secret: "tok"}, Event{Kind: "underattack", Text: "x"}); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer tok" || gotPrio != "urgent" {
		t.Errorf("ntfy headers: %q %q", gotAuth, gotPrio)
	}
}

func TestSafetyRefusals(t *testing.T) {
	s := &Sender{}
	for name, d := range map[string]Dest{
		"http webhook":    {Kind: "webhook", Target: "http://example.com/x", Secret: "k"},
		"loopback target": {Kind: "webhook", Target: "https://127.0.0.1:9/x", Secret: "k"},
		"private target":  {Kind: "ntfy", Target: "https://10.0.0.5/topic"},
		"userinfo":        {Kind: "ntfy", Target: "https://u:p@example.com/t"},
	} {
		if err := s.Send(context.Background(), d, Event{Kind: "ban", Text: "x"}); err == nil {
			t.Errorf("%s was delivered", name)
		}
	}
	// an error never echoes the target
	err := s.Send(context.Background(), Dest{Kind: "ntfy", Target: "https://127.0.0.1:9/secret-topic"}, Event{Kind: "ban"})
	if err == nil || strings.Contains(err.Error(), "secret-topic") {
		t.Errorf("error leaks the target: %v", err)
	}
}

func TestPushoverAndTwilio(t *testing.T) {
	var path, user, form string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		user, _, _ = r.BasicAuth()
		_ = r.ParseForm()
		form = r.PostForm.Encode()
	}))
	defer srv.Close()
	s := &Sender{AllowLocal: true, PushoverURL: srv.URL + "/1/messages.json", TwilioBase: srv.URL}
	if err := s.Send(context.Background(), Dest{Kind: "pushover", Target: "u", Secret: "t"}, Event{Kind: "x402", Text: "paid"}); err != nil || !strings.Contains(form, "priority=1") {
		t.Errorf("pushover %v %q", err, form)
	}
	long := strings.Repeat("a", 500)
	if err := s.Send(context.Background(), Dest{Kind: "twilio", Target: "+1,+2", Secret: "AC1:tok"}, Event{Kind: "ban", Text: long}); err != nil {
		t.Fatal(err)
	}
	if user != "AC1" || !strings.Contains(path, "/Accounts/AC1/Messages.json") || len(form) > 600 {
		t.Errorf("twilio %q %q %d", user, path, len(form))
	}
	for _, bad := range [][3]string{{"twilio", "+1", "x"}, {"pushover", "", ""}, {"webhook", "https://example.com", ""}, {"email", "nope", ""}} {
		if ValidateTarget(bad[0], bad[1], bad[2]) == nil {
			t.Errorf("%v validated", bad)
		}
	}
}

func TestNotifierDedupesAndRecordsResult(t *testing.T) {
	now := time.Unix(1000, 0)
	n := NewNotifier(&Sender{})
	n.Now = func() time.Time { return now }
	var sent atomic.Int32
	n.Resolve = func(context.Context, Event) ([]Dest, error) {
		return []Dest{{ID: 1, Name: "d", Kind: "ntfy", Target: "http://bad"}}, nil
	}
	n.Result = func(Dest, error) { sent.Add(1) }
	n.Notify(Event{Kind: "ban", Site: "a"})
	n.Notify(Event{Kind: "ban", Site: "a"}) // inside the cooldown
	n.Notify(Event{Kind: "ban", Site: "b"})
	if len(n.queue) != 2 {
		t.Fatalf("queued %d, want 2", len(n.queue))
	}
	now = now.Add(6 * time.Minute)
	n.Notify(Event{Kind: "ban", Site: "a"})
	if len(n.queue) != 3 {
		t.Errorf("cooldown did not expire: %d", len(n.queue))
	}
	n.Fire(context.Background(), Event{Kind: "backup", Text: "x"})
	if sent.Load() != 1 {
		t.Errorf("result callbacks: %d", sent.Load())
	}
}
