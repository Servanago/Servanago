package web

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/servanago/servanago/internal/store"
	"github.com/servanago/servanago/internal/update"
)

// updateServer is a signed-in server whose "GitHub" serves one signed manifest for version ver.
func updateServer(t *testing.T, running, ver string) (*Server, *int, *http.Cookie) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	deb := filepath.Join(t.TempDir(), "servanago_"+ver+"_amd64.deb")
	if err := os.WriteFile(deb, []byte("deb"), 0o600); err != nil {
		t.Fatal(err)
	}
	mf, err := update.Build(deb, "https://example.test/notes", "0.5.0", true, false)
	if err != nil {
		t.Fatal(err)
	}
	sig := update.Sign(priv, mf)
	gets := 0
	s := newServer(t, "pw")
	s.deps.Cfg.UpdateCheck = true
	s.deps.Version = running
	s.deps.UpdateKeys = []ed25519.PublicKey{pub}
	s.deps.HTTPGet = func(_ context.Context, u string) ([]byte, error) {
		gets++
		switch u {
		case update.ManifestURL:
			return mf, nil
		case update.SigURL:
			return sig, nil
		}
		return nil, errors.New("unexpected url " + u)
	}
	return s, &gets, sessionCookie(t, login(s, "pw", nil, ""))
}

func TestUpdateCheckShowsANewerRelease(t *testing.T) {
	s, _, c := updateServer(t, "0.18.0", "0.19.0")
	if err := s.runUpdateCheck(context.Background()); err != nil {
		t.Fatal(err)
	}
	w := s.do(req{path: "/updates", cookies: []*http.Cookie{c}})
	body := w.Body.String()
	for _, want := range []string{"0.19.0", "0.18.0", "https://example.test/notes", "Check now", "</article>"} {
		if w.Code != 200 || !strings.Contains(body, want) {
			t.Fatalf("%d, page lacks %q:\n%s", w.Code, want, body)
		}
	}
	if !strings.Contains(body, "new database migration") {
		t.Errorf("schema change not shown:\n%s", body)
	}
}

func TestUpdateCheckSaysUpToDate(t *testing.T) {
	s, _, c := updateServer(t, "0.19.0", "0.19.0")
	if err := s.runUpdateCheck(context.Background()); err != nil {
		t.Fatal(err)
	}
	if body := s.do(req{path: "/updates", cookies: []*http.Cookie{c}}).Body.String(); !strings.Contains(body, "up to date") {
		t.Errorf("want an up to date notice:\n%s", body)
	}
}

func TestUpdateCheckRejectsAManifestNobodyTrustedSigned(t *testing.T) {
	s, _, _ := updateServer(t, "0.18.0", "0.19.0")
	other, _, _ := ed25519.GenerateKey(nil)
	s.deps.UpdateKeys = []ed25519.PublicKey{other}
	if err := s.runUpdateCheck(context.Background()); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("err = %v, want a signature rejection", err)
	}
	if js, at, _ := s.deps.Store.UpdateCheck(context.Background()); js != "" || at != 0 {
		t.Errorf("an untrusted manifest was stored: %q %d", js, at)
	}
}

func TestUpdateCheckFailureKeepsThePreviousResult(t *testing.T) {
	s, _, _ := updateServer(t, "0.18.0", "0.19.0")
	if err := s.runUpdateCheck(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.deps.HTTPGet = func(context.Context, string) ([]byte, error) { return nil, errors.New("offline") }
	if err := s.runUpdateCheck(context.Background()); err == nil || !strings.Contains(err.Error(), "offline") {
		t.Fatalf("err = %v", err)
	}
	if res, at := s.loadUpdate(context.Background()); at == 0 || res.Manifest.Version != "0.19.0" {
		t.Errorf("the earlier result was lost: %+v %d", res, at)
	}
}

func TestUpdateCheckDisabledMakesNoRequest(t *testing.T) {
	s, gets, _ := updateServer(t, "0.18.0", "0.19.0")
	s.deps.Cfg.UpdateCheck = false
	if err := s.runUpdateCheck(context.Background()); err == nil || !strings.Contains(err.Error(), "turned off") {
		t.Fatalf("err = %v", err)
	}
	if *gets != 0 {
		t.Errorf("%d requests while the check is off", *gets)
	}
}

func TestReleaseMailNamesTheReportingHost(t *testing.T) {
	s, _, _ := updateServer(t, "0.1.0", "0.2.0")
	s.deps.Cfg.Host = "bee.example.test"
	if err := s.deps.Store.SaveSettings(context.Background(), store.Settings{SMTPHost: "mail", SMTPPort: 587, MailFrom: "ops@example.com"}); err != nil {
		t.Fatal(err)
	}
	var subject, body string
	s.sendMail = func(_, _, sub, b string) error { subject, body = sub, b; return nil }
	if err := s.runUpdateCheck(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(subject, "bee.example.test") || !strings.Contains(body, "available on bee.example.test") {
		t.Errorf("host missing: %q / %q", subject, body)
	}
}
