package update

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func deb(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte("not really a deb"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func signed(t *testing.T) (mf, sig []byte, pub ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	mf, err = Build(deb(t, "servanago_0.19.0_amd64.deb"), "https://github.com/Servanago/Servanago/releases/tag/v0.19.0", "0.5.0", true, false)
	if err != nil {
		t.Fatal(err)
	}
	return mf, Sign(priv, mf), pub
}

func TestVerifyAcceptsASignedManifest(t *testing.T) {
	mf, sig, pub := signed(t)
	m, err := Verify([]ed25519.PublicKey{pub}, mf, sig)
	if err != nil {
		t.Fatal(err)
	}
	if m.Version != "0.19.0" || !m.SchemaChange || m.Debs["amd64"].Size == 0 {
		t.Fatalf("manifest %+v", m)
	}
}

func TestVerifyRejects(t *testing.T) {
	mf, sig, pub := signed(t)
	other, _, _ := ed25519.GenerateKey(nil)
	tampered := []byte(strings.Replace(string(mf), `"0.19.0"`, `"0.19.1"`, 1))
	cases := []struct {
		name string
		keys []ed25519.PublicKey
		mf   []byte
		sig  []byte
		want string
	}{
		{"tampered manifest", []ed25519.PublicKey{pub}, tampered, sig, "signature"},
		{"wrong key", []ed25519.PublicKey{other}, mf, sig, "signature"},
		{"no trusted keys", nil, mf, sig, "no trusted"},
		{"bad base64", []ed25519.PublicKey{pub}, mf, []byte("!!"), "signature"},
	}
	for _, c := range cases {
		if _, err := Verify(c.keys, c.mf, c.sig); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", c.name, err, c.want)
		}
	}
}

func TestVerifyRotatedKeyListAcceptsEither(t *testing.T) {
	mf, sig, pub := signed(t)
	other, _, _ := ed25519.GenerateKey(nil)
	if _, err := Verify([]ed25519.PublicKey{other, pub}, mf, sig); err != nil {
		t.Fatal(err)
	}
}

// A valid signature must not let the manifest point the root downloader elsewhere.
func TestVerifyRejectsAnUnexpectedDebURL(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	mf, err := Build(deb(t, "servanago_0.19.0_amd64.deb"), "n", "0.5.0", false, false)
	if err != nil {
		t.Fatal(err)
	}
	evil := []byte(strings.Replace(string(mf), "https://github.com/Servanago/Servanago/", "https://evil.example/", 1))
	if _, err := Verify([]ed25519.PublicKey{pub}, evil, Sign(priv, evil)); err == nil || !strings.Contains(err.Error(), "url") {
		t.Fatalf("err = %v, want a url rejection", err)
	}
}

func TestBuildRejectsABadDebName(t *testing.T) {
	if _, err := Build(deb(t, "servanago.deb"), "n", "0.5.0", false, false); err == nil {
		t.Fatal("want an error for a deb without version and arch in its name")
	}
}

func TestNewer(t *testing.T) {
	cases := []struct {
		running, cand string
		want          bool
	}{
		{"0.18.0", "0.19.0", true},
		{"0.18.0", "0.18.0", false},
		{"0.18.1", "0.18.0", false},
		{"0.9.0", "0.10.0", true}, // numeric, not lexical
		{"dev", "0.19.0", false},
		{"0.18.0", "junk", false},
	}
	for _, c := range cases {
		if got := Newer(c.running, c.cand); got != c.want {
			t.Errorf("Newer(%q,%q) = %v", c.running, c.cand, got)
		}
	}
}

func TestSignatureFileIsBase64(t *testing.T) {
	_, sig, _ := signed(t)
	if b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig))); err != nil || len(b) != ed25519.SignatureSize {
		t.Fatalf("sig not a base64 ed25519 signature: %v", err)
	}
}
