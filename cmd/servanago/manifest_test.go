package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/servanago/servanago/internal/update"
)

func TestManifestKeygenBuildSignVerify(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "release.key")
	deb := filepath.Join(dir, "servanago_0.19.0_amd64.deb")
	if err := os.WriteFile(deb, []byte("deb"), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := runManifest([]string{"keygen", key}, &out); err != nil {
		t.Fatal(err)
	}
	pubB64 := strings.TrimSpace(out.String()[strings.LastIndex(out.String(), " ")+1:])
	pub, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(key); st.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode %v", st.Mode().Perm())
	}
	if err := runManifest([]string{"keygen", key}, &out); err == nil {
		t.Fatal("keygen overwrote an existing key")
	}

	out.Reset()
	if err := runManifest([]string{"build", "--deb", deb, "--notes", "n", "--schema-change"}, &out); err != nil {
		t.Fatal(err)
	}
	mf := filepath.Join(dir, "latest.json")
	if err := os.WriteFile(mf, out.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runManifest([]string{"sign", key, mf}, &out); err != nil {
		t.Fatal(err)
	}
	sig, _ := os.ReadFile(mf + ".sig")
	body, _ := os.ReadFile(mf)
	m, err := update.Verify([]ed25519.PublicKey{pub}, body, sig)
	if err != nil || m.Version != "0.19.0" || !m.SchemaChange {
		t.Fatalf("round trip: %+v %v", m, err)
	}
}
