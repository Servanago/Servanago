package phpbuild

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// signer makes a throwaway key, signs a file with it, and returns the public keyring, the file and its signature.
func signer(t *testing.T, name string) (ring []byte, file, sig string) {
	t.Helper()
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("no gpg")
	}
	home := t.TempDir()
	run := func(args ...string) []byte {
		t.Helper()
		out, err := exec.Command("gpg", append([]string{"--homedir", home, "--batch", "--no-tty"}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("gpg %v: %v\n%s", args, err, out)
		}
		return out
	}
	run("--passphrase", "", "--quick-gen-key", name+"@example.com", "ed25519", "sign", "never")
	dir := t.TempDir()
	file = filepath.Join(dir, "php.tar.xz")
	if err := os.WriteFile(file, []byte("php source"), 0o644); err != nil {
		t.Fatal(err)
	}
	sig = file + ".asc"
	run("--armor", "--output", sig, "--detach-sign", file)
	ring, err := exec.Command("gpg", "--homedir", home, "--batch", "--no-tty", "--export", name+"@example.com").Output() // stdout only: binary key data
	if err != nil {
		t.Fatal(err)
	}
	return ring, file, sig
}

func TestVerifyGPG(t *testing.T) {
	ring, file, sig := signer(t, "release")
	if err := VerifyGPG(context.Background(), ring, file, sig); err != nil {
		t.Fatalf("a good signature failed: %v", err)
	}

	// Each row must fail for the reason named, never for a setup mistake.
	otherRing, _, _ := signer(t, "other")
	tampered := filepath.Join(t.TempDir(), "php.tar.xz")
	if err := os.WriteFile(tampered, []byte("php source, patched"), 0o644); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		ring []byte
		file string
		sig  string
		want string
	}{
		{"tampered file", ring, tampered, sig, "gpg --verify failed"},
		{"a key that is not a release manager's", otherRing, file, sig, "gpg --verify failed"},
		{"missing signature", ring, file, file + ".nope", "gpg --verify failed"},
		{"empty keyring", nil, file, sig, "import the PHP keyring"},
		{"garbage keyring", []byte("not a key"), file, sig, "import the PHP keyring"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyGPG(context.Background(), tt.ring, tt.file, tt.sig)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err %v, want one mentioning %q", err, tt.want)
			}
		})
	}
}

// The embedded keyring must actually be a keyring with the release managers in it.
func TestEmbeddedKeyring(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("no gpg")
	}
	if len(Keyring) < 10_000 {
		t.Fatalf("embedded keyring is %d bytes", len(Keyring))
	}
	home := t.TempDir()
	cmd := exec.Command("gpg", "--homedir", home, "--batch", "--no-tty", "--import")
	cmd.Stdin = strings.NewReader(string(Keyring))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("import: %v\n%s", err, out)
	}
	out, err := exec.Command("gpg", "--homedir", home, "--batch", "--list-keys", "--with-colons").Output()
	if err != nil || strings.Count(string(out), "\npub:") < 10 {
		t.Errorf("keys: %v\n%s", err, out)
	}
}
