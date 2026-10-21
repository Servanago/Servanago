package phpbuild

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Keyring is the PHP release managers' public keys, from https://www.php.net/distributions/php-keyring.gpg
// (downloaded once and committed, so a compromised php.net cannot swap it later; refresh it when PHP changes release
// managers). The keys are trusted on first use: php.net is the only place that publishes them.
//
//go:embed php-keyring.gpg
var Keyring []byte

// VerifyGPG checks the detached signature sig of file against the keys in keyring, using a throwaway GnuPG home so the
// host's keyrings are never read or changed. Anything but a plain good signature fails: unknown key, expired or revoked
// key, bad signature.
func VerifyGPG(ctx context.Context, keyring []byte, file, sig string) error {
	home, err := os.MkdirTemp("", "servanago-gpg-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(home)
	if err := os.Chmod(home, 0o700); err != nil {
		return err
	}
	ring := filepath.Join(home, "keyring.gpg")
	if err := os.WriteFile(ring, keyring, 0o600); err != nil {
		return err
	}
	gpg := func(args ...string) (string, error) {
		cmd := exec.CommandContext(ctx, "gpg", append([]string{"--homedir", home, "--batch", "--no-tty", "--status-fd", "1"}, args...)...)
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		err := cmd.Run()
		return out.String(), err
	}
	if out, err := gpg("--import", ring); err != nil {
		return fmt.Errorf("import the PHP keyring: %w: %.200s", err, out)
	}
	out, err := gpg("--verify", sig, file)
	if err != nil {
		return fmt.Errorf("gpg --verify failed: %w: %.200s", err, firstStatus(out))
	}
	for _, bad := range []string{"BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG"} {
		if strings.Contains(out, "[GNUPG:] "+bad) {
			return fmt.Errorf("gpg reports %s", bad)
		}
	}
	if !strings.Contains(out, "[GNUPG:] GOODSIG") || !strings.Contains(out, "[GNUPG:] VALIDSIG") {
		return fmt.Errorf("no good signature in gpg's answer")
	}
	return nil
}

func firstStatus(out string) string {
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "[GNUPG:] ") && !strings.Contains(l, "NEWSIG") {
			return l
		}
	}
	return out
}
