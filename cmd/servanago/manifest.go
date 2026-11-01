package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/servanago/servanago/internal/update"
)

// runManifest is the release-side tool: `manifest keygen FILE`, `manifest build --deb F ...` (manifest on
// stdout), `manifest sign KEYFILE MANIFEST` (writes MANIFEST.sig). Run by the release script, never by a host.
func runManifest(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: servanago manifest keygen FILE | build --deb F --notes URL | sign KEYFILE MANIFEST")
	}
	switch args[0] {
	case "keygen":
		if len(args) != 2 {
			return errors.New("usage: servanago manifest keygen FILE")
		}
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			return err
		}
		// ponytail: 0600 file, no passphrase. Add one (age/scrypt) when the key leaves this machine.
		f, err := os.OpenFile(args[1], os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintln(f, base64.StdEncoding.EncodeToString(priv.Seed())); err != nil {
			_ = f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		_, err = fmt.Fprintf(out, "public key (add to update.Keys): %s\n", base64.StdEncoding.EncodeToString(pub))
		return err
	case "build":
		fs := flag.NewFlagSet("manifest build", flag.ContinueOnError)
		deb := fs.String("deb", "", "the package, named servanago_X.Y.Z_ARCH.deb")
		notes := fs.String("notes", "", "release notes URL")
		minFrom := fs.String("min-from", "0.5.0", "oldest version that may upgrade straight to this one")
		schema := fs.Bool("schema-change", false, "the release adds a database migration")
		breaking := fs.Bool("breaking", false, "the admin must act on this release")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		b, err := update.Build(*deb, *notes, *minFrom, *schema, *breaking)
		if err != nil {
			return err
		}
		_, err = out.Write(b)
		return err
	case "sign":
		if len(args) != 3 {
			return errors.New("usage: servanago manifest sign KEYFILE MANIFEST")
		}
		seed, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(seed)))
		if err != nil || len(raw) != ed25519.SeedSize {
			return errors.New("key file is not a servanago signing key")
		}
		mf, err := os.ReadFile(args[2])
		if err != nil {
			return err
		}
		return os.WriteFile(args[2]+".sig", update.Sign(ed25519.NewKeyFromSeed(raw), mf), 0o644)
	}
	return fmt.Errorf("unknown manifest command %q", args[0])
}
