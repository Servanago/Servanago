// Package update is the release manifest (latest.json) and its signature: what a release publishes, what an
// install checks before it trusts a newer version. Nothing here touches the network or the host.
package update

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	releases    = "https://github.com/Servanago/Servanago/releases"
	ManifestURL = releases + "/latest/download/latest.json"
	SigURL      = ManifestURL + ".sig"
)

// ManifestAt is the manifest of one release (the previous version's, for a rollback).
func ManifestAt(version string) string {
	return releases + "/download/v" + version + "/latest.json"
}

// Keys are the trusted public keys, any one of which may have signed a manifest. A rotation ships a release
// that carries the old and the new key. Empty until the first key is generated (`servanago manifest keygen`).
var Keys []ed25519.PublicKey

type Deb struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type Manifest struct {
	Schema         int            `json:"schema"`
	Version        string         `json:"version"`
	Released       string         `json:"released"`
	NotesURL       string         `json:"notes_url"`
	MinUpgradeFrom string         `json:"min_upgrade_from"`
	SchemaChange   bool           `json:"schema_change"` // the release adds a database migration
	Breaking       bool           `json:"breaking"`      // set by hand: needs an edit the admin must know about
	Debs           map[string]Deb `json:"debs"`          // by architecture
}

var (
	semverRE = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)$`)
	debRE    = regexp.MustCompile(`^servanago_(\d+\.\d+\.\d+)_([a-z0-9]+)\.deb$`)
	sumRE    = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// DebURL is the only address a release's package may have; a valid signature does not widen it.
func DebURL(version, arch string) string {
	return fmt.Sprintf("%s/download/v%s/servanago_%s_%s.deb", releases, version, version, arch)
}

// Verify checks the signature (base64 Ed25519 over the exact manifest bytes) against the trusted keys,
// then the manifest's own shape.
func Verify(keys []ed25519.PublicKey, manifest, sig []byte) (Manifest, error) {
	if len(keys) == 0 {
		return Manifest{}, errors.New("no trusted signing keys in this build")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if err != nil || len(raw) != ed25519.SignatureSize {
		return Manifest{}, errors.New("manifest signature is not valid")
	}
	ok := false
	for _, k := range keys {
		ok = ok || ed25519.Verify(k, manifest, raw)
	}
	if !ok {
		return Manifest{}, errors.New("manifest signature does not match a trusted key")
	}
	var m Manifest
	if err := json.Unmarshal(manifest, &m); err != nil {
		return Manifest{}, fmt.Errorf("manifest: %w", err)
	}
	if m.Schema != 1 || !semverRE.MatchString(m.Version) || !semverRE.MatchString(m.MinUpgradeFrom) || len(m.Debs) == 0 {
		return Manifest{}, errors.New("manifest: unsupported or incomplete")
	}
	for arch, d := range m.Debs {
		if d.URL != DebURL(m.Version, arch) {
			return Manifest{}, fmt.Errorf("manifest: url for %s is not the release's package address", arch)
		}
		if !sumRE.MatchString(d.SHA256) || d.Size <= 0 {
			return Manifest{}, fmt.Errorf("manifest: bad checksum or size for %s", arch)
		}
	}
	return m, nil
}

// Build writes the manifest for one package; the version and architecture come from its file name.
func Build(debPath, notesURL, minFrom string, schemaChange, breaking bool) ([]byte, error) {
	f := debRE.FindStringSubmatch(filepath.Base(debPath))
	if f == nil {
		return nil, fmt.Errorf("%s: want servanago_X.Y.Z_ARCH.deb", filepath.Base(debPath))
	}
	b, err := os.ReadFile(debPath)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	m := Manifest{
		Schema: 1, Version: f[1], Released: time.Now().UTC().Format("2006-01-02"), NotesURL: notesURL,
		MinUpgradeFrom: minFrom, SchemaChange: schemaChange, Breaking: breaking,
		Debs: map[string]Deb{f[2]: {URL: DebURL(f[1], f[2]), SHA256: hex.EncodeToString(sum[:]), Size: int64(len(b))}},
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(m); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// Sign is the detached signature a release publishes beside the manifest.
func Sign(priv ed25519.PrivateKey, manifest []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, manifest)) + "\n")
}

// Newer reports whether candidate is a strictly higher release than running. A source build ("dev") and
// anything that is not X.Y.Z is never upgraded.
func Newer(running, candidate string) bool {
	a, b := semverRE.FindStringSubmatch(running), semverRE.FindStringSubmatch(candidate)
	if a == nil || b == nil {
		return false
	}
	for i := 1; i <= 3; i++ {
		x, _ := strconv.Atoi(a[i])
		y, _ := strconv.Atoi(b[i])
		if x != y {
			return y > x
		}
	}
	return false
}
