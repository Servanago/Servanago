// Package phplibs knows the libraries a source-built PHP links against: where each one's latest stable
// release and its sha256 come from (the project's own release feed), and how to build it into a prefix.
// Nothing here downloads a tarball or runs a command: callers inject the HTTP getter and run the Cmds.
package phplibs

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Getter fetches a URL's body. The builder passes a real HTTP client; tests pass recorded feeds.
type Getter func(ctx context.Context, url string) ([]byte, error)

// Resolved is one library's latest stable release. Sum is lowercase hex of Algo; it comes from the project's
// own feed, or from the pinned table when Pinned is set (not feed-tracked: a newer release needs a code change).
// A library with neither fails to resolve instead of building unverified.
type Resolved struct {
	Name, Version, URL, Algo, Sum string
	Pinned                        bool
}

// pinned holds the libraries whose projects publish no sha256 in any feed (GPG signature or md5 only). Each
// entry was downloaded over https once, at dev time, checked against everything the project publishes, and
// its sha256 computed locally. Bump an entry the same way: new version, checks below, new sum.
var pinned = map[string]Resolved{
	// libpng 1.6.59 (2026-10): tarball from SourceForge, the project's release host. The project publishes no
	// .asc for tarballs (404 on SourceForge, GitHub releases and the OSUOSL mirror), so the tarball itself has
	// NO GPG check. Verified instead: the md5 (fce35ac83494252c178249c3aad9621e) and the sha256 that
	// SourceForge's file index publishes both match the downloaded file; the git tag v1.6.59 carries a valid
	// signature by Cosmin Truta, fingerprint 1FED 507E 3236 B4A6 E53E 922B B292 C648 43FF 5BCF (key from
	// github.com/ctruta.gpg), but a tag signs the source commit, not this tarball.
	// The URL uses the /project/ path: the short download.sourceforge.net/libpng/ path serves an HTML page to a Go
	// client (found by a real build: the checksum check refused it).
	"libpng": {Name: "libpng", Version: "1.6.59", URL: "https://downloads.sourceforge.net/project/libpng/libpng16/1.6.59/libpng-1.6.59.tar.xz", Algo: AlgoSHA256,
		Sum: "d80dd2a38a37f803cb9b6ac7b14bd6e74ddc3b654780a8380bdf93523fdb4389", Pinned: true},
	// freetype 2.15.0 (2026-10-12): tarball from download.savannah.gnu.org. GPG verified: the .sig is a good
	// signature by Werner Lemberg <wl@gnu.org>, fingerprint E306 7470 7856 409F F194 8010 BE6C 3AAC 63AD 8E3F
	// (key from keyserver.ubuntu.com; the same key also verifies 2.14.3). The project publishes no md5 or sha
	// file. The key's owner is not documented on any project page, so the key is trusted on first use.
	"freetype": {Name: "freetype", Version: "2.15.0", URL: "https://download.savannah.gnu.org/releases/freetype/freetype-2.15.0.tar.xz", Algo: AlgoSHA256,
		Sum: "93cd47eb719c325107f2d3cf087d06299e944c3b48a40b55537302304dea1dd5", Pinned: true},
	// libwebp 1.6.0 (2025-07-09): tarball from downloads.webmproject.org (Google Cloud Storage). md5 verified:
	// the md5 the host publishes in its x-goog-hash header (cceb6447180f961473b181c9ef38b630) matches. GPG
	// verified: good signature by "WebP release signing key <webp-discuss@webmproject.org>", fingerprint
	// 6B0E 6B70 976D E303 EDF2 F601 F9C3 D6BD B823 2B5D (key from keyserver.ubuntu.com; it also verifies
	// 1.5.0). Key ownership is not documented on a project page, so it is trusted on first use.
	"libwebp": {Name: "libwebp", Version: "1.6.0", URL: "https://storage.googleapis.com/downloads.webmproject.org/releases/webp/libwebp-1.6.0.tar.gz", Algo: AlgoSHA256,
		Sum: "e4ab7009bf0629fd11982d4c2aa83964cf244cffba7347ecd39019a9e38c4564", Pinned: true},
}

// Algo values: sha256 everywhere except sqlite, which publishes only SHA3-256 (stdlib crypto/sha3).
const (
	AlgoSHA256 = "sha256"
	AlgoSHA3   = "sha3-256"
)

// names is the build order: a library comes after the ones its recipe links against.
var names = []string{"zlib", "openssl", "curl", "libxml2", "libpng", "libjpeg-turbo", "freetype", "libwebp", "libzip", "icu", "oniguruma", "sqlite", "libpq"}

// Names returns the build order, dependencies first.
func Names() []string { return append([]string(nil), names...) }

var (
	versionRE = regexp.MustCompile(`^[0-9]+(\.[0-9]+){1,3}$`) // checked before a version reaches a URL or a path
	sumRE     = regexp.MustCompile(`^[0-9a-f]{64}$`)

	plainVersion = regexp.MustCompile(`^\d+\.\d+\.\d+$`)
	sqliteRow    = regexp.MustCompile(`^\d{4}/sqlite-autoconf-\d+\.tar\.gz$`)
	pgDir        = regexp.MustCompile(`href="v(\d+\.\d+(?:\.\d+)?)/"`)
)

// Resolve finds the latest stable release of one library.
func Resolve(ctx context.Context, get Getter, name string) (Resolved, error) {
	var r Resolved
	var err error
	switch name {
	case "zlib":
		r, err = github(ctx, get, "madler/zlib", `^v(\d+\.\d+(?:\.\d+)?)$`, "zlib-%s.tar.xz")
	case "openssl":
		// ponytail: pinned to the 3.x series, PHP does not build against OpenSSL 4 yet; lift when PHP does
		r, err = github(ctx, get, "openssl/openssl", `^openssl-(3\.\d+\.\d+)$`, "openssl-%s.tar.gz")
	case "curl":
		r, err = github(ctx, get, "curl/curl", `^curl-(\d+_\d+_\d+)$`, "curl-%s.tar.xz")
	case "libjpeg-turbo":
		r, err = github(ctx, get, "libjpeg-turbo/libjpeg-turbo", `^(\d+\.\d+(?:\.\d+){1,2})$`, "libjpeg-turbo-%s.tar.gz")
	case "libzip":
		r, err = github(ctx, get, "nih-at/libzip", `^v(\d+\.\d+\.\d+)$`, "libzip-%s.tar.xz")
	case "icu":
		r, err = github(ctx, get, "unicode-org/icu", `^release-(\d+[.-]\d+)$`, "icu4c-%s-sources.tgz")
	case "oniguruma":
		r, err = github(ctx, get, "kkos/oniguruma", `^v(\d+\.\d+\.\d+)$`, "onig-%s.tar.gz")
	case "libxml2":
		r, err = libxml2(ctx, get)
	case "sqlite":
		r, err = sqlite(ctx, get)
	case "libpq":
		r, err = postgres(ctx, get)
	case "libpng", "freetype", "libwebp":
		r = pinned[name]
	default:
		return Resolved{}, fmt.Errorf("unknown library %q", name)
	}
	if err != nil {
		return Resolved{}, fmt.Errorf("%s: %w", name, err)
	}
	r.Name = name
	switch {
	case !versionRE.MatchString(r.Version):
		return Resolved{}, fmt.Errorf("%s: version %q is not a plain dotted number", name, r.Version)
	case !strings.HasPrefix(r.URL, "https://"):
		return Resolved{}, fmt.Errorf("%s: tarball URL %q is not https", name, r.URL)
	case !sumRE.MatchString(r.Sum):
		return Resolved{}, fmt.Errorf("%s: checksum %q is not 64 hex digits", name, r.Sum)
	}
	return r, nil
}

// SourceDir is the directory the tarball extracts to.
func SourceDir(r Resolved) string {
	switch r.Name {
	case "icu":
		return "icu"
	case "oniguruma":
		return "onig-" + r.Version
	case "libpq":
		return "postgresql-" + r.Version
	case "sqlite":
		return "sqlite-autoconf-" + sqliteNumber(r.Version)
	}
	return r.Name + "-" + r.Version
}

// sqliteNumber turns 3.54.1 into the 7-digit 3540100 sqlite names its files with.
func sqliteNumber(v string) string {
	p := parts(v)
	for len(p) < 3 {
		p = append(p, 0)
	}
	return strconv.Itoa(p[0]*1000000 + p[1]*10000 + p[2]*100)
}

// ---- feeds ----

type ghAsset struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
	URL    string `json:"browser_download_url"`
}

type ghRelease struct {
	Tag        string    `json:"tag_name"`
	Prerelease bool      `json:"prerelease"`
	Draft      bool      `json:"draft"`
	Assets     []ghAsset `json:"assets"`
}

// github picks the newest published, non-prerelease release whose tag matches tagRE (one capture group: the
// version, with _ and - read as dots) that carries the asset. The sum is GitHub's own digest of that asset, or
// the project's .sha256 sidecar when there is no digest.
func github(ctx context.Context, get Getter, repo, tagRE, assetFmt string) (Resolved, error) {
	body, err := get(ctx, "https://api.github.com/repos/"+repo+"/releases?per_page=100")
	if err != nil {
		return Resolved{}, err
	}
	var rels []ghRelease
	if err := json.Unmarshal(body, &rels); err != nil {
		return Resolved{}, fmt.Errorf("release list: %w", err)
	}
	re := regexp.MustCompile(tagRE)
	var best *ghRelease
	var bestVer string
	for i, rel := range rels {
		m := re.FindStringSubmatch(rel.Tag)
		if m == nil || rel.Prerelease || rel.Draft {
			continue
		}
		v := strings.NewReplacer("_", ".", "-", ".").Replace(m[1])
		if !versionRE.MatchString(v) || findAsset(rel, fmt.Sprintf(assetFmt, v)) == nil {
			continue
		}
		if best == nil || newer(v, bestVer) {
			best, bestVer = &rels[i], v
		}
	}
	if best == nil {
		return Resolved{}, fmt.Errorf("no stable %s release with a %s asset", repo, fmt.Sprintf(assetFmt, "<version>"))
	}
	name := fmt.Sprintf(assetFmt, bestVer)
	a := findAsset(*best, name)
	sum, ok := strings.CutPrefix(a.Digest, "sha256:")
	if !ok {
		side := findAsset(*best, name+".sha256")
		if side == nil {
			return Resolved{}, fmt.Errorf("release %s has no sha256 digest and no %s.sha256 sidecar", best.Tag, name)
		}
		b, err := get(ctx, side.URL)
		if err != nil {
			return Resolved{}, err
		}
		if sum = sumFor(string(b), name); sum == "" {
			return Resolved{}, fmt.Errorf("%s.sha256 holds no sum for %s", name, name)
		}
	}
	return Resolved{Version: bestVer, URL: a.URL, Algo: AlgoSHA256, Sum: strings.ToLower(sum)}, nil
}

func findAsset(r ghRelease, name string) *ghAsset {
	for i := range r.Assets {
		if r.Assets[i].Name == name {
			return &r.Assets[i]
		}
	}
	return nil
}

// sumFor reads a `sha256sum`-style listing ("<hex>  file" or "<hex> *file", or a bare hash) for one file.
func sumFor(listing, file string) string {
	for _, line := range strings.Split(listing, "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == file {
			return strings.ToLower(f[0])
		}
		if len(f) == 1 && sumRE.MatchString(strings.ToLower(f[0])) {
			return strings.ToLower(f[0])
		}
	}
	return ""
}

// libxml2: GNOME's cache.json lists every file per version with its .sha256sum path.
func libxml2(ctx context.Context, get Getter) (Resolved, error) {
	const base = "https://download.gnome.org/sources/libxml2/"
	body, err := get(ctx, base+"cache.json")
	if err != nil {
		return Resolved{}, err
	}
	var cache [4]json.RawMessage
	var files map[string]map[string]map[string]string
	if err := json.Unmarshal(body, &cache); err != nil {
		return Resolved{}, fmt.Errorf("cache.json: %w", err)
	}
	if err := json.Unmarshal(cache[1], &files); err != nil {
		return Resolved{}, fmt.Errorf("cache.json: %w", err)
	}
	best := ""
	for v, f := range files["libxml2"] {
		if plainVersion.MatchString(v) && f["tar.xz"] != "" && f["sha256sum"] != "" && (best == "" || newer(v, best)) {
			best = v
		}
	}
	if best == "" {
		return Resolved{}, fmt.Errorf("no release with a tar.xz and a sha256sum in cache.json")
	}
	f := files["libxml2"][best]
	list, err := get(ctx, base+f["sha256sum"])
	if err != nil {
		return Resolved{}, err
	}
	sum := sumFor(string(list), "libxml2-"+best+".tar.xz")
	if sum == "" {
		return Resolved{}, fmt.Errorf("%s holds no sum for libxml2-%s.tar.xz", f["sha256sum"], best)
	}
	return Resolved{Version: best, URL: base + f["tar.xz"], Algo: AlgoSHA256, Sum: sum}, nil
}

// sqlite: the download page carries a machine-readable PRODUCT,VERSION,URL,SIZE,SHA3 table.
func sqlite(ctx context.Context, get Getter) (Resolved, error) {
	body, err := get(ctx, "https://sqlite.org/download.html")
	if err != nil {
		return Resolved{}, err
	}
	for _, line := range strings.Split(string(body), "\n") {
		f := strings.Split(strings.TrimSpace(line), ",")
		if len(f) == 5 && f[0] == "PRODUCT" && sqliteRow.MatchString(f[2]) {
			return Resolved{Version: f[1], URL: "https://sqlite.org/" + f[2], Algo: AlgoSHA3, Sum: strings.ToLower(f[4])}, nil
		}
	}
	return Resolved{}, fmt.Errorf("no sqlite-autoconf row in download.html")
}

// postgres: ftp.postgresql.org keeps one directory per release (v18.6/) with a .sha256 beside each tarball.
// libpq is built from the server tarball.
func postgres(ctx context.Context, get Getter) (Resolved, error) {
	const base = "https://ftp.postgresql.org/pub/source/"
	idx, err := get(ctx, base)
	if err != nil {
		return Resolved{}, err
	}
	best := ""
	for _, m := range pgDir.FindAllStringSubmatch(string(idx), -1) {
		if best == "" || newer(m[1], best) { // beta and rc directories (v19beta1/) do not match
			best = m[1]
		}
	}
	if best == "" {
		return Resolved{}, fmt.Errorf("no release directory in the source index")
	}
	file := "postgresql-" + best + ".tar.gz"
	list, err := get(ctx, base+"v"+best+"/"+file+".sha256")
	if err != nil {
		return Resolved{}, err
	}
	sum := sumFor(string(list), file)
	if sum == "" {
		return Resolved{}, fmt.Errorf("%s.sha256 holds no sum for %s", file, file)
	}
	return Resolved{Version: best, URL: base + "v" + best + "/" + file, Algo: AlgoSHA256, Sum: sum}, nil
}

// newer compares dotted versions numerically.
func newer(a, b string) bool {
	pa, pb := parts(a), parts(b)
	for i := 0; i < len(pa) || i < len(pb); i++ {
		x, y := 0, 0
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			return x > y
		}
	}
	return false
}

func parts(v string) []int {
	var out []int
	for _, p := range strings.Split(v, ".") {
		n, _ := strconv.Atoi(p)
		out = append(out, n)
	}
	return out
}
