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
	Rev                           int // recipe revision, from recipeRev: part of the installed directory's name
}

// recipeRev is bumped, per library, whenever its recipe in recipe.go changes in a way that alters the installed files
// (a flag, a patch, a dependency). An installed library directory is never replaced, so without the bump an old build
// of the same version would be reused forever. Absent = revision 0 = the plain name every installed library has.
var recipeRev = map[string]int{}

// Dir is the library's directory name under libs/: name-version, plus -rN once its recipe has been revised.
func Dir(r Resolved) string {
	if r.Rev > 0 {
		return fmt.Sprintf("%s-%s-r%d", r.Name, r.Version, r.Rev)
	}
	return r.Name + "-" + r.Version
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
	// gmp 6.3.0 (2023-07-29): tarball from ftp.gnu.org. GPG verified: good signature by Niels Möller
	// <nisse@lysator.liu.se>, fingerprint 343C 2FF0 FBEE 5EC2 EDBE F399 F359 9FF8 28C6 7298 (key from
	// keyserver.ubuntu.com; it has since expired, the signature predates that). No sha file is published.
	"gmp": {Name: "gmp", Version: "6.3.0", URL: "https://ftp.gnu.org/gnu/gmp/gmp-6.3.0.tar.xz", Algo: AlgoSHA256,
		Sum: "a3c2b80201b89e68616f4ad30bc66aee4927c3ce50e33929ca819d5c43538898", Pinned: true},
	// bzip2 1.0.8 (2019-07-13): tarball from sourceware.org/pub/bzip2, the project's release host. GPG verified
	// (2026-11-01): good signature by Mark Wielaard <mark@klomp.org>, fingerprint 1276 8A96 7959 9010 7A0D 2FDF
	// FC57 E3CC ACD9 9A78 (key from keyserver.ubuntu.com). The project publishes no sha file.
	"bzip2": {Name: "bzip2", Version: "1.0.8", URL: "https://sourceware.org/pub/bzip2/bzip2-1.0.8.tar.gz", Algo: AlgoSHA256,
		Sum: "ab5a03176ee106d3f0fa90e381da478ddae405918153cca248e682cd0c4a2269", Pinned: true},
	// libsodium 1.0.22 (stable-branch tarball): download.libsodium.org, the project's release host. The project
	// signs it with minisign (a .minisig is published); that signature was NOT checked (no minisign tool here), so
	// the trust is the https host, as for the PECL sources. The tarball extracts to libsodium-stable (SourceDir).
	"libsodium": {Name: "libsodium", Version: "1.0.22", URL: "https://download.libsodium.org/libsodium/releases/libsodium-1.0.22-stable.tar.gz", Algo: AlgoSHA256,
		Sum: "e30a1aa4a4e9e19d5ceaafd7fd2fa83999233b2b7338c5ef52f5deab054501d8", Pinned: true},
	// OpenLDAP 2.7.2 (2026-10): openldap.org's release directory. GPG verified (2026-11-01): good signature by
	// "OpenLDAP Project <project@openldap.org>", fingerprint 3CE2 69B5 398B C8B7 8564 5E98 7F67 D5FD 1CE1 CBCE (key
	// from keyserver.ubuntu.com). The project publishes no sha file.
	"openldap": {Name: "openldap", Version: "2.7.2", URL: "https://www.openldap.org/software/download/OpenLDAP/openldap-release/openldap-2.7.2.tgz", Algo: AlgoSHA256,
		Sum: "aad731aa22118ff327b9b4ddfc4b6f18ef9476586205da88a532e90940b523d2", Pinned: true},
	// libmemcached 1.1.4, the maintained awesomized fork (the original is dormant): GitHub's archive of the tag; the
	// project publishes no release asset, signature or checksum. The sha256 is of the archive as downloaded
	// 2026-11-01. GitHub can regenerate archives; the checksum check then fails closed and this entry needs the new
	// sum after a look at the tag.
	"libmemcached": {Name: "libmemcached", Version: "1.1.4", URL: "https://github.com/awesomized/libmemcached/archive/refs/tags/1.1.4.tar.gz", Algo: AlgoSHA256,
		Sum: "c477e1f6510e1dc698e84f3717ce690a8f65b94c616ecaa62306cce0f5e3116a", Pinned: true},
}

// Algo values: sha256 everywhere except sqlite, which publishes only SHA3-256 (stdlib crypto/sha3).
const (
	AlgoSHA256 = "sha256"
	AlgoSHA3   = "sha3-256"
)

// names is the build order: a library comes after the ones its recipe links against.
var names = []string{"zlib", "openssl", "curl", "libxml2", "libpng", "libjpeg-turbo", "freetype", "libwebp", "imagemagick", "libzip", "icu", "oniguruma", "sqlite", "libpq", "gmp", "bzip2", "libsodium", "openldap", "libmemcached"}

// Names returns the build order, dependencies first.
func Names() []string { return append([]string(nil), names...) }

// baseLibs are always built: PHP itself links openssl, libxml2 and zlib.
var baseLibs = []string{"zlib", "openssl", "libxml2"}

// libNeeds is what each recipe links against (see Recipe); Needed closes a selection over it.
var libNeeds = map[string][]string{
	"curl":        {"openssl", "zlib"},
	"libxml2":     {"zlib"},
	"libpng":      {"zlib"},
	"freetype":    {"zlib", "libpng"},
	"libzip":      {"openssl"},
	"libpq":       {"openssl"},
	"imagemagick": {"zlib", "libxml2", "libpng", "libjpeg-turbo", "freetype", "libwebp"},
}

// Needed returns the libraries to build for a selection: the base ones, the named ones and everything they link,
// in build order.
func Needed(libs []string) []string {
	want := map[string]bool{}
	var add func(n string)
	add = func(n string) {
		if want[n] {
			return
		}
		want[n] = true
		for _, d := range libNeeds[n] {
			add(d)
		}
	}
	for _, n := range append(append([]string(nil), baseLibs...), libs...) {
		add(n)
	}
	var out []string
	for _, n := range names {
		if want[n] {
			out = append(out, n)
		}
	}
	return out
}

var (
	versionRE = regexp.MustCompile(`^[0-9]+(\.[0-9]+){1,3}(-[0-9]+)?$`) // checked before a version reaches a URL or a path; ImageMagick adds -N
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
		r, err = github(ctx, get, "unicode-org/icu", `^release-(\d+\.\d+)$`, "icu4c-%s-sources.tgz")
	case "imagemagick":
		r, err = github(ctx, get, "ImageMagick/ImageMagick", `^(\d+\.\d+\.\d+-\d+)$`, "ImageMagick-%s.tar.xz")
	case "oniguruma":
		r, err = github(ctx, get, "kkos/oniguruma", `^v(\d+\.\d+\.\d+)$`, "onig-%s.tar.gz")
	case "libxml2":
		r, err = libxml2(ctx, get)
	case "sqlite":
		r, err = sqlite(ctx, get)
	case "libpq":
		r, err = postgres(ctx, get)
	case "libpng", "freetype", "libwebp", "gmp", "bzip2", "libsodium", "openldap", "libmemcached":
		r = pinned[name]
	default:
		return Resolved{}, fmt.Errorf("unknown library %q", name)
	}
	if err != nil {
		return Resolved{}, fmt.Errorf("%s: %w", name, err)
	}
	r.Name, r.Rev = name, recipeRev[name]
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
	case "libsodium":
		return "libsodium-stable" // the stable-branch tarball does not name its version
	case "imagemagick":
		return "ImageMagick-" + r.Version
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
		v := strings.ReplaceAll(m[1], "_", ".") // curl tags read 8_23_0
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
	for _, p := range strings.FieldsFunc(v, func(r rune) bool { return r == '.' || r == '-' }) { // 7.1.2-34 is 7,1,2,34
		n, _ := strconv.Atoi(p)
		out = append(out, n)
	}
	return out
}
