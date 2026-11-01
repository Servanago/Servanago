package phplibs

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/Masterminds/semver/v3"
)

// ExtSource is one PHP extension's newest stable release that runs on the PHP being built, as Packagist (the PIE
// package format) describes it. Packagist carries no checksum for a GitHub zipball: the pin is the 40-hex Commit, and
// the caller logs the zipball's sha256. Trust is Packagist plus GitHub over https, decided; nothing here weakens that.
type ExtSource struct {
	Name, Package, Version, URL, Commit string
	Php                                 string // the release's own php requirement, for the log
	Zend                                bool   // the package type is php-ext-zend: loaded with zend_extension=
}

// extSpec is what ServanaGo knows about one extension it builds from Packagist: the package, the GitHub repository its
// release zipball must come from, the configure arguments (after --with-php-config; "{lib}" is that library's prefix)
// and the libraries that must have been built.
type extSpec struct {
	Package, Repo string
	Flags         []string
	Libs          []string
}

var extSpecs = map[string]extSpec{
	"apcu":      {Package: "apcu/apcu", Repo: "krakjoe/apcu", Flags: []string{"--enable-apcu"}},
	"imagick":   {Package: "imagick/imagick", Repo: "Imagick/imagick", Flags: []string{"--with-imagick={imagemagick}"}, Libs: []string{"imagemagick"}},
	"redis":     {Package: "phpredis/phpredis", Repo: "phpredis/phpredis", Flags: []string{"--enable-redis"}}, // serializers and compressors stay off: they need other libraries
	"xdebug":    {Package: "xdebug/xdebug", Repo: "xdebug/xdebug", Flags: []string{"--enable-xdebug"}},
	"msgpack":   {Package: "msgpack/msgpack-php", Repo: "msgpack/msgpack-php", Flags: []string{"--with-msgpack"}},
	"pcov":      {Package: "pecl/pcov", Repo: "krakjoe/pcov", Flags: []string{"--enable-pcov"}},
	"mailparse": {Package: "pecl/mailparse", Repo: "php/pecl-mail-mailparse", Flags: []string{"--enable-mailparse"}},
	"memcached": {Package: "php-memcached/php-memcached", Repo: "php-memcached-dev/php-memcached",
		Flags: []string{"--enable-memcached", "--with-libmemcached-dir={libmemcached}", "--with-zlib-dir={zlib}", "--disable-memcached-sasl"}, // SASL: libmemcached is built without it
		Libs:  []string{"libmemcached", "zlib"}},
}

var zipballRE = regexp.MustCompile(`^https://api\.github\.com/repos/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/zipball/([0-9a-f]{40})$`)

// packagistEntry is one version of a package in Composer's p2 format.
type packagistEntry map[string]json.RawMessage

// ResolveExt finds the newest stable release of one extension that runs on phpVersion (the PHP being built). It is
// stricter than Composer needs to be: the package must be a php-ext (or php-ext-zend) whose extension-name is the name
// asked for, it must not rule out Linux or non-thread-safe PHP or ask for a download method other than the default, the
// dist must be the GitHub zipball of exactly the commit that source and dist both name, in the repository listed for
// the extension, and the configure arguments ServanaGo passes must be ones the package declares.
func ResolveExt(ctx context.Context, get Getter, name, phpVersion string) (ExtSource, error) {
	spec, ok := extSpecs[name]
	if !ok {
		return ExtSource{}, fmt.Errorf("unknown extension %q", name)
	}
	body, err := get(ctx, "https://repo.packagist.org/p2/"+spec.Package+".json")
	if err != nil {
		return ExtSource{}, fmt.Errorf("%s: %w", name, err)
	}
	var feed struct {
		Packages map[string][]packagistEntry `json:"packages"`
	}
	if err := json.Unmarshal(body, &feed); err != nil {
		return ExtSource{}, fmt.Errorf("%s: packagist feed: %w", name, err)
	}
	type release struct {
		version string
		fields  map[string]json.RawMessage
	}
	var stable []release
	for _, e := range expand(feed.Packages[spec.Package]) {
		var v string
		if json.Unmarshal(e["version"], &v) != nil {
			continue
		}
		if v = strings.TrimPrefix(v, "v"); versionRE.MatchString(v) { // drops dev-*, alpha, beta, RC and anything odd
			stable = append(stable, release{v, e})
		}
	}
	if len(stable) == 0 {
		return ExtSource{}, fmt.Errorf("%s: no stable release of %s in the packagist feed", name, spec.Package)
	}
	sort.SliceStable(stable, func(i, j int) bool { return newer(stable[i].version, stable[j].version) })
	var best *release
	for i, r := range stable {
		var req struct {
			Php string `json:"php"`
		}
		_ = json.Unmarshal(r.fields["require"], &req) // an entry with no require block has no php limit
		if req.Php != "" {
			ok, err := phpSatisfies(req.Php, phpVersion)
			if err != nil {
				return ExtSource{}, fmt.Errorf("%s %s: %w", name, r.version, err)
			}
			if !ok {
				continue
			}
		}
		best = &stable[i]
		break
	}
	if best == nil {
		var req struct {
			Php string `json:"php"`
		}
		_ = json.Unmarshal(stable[0].fields["require"], &req)
		return ExtSource{}, fmt.Errorf("%s: no release supports PHP %s (newest %s requires %s)", name, phpVersion, stable[0].version, req.Php)
	}
	bestVer, fields := best.version, best.fields

	var typ string
	var phpExt struct {
		Name        string          `json:"extension-name"`
		SupportNTS  *bool           `json:"support-nts"`
		OS          []string        `json:"os-families"`
		OSExclude   []string        `json:"os-families-exclude"`
		DownloadURL json.RawMessage `json:"download-url-method"`
		Options     []struct {
			Name string `json:"name"`
		} `json:"configure-options"`
	}
	var require struct {
		Php string `json:"php"`
	}
	var dist, source struct {
		URL       string `json:"url"`
		Reference string `json:"reference"`
	}
	for key, dst := range map[string]any{"type": &typ, "php-ext": &phpExt, "dist": &dist, "source": &source} {
		if err := json.Unmarshal(fields[key], dst); err != nil {
			return ExtSource{}, fmt.Errorf("%s %s: field %q: %w", name, bestVer, key, err)
		}
	}
	_ = json.Unmarshal(fields["require"], &require)
	extName := phpExt.Name
	if extName == "" { // PIE: derived from the package name without its vendor
		extName = spec.Package[strings.Index(spec.Package, "/")+1:]
	}
	m := zipballRE.FindStringSubmatch(dist.URL)
	switch {
	case typ != "php-ext" && typ != "php-ext-zend":
		return ExtSource{}, fmt.Errorf("%s %s: package type is %q, not php-ext or php-ext-zend", name, bestVer, typ)
	case extName != name:
		return ExtSource{}, fmt.Errorf("%s %s: php-ext extension-name is %q", name, bestVer, extName)
	case phpExt.SupportNTS != nil && !*phpExt.SupportNTS:
		return ExtSource{}, fmt.Errorf("%s %s: the package does not support non-thread-safe PHP", name, bestVer)
	case len(phpExt.OS) > 0 && !slices.Contains(phpExt.OS, "linux"), slices.Contains(phpExt.OSExclude, "linux"):
		return ExtSource{}, fmt.Errorf("%s %s: the package is not for linux", name, bestVer)
	case !defaultDownload(phpExt.DownloadURL):
		return ExtSource{}, fmt.Errorf("%s %s: download-url-method %s is not supported (only the default zipball)", name, bestVer, phpExt.DownloadURL)
	case m == nil:
		return ExtSource{}, fmt.Errorf("%s %s: dist url %q is not a https GitHub zipball of a commit", name, bestVer, dist.URL)
	case dist.Reference != m[3] || source.Reference != m[3]:
		return ExtSource{}, fmt.Errorf("%s %s: dist reference %q and source reference %q do not both name commit %s", name, bestVer, dist.Reference, source.Reference, m[3])
	case !strings.EqualFold(m[1]+"/"+m[2], spec.Repo):
		return ExtSource{}, fmt.Errorf("%s %s: zipball repository %q is not %s", name, bestVer, m[1]+"/"+m[2], spec.Repo)
	}
	if len(phpExt.Options) > 0 { // a package that declares none (xdebug, mailparse) is not held to any
		declared := map[string]bool{}
		for _, o := range phpExt.Options {
			declared[o.Name] = true
		}
		for _, f := range spec.Flags {
			if n := flagName(f); !declared[n] {
				return ExtSource{}, fmt.Errorf("%s %s: the package declares no %q configure option (ServanaGo passes %s)", name, bestVer, n, f)
			}
		}
	}
	return ExtSource{Name: name, Package: spec.Package, Version: bestVer, URL: dist.URL, Commit: m[3], Php: require.Php, Zend: typ == "php-ext-zend"}, nil
}

// phpSatisfies reports whether a Composer php requirement (">=8.0,<8.6", "^7.4 || ^8.0") allows the PHP version.
func phpSatisfies(req, phpVersion string) (bool, error) {
	c, err := semver.NewConstraint(req)
	if err != nil {
		return false, fmt.Errorf("php requirement %q is not understood: %w", req, err)
	}
	v, err := semver.NewVersion(phpVersion)
	if err != nil {
		return false, fmt.Errorf("php version %q: %w", phpVersion, err)
	}
	return c.Check(v), nil
}

// defaultDownload reports whether the package's download-url-method is absent or includes the default zipball.
func defaultDownload(raw json.RawMessage) bool {
	if len(raw) == 0 || string(raw) == "null" {
		return true
	}
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return one == "composer-default"
	}
	var many []string
	return json.Unmarshal(raw, &many) == nil && slices.Contains(many, "composer-default")
}

// flagName is the name under which a package declares a configure argument: "--disable-x" and "--without-x" are
// declared as "enable-x" and "with-x", and a value ("=/dir") is not part of the name.
func flagName(flag string) string {
	n, _, _ := strings.Cut(strings.TrimPrefix(flag, "--"), "=")
	if r, ok := strings.CutPrefix(n, "disable-"); ok {
		return "enable-" + r
	}
	if r, ok := strings.CutPrefix(n, "without-"); ok {
		return "with-" + r
	}
	return n
}

// expand undoes Composer's minified p2 format: every entry after the first lists only what differs from the
// one before it, and the string "__unset" removes a field.
func expand(entries []packagistEntry) []map[string]json.RawMessage {
	var out []map[string]json.RawMessage
	var prev map[string]json.RawMessage
	for _, e := range entries {
		cur := map[string]json.RawMessage{}
		for k, v := range prev {
			cur[k] = v
		}
		for k, v := range e {
			if string(v) == `"__unset"` {
				delete(cur, k)
			} else {
				cur[k] = v
			}
		}
		out = append(out, cur)
		prev = cur
	}
	return out
}

// ExtRecipe builds and installs one extension against a built PHP: phpize, configure, make, install. Dir "" is
// the unpacked extension directory. It fails for an extension with no recipe and for one whose library is missing
// from deps, and says which.
func ExtRecipe(e ExtSource, phpPrefix string, deps map[string]string, jobs int) ([]Cmd, error) {
	spec, ok := extSpecs[e.Name]
	if !ok {
		return nil, fmt.Errorf("no build recipe for extension %q", e.Name)
	}
	for _, l := range spec.Libs {
		if deps[l] == "" {
			return nil, fmt.Errorf("%s needs %s, which was not built", e.Name, l)
		}
	}
	args := []string{"--with-php-config=" + phpPrefix + "/bin/php-config"}
	for _, f := range spec.Flags {
		for lib, p := range deps {
			f = strings.ReplaceAll(f, "{"+lib+"}", p)
		}
		args = append(args, f)
	}
	env := BuildEnv(phpPrefix, deps)
	return []Cmd{
		{Env: env, Name: phpPrefix + "/bin/phpize"},
		{Env: env, Name: "./configure", Args: args},
		{Env: env, Name: "make", Args: []string{"-j" + strconv.Itoa(max(jobs, 1))}},
		{Env: env, Name: "make", Args: []string{"install"}},
	}, nil
}
