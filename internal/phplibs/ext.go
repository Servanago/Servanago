package phplibs

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ExtSource is one PHP extension's latest stable release, as Packagist (the PIE package format) describes it.
// Packagist carries no checksum for a GitHub zipball: the pin is the 40-hex Commit, and the caller logs the
// zipball's sha256. Trust is Packagist plus GitHub over https, decided; nothing here weakens that further.
type ExtSource struct{ Name, Package, Version, URL, Commit string }

var extPackages = map[string]string{"apcu": "apcu/apcu", "imagick": "imagick/imagick"}

// ExtNames lists the extensions built from Packagist sources.
func ExtNames() []string { return []string{"apcu", "imagick"} }

var zipballRE = regexp.MustCompile(`^https://api\.github\.com/repos/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/zipball/([0-9a-f]{40})$`)

// packagistEntry is one version of a package in Composer's p2 format.
type packagistEntry map[string]json.RawMessage

// ResolveExt finds the latest stable release of one extension. It is stricter than Composer needs to be: the
// package must be a php-ext whose extension-name is the name asked for, and the dist must be the GitHub zipball
// of exactly the commit that source and dist both name, in a repository called like the package.
func ResolveExt(ctx context.Context, get Getter, name string) (ExtSource, error) {
	pkg, ok := extPackages[name]
	if !ok {
		return ExtSource{}, fmt.Errorf("unknown extension %q", name)
	}
	body, err := get(ctx, "https://repo.packagist.org/p2/"+pkg+".json")
	if err != nil {
		return ExtSource{}, fmt.Errorf("%s: %w", name, err)
	}
	var feed struct {
		Packages map[string][]packagistEntry `json:"packages"`
	}
	if err := json.Unmarshal(body, &feed); err != nil {
		return ExtSource{}, fmt.Errorf("%s: packagist feed: %w", name, err)
	}
	var best map[string]json.RawMessage
	var bestVer string
	for _, e := range expand(feed.Packages[pkg]) {
		var v string
		if json.Unmarshal(e["version"], &v) != nil {
			continue
		}
		if v = strings.TrimPrefix(v, "v"); !versionRE.MatchString(v) { // drops dev-*, alpha, beta, RC and anything odd
			continue
		}
		if best == nil || newer(v, bestVer) {
			best, bestVer = e, v
		}
	}
	if best == nil {
		return ExtSource{}, fmt.Errorf("%s: no stable release of %s in the packagist feed", name, pkg)
	}
	var typ string
	var phpExt struct {
		Name string `json:"extension-name"`
	}
	var dist, source struct {
		URL       string `json:"url"`
		Reference string `json:"reference"`
	}
	for key, dst := range map[string]any{"type": &typ, "php-ext": &phpExt, "dist": &dist, "source": &source} {
		if err := json.Unmarshal(best[key], dst); err != nil {
			return ExtSource{}, fmt.Errorf("%s %s: field %q: %w", name, bestVer, key, err)
		}
	}
	m := zipballRE.FindStringSubmatch(dist.URL)
	switch {
	case typ != "php-ext":
		return ExtSource{}, fmt.Errorf("%s %s: package type is %q, not php-ext", name, bestVer, typ)
	case phpExt.Name != name:
		return ExtSource{}, fmt.Errorf("%s %s: php-ext extension-name is %q", name, bestVer, phpExt.Name)
	case m == nil:
		return ExtSource{}, fmt.Errorf("%s %s: dist url %q is not a https GitHub zipball of a commit", name, bestVer, dist.URL)
	case dist.Reference != m[3] || source.Reference != m[3]:
		return ExtSource{}, fmt.Errorf("%s %s: dist reference %q and source reference %q do not both name commit %s", name, bestVer, dist.Reference, source.Reference, m[3])
	case !strings.EqualFold(m[2], name):
		return ExtSource{}, fmt.Errorf("%s %s: zipball repository %q is not called %s", name, bestVer, m[2], name)
	}
	return ExtSource{Name: name, Package: pkg, Version: bestVer, URL: dist.URL, Commit: m[3]}, nil
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
// the unpacked extension directory. It returns nil for an unknown extension or when a library the extension
// needs is missing from deps, so the caller can fail with a clear message.
func ExtRecipe(e ExtSource, phpPrefix string, deps map[string]string, jobs int) []Cmd {
	env := BuildEnv(phpPrefix, deps)
	args := []string{"--with-php-config=" + phpPrefix + "/bin/php-config"}
	switch e.Name {
	case "apcu":
		args = append(args, "--enable-apcu")
	case "imagick":
		im := deps["imagemagick"]
		if im == "" {
			return nil
		}
		args = append(args, "--with-imagick="+im)
	default:
		return nil
	}
	return []Cmd{
		{Env: env, Name: phpPrefix + "/bin/phpize"},
		{Env: env, Name: "./configure", Args: args},
		{Env: env, Name: "make", Args: []string{"-j" + strconv.Itoa(max(jobs, 1))}},
		{Env: env, Name: "make", Args: []string{"install"}},
	}
}
