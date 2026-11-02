package runtimes

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Ext is one PHP extension a site can switch on and a build can include. Every one is a shared object in ServanaGo's
// own PHP builds (loaded by the site's php.ini); Zend marks zend_extension= (opcache). Extensions the builds always
// include (ctype, filter, tokenizer, session, fileinfo, pdo, phar, openssl, libxml, zlib) are not listed: they are not
// optional.
type Ext struct {
	Name  string
	Group string   // core | web | db | extra, for the checklist
	Zend  bool     // loaded with zend_extension=
	PECL  bool     // built from its Packagist source after PHP (phplibs.ResolveExt); false = compiled with PHP
	Needs []string // other extensions that must be built with it (and load before it)
	Libs  []string // libraries (phplibs names) the extension links; the build compiles only the ones selected
	Tools []string // host programs only this extension's build needs (also their apt package names)
}

// PHPExtensions is the allowlist, in the order the ini loads them.
var PHPExtensions = []Ext{
	{Name: "mbstring", Group: "core", Libs: []string{"oniguruma"}},
	{Name: "opcache", Group: "core", Zend: true},
	{Name: "sqlite3", Group: "core", Libs: []string{"sqlite"}},
	{Name: "pdo_sqlite", Group: "core", Libs: []string{"sqlite"}},
	{Name: "dom", Group: "web"}, {Name: "simplexml", Group: "web"}, {Name: "xml", Group: "web"}, {Name: "xmlreader", Group: "web"}, {Name: "xmlwriter", Group: "web"},
	{Name: "curl", Group: "web", Libs: []string{"curl"}},
	{Name: "zip", Group: "web", Libs: []string{"libzip"}},
	{Name: "gd", Group: "web", Libs: []string{"libpng", "libjpeg-turbo", "freetype", "libwebp"}},
	{Name: "intl", Group: "web", Libs: []string{"icu"}},
	{Name: "soap", Group: "web"},
	{Name: "bcmath", Group: "core"}, {Name: "gmp", Group: "core", Libs: []string{"gmp"}},
	{Name: "mysqli", Group: "db"}, {Name: "pdo_mysql", Group: "db"},
	{Name: "pgsql", Group: "db", Libs: []string{"libpq"}}, {Name: "pdo_pgsql", Group: "db", Libs: []string{"libpq"}},
	{Name: "sockets", Group: "core"}, {Name: "pcntl", Group: "core"},
	{Name: "exif", Group: "web"}, // mbstring, when both are built, must load first (the registry order does that)
	{Name: "bz2", Group: "core", Libs: []string{"bzip2"}},
	{Name: "sodium", Group: "core", Libs: []string{"libsodium"}},
	{Name: "ldap", Group: "extra", Libs: []string{"openldap"}},
	// PECL packages, built from their Packagist source after PHP (phplibs extSpecs).
	{Name: "apcu", Group: "extra", PECL: true},
	{Name: "imagick", Group: "extra", PECL: true, Libs: []string{"imagemagick"}},
	{Name: "msgpack", Group: "extra", PECL: true},
	{Name: "redis", Group: "extra", PECL: true},
	{Name: "memcached", Group: "extra", PECL: true, Libs: []string{"libmemcached"}},
	// The manual: mbstring must be loaded before mailparse. Its release zipball lacks the generated lexer (found by a
	// real build: "re2c: command not found"), so the host needs re2c.
	{Name: "mailparse", Group: "extra", PECL: true, Needs: []string{"mbstring"}, Tools: []string{"re2c"}},
	{Name: "pcov", Group: "extra", PECL: true},
	{Name: "xdebug", Group: "extra", PECL: true, Zend: true}, // a php-ext-zend package: loaded with zend_extension=
}

// CoreExtensions is what a site gets when it selects none.
var CoreExtensions = []string{"mbstring", "opcache", "sqlite3", "pdo_sqlite"}

// LegacyExtensions is what every build made before extensions became a build choice contains (those builds have no
// exts.txt). Fixed: adding to PHPExtensions must not change what an old build is assumed to hold.
var LegacyExtensions = []string{
	"mbstring", "opcache", "sqlite3", "pdo_sqlite", "dom", "simplexml", "xml", "xmlreader", "xmlwriter", "curl", "zip", "gd", "intl", "soap",
	"bcmath", "gmp", "mysqli", "pdo_mysql", "pgsql", "pdo_pgsql", "apcu", "imagick",
}

// Lookup finds an extension in the allowlist.
func Lookup(name string) (Ext, bool) { return lookup(name) }

func lookup(name string) (Ext, bool) {
	i := slices.IndexFunc(PHPExtensions, func(e Ext) bool { return e.Name == name })
	if i < 0 {
		return Ext{}, false
	}
	return PHPExtensions[i], true
}

// ParseExtensions validates a list of names against the allowlist and returns it deduplicated in load order.
// An empty list stays empty (the caller means "the core set").
func ParseExtensions(names []string) ([]string, error) {
	want := map[string]bool{}
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		if _, ok := lookup(n); !ok {
			return nil, fmt.Errorf("php extension %q is not one of the available extensions", n)
		}
		want[n] = true
	}
	var out []string
	for _, e := range PHPExtensions {
		if want[e.Name] {
			out = append(out, e.Name)
		}
	}
	return out, nil
}

// Close adds every extension the selection needs, transitively, and returns the result in load order. The names must
// already be valid (ParseExtensions).
func Close(names []string) []string {
	want := map[string]bool{}
	var add func(n string)
	add = func(n string) {
		if want[n] {
			return
		}
		want[n] = true
		e, _ := lookup(n)
		for _, d := range e.Needs {
			add(d)
		}
	}
	for _, n := range names {
		add(n)
	}
	var out []string
	for _, e := range PHPExtensions {
		if want[e.Name] {
			out = append(out, e.Name)
		}
	}
	return out
}

// LibsFor lists the libraries a selection links, without duplicates; the build adds the always-needed ones.
func LibsFor(names []string) []string {
	var out []string
	for _, n := range names {
		e, _ := lookup(n)
		for _, l := range e.Libs {
			if !slices.Contains(out, l) {
				out = append(out, l)
			}
		}
	}
	return out
}

// Shared reports whether the extension is a loadable .so in builds of this branch (8.4). Since PHP 8.5 opcache is
// always compiled in and always loaded: there is no opcache.so, and zend_extension=opcache would only warn.
func (e Ext) Shared(branch string) bool {
	if e.Name == "opcache" {
		return !atLeast(branch, "8.5")
	}
	return true
}

// SharedExtensions lists the extensions a build of this branch ships as .so files, in load order.
func SharedExtensions(branch string) []Ext {
	var out []Ext
	for _, e := range PHPExtensions {
		if e.Shared(branch) {
			out = append(out, e)
		}
	}
	return out
}

// atLeast compares major.minor branches numerically.
func atLeast(branch, min string) bool {
	return !newest(min, branch) // newest(a, b) is true when a is the greater version
}

// Directive is the ini line that loads the extension.
func (e Ext) Directive() string {
	if e.Zend {
		return "zend_extension=" + e.Name
	}
	return "extension=" + e.Name
}

// BuildExts lists the extensions a build was made with (the first word of each line of its exts.txt); nil for a
// build without the file, which holds LegacyExtensions.
func BuildExts(label string) []string {
	if !BuildRE.MatchString(label) {
		return nil
	}
	b, err := os.ReadFile(filepath.Join(PHPRoot, label, "exts.txt"))
	if err != nil {
		return nil
	}
	return BuildExtsOf(string(b))
}

// BuildExtsOf is the extension names in the text of an exts.txt (the first word of each line).
func BuildExtsOf(text string) []string {
	var out []string
	for _, l := range strings.Split(text, "\n") {
		if f := strings.Fields(l); len(f) > 0 {
			out = append(out, f[0])
		}
	}
	return out
}

// Has reports whether the version's build holds the extension (a legacy build holds LegacyExtensions).
func (v PHPVersion) Has(name string) bool {
	if !v.Source {
		return true // a distro php-fpm: ServanaGo does not know, and does not pick its extensions
	}
	if v.Exts == nil {
		return slices.Contains(LegacyExtensions, name)
	}
	return slices.Contains(v.Exts, name)
}
