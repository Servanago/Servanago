package runtimes

import (
	"fmt"
	"slices"
	"strings"
)

// Ext is one PHP extension a site can switch on. Every one is a shared object in ServanaGo's own PHP builds
// (loaded by the site's php.ini); Zend marks zend_extension= (opcache). Extensions the builds always include
// (ctype, filter, tokenizer, session, fileinfo, pdo, phar, openssl, libxml) are not listed: they are not optional.
type Ext struct {
	Name  string
	Group string // core | web | db, for the checklist
	Zend  bool
}

// PHPExtensions is the allowlist, in the order the ini loads them.
var PHPExtensions = []Ext{
	{"mbstring", "core", false}, {"opcache", "core", true}, {"sqlite3", "core", false}, {"pdo_sqlite", "core", false},
	{"dom", "web", false}, {"simplexml", "web", false}, {"xml", "web", false}, {"xmlreader", "web", false}, {"xmlwriter", "web", false},
	{"curl", "web", false}, {"zip", "web", false}, {"gd", "web", false}, {"intl", "web", false},
	{"mysqli", "db", false}, {"pdo_mysql", "db", false}, {"pgsql", "db", false}, {"pdo_pgsql", "db", false},
}

// CoreExtensions is what a site gets when it selects none.
var CoreExtensions = []string{"mbstring", "opcache", "sqlite3", "pdo_sqlite"}

// ParseExtensions validates a list of names against the allowlist and returns it deduplicated in load order.
// An empty list stays empty (the caller means "the core set").
func ParseExtensions(names []string) ([]string, error) {
	want := map[string]bool{}
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		if !slices.ContainsFunc(PHPExtensions, func(e Ext) bool { return e.Name == n }) {
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
