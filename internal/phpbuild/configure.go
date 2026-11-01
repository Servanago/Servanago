package phpbuild

import (
	"slices"
	"strings"

	"github.com/servanago/servanago/internal/phplibs"
	"github.com/servanago/servanago/internal/runtimes"
)

// switches is how each extension compiled with PHP is turned on and, for the ones PHP builds by default, off.
// "{lib}" is replaced by that library's prefix. PECL extensions (apcu, imagick) are not here: they build after PHP.
var switches = map[string]struct{ on, off []string }{
	"mbstring":   {on: []string{"--enable-mbstring=shared"}},
	"opcache":    {on: []string{"--enable-opcache=shared"}, off: []string{"--disable-opcache"}}, // 8.5+: always built, no flag either way
	"sqlite3":    {on: []string{"--with-sqlite3=shared"}, off: []string{"--without-sqlite3"}},
	"pdo_sqlite": {on: []string{"--with-pdo-sqlite=shared"}, off: []string{"--without-pdo-sqlite"}},
	"dom":        {on: []string{"--enable-dom=shared"}, off: []string{"--disable-dom"}},
	"simplexml":  {on: []string{"--enable-simplexml=shared"}, off: []string{"--disable-simplexml"}},
	"xml":        {on: []string{"--enable-xml=shared"}, off: []string{"--disable-xml"}},
	"xmlreader":  {on: []string{"--enable-xmlreader=shared"}, off: []string{"--disable-xmlreader"}},
	"xmlwriter":  {on: []string{"--enable-xmlwriter=shared"}, off: []string{"--disable-xmlwriter"}},
	"curl":       {on: []string{"--with-curl=shared"}},
	"zip":        {on: []string{"--with-zip=shared"}},
	"intl":       {on: []string{"--enable-intl=shared"}},
	"gd":         {on: []string{"--enable-gd=shared", "--with-jpeg", "--with-freetype", "--with-webp"}},
	"soap":       {on: []string{"--enable-soap=shared"}},
	"bcmath":     {on: []string{"--enable-bcmath=shared"}},
	"gmp":        {on: []string{"--with-gmp=shared,{gmp}"}},
	"mysqli":     {on: []string{"--with-mysqli=shared,mysqlnd"}},
	"pdo_mysql":  {on: []string{"--with-pdo-mysql=shared,mysqlnd"}},
	"pgsql":      {on: []string{"--with-pgsql=shared"}},
	"pdo_pgsql":  {on: []string{"--with-pdo-pgsql=shared"}},
}

// PHPConfigure returns the ./configure arguments and environment for a PHP build into prefix, linked against the
// libraries in deps (name -> prefix), with the extensions in exts.
//
// Always built in: openssl, libxml, zlib, pdo, session, ctype, tokenizer, filter, fileinfo, phar (nothing to select,
// and mysqlnd needs openssl built in). Every extension in exts is a shared object, so a site's php.ini chooses what
// loads; one PHP would build by default but exts leaves out is switched off. php-fpm and the CLI are built; CGI,
// phpdbg and PEAR are not.
func PHPConfigure(version, prefix string, deps map[string]string, exts []string) (args, env []string) {
	args = []string{
		"--prefix=" + prefix,
		"--with-config-file-path=" + prefix + "/etc",
		"--with-config-file-scan-dir=" + prefix + "/etc/conf.d",
		"--enable-fpm", "--disable-cgi", "--disable-phpdbg", "--without-pear",
		"--with-openssl", "--with-libxml", "--with-zlib",
	}
	branch := runtimes.Branch(version)
	for _, e := range runtimes.PHPExtensions {
		sw, ok := switches[e.Name]
		if !ok || !e.Shared(branch) {
			continue
		}
		flags := sw.off
		if slices.Contains(exts, e.Name) {
			flags = sw.on
		}
		for _, f := range flags {
			for lib, p := range deps {
				f = strings.ReplaceAll(f, "{"+lib+"}", p)
			}
			args = append(args, f)
		}
	}
	return args, phplibs.BuildEnv(prefix, deps)
}
