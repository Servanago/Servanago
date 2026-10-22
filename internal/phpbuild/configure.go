package phpbuild

import (
	"github.com/servanago/servanago/internal/phplibs"
	"github.com/servanago/servanago/internal/runtimes"
)

// PHPConfigure returns the ./configure arguments and environment for a PHP build into prefix, linked against the
// libraries in deps (name -> prefix).
//
// Always built in: openssl, libxml, zlib, pdo, session, ctype, tokenizer, filter, fileinfo, phar (nothing to select,
// and mysqlnd needs openssl built in). Every other extension in runtimes.PHPExtensions is a shared object, so a
// site's php.ini chooses what loads. php-fpm and the CLI are built; CGI, phpdbg and PEAR are not.
func PHPConfigure(version, prefix string, deps map[string]string) (args, env []string) {
	args = []string{
		"--prefix=" + prefix,
		"--with-config-file-path=" + prefix + "/etc",
		"--with-config-file-scan-dir=" + prefix + "/etc/conf.d",
		"--enable-fpm", "--disable-cgi", "--disable-phpdbg", "--without-pear",
		"--with-openssl", "--with-libxml", "--with-zlib",
		"--enable-mbstring=shared",
		"--with-sqlite3=shared", "--with-pdo-sqlite=shared",
		"--enable-dom=shared", "--enable-simplexml=shared", "--enable-xml=shared", "--enable-xmlreader=shared", "--enable-xmlwriter=shared",
		"--with-curl=shared", "--with-zip=shared", "--enable-intl=shared",
		"--enable-gd=shared", "--with-jpeg", "--with-freetype", "--with-webp",
		"--with-mysqli=shared,mysqlnd", "--with-pdo-mysql=shared,mysqlnd",
		"--with-pgsql=shared", "--with-pdo-pgsql=shared",
		"--enable-bcmath=shared", "--enable-soap=shared", "--with-gmp=shared," + deps["gmp"],
	}
	if (runtimes.Ext{Name: "opcache"}).Shared(runtimes.Branch(version)) { // 8.5 and later: always built in, the flag is gone
		args = append(args, "--enable-opcache=shared")
	}
	return args, phplibs.BuildEnv(prefix, deps)
}
