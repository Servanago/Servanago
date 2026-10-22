package phplibs

import (
	"path/filepath"
	"strconv"
	"strings"
)

// Cmd is one build command. Dir is relative to the unpacked source directory ("" = its root); Env entries are
// KEY=VALUE added to the environment.
type Cmd struct {
	Dir  string
	Env  []string
	Name string
	Args []string
}

// Pkg lists the pkg-config directories a library installed under prefix exposes.
func Pkg(prefix string) []string {
	return []string{filepath.Join(prefix, "lib", "pkgconfig"), filepath.Join(prefix, "lib64", "pkgconfig")}
}

// Recipe builds and installs one library into prefix. deps maps the names of already-built libraries to
// their prefixes. Every library is linked with a RUNPATH to its own and its dependencies' lib directories, so
// nothing needs ld.so configuration at run time.
func Recipe(r Resolved, prefix string, deps map[string]string, jobs int) []Cmd {
	j := "-j" + strconv.Itoa(max(jobs, 1))
	env := buildEnv(prefix, deps)
	dep := func(n string) string { return deps[n] }
	cfg := func(args ...string) Cmd {
		return Cmd{Env: env, Name: "./configure", Args: append([]string{"--prefix=" + prefix, "--disable-static"}, args...)}
	}
	mk := func(args ...string) Cmd { return Cmd{Env: env, Name: "make", Args: args} }
	cmake := func(args ...string) []Cmd {
		a := append([]string{"-S", ".", "-B", "build", "-DCMAKE_BUILD_TYPE=Release", "-DCMAKE_INSTALL_PREFIX=" + prefix,
			"-DCMAKE_INSTALL_LIBDIR=lib", "-DCMAKE_INSTALL_RPATH=" + rpathList(prefix, deps), "-DCMAKE_PREFIX_PATH=" + strings.Join(depPrefixes(deps), ";")}, args...)
		return []Cmd{{Env: env, Name: "cmake", Args: a}, {Env: env, Name: "cmake", Args: []string{"--build", "build", j}}, {Env: env, Name: "cmake", Args: []string{"--install", "build"}}}
	}
	std := func(extra ...string) []Cmd { return []Cmd{cfg(extra...), mk(j), mk("install")} }

	switch r.Name {
	case "zlib":
		return []Cmd{{Env: env, Name: "./configure", Args: []string{"--prefix=" + prefix}}, mk(j), mk("install")}
	case "openssl":
		// The CA bundle stays the host's: openssldir is /etc/ssl and install_sw never writes there.
		return []Cmd{{Env: env, Name: "./config", Args: []string{"--prefix=" + prefix, "--libdir=lib", "--openssldir=/etc/ssl", "shared", "no-tests", "-Wl,-rpath," + prefix + "/lib"}}, mk(j), mk("install_sw")}
	case "curl":
		return std("--with-openssl="+dep("openssl"), "--with-zlib="+dep("zlib"), "--with-ca-path=/etc/ssl/certs", "--with-ca-bundle=/etc/ssl/certs/ca-certificates.crt",
			"--without-libpsl", "--without-brotli", "--without-zstd", "--without-nghttp2", "--without-libidn2", "--without-librtmp", "--disable-ldap", "--disable-docs", "--disable-manual")
	case "libxml2":
		return std("--without-python", "--without-lzma", "--without-icu", "--with-zlib="+dep("zlib"))
	case "libpng":
		return std()
	case "libjpeg-turbo":
		return cmake("-DENABLE_STATIC=OFF", "-DWITH_JAVA=OFF", "-DWITH_TURBOJPEG=OFF")
	case "freetype":
		return std("--with-zlib=yes", "--with-png=yes", "--with-harfbuzz=no", "--with-brotli=no", "--with-bzip2=no")
	case "libwebp":
		return std("--disable-gl", "--disable-sdl", "--disable-png", "--disable-jpeg", "--disable-tiff", "--disable-gif") // demux stays: ImageMagick's webp coder links it
	case "imagemagick":
		// Libraries only (no convert/magick tools), and only the coders for libraries built here. It installs
		// MagickWand.pc and ImageMagick.pc for the imagick extension.
		return std("--without-utilities", "--without-magick-plus-plus", "--without-perl", "--disable-docs", "--disable-openmp", "--disable-opencl",
			"--with-png=yes", "--with-jpeg=yes", "--with-webp=yes", "--with-freetype=yes", "--with-xml=yes", "--with-zlib=yes",
			"--without-x", "--without-lzma", "--without-bzlib", "--without-fontconfig", "--without-tiff", "--without-heic", "--without-jxl",
			"--without-openexr", "--without-raw", "--without-lcms", "--without-pango", "--without-rsvg", "--without-wmf", "--without-djvu",
			"--without-openjp2", "--without-lqr", "--without-fftw", "--without-gslib", "--without-zstd", "--without-gvc", "--without-jbig",
			"--without-autotrace", "--without-dps", "--without-flif", "--without-fpx", "--without-raqm")
	case "libzip":
		return cmake("-DBUILD_SHARED_LIBS=ON", "-DBUILD_TOOLS=OFF", "-DBUILD_REGRESS=OFF", "-DBUILD_EXAMPLES=OFF", "-DBUILD_DOC=OFF",
			"-DENABLE_OPENSSL=ON", "-DENABLE_GNUTLS=OFF", "-DENABLE_MBEDTLS=OFF", "-DENABLE_COMMONCRYPTO=OFF", "-DENABLE_BZIP2=OFF", "-DENABLE_LZMA=OFF", "-DENABLE_ZSTD=OFF",
			"-DOPENSSL_ROOT_DIR="+dep("openssl"))
	case "icu":
		c := std("--disable-tests", "--disable-samples", "--disable-extras", "--disable-layoutex")
		for i := range c {
			c[i].Dir = "source"
		}
		return c
	case "oniguruma":
		return std()
	case "gmp":
		return std("--disable-cxx")
	case "sqlite":
		// PHP's sqlite3 and pdo_sqlite use the column metadata API.
		c := std()
		for i := range c {
			c[i].Env = append(append([]string(nil), c[i].Env...), "CPPFLAGS=-DSQLITE_ENABLE_COLUMN_METADATA=1 -DSQLITE_ENABLE_FTS5=1 "+cppFlags(deps))
		}
		return c
	case "libpq":
		// Only the client library: headers, libpq and its pkg-config file.
		return []Cmd{
			{Env: env, Name: "./configure", Args: []string{"--prefix=" + prefix, "--with-ssl=openssl", "--without-readline", "--without-zlib", "--without-icu"}},
			mk("-C", "src/include", "install"),
			mk("-C", "src/interfaces/libpq", j),
			mk("-C", "src/interfaces/libpq", "install"),
		}
	}
	return nil
}

func depPrefixes(deps map[string]string) []string {
	var out []string
	for _, n := range names { // build order keeps the result stable
		if p, ok := deps[n]; ok {
			out = append(out, p)
		}
	}
	return out
}

func rpathList(prefix string, deps map[string]string) string {
	out := []string{prefix + "/lib"}
	for _, p := range depPrefixes(deps) {
		out = append(out, p+"/lib")
	}
	return strings.Join(out, ";")
}

func cppFlags(deps map[string]string) string {
	var f []string
	for _, p := range depPrefixes(deps) {
		f = append(f, "-I"+p+"/include")
	}
	return strings.Join(f, " ")
}

// BuildEnv is the PKG_CONFIG_PATH, CPPFLAGS and LDFLAGS (with RUNPATH) for building something against deps into prefix.
func BuildEnv(prefix string, deps map[string]string) []string { return buildEnv(prefix, deps) }

func buildEnv(prefix string, deps map[string]string) []string {
	var pkg []string
	ld := []string{"-Wl,-rpath," + prefix + "/lib"}
	for _, p := range depPrefixes(deps) {
		pkg = append(pkg, Pkg(p)...)
		ld = append(ld, "-L"+p+"/lib", "-Wl,-rpath,"+p+"/lib")
	}
	return []string{"PKG_CONFIG_PATH=" + strings.Join(pkg, ":"), "CPPFLAGS=" + cppFlags(deps), "LDFLAGS=" + strings.Join(ld, " ")}
}
