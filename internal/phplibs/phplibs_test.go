package phplibs

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
)

// feeds maps a feed URL to a recorded response under testdata (trimmed to the fields the resolvers read).
var feeds = map[string]string{
	"https://api.github.com/repos/madler/zlib/releases?per_page=100":                        "github-madler-zlib.json",
	"https://api.github.com/repos/openssl/openssl/releases?per_page=100":                    "github-openssl-openssl.json",
	"https://api.github.com/repos/curl/curl/releases?per_page=100":                          "github-curl-curl.json",
	"https://api.github.com/repos/libjpeg-turbo/libjpeg-turbo/releases?per_page=100":        "github-libjpeg-turbo-libjpeg-turbo.json",
	"https://api.github.com/repos/nih-at/libzip/releases?per_page=100":                      "github-nih-at-libzip.json",
	"https://api.github.com/repos/unicode-org/icu/releases?per_page=100":                    "github-unicode-org-icu.json",
	"https://api.github.com/repos/kkos/oniguruma/releases?per_page=100":                     "github-kkos-oniguruma.json",
	"https://github.com/kkos/oniguruma/releases/download/v6.9.10/onig-6.9.10.tar.gz.sha256": "onig-6.9.10.tar.gz.sha256",
	"https://api.github.com/repos/ImageMagick/ImageMagick/releases?per_page=100":            "github-ImageMagick-ImageMagick.json",
	"https://repo.packagist.org/p2/apcu/apcu.json":                                          "packagist-apcu.json",
	"https://repo.packagist.org/p2/imagick/imagick.json":                                    "packagist-imagick.json",
	"https://download.gnome.org/sources/libxml2/cache.json":                                 "libxml2-cache.json",
	"https://download.gnome.org/sources/libxml2/2.15/libxml2-2.15.4.sha256sum":              "libxml2-2.15.4.sha256sum",
	"https://sqlite.org/download.html":                                                      "sqlite-download.html",
	"https://ftp.postgresql.org/pub/source/":                                                "postgres-source-index.html",
	"https://ftp.postgresql.org/pub/source/v18.6/postgresql-18.6.tar.gz.sha256":             "postgresql-18.6.tar.gz.sha256",
}

func fixtureGetter(t *testing.T) Getter {
	t.Helper()
	return func(_ context.Context, url string) ([]byte, error) {
		f, ok := feeds[url]
		if !ok {
			return nil, fmt.Errorf("unexpected request %s", url)
		}
		return os.ReadFile("testdata/" + f)
	}
}

func TestResolveRecordedFeeds(t *testing.T) {
	tests := []struct {
		name, version, url, algo, sum string
	}{
		{"zlib", "1.3.2", "https://github.com/madler/zlib/releases/download/v1.3.2/zlib-1.3.2.tar.xz", AlgoSHA256, "d7a0654783a4da529d1bb793b7ad9c3318020af77667bcae35f95d0e42a792f3"},
		{"openssl", "3.6.5", "https://github.com/openssl/openssl/releases/download/openssl-3.6.5/openssl-3.6.5.tar.gz", AlgoSHA256, ""}, // 4.x and betas are skipped
		{"curl", "8.23.0", "https://github.com/curl/curl/releases/download/curl-8_23_0/curl-8.23.0.tar.xz", AlgoSHA256, "8dadd7d2536a314f982ad05a651b713f426bf7d02cc2c76cffb9796f2218e6c5"},
		{"libjpeg-turbo", "3.2.0", "https://github.com/libjpeg-turbo/libjpeg-turbo/releases/download/3.2.0/libjpeg-turbo-3.2.0.tar.gz", AlgoSHA256, "6f30092cef9fb839779646608f4ee14ae3cbac989c47fa05e841b0841f09878e"},
		{"libzip", "1.12.1", "https://github.com/nih-at/libzip/releases/download/v1.12.1/libzip-1.12.1.tar.xz", AlgoSHA256, "c40062022a1963c80573d48f6070792297cecd7c6bffe3aefcac0d8b9bee8913"},
		{"icu", "78.3", "https://github.com/unicode-org/icu/releases/download/release-78.3/icu4c-78.3-sources.tgz", AlgoSHA256, "3a2e7a47604ba702f345878308e6fefeca612ee895cf4a5f222e7955fabfe0c0"},
		{"imagemagick", "7.1.2-34", "https://github.com/ImageMagick/ImageMagick/releases/download/7.1.2-34/ImageMagick-7.1.2-34.tar.xz", AlgoSHA256, "55fe0ec246245b46c429f9e6bc65294ad4a78a66b88abd9817971ca157856323"},
		{"oniguruma", "6.9.10", "https://github.com/kkos/oniguruma/releases/download/v6.9.10/onig-6.9.10.tar.gz", AlgoSHA256, "2a5cfc5ae259e4e97f86b68dfffc152cdaffe94e2060b770cb827238d769fc05"}, // sum from the .sha256 sidecar
		{"libxml2", "2.15.4", "https://download.gnome.org/sources/libxml2/2.15/libxml2-2.15.4.tar.xz", AlgoSHA256, "98087fd181d9070724f3fbc65c7377db03038eb92bd882374daff44940138821"},
		{"sqlite", "3.54.1", "https://sqlite.org/2026/sqlite-autoconf-3540100.tar.gz", AlgoSHA3, "b6ced585c750916b1052667239a12c25a7ff34e7f06e1e6e01ecb0427657d9c4"},
		{"libpq", "18.6", "https://ftp.postgresql.org/pub/source/v18.6/postgresql-18.6.tar.gz", AlgoSHA256, "983ee554ec53dbeb9b70797bef9fcf4e67e117e7e48ca1463cc80b3ff8e8ff3f"}, // v19beta* is skipped
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := Resolve(context.Background(), fixtureGetter(t), tt.name)
			if err != nil {
				t.Fatal(err)
			}
			if r.Name != tt.name || r.Version != tt.version || r.URL != tt.url || r.Algo != tt.algo {
				t.Errorf("got %+v", r)
			}
			if tt.sum != "" && r.Sum != tt.sum {
				t.Errorf("sum %s, want %s", r.Sum, tt.sum)
			}
			if len(r.Sum) != 64 {
				t.Errorf("sum %q is not 64 hex digits", r.Sum)
			}
		})
	}
}

// TestResolveRejects asserts why each case fails: a library without an authenticated sum must never resolve.
func TestResolveRejects(t *testing.T) {
	gh := func(body string) Getter {
		return func(_ context.Context, url string) ([]byte, error) {
			if strings.HasSuffix(url, ".sha256") {
				return []byte("not a sum here"), nil
			}
			return []byte(body), nil
		}
	}
	rel := func(tag, prerelease, assets string) string {
		return `[{"tag_name":"` + tag + `","prerelease":` + prerelease + `,"draft":false,"assets":[` + assets + `]}]`
	}
	good := `{"name":"zlib-1.3.2.tar.xz","digest":"sha256:` + strings.Repeat("a", 64) + `","browser_download_url":"https://github.com/madler/zlib/releases/download/v1.3.2/zlib-1.3.2.tar.xz"}`
	tests := []struct {
		name string
		get  Getter
		lib  string
		want string
	}{
		{"unknown library", nil, "libfoo", "unknown library"},
		{"only a prerelease", gh(rel("v1.3.2", "true", good)), "zlib", "no stable"},
		{"asset missing", gh(rel("v1.3.2", "false", "")), "zlib", "no stable"},
		{"no digest, no sidecar", gh(rel("v6.9.10", "false", `{"name":"onig-6.9.10.tar.gz","digest":null,"browser_download_url":"https://x/y"}`)), "oniguruma", "no sha256 digest"},
		{"sidecar without the file's sum", gh(rel("v6.9.10", "false", `{"name":"onig-6.9.10.tar.gz","digest":null,"browser_download_url":"https://x/y"},{"name":"onig-6.9.10.tar.gz.sha256","digest":null,"browser_download_url":"https://x/z.sha256"}`)), "oniguruma", "holds no sum"},
		{"non-https tarball", gh(rel("v1.3.2", "false", strings.Replace(good, "https://", "http://", 1))), "zlib", "not https"},
		{"digest of another algorithm", gh(rel("v1.3.2", "false", strings.Replace(good, "sha256:", "sha512:", 1))), "zlib", "no sha256 digest"},
		{"short digest", gh(rel("v1.3.2", "false", strings.Replace(good, strings.Repeat("a", 64), "abc", 1))), "zlib", "64 hex"},
		{"sqlite page without the table", gh("<html></html>"), "sqlite", "no sqlite-autoconf row"},
		{"feed error", func(context.Context, string) ([]byte, error) { return nil, fmt.Errorf("boom") }, "libxml2", "boom"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Resolve(context.Background(), tt.get, tt.lib)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error %v, want one containing %q", err, tt.want)
			}
		})
	}
}

// TestPinned: the three libraries without a feed sum resolve from the table, flagged as pinned, and nothing
// else is flagged. A pinned entry is held to the same rules as a feed one.
func TestPinned(t *testing.T) {
	for _, n := range []string{"libpng", "freetype", "libwebp"} {
		r, err := Resolve(context.Background(), nil, n) // pinned entries touch no feed
		if err != nil {
			t.Fatalf("%s: %v", n, err)
		}
		if !r.Pinned || r.Name != n || r.Algo != AlgoSHA256 || !sumRE.MatchString(r.Sum) || !strings.HasPrefix(r.URL, "https://") || !versionRE.MatchString(r.Version) {
			t.Errorf("%s: %+v", n, r)
		}
		if !strings.Contains(r.URL, SourceDir(r)) {
			t.Errorf("%s: URL %s does not name the tarball %s extracts from", n, r.URL, SourceDir(r))
		}
	}
	for _, n := range []string{"zlib", "sqlite", "libpq"} {
		if r, err := Resolve(context.Background(), fixtureGetter(t), n); err != nil || r.Pinned {
			t.Errorf("%s: feed-tracked, got %+v %v", n, r, err)
		}
	}
	// A broken table entry must be refused by Resolve, never handed out.
	bad := pinned["libpng"]
	for _, c := range []struct {
		mut  func(*Resolved)
		want string
	}{
		{func(r *Resolved) { r.Sum = "" }, "64 hex"},
		{func(r *Resolved) { r.URL = "http://x/libpng.tar.xz" }, "not https"},
		{func(r *Resolved) { r.Version = "1.6.x" }, "plain dotted"},
	} {
		e := bad
		c.mut(&e)
		pinned["libpng"] = e
		_, err := Resolve(context.Background(), nil, "libpng")
		pinned["libpng"] = bad
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("error %v, want one containing %q", err, c.want)
		}
	}
}

func TestSourceDir(t *testing.T) {
	tests := []struct {
		r    Resolved
		want string
	}{
		{Resolved{Name: "zlib", Version: "1.3.2"}, "zlib-1.3.2"},
		{Resolved{Name: "icu", Version: "78.3"}, "icu"},
		{Resolved{Name: "imagemagick", Version: "7.1.2-34"}, "ImageMagick-7.1.2-34"}, // the tarball's real top directory
		{Resolved{Name: "oniguruma", Version: "6.9.10"}, "onig-6.9.10"},
		{Resolved{Name: "libpq", Version: "18.6"}, "postgresql-18.6"},
		{Resolved{Name: "sqlite", Version: "3.54.1"}, "sqlite-autoconf-3540100"},
		{Resolved{Name: "sqlite", Version: "3.9.0"}, "sqlite-autoconf-3090000"},
	}
	for _, tt := range tests {
		if got := SourceDir(tt.r); got != tt.want {
			t.Errorf("SourceDir(%s %s) = %s, want %s", tt.r.Name, tt.r.Version, got, tt.want)
		}
	}
}

func TestNewer(t *testing.T) {
	for _, tt := range []struct {
		a, b string
		want bool
	}{{"3.6.5", "3.6.4", true}, {"3.10.0", "3.9.9", true}, {"8.23.0", "8.4.1", true}, {"1.3", "1.3.0", false}, {"1.3.1", "1.3", true}, {"7.1.2-34", "7.1.2-9", true}, {"7.1.2-1", "7.1.1-99", true}, {"7.1.2", "7.1.2-1", false}, {"18.6", "18.10", false}} {
		if got := newer(tt.a, tt.b); got != tt.want {
			t.Errorf("newer(%s, %s) = %v", tt.a, tt.b, got)
		}
	}
}

// TestRecipes checks every library has a recipe whose commands install into the prefix and carry the RUNPATH
// of the library itself and of its dependencies.
func TestRecipes(t *testing.T) {
	deps := map[string]string{"zlib": "/opt/p/libs/zlib-1.3.2", "openssl": "/opt/p/libs/openssl-3.6.5", "libpng": "/opt/p/libs/libpng-1.6.59"}
	for _, n := range Names() {
		prefix := "/opt/p/libs/" + n + "-1.0"
		cmds := Recipe(Resolved{Name: n, Version: "1.0"}, prefix, deps, 4)
		if len(cmds) == 0 {
			t.Errorf("%s: no recipe", n)
			continue
		}
		joined := ""
		for _, c := range cmds {
			joined += c.Name + " " + strings.Join(c.Args, " ") + " " + strings.Join(c.Env, " ") + "\n"
		}
		if !strings.Contains(joined, prefix) {
			t.Errorf("%s: nothing installs into %s:\n%s", n, prefix, joined)
		}
		if !strings.Contains(joined, "-Wl,-rpath,"+prefix+"/lib") && !strings.Contains(joined, "CMAKE_INSTALL_RPATH="+prefix+"/lib") {
			t.Errorf("%s: no RUNPATH for its own lib dir:\n%s", n, joined)
		}
		if n == "curl" && !strings.Contains(joined, "--with-openssl=/opt/p/libs/openssl-3.6.5") {
			t.Errorf("curl is not linked to the built openssl:\n%s", joined)
		}
		if n == "freetype" && !strings.Contains(joined, "/opt/p/libs/libpng-1.6.59/lib/pkgconfig") {
			t.Errorf("freetype cannot see libpng's pkg-config dir:\n%s", joined)
		}
	}
	if got := Recipe(Resolved{Name: "zlib"}, "/p", nil, 0); !strings.Contains(strings.Join(got[1].Args, " "), "-j1") {
		t.Errorf("jobs below 1 must run as -j1: %+v", got[1])
	}
	if icu := Recipe(Resolved{Name: "icu"}, "/p", nil, 2); icu[0].Dir != "source" {
		t.Errorf("icu builds in its source/ directory: %+v", icu[0])
	}
}
