package phplibs

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func TestNamesOrder(t *testing.T) {
	n := Names()
	for i, v := range n {
		if v == "libwebp" && n[i+1] != "imagemagick" {
			t.Errorf("imagemagick must follow libwebp: %v", n)
		}
	}
	if !versionRE.MatchString("7.1.2-34") || versionRE.MatchString("7.1.2-") || versionRE.MatchString("7.1.2-x") || versionRE.MatchString("7.1.2--1") {
		t.Error("version regexp must take an optional -N and nothing else")
	}
}

func TestResolveExtRecorded(t *testing.T) {
	tests := []struct{ name, pkg, version, commit string }{
		{"apcu", "apcu/apcu", "5.1.28", "819fce90c469a5666b1706036cd66120af419f1f"},
		{"imagick", "imagick/imagick", "3.8.1", "70087bab33eab913e99ac77d64d04d1a2fd0b7b0"}, // 3.8.0RC1/RC2 are skipped
	}
	for _, tt := range tests {
		e, err := ResolveExt(context.Background(), fixtureGetter(t), tt.name)
		if err != nil {
			t.Fatalf("%s: %v", tt.name, err)
		}
		repo := strings.Split(tt.pkg, "/")[1]
		if e.Name != tt.name || e.Package != tt.pkg || e.Version != tt.version || e.Commit != tt.commit ||
			!strings.HasPrefix(strings.ToLower(e.URL), "https://api.github.com/repos/") || !strings.HasSuffix(e.URL, "/"+repo+"/zipball/"+tt.commit) && !strings.HasSuffix(strings.ToLower(e.URL), "/"+repo+"/zipball/"+tt.commit) {
			t.Errorf("%s: %+v", tt.name, e)
		}
	}
	if got := ExtNames(); len(got) != 2 || got[0] != "apcu" || got[1] != "imagick" {
		t.Errorf("ExtNames %v", got)
	}
}

// feed builds a minified p2 document the way Packagist serves it: the first entry is complete, the rest list
// only their differences.
func feed(pkg string, entries ...string) string {
	return `{"minified":"composer/2.0","packages":{"` + pkg + `":[` + strings.Join(entries, ",") + `]}}`
}

const commit = "0123456789abcdef0123456789abcdef01234567"

func dist(owner, repo, ref string) string {
	return `"dist":{"url":"https://api.github.com/repos/` + owner + `/` + repo + `/zipball/` + ref + `","type":"zip","reference":"` + ref + `"},"source":{"url":"https://github.com/` + owner + `/` + repo + `.git","type":"git","reference":"` + ref + `"}`
}

func full(version, typ, extName, distAndSource string) string {
	return `{"version":"` + version + `","type":"` + typ + `","php-ext":{"extension-name":"` + extName + `"},` + distAndSource + `}`
}

func TestResolveExtStableFilter(t *testing.T) {
	other := strings.Repeat("b", 40)
	// dev-master leads (a complete entry), then a beta, an RC and an alpha that inherit from it, then the stable
	// ones. The newest stable inherits type and php-ext from entries above it.
	body := feed("apcu/apcu",
		full("dev-master", "php-ext", "apcu", dist("krakjoe", "apcu", other)),
		`{"version":"v6.0.0-beta1",`+dist("krakjoe", "apcu", other)+`}`,
		`{"version":"6.0.0RC1",`+dist("krakjoe", "apcu", other)+`}`,
		`{"version":"v6.0.0-alpha2",`+dist("krakjoe", "apcu", other)+`}`,
		`{"version":"v5.1.9",`+dist("krakjoe", "apcu", commit)+`}`,
		`{"version":"v5.1.10",`+dist("krakjoe", "apcu", other)+`}`,
	)
	e, err := ResolveExt(context.Background(), func(context.Context, string) ([]byte, error) { return []byte(body), nil }, "apcu")
	if err != nil {
		t.Fatal(err)
	}
	if e.Version != "5.1.10" || e.Commit != other {
		t.Errorf("must pick the highest stable (5.1.10, numerically above 5.1.9): %+v", e)
	}
}

func TestResolveExtRejects(t *testing.T) {
	d := dist("krakjoe", "apcu", commit)
	tests := []struct{ name, body, want string }{
		{"not a php-ext", feed("apcu/apcu", full("v5.1.0", "library", "apcu", d)), `not php-ext`},
		{"wrong extension name", feed("apcu/apcu", full("v5.1.0", "php-ext", "apc", d)), `extension-name is "apc"`},
		{"dist is not a zipball", feed("apcu/apcu", full("v5.1.0", "php-ext", "apcu", strings.Replace(d, "api.github.com/repos/krakjoe/apcu/zipball/"+commit, "example.com/apcu.zip", 1))), "not a https GitHub zipball"},
		{"dist over http", feed("apcu/apcu", full("v5.1.0", "php-ext", "apcu", strings.Replace(d, `"url":"https://api`, `"url":"http://api`, 1))), "not a https GitHub zipball"},
		{"dist host look-alike", feed("apcu/apcu", full("v5.1.0", "php-ext", "apcu", strings.Replace(d, "https://api.github.com", "https://api.github.com.evil.example", 1))), "not a https GitHub zipball"},
		{"zipball of a branch, not a commit", feed("apcu/apcu", full("v5.1.0", "php-ext", "apcu", strings.Replace(d, "zipball/"+commit, "zipball/master", 1))), "not a https GitHub zipball"},
		{"source names another commit", feed("apcu/apcu", full("v5.1.0", "php-ext", "apcu", strings.Replace(d, `"source":{"url":"https://github.com/krakjoe/apcu.git","type":"git","reference":"`+commit, `"source":{"url":"https://github.com/krakjoe/apcu.git","type":"git","reference":"`+strings.Repeat("c", 40), 1))), "do not both name commit"},
		{"dist reference names another commit", feed("apcu/apcu", full("v5.1.0", "php-ext", "apcu", strings.Replace(d, `"type":"zip","reference":"`+commit, `"type":"zip","reference":"`+strings.Repeat("c", 40), 1))), "do not both name commit"},
		{"repository is not the package", feed("apcu/apcu", full("v5.1.0", "php-ext", "apcu", dist("krakjoe", "evil", commit))), `repository "evil"`},
		{"only unstable versions", feed("apcu/apcu", full("dev-master", "php-ext", "apcu", d), `{"version":"v6.0.0-beta1"}`, `{"version":"v6.0.0RC2"}`), "no stable release"},
		{"version is not dotted numbers", feed("apcu/apcu", full("5.1.0.1.1", "php-ext", "apcu", d)), "no stable release"},
		{"php-ext unset on the stable release", feed("apcu/apcu", full("dev-master", "php-ext", "apcu", d), `{"version":"v5.1.0","php-ext":"__unset"}`), `field "php-ext"`},
		{"package missing from the feed", feed("other/pkg", full("v5.1.0", "php-ext", "apcu", d)), "no stable release"},
		{"not json", "<html>", "packagist feed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ResolveExt(context.Background(), func(context.Context, string) ([]byte, error) { return []byte(tt.body), nil }, "apcu")
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error %v, want one containing %q", err, tt.want)
			}
		})
	}
	if _, err := ResolveExt(context.Background(), nil, "redis"); err == nil || !strings.Contains(err.Error(), "unknown extension") {
		t.Errorf("unknown extension: %v", err)
	}
	if _, err := ResolveExt(context.Background(), func(context.Context, string) ([]byte, error) { return nil, fmt.Errorf("boom") }, "imagick"); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("feed error: %v", err)
	}
}

func TestExtRecipe(t *testing.T) {
	deps := map[string]string{"imagemagick": "/opt/p/libs/imagemagick-7.1.2-34", "zlib": "/opt/p/libs/zlib-1.3.2"}
	join := func(cs []Cmd) string {
		var b strings.Builder
		for _, c := range cs {
			b.WriteString(c.Name + " " + strings.Join(c.Args, " ") + "\n")
		}
		return b.String()
	}
	apcu := ExtRecipe(ExtSource{Name: "apcu"}, "/opt/php/8.4.27-1", nil, 4)
	if len(apcu) != 4 || apcu[0].Name != "/opt/php/8.4.27-1/bin/phpize" || apcu[0].Dir != "" ||
		!strings.Contains(join(apcu), "./configure --with-php-config=/opt/php/8.4.27-1/bin/php-config --enable-apcu") ||
		!strings.Contains(join(apcu), "make -j4") || !strings.Contains(join(apcu), "make install") {
		t.Errorf("apcu:\n%s", join(apcu))
	}
	im := ExtRecipe(ExtSource{Name: "imagick"}, "/opt/php/8.4.27-1", deps, 0)
	if len(im) != 4 || !strings.Contains(join(im), "--with-imagick=/opt/p/libs/imagemagick-7.1.2-34") || !strings.Contains(join(im), "make -j1") {
		t.Errorf("imagick:\n%s", join(im))
	}
	if !strings.Contains(strings.Join(im[1].Env, " "), "/opt/p/libs/imagemagick-7.1.2-34/lib/pkgconfig") {
		t.Errorf("imagick cannot see ImageMagick's pkg-config dir: %v", im[1].Env)
	}
	if got := ExtRecipe(ExtSource{Name: "imagick"}, "/opt/php/8.4.27-1", map[string]string{"zlib": "/z"}, 2); got != nil {
		t.Errorf("imagick without imagemagick must return nil, got %+v", got)
	}
	if got := ExtRecipe(ExtSource{Name: "redis"}, "/opt/php/8.4.27-1", deps, 2); got != nil {
		t.Errorf("unknown extension must return nil, got %+v", got)
	}
}
