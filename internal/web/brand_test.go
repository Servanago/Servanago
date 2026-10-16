package web

import (
	"io/fs"
	"math"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func readAsset(t *testing.T, name string) string {
	t.Helper()
	b, err := fs.ReadFile(assets, name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

func TestBrandAssetsShipped(t *testing.T) {
	for _, f := range []string{"servanago.css", "favicon-16.png", "favicon-32.png", "apple-touch-icon.png", "mark-64.png", "mark-192.png"} {
		if _, err := fs.Stat(assets, "static/"+f); err != nil {
			t.Errorf("static/%s missing: %v", f, err)
		}
	}
}

func TestTemplatesUseBrandAndExistingStatics(t *testing.T) {
	ref := regexp.MustCompile(`/static/([A-Za-z0-9._-]+)`)
	entries, err := fs.ReadDir(assets, "templates")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		body := readAsset(t, "templates/"+e.Name())
		if strings.Contains(strings.ToLower(body), "takarr") {
			t.Errorf("%s still carries the old product name", e.Name())
		}
		for _, m := range ref.FindAllStringSubmatch(body, -1) {
			if _, err := fs.Stat(assets, "static/"+m[1]); err != nil {
				t.Errorf("%s references /static/%s, which is not embedded", e.Name(), m[1])
			}
		}
	}
	if !strings.Contains(readAsset(t, "templates/layout.html"), `Servana<b>Go</b>`) {
		t.Error("layout wordmark is not Servana<b>Go</b>")
	}
}

func luminance(hex string) float64 {
	n, _ := strconv.ParseUint(strings.TrimPrefix(hex, "#"), 16, 32)
	ch := func(v uint64) float64 {
		c := float64(v) / 255
		if c <= 0.03928 {
			return c / 12.92
		}
		return math.Pow((c+0.055)/1.055, 2.4)
	}
	return 0.2126*ch(n>>16&255) + 0.7152*ch(n>>8&255) + 0.0722*ch(n&255)
}

func contrast(a, b string) float64 {
	x, y := luminance(a), luminance(b)
	if x < y {
		x, y = y, x
	}
	return (x + 0.05) / (y + 0.05)
}

// The pack's light-surface tokens (green-700 under white text, slate-500 muted text, semantic
// success/danger/info) fail WCAG AA on the dark UI; the theme must use the passing variants.
func TestThemeMeetsContrast(t *testing.T) {
	css := readAsset(t, "static/servanago.css")
	if strings.Contains(css, "--ct-") {
		t.Error("old --ct-* tokens remain")
	}
	tok := map[string]string{}
	alias := map[string]string{}
	for _, m := range regexp.MustCompile(`--sg-([a-z0-9-]+):\s*(#[0-9A-Fa-f]{6}|var\(--sg-[a-z0-9-]+\))`).FindAllStringSubmatch(css, -1) {
		if strings.HasPrefix(m[2], "var(") {
			alias[m[1]] = strings.TrimSuffix(strings.TrimPrefix(m[2], "var(--sg-"), ")")
			continue
		}
		tok[m[1]] = m[2]
	}
	for k, v := range alias { // one level of aliasing is all the theme uses
		tok[k] = tok[v]
	}
	pairs := []struct{ fg, bg string }{
		{"white", "green-800"}, // primary button label
		{"text", "bg"}, {"text", "surface"}, {"text-secondary", "bg"}, {"text-secondary", "surface"},
		{"text-muted", "bg"}, {"text-muted", "surface"}, {"text-muted", "surface-raised"},
		{"accent", "bg"}, {"accent", "surface"},
		{"success", "bg"}, {"success", "surface"}, {"warning", "bg"}, {"warning", "surface"},
		{"danger", "bg"}, {"danger", "surface"}, {"info", "bg"},
		{"white", "green-900"}, // primary button hover
	}
	for _, p := range pairs {
		fg, ok1 := tok[p.fg]
		bg, ok2 := tok[p.bg]
		if !ok1 || !ok2 {
			t.Errorf("token --sg-%s or --sg-%s is not defined", p.fg, p.bg)
			continue
		}
		if r := contrast(fg, bg); r < 4.5 {
			t.Errorf("--sg-%s (%s) on --sg-%s (%s) = %.2f:1, want >= 4.5", p.fg, fg, p.bg, bg, r)
		}
	}
	for _, want := range []string{"--pico-primary-background: var(--sg-green-800)", "--pico-primary-inverse: var(--sg-white)"} {
		if !strings.Contains(css, want) {
			t.Errorf("css lacks %q", want)
		}
	}
}
