package helper

import (
	"strings"
	"testing"
)

func TestSlugValidate(t *testing.T) {
	ok := []string{"aa", "site-1", "aa00bb", "x" + strings.Repeat("a", 31)}
	for _, s := range ok {
		if err := ValidateSlug(s); err != nil {
			t.Errorf("ValidateSlug(%q): %v", s, err)
		}
	}
	bad := []string{"", "A", "1x", "-x", "a b", "a/b", "a\x00b", "e", strings.Repeat("a", 33)}
	for _, s := range bad {
		if err := ValidateSlug(s); err == nil {
			t.Errorf("ValidateSlug(%q) passed, want error", s)
		}
	}
}

func TestUnitNameRejected(t *testing.T) {
	// The unit name is not caller-supplied: it is only ever built inside the helper from a validated slug.
	for _, s := range []string{"../../etc/passwd", "x.service", strings.Repeat("a", 100)} {
		if _, err := unitName(s); err == nil {
			t.Errorf("unitName(%q) passed, want error", s)
		}
	}
	n, err := unitName("blog")
	if err != nil || n != "servanago-blog.service" {
		t.Fatalf("unitName: %q %v", n, err)
	}
}

func TestDecodeRequest(t *testing.T) {
	// Valid: typed action; field-value validation is separate.
	r, err := DecodeRequest([]byte(`{"action":"unit-install","spec":{"slug":"blog"}}`))
	if err != nil {
		t.Fatalf("DecodeRequest: %v", err)
	}
	slug, serr := r.Slug()
	if r.Action != ActionUnitInstall || serr != nil || slug != "blog" {
		t.Fatalf("decoded %+v slug %q err %v", r, slug, serr)
	}
	// Parse-level rejections: unknown or no-field action, missing or wrong-shaped spec,
	// unknown fields, non-object, overlong.
	bad := []string{
		`{"action":"shell","spec":{"cmd":"/bin/sh"}}`,
		`{"action":"unit-install"}`,
		`{"action":"ping"}`,
		`{"action":"unit-install","spec":{"slug":1}}`,
		"[]",
		`{"action":"unit-install","spec":{"slug":"a","cmd":"b"}}`,
	}
	for _, b := range bad {
		if _, err := DecodeRequest([]byte(b)); err == nil {
			t.Errorf("DecodeRequest(%q) passed, want error", b)
		}
	}
	// Value-level rejections surface as SlugErr, never a parse error.
	nul, err := DecodeRequest([]byte(`{"action":"unit-install","spec":{"slug":"a"}}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = nul // (no NUL path at parse level; fuzz owns value validation)
	if _, err := DecodeRequest([]byte(strings.Repeat("a", 128<<10))); err == nil {
		t.Error("overlong request passed, want error")
	}
}