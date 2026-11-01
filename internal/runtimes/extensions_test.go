package runtimes

import (
	"strings"
	"testing"
)

func TestParseExtensions(t *testing.T) {
	got, err := ParseExtensions([]string{" curl ", "mbstring", "curl", ""})
	if err != nil || strings.Join(got, ",") != "mbstring,curl" { // canonical load order, deduplicated
		t.Errorf("got %v, %v", got, err)
	}
	if got, err := ParseExtensions(nil); err != nil || len(got) != 0 {
		t.Errorf("empty must stay empty (the caller means the core set): %v %v", got, err)
	}
	for _, bad := range []string{"evil", "curl\nx", "CURL", "pdo", "openssl"} { // pdo and openssl are always on, not selectable
		if _, err := ParseExtensions([]string{bad}); err == nil || !strings.Contains(err.Error(), "not one of") {
			t.Errorf("%q accepted: %v", bad, err)
		}
	}
}

// Since PHP 8.5 opcache is built in: no opcache.so exists, so it is neither expected from a build nor loaded by an ini.
func TestOpcacheIsBuiltInFromPHP85(t *testing.T) {
	for branch, shared := range map[string]bool{"8.2": true, "8.4": true, "8.5": false, "8.6": false, "8.10": false, "9.0": false} {
		has := false
		for _, e := range SharedExtensions(branch) {
			has = has || e.Name == "opcache"
		}
		if has != shared {
			t.Errorf("branch %s: opcache shared = %v, want %v", branch, has, shared)
		}
	}
	if n := len(SharedExtensions("8.4")) - len(SharedExtensions("8.5")); n != 1 {
		t.Errorf("only opcache differs, got %d", n)
	}
}

// A selection is closed over Needs, in load order; with Needs empty it is just the sorted selection.
func TestCloseAddsWhatIsNeeded(t *testing.T) {
	old := PHPExtensions
	t.Cleanup(func() { PHPExtensions = old })
	PHPExtensions = append(append([]Ext(nil), old...), Ext{Name: "needy", Group: "extra", Needs: []string{"mbstring"}})
	if got := strings.Join(Close([]string{"needy", "curl"}), ","); got != "mbstring,curl,needy" {
		t.Errorf("got %s", got)
	}
	if got := strings.Join(Close([]string{"gd"}), ","); got != "gd" {
		t.Errorf("got %s", got)
	}
}

func TestLibsFor(t *testing.T) {
	if got := strings.Join(LibsFor([]string{"gd", "imagick", "sqlite3", "pdo_sqlite", "bcmath"}), ","); got != "libpng,libjpeg-turbo,freetype,libwebp,imagemagick,sqlite" {
		t.Errorf("got %s", got)
	}
}

// A build with no exts.txt holds what builds held before extensions were a choice; one with it holds exactly its list.
func TestPHPVersionHas(t *testing.T) {
	legacy := PHPVersion{Version: "8.4.1-1", Source: true}
	if !legacy.Has("imagick") || legacy.Has("redis") {
		t.Error("a legacy build holds LegacyExtensions only")
	}
	chosen := PHPVersion{Version: "8.4.2-1", Source: true, Exts: []string{"mbstring"}}
	if !chosen.Has("mbstring") || chosen.Has("curl") {
		t.Error("a build holds exactly its exts.txt")
	}
	if !(PHPVersion{Version: "8.2"}).Has("anything") {
		t.Error("a distro php-fpm is not judged")
	}
}
