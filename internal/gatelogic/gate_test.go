package gatelogic

import (
	"testing"
	"time"
)

func TestNormalizeHost(t *testing.T) {
	for h, want := range map[string]string{
		"Staging.Example.com":     "staging.example.com",
		"staging.example.com.":    "staging.example.com",
		"staging.example.com:443": "staging.example.com",
		"S.ONARR.EXAMPLE.COM:80":  "s.onarr.example.com",
		"":                        "",
	} {
		if got := NormalizeHost(h); got != want {
			t.Errorf("NormalizeHost(%q) = %q, want %q", h, got, want)
		}
	}
}

func TestNormalizeEmail(t *testing.T) {
	if e, err := NormalizeEmail(" Alice@Example.COM "); err != nil || e != "alice@example.com" {
		t.Errorf("got %q %v", e, err)
	}
	for _, bad := range []string{"", "a b@example.com", "Alice <a@example.com>", "@example.com", "a@", "not-an-email"} {
		if _, err := NormalizeEmail(bad); err == nil {
			t.Errorf("NormalizeEmail(%q) accepted", bad)
		}
	}
}

func TestParseACL(t *testing.T) {
	rules, err := ParseACL("alice@example.com\n@Contractor.example\n\nBob@x.io\nalice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	want := []Rule{
		{"email", "alice@example.com"},
		{"domain", "contractor.example"},
		{"email", "bob@x.io"},
	}
	if len(rules) != len(want) {
		t.Fatalf("rules: %+v", rules)
	}
	for i, w := range want {
		if rules[i] != w {
			t.Errorf("rule %d: %+v, want %+v", i, rules[i], w)
		}
	}
	for _, bad := range []string{"alice", "@nodot", "@.bad", "a b@x.com", "a@x\njoe", "@"} {
		if _, err := ParseACL(bad); err == nil {
			t.Errorf("ParseACL(%q) accepted", bad)
		}
	}
	if rules, err := ParseACL(""); err != nil || len(rules) != 0 {
		t.Errorf("empty: %v %v", rules, err)
	}
	// A bare word is refused: silent interpretations are not allowed.
	if _, err := ParseACL("xexample.com"); err == nil {
		t.Error("bare word accepted")
	}
}

func TestQualify(t *testing.T) {
	rules := []Rule{{"email", "alice@example.com"}, {"domain", "dev.example"}}
	for email, want := range map[string]bool{
		"alice@example.com":        true,
		"bob@example.com":          false,
		"anyone@dev.example":       true,
		"evil@notdev.example":      false,
		"alice@example.org":        false,
		"alice@xalice@example.com": false,
	} {
		if got := Qualify(email, rules); got != want {
			t.Errorf("Qualify(%q) = %v, want %v", email, got, want)
		}
	}
}

func TestWindow(t *testing.T) {
	if Window("acl") != 30*24*time.Hour || Window("open") != 7*24*time.Hour {
		t.Fatal("windows wrong")
	}
	if Window("") < 7*24*time.Hour { // unknown mode: the short window, fail closed
		t.Fatal("unknown mode got long window")
	}
}
