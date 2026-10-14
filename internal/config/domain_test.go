package config

import "testing"

func TestValidateDomain(t *testing.T) {
	ok := []string{"example.com", "a-b.example.co.uk", "xn--bcher-kva.example", "x1.io"}
	bad := []string{
		"", "example", "foo.local", "foo.internal", "foo.home.arpa", "home.arpa", "FOO.LOCAL",
		"192.168.1.1", "::1", "[::1]", "1.2.3.4", "-a.com", "a-.com", "a..com", "exa mple.com",
		"example.com.", "https://example.com", "example.com/path", "under_score.com",
	}
	for _, d := range ok {
		if err := ValidateDomain(d); err != nil {
			t.Errorf("%q rejected: %v", d, err)
		}
	}
	for _, d := range bad {
		if err := ValidateDomain(d); err == nil {
			t.Errorf("%q accepted", d)
		}
	}
}
