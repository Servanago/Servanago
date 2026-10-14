package config

import (
	"strings"
	"testing"
)

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

func TestValidateLANIP(t *testing.T) {
	ok := []string{"10.0.0.0", "10.255.255.255", "172.16.0.0", "172.31.255.255", "192.168.0.1", "192.168.25.165", "100.64.0.0", "100.127.255.255"}
	bad := []string{
		"172.15.255.255", "172.32.0.0", "100.63.255.255", "100.128.0.0", "192.167.255.255", "11.0.0.0",
		"8.8.8.8", "203.0.113.10", "127.0.0.1", "169.254.1.1", "0.0.0.0", "224.0.0.1", "255.255.255.255",
		"::1", "fd00::1", "::ffff:192.168.1.1", "", "not-an-ip", "192.168.1.1/24", "192.168.1",
	}
	for _, s := range ok {
		if _, err := ValidateLANIP(s); err != nil {
			t.Errorf("%q rejected: %v", s, err)
		}
	}
	for _, s := range bad {
		if _, err := ValidateLANIP(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
	_, err := ValidateLANIP("8.8.8.8")
	if err == nil || !strings.Contains(err.Error(), "192.168.0.0/16") || !strings.Contains(err.Error(), "100.64.0.0/10") {
		t.Errorf("error should list allowed ranges: %v", err)
	}
}
