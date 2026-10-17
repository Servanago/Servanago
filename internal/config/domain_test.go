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

// A hosting manager publishes public addresses as well as LAN and CGNAT ones; only addresses that can
// never be a server's public or private address are refused.
func TestValidateIP(t *testing.T) {
	ok := []string{
		"10.0.0.0", "10.255.255.255", "172.16.0.0", "172.31.255.255", "192.168.0.1", "192.168.25.165", "100.64.0.0", "100.127.255.255",
		"8.8.8.8", "1.1.1.1", "203.0.113.10", "172.15.255.255", "172.32.0.0", "11.0.0.0", "100.128.0.0", "223.255.255.254",
	}
	bad := []string{
		"127.0.0.1", "127.255.255.254", "169.254.1.1", "0.0.0.0", "0.1.2.3", "224.0.0.1", "239.255.255.255", "240.0.0.1",
		"255.255.255.255", "::1", "fd00::1", "2001:db8::1", "::ffff:192.168.1.1", "", "not-an-ip", "192.168.1.1/24", "192.168.1", "999.1.1.1",
	}
	for _, s := range ok {
		if _, err := ValidateIP(s); err != nil {
			t.Errorf("%q rejected: %v", s, err)
		}
	}
	for _, s := range bad {
		if _, err := ValidateIP(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
	_, err := ValidateIP("127.0.0.1")
	if err == nil || !strings.Contains(err.Error(), "IPv4") || !strings.Contains(err.Error(), "loopback") {
		t.Errorf("error should say what is refused: %v", err)
	}
}

func TestValidateIP6(t *testing.T) {
	ok := []string{"2001:db8::1", "2606:4700:4700::1111", "2a00:1450:4001:81c::200e", "fd00::1", "fc00::1", "64:ff9b::808:808"}
	bad := []string{
		"::1", "::", "fe80::1", "fe80::1%eth0", "ff02::1", "::ffff:192.0.2.1", "192.168.1.1", "8.8.8.8",
		"", "not-an-ip", "2001:db8::/32", "2001:db8::1 ", "2001:db8:::1", "[2001:db8::1]",
	}
	for _, s := range ok {
		if _, err := ValidateIP6(s); err != nil {
			t.Errorf("%q rejected: %v", s, err)
		}
	}
	for _, s := range bad {
		if _, err := ValidateIP6(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
	if _, err := ValidateIP6("::1"); err == nil || !strings.Contains(err.Error(), "IPv6") {
		t.Errorf("error should name IPv6: %v", err)
	}
	// each validator refuses the other family
	if _, err := ValidateIP("2001:db8::1"); err == nil {
		t.Error("ValidateIP must stay IPv4-only")
	}
}

func TestValidateUsername(t *testing.T) {
	for _, s := range []string{"admin", "a", "bob.smith", "k_9-x", "0day", strings.Repeat("a", 32)} {
		if err := ValidateUsername(s); err != nil {
			t.Errorf("%q rejected: %v", s, err)
		}
	}
	for _, s := range []string{"", "Admin", "-bob", ".bob", "_bob", "bob smith", "bob@x.io", "bób", strings.Repeat("a", 33), "a/b", "a\x00b"} {
		if err := ValidateUsername(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestValidatePassword(t *testing.T) {
	for _, s := range []string{"12345678", "correct horse battery", strings.Repeat("x", 72), "pässwörd1"} {
		if err := ValidatePassword(s); err != nil {
			t.Errorf("%q rejected: %v", s, err)
		}
	}
	for _, s := range []string{"", "short", "1234567", strings.Repeat("x", 73), "has\x00nul-byte", strings.Repeat("é", 37)} { // 37 x 2 bytes = 74
		if err := ValidatePassword(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}
