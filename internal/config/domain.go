package config

import (
	"fmt"
	"net/netip"
	"strings"
)

var internalSuffixes = []string{".local", ".internal", ".home.arpa"}

// ValidateDomain accepts a lowercase public DNS name Caddy will send to ACME.
// It rejects IP literals and suffixes Caddy would hand to its internal CA.
func ValidateDomain(name string) error {
	if name == "" || len(name) > 253 {
		return fmt.Errorf("domain %q: invalid length", name)
	}
	if _, err := netip.ParseAddr(strings.Trim(name, "[]")); err == nil {
		return fmt.Errorf("domain %q: IP literals are not allowed", name)
	}
	for _, s := range internalSuffixes {
		if strings.HasSuffix(name, s) || name == s[1:] {
			return fmt.Errorf("domain %q: %s names use Caddy's internal CA, not ACME", name, s)
		}
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return fmt.Errorf("domain %q: need at least two labels", name)
	}
	for _, l := range labels {
		if err := ValidateLabel(l); err != nil {
			return fmt.Errorf("domain %q: %w", name, err)
		}
	}
	return nil
}

// ValidateLabel checks one lowercase DNS label.
func ValidateLabel(l string) error {
	if l == "" || len(l) > 63 {
		return fmt.Errorf("label %q: length must be 1-63", l)
	}
	if l[0] == '-' || l[len(l)-1] == '-' {
		return fmt.Errorf("label %q: must not start or end with '-'", l)
	}
	for _, c := range l {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return fmt.Errorf("label %q: only a-z, 0-9 and '-' allowed", l)
		}
	}
	return nil
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// ValidateLANIP accepts private IPv4 (10/8, 172.16/12, 192.168/16) and CGNAT (100.64/10, Tailscale).
// Caretakarr never publishes public addresses.
func ValidateLANIP(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is4() || !(a.IsPrivate() || cgnat.Contains(a)) {
		return netip.Addr{}, fmt.Errorf("%q must be a private IPv4 address (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 or 100.64.0.0/10)", s)
	}
	return a, nil
}
