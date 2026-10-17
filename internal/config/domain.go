package config

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
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

var usernameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)

// ValidateUsername accepts a lower-case admin username: 1-32 characters of a-z, 0-9, '.', '_' and '-', starting with a letter or digit.
func ValidateUsername(name string) error {
	if !usernameRE.MatchString(name) {
		return fmt.Errorf("username %q: use 1-32 lower-case letters, digits, '.', '_' or '-', starting with a letter or digit", name)
	}
	return nil
}

// ValidatePassword accepts a password an admin may set in the UI or CLI: 8 to 72 bytes (bcrypt ignores the rest,
// so longer would be silently truncated) and no NUL byte. The ADMIN_PASSWORD seed is exempt: it is the operator's call.
func ValidatePassword(pw string) error {
	switch {
	case len(pw) < 8:
		return errors.New("password must be at least 8 characters")
	case len(pw) > 72:
		return errors.New("password must be at most 72 bytes")
	case strings.ContainsRune(pw, 0):
		return errors.New("password must not contain a NUL byte")
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

var reservedV4 = netip.MustParsePrefix("240.0.0.0/4")
var thisNetworkV4 = netip.MustParsePrefix("0.0.0.0/8")

// ValidateIP accepts any IPv4 address a server can have: public, private (10/8, 172.16/12, 192.168/16)
// or CGNAT (100.64/10, Tailscale). Loopback, link-local, multicast, broadcast, reserved and "this network"
// addresses are refused, and so is IPv6: use ValidateIP6 for AAAA targets.
func ValidateIP(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is4() || !a.IsGlobalUnicast() || reservedV4.Contains(a) || thisNetworkV4.Contains(a) {
		return netip.Addr{}, fmt.Errorf("%q must be a usable IPv4 address (loopback, link-local, multicast and reserved addresses, and IPv6, are not)", s)
	}
	return a, nil
}

// ValidateIP6 accepts a global unicast IPv6 address (public, or unique-local fc00::/7). Loopback, the
// unspecified address, link-local, multicast, IPv4-mapped addresses, scoped addresses (fe80::1%eth0) and
// any IPv4 text are refused.
func ValidateIP6(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is6() || a.Is4In6() || a.Zone() != "" || !a.IsGlobalUnicast() {
		return netip.Addr{}, fmt.Errorf("%q must be a usable IPv6 address (loopback, link-local, multicast and IPv4-mapped addresses, and IPv4, are not)", s)
	}
	return a, nil
}
