// Package gatelogic is the pure rule matching for the site access gate: host and email
// normalization, ACL rule parsing and qualification, per-mode session windows.
// No I/O of any kind; the store and the Caddy module both build on it.
package gatelogic

import (
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"time"
)

var domainRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

// Rule is one ACL entry: an exact email or an "@"+domain rule meaning any address at that domain.
type Rule struct {
	Mode  string // email | domain
	Value string // normalized
}

// NormalizeHost lowercases and strips the trailing dot and a port. Hosts in requests are
// hostname[:port] or [v6][:port]; "count==1 colon" covers every unbracketed case.
func NormalizeHost(h string) string {
	if i := strings.IndexByte(h, ':'); strings.Count(h, ":") == 1 {
		h = h[:i]
	}
	if h != "" && strings.HasSuffix(h, ":") { // bracketed v6 without port cannot occur as a Host here
		h = h[:len(h)-1]
	}
	if h != "" && strings.HasSuffix(h, ".") {
		h = h[:len(h)-1]
	}
	return strings.ToLower(h)
}

// NormalizeEmail trims and lowercases; returns an error for anything that is not a bare address.
func NormalizeEmail(s string) (string, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	a, err := mail.ParseAddress(s)
	if err != nil || a.Address != s {
		return "", fmt.Errorf("%q is not a bare email address", s)
	}
	return s, nil
}

// validDomain needs the same shape ServanaGo requires for real domains.
func validDomain(s string) bool { return domainRE.MatchString(s) }

// ParseACL turns textarea lines into rules. A line starting with @ is a domain rule and must
// carry a real domain; anything else must be a bare email. Lines are deduplicated.
func ParseACL(text string) ([]Rule, error) {
	var rules []Rule
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var mode string
		if strings.HasPrefix(line, "@") {
			line = strings.ToLower(line[1:])
			if !validDomain(line) {
				return nil, fmt.Errorf("%q is not a domain: use the full address for one person, @domain.com for everyone there", line)
			}
			mode = "domain"
		} else {
			e, err := NormalizeEmail(line)
			if err != nil {
				return nil, fmt.Errorf("allowlist: %w", err)
			}
			line = e
			mode = "email"
		}
		if seen[line] {
			continue
		}
		seen[line] = true
		rules = append(rules, Rule{Mode: mode, Value: line})
	}
	return rules, nil
}

// Qualify is the ACL check: does email match any of the site's rules.
func Qualify(email string, rules []Rule) bool {
	for _, r := range rules {
		if r.Mode == "email" {
			if r.Value == email {
				return true
			}
			continue
		}
		if strings.HasSuffix(email, "@"+r.Value) {
			return true
		}
	}
	return false
}

// Window is the sliding session window for a mode: allowlisted identities are trusted longer
// than open-site ones. Unknown modes get the short window (fail closed).
func Window(mode string) time.Duration {
	if mode == "acl" {
		return 30 * 24 * time.Hour
	}
	return 7 * 24 * time.Hour
}
